#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, map_db_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, ClaimId, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput,
    TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::access_control::{
    batch_check_content_access, check_content_access, ContentAccess,
};
use epigraph_db::PatchClaimInput;
use epigraph_db::{
    ClaimRepository, DbError, EdgeRepository, EvidenceRepository, ReasoningTraceRepository,
};
use uuid::Uuid;

/// Resolve an agent-supplied methodology string to a [`Methodology`].
///
/// The accepted vocabulary is the union of three sets, and nothing else — that
/// rule is what keeps this function from drifting into ad-hoc synonyms:
///
/// 1. every canonical key in `calibration.toml` `[methodology_profiles]` and
///    every alias in `[methodology_aliases]`. The DS calibrator already has a
///    tuned profile for each; rejecting one here means the write surface will
///    not accept a methodology the belief engine is calibrated to score.
///    Enforced by `tests::the_calibrated_methodology_vocabulary_is_accepted`.
/// 2. the serde (snake_case) name of every `Methodology` variant, so a value
///    read back off a stored `ReasoningTrace` round-trips. Enforced by
///    `tests::every_methodology_variant_is_reachable_from_the_mcp_surface`.
/// 3. `direct_observation` / `observation` — the plain-language names for the
///    dominant evidence mode of an engineering defect report (BL-9).
///
/// Hyphens normalize to underscores, so calibration's `"meta-analysis"` alias
/// resolves too.
///
/// `Methodology` is deliberately coarser (9 variants) than the calibration
/// vocabulary (15 profiles + 14 aliases), so several strings share a variant.
/// The enum is the trust-modifier bucket; the calibration key is the tuned
/// mass profile.
fn parse_methodology(s: &str) -> Result<Methodology, String> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "bayesian_inference" | "bayesian" => Ok(Methodology::BayesianInference),

        "deductive_logic" | "deductive" | "deductive_reasoning" | "theoretical_derivation" => {
            Ok(Methodology::Deductive)
        }

        // meta-analysis is a statistical synthesis over a population of prior
        // studies — an inductive generalization, not a formal proof. It used to
        // map to FormalProof, handing the single highest trust modifier in the
        // system (1.2, above Deductive's 1.1) to an empirical synthesis that
        // calibration.toml itself ranks BELOW deductive_logic (0.80 vs 0.85).
        "inductive_generalization" | "inductive" | "meta_analysis" | "meta" => {
            Ok(Methodology::Inductive)
        }

        "abductive" => Ok(Methodology::Abductive),

        // Direct observation lands on Instrumental by the repo's own authority:
        // calibration.toml [methodology_aliases] maps
        // `experimental_observation = "instrumental"`. `statistical_analysis`
        // stays here to agree with the sibling mapping
        // `ingestion::methodology_from_planned`.
        "statistical_analysis"
        | "statistical"
        | "statistical_inference"
        | "instrumental"
        | "instrumental_measurement"
        | "computational"
        | "computational_simulation"
        | "observational"
        | "observation"
        | "direct_observation"
        | "experimental_observation"
        | "negative_result" => Ok(Methodology::Instrumental),

        "visual_inspection" => Ok(Methodology::VisualInspection),

        // Reading an assertion out of a document, rather than deriving or
        // measuring it.
        "extraction"
        | "llm_extraction"
        | "literature_synthesis"
        | "legal_document_review"
        | "textbook_assertion" => Ok(Methodology::Extraction),

        "formal_proof" | "proof" | "mathematical_proof" => Ok(Methodology::FormalProof),

        "expert_elicitation" | "expert" | "testimonial" | "heuristic" => Ok(Methodology::Heuristic),

        other => Err(format!("unknown methodology: {other}")),
    }
}

/// Load the evidence-type weight from CalibrationConfig.
///
/// I-3: Checks `CALIBRATION_PATH` env var first, then falls back to the
/// relative path "calibration.toml". On any failure silently returns 0.7 so
/// that DS wiring is never blocked by a missing config file.
fn load_evidence_type_weight(evidence_type: &str) -> f64 {
    let path = std::env::var("CALIBRATION_PATH").unwrap_or_else(|_| "calibration.toml".to_string());
    epigraph_engine::calibration::CalibrationConfig::load(std::path::Path::new(&path))
        .ok()
        .map(|c| c.get_evidence_type_weight(evidence_type))
        .unwrap_or(0.7)
}

fn parse_evidence_type(s: &str, source_url: Option<&str>) -> Result<EvidenceType, String> {
    match s.to_lowercase().as_str() {
        "empirical" => Ok(EvidenceType::Observation {
            observed_at: chrono::Utc::now(),
            method: "empirical".to_string(),
            location: None,
        }),
        "statistical" | "logical" | "circumstantial" => Ok(EvidenceType::Document {
            source_url: source_url.map(String::from),
            mime_type: "text/plain".to_string(),
            checksum: None,
        }),
        "testimonial" => Ok(EvidenceType::Testimony {
            source: source_url.unwrap_or("unknown").to_string(),
            testified_at: chrono::Utc::now(),
            verification: None,
        }),
        other => Err(format!(
            "unknown evidence type: {other}. Expected: empirical, statistical, logical, testimonial, circumstantial"
        )),
    }
}

const MAX_CONFIDENCE_SCOPE_CHARS: usize = 2000;
const MAX_KNOWN_ISSUES: usize = 32;
const MAX_KNOWN_ISSUE_CHARS: usize = 500;

/// Validate a writer's confidence declaration and render it as a `properties`
/// patch, or `Ok(None)` when nothing was declared.
///
/// A bare `confidence: 0.9` records a number with no conditions of validity: a
/// reader cannot tell whether it means "n=1 on one laptop" or "n=10000 across
/// three platforms". `confidence_scope` and `known_issues` are the writer's
/// answer to that, stored beside the scalar they qualify.
///
/// Three load-bearing decisions live here:
///
/// 1. **One top-level key.** Everything nests under a single
///    `confidence_declaration` object. `ClaimRepository::merge_properties` is a
///    shallow `||`, so a patch with several top-level keys could clobber a
///    sibling from the documented `properties` vocabulary (`level`, `event`,
///    `methodology`, `section`, `reasoning_chain`, `asserted_by_authors`,
///    `source_doi`, `extraction_persona`). With exactly one key it cannot.
/// 2. **The block is written whole.** A later re-declaration is last-writer-wins
///    over the entire block, not a per-field merge — re-submitting with only
///    `confidence_scope` DROPS a previously stored `known_issues`. That is
///    intended: the declaration is the unit of assertion, and a half-updated
///    caveat is worse than a replaced one. It is also stated in the schemars
///    description so a caller is not surprised.
/// 3. **Bounds count `chars()`, never bytes, and nothing is truncated.** An
///    over-long declaration is REJECTED, because a silently truncated caveat
///    reads as a complete one and is worse than no caveat at all. Counting
///    chars also means no byte-slicing panic on multi-byte input.
///
/// The function takes no clock and touches no database, which is what makes it
/// unit-testable in-crate (see `tests` at the bottom of this file) and what
/// lets `submit_claim` reject a bad declaration before it writes anything.
fn build_confidence_declaration(
    scope: Option<&str>,
    known_issues: &[String],
) -> Result<Option<serde_json::Value>, String> {
    let mut block = serde_json::Map::new();

    if let Some(raw) = scope {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(
                "confidence_scope must not be empty or whitespace-only; omit the field instead"
                    .to_string(),
            );
        }
        let len = trimmed.chars().count();
        if len > MAX_CONFIDENCE_SCOPE_CHARS {
            return Err(format!(
                "confidence_scope is {len} characters; the maximum is {MAX_CONFIDENCE_SCOPE_CHARS}"
            ));
        }
        block.insert(
            "scope".to_string(),
            serde_json::Value::String(trimmed.to_string()),
        );
    }

    if !known_issues.is_empty() {
        if known_issues.len() > MAX_KNOWN_ISSUES {
            return Err(format!(
                "known_issues has {} entries; the maximum is {MAX_KNOWN_ISSUES}",
                known_issues.len()
            ));
        }
        let mut issues = Vec::with_capacity(known_issues.len());
        for (i, raw) in known_issues.iter().enumerate() {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(format!(
                    "known_issues[{i}] must not be empty or whitespace-only"
                ));
            }
            let len = trimmed.chars().count();
            if len > MAX_KNOWN_ISSUE_CHARS {
                return Err(format!(
                    "known_issues[{i}] is {len} characters; the maximum is {MAX_KNOWN_ISSUE_CHARS}"
                ));
            }
            issues.push(serde_json::Value::String(trimmed.to_string()));
        }
        block.insert("known_issues".to_string(), serde_json::Value::Array(issues));
    }

    if block.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        serde_json::json!({ "confidence_declaration": serde_json::Value::Object(block) }),
    ))
}

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn submit_claim(
    server: &EpiGraphMcpFull,
    mut params: SubmitClaimParams,
) -> Result<CallToolResult, McpError> {
    let methodology = parse_methodology(&params.methodology).map_err(invalid_params)?;
    let evidence_type = parse_evidence_type(&params.evidence_type, params.source_url.as_deref())
        .map_err(invalid_params)?;
    // Sits with the other two parse-and-reject calls on purpose: an invalid
    // declaration must fail with `invalid_params` BEFORE the agent lookup,
    // before the novelty gate's embedder call, and before any row is inserted.
    // Building the owned value here also sidesteps the later partial move of
    // `params.reasoning`.
    let confidence_declaration =
        build_confidence_declaration(params.confidence_scope.as_deref(), &params.known_issues)
            .map_err(invalid_params)?;
    // Same reasoning as the two calls above: `update_labels` below already
    // runs this guard, but it fires AFTER `create_claim_idempotent` has
    // inserted the row, which would leave a persisted claim with none of the
    // caller's labels. Validating the caller's labels at fn entry rejects the
    // submission before anything is written. The one label this function adds
    // itself ("near-duplicate", pushed by the novelty gate below) is a
    // constant and always clean, so checking here loses no coverage.
    epigraph_db::reject_shell_expansion(&params.labels).map_err(map_db_error)?;

    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();
    let confidence = params.confidence.clamp(0.0, 1.0);

    let weight = load_evidence_type_weight(&params.evidence_type);
    let raw_truth = (confidence * weight).clamp(0.01, 0.99);
    let truth_value = TruthValue::clamped(raw_truth);

    let mut claim = Claim::new(params.content.clone(), agent_id_typed, pub_key, truth_value);
    let content_hash = ContentHasher::hash(params.content.as_bytes());
    claim.content_hash = content_hash;
    claim.signature = Some(server.signer.sign(&content_hash));

    // Write-side semantic novelty gate (backlog 1bcaed94, Task 6.4). Runs
    // ONLY on genuinely new content: a read-only content-hash existence
    // check happens FIRST so an exact-content resubmit takes the existing
    // create_claim_idempotent dedup path unchanged (no embedding call, no
    // gate, byte-identical to pre-gate behavior — the gate augments that
    // path, it does not replace it). See crate::tools::novelty_gate.
    let is_exact_resubmit = {
        let mut conn = server.pool.acquire().await.map_err(internal_error)?;
        ClaimRepository::find_by_content_hash_and_agent(&mut conn, &content_hash, agent_id)
            .await
            .map_err(internal_error)?
            .is_some()
    };
    let mut pending_embedding: Option<String> = None;
    // Neighbours the write-time contradiction scan flagged (backlog 6ed02d04).
    // Computed by the same `decide` call — it scans the ANN neighbours the gate
    // already fetched — and staged for review AFTER the claim row and its
    // embedding exist, since `match_candidates.claim_a/claim_b` are FKs into
    // `claims(id)`.
    let mut contradiction_signals: Vec<crate::tools::contradiction_scan::ContradictionSignal> =
        Vec::new();
    if !is_exact_resubmit {
        let novelty_threshold = params
            .novelty_threshold
            .unwrap_or(crate::tools::novelty_gate::DEFAULT_NOVELTY_THRESHOLD);
        if let Some(outcome) = crate::tools::novelty_gate::decide(
            &server.pool,
            server.embedder.as_ref(),
            &params.content,
            novelty_threshold,
        )
        .await
        {
            let decision = outcome.decision;
            if let crate::tools::novelty_gate::GateDecision::ReturnExisting(existing_id) = decision
            {
                // Semantic duplicate: suppress the insert entirely and
                // report the existing claim, mirroring the shape of a
                // content-hash dedup hit (no new Evidence/Trace/edges/DS).
                //
                // Two deliberate differences from the content-hash dedup
                // this composes with, both intended per the backlog spec
                // (nearest_by_embedding scans ALL is_current claims, not
                // scoped to this agent):
                //   1. `existing_id` can belong to ANOTHER agent's claim —
                //      unlike find_by_content_hash_and_agent's same-agent
                //      dedup, semantic novelty is corpus-wide. CONCRETE
                //      CONSEQUENCE: if agent B asserts a near-paraphrase of
                //      a fact agent A already asserted, B's submission is
                //      suppressed at the default threshold and B receives
                //      A's claim id — with NO independent AUTHORED edge,
                //      Evidence, or ReasoningTrace recorded for B. In a
                //      Dempster-Shafer system where independent
                //      corroboration from a second source is itself
                //      evidentiary signal (BBA combination), that is a real
                //      loss of corroboration data, not just a dedup nicety.
                //      This is what the backlog spec asks for (no agent
                //      filter on the ANN query) — flagging it here for a
                //      future owner to reconsider, not changing it
                //      unilaterally.
                //   2. `params.labels` (the CALLER's requested labels on
                //      THIS submission) are silently dropped here, since
                //      nothing is inserted. `resolve_backlog_item` is
                //      unaffected (it hardcodes novelty_threshold=0.0 so
                //      this branch never fires for it).
                let existing =
                    ClaimRepository::get_by_id(&server.pool, ClaimId::from_uuid(existing_id))
                        .await
                        .map_err(internal_error)?
                        .ok_or_else(|| {
                            internal_error(format!(
                            "novelty gate: nearest claim {existing_id} vanished before read-back"
                        ))
                        })?;
                return success_json(&SubmitClaimResponse {
                    claim_id: existing_id.to_string(),
                    truth_value: existing.truth_value.value(),
                    content_hash: ContentHasher::to_hex(&existing.content_hash),
                    embedded: false,
                    belief: None,
                    plausibility: None,
                    pignistic_prob: None,
                    frame_id: None,
                    // Nothing was inserted, so there is no claim id on this
                    // side of the pair to stage a `match_candidates` row
                    // against.
                    //
                    // RESIDUAL, deliberately not fixed: reaching this branch
                    // now means the NEAREST neighbour drew no signal (a signal
                    // against it vetoes suppression — see
                    // `novelty_gate::classify`), but a FARTHER neighbour may
                    // still have fired, and those signals are dropped with the
                    // submission. That is a hard constraint, not an oversight:
                    // `match_candidates.claim_a/claim_b` are FKs into
                    // `claims(id)` and no row exists to stage against, and
                    // reporting them here unstaged would break this field's
                    // documented invariant that each entry also staged a
                    // `pending` row.
                    possible_contradictions: Vec::new(),
                });
            }
            // Insert / InsertFlagged: stash the already-generated,
            // pgvector-formatted embedding so the was_created branch below
            // can store it directly instead of paying for a second
            // embedding call via embed_and_store.
            pending_embedding = Some(outcome.pgvector);
            contradiction_signals = outcome.contradictions;
            if matches!(
                decision,
                crate::tools::novelty_gate::GateDecision::InsertFlagged
            ) && !params.labels.iter().any(|l| l == "near-duplicate")
            {
                params.labels.push("near-duplicate".to_string());
            }
        }
        // embedder failure (None): fall through exactly as before this
        // feature existed — insert, then embed best-effort post-insert.
    }

    // Idempotent canonical claim create + AUTHORED verb-edge.
    let (claim, was_created) =
        crate::claim_helper::create_claim_idempotent(&server.pool, &claim, "submit_claim").await?;
    let claim_uuid = claim.id.as_uuid();

    if !params.labels.is_empty() {
        // `map_db_error`, not `internal_error`: a rejected label is a caller
        // mistake and must surface as INVALID_PARAMS, or the agent retries the
        // same bad payload forever. The fn-entry guard above means this branch
        // should no longer see a shell-expansion rejection at all, but the
        // classification is correct for any other `InvalidData` the repo
        // raises.
        ClaimRepository::update_labels(&server.pool, claim_uuid, &params.labels, &[])
            .await
            .map_err(map_db_error)?;
    }

    // Attach the writer's confidence declaration, if any.
    //
    // `merge_properties` is a RUNTIME `sqlx::query`, not a compile-time macro,
    // so this needs no `.sqlx` regeneration and no database to build.
    //
    // The error is PROPAGATED, not warn-swallowed, deliberately matching the
    // adjacent `update_labels` call: a claim that lands with an un-caveated
    // confidence is the exact failure this field exists to prevent, so a
    // best-effort write here would defeat the point.
    //
    // Placement is load-bearing. This site is only reachable AFTER
    // `create_claim_idempotent`, whose `create_or_get` dedups on
    // `(content_hash, agent_id)` — so `claim.id` is always THIS agent's own
    // row. The novelty gate's `GateDecision::ReturnExisting` branch above
    // returns early with an id that can belong to ANOTHER agent (the ANN scan
    // is corpus-wide, as documented there); a properties write must never
    // reach that path. Do not hoist this block above that early return.
    if let Some(declaration) = &confidence_declaration {
        ClaimRepository::merge_properties(&server.pool, claim.id, declaration)
            .await
            .map_err(internal_error)?;
    }

    // Build Evidence + Trace from this submission. Both are noun-claims with
    // their own UUIDs and signatures regardless of was_created.
    let evidence_hash = ContentHasher::hash(params.evidence_data.as_bytes());
    let evidence = Evidence::new(
        agent_id_typed,
        pub_key,
        evidence_hash,
        evidence_type,
        Some(params.evidence_data.clone()),
        claim.id,
    );
    let evidence_with_sig = {
        let mut e = evidence;
        e.signature = Some(server.signer.sign(&evidence_hash));
        e
    };

    let explanation = params.reasoning.unwrap_or_else(|| {
        format!(
            "Claim submitted via MCP with {} methodology",
            params.methodology
        )
    });
    let trace = ReasoningTrace::new(
        agent_id_typed,
        pub_key,
        methodology,
        vec![TraceInput::Evidence {
            id: evidence_with_sig.id,
        }],
        confidence,
        explanation,
    );

    // Persist Trace + Evidence on every submission.
    ReasoningTraceRepository::create(&server.pool, &trace, claim.id)
        .await
        .map_err(internal_error)?;
    EvidenceRepository::create(&server.pool, &evidence_with_sig)
        .await
        .map_err(internal_error)?;

    // Verb-edges: every submission references its own Evidence + Trace.
    // Emitted on both branches per the architecture doc's "re-occurrence
    // = new edge" rule (S3a Task 6, fix #1).
    // The was_created marker on properties lets queries distinguish
    // first-create from resubmit edges.
    //
    // Note: the API handler at routes/claims.rs:585-614 still follows the
    // pre-S3a skip-on-resubmit rule. Aligning the API to MCP's accumulating
    // semantics is spec backlog item #10.
    let _ = EdgeRepository::create(
        &server.pool,
        claim_uuid,
        "claim",
        evidence_with_sig.id.as_uuid(),
        "evidence",
        "DERIVED_FROM",
        Some(serde_json::json!({"was_created": was_created})),
        None,
        None,
    )
    .await;
    let _ = EdgeRepository::create(
        &server.pool,
        claim_uuid,
        "claim",
        trace.id.as_uuid(),
        "trace",
        "HAS_TRACE",
        Some(serde_json::json!({"was_created": was_created})),
        None,
        None,
    )
    .await;

    // Neighbour ids reported back to the caller (STRINGS, to match the rest of
    // this response type). Populated only on the first-create branch — see the
    // enqueue site below for why a resubmit stages nothing.
    let mut possible_contradictions: Vec<String> = Vec::new();

    let (final_truth, ds, embedded) = if was_created {
        // First-create: full lineage. update_trace_id, DS auto-wire, embed.
        ClaimRepository::update_trace_id(&server.pool, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        let ds_result = ds_auto::auto_wire_ds_for_claim(
            &server.pool,
            claim_uuid,
            agent_id,
            confidence,
            weight,
            true,
            Some(&params.evidence_type),
        )
        .await;
        if let Err(ref e) = ds_result {
            tracing::warn!(claim_id = %claim_uuid, "ds auto-wire failed: {e}");
        }
        if let Ok(ref ds) = ds_result {
            let ds_truth = TruthValue::clamped(ds.pignistic_prob);
            if let Err(e) = ClaimRepository::update_truth_value(
                &server.pool,
                ClaimId::from_uuid(claim_uuid),
                ds_truth,
            )
            .await
            {
                tracing::warn!(
                    claim_id = %claim_uuid,
                    "failed to update truth from DS pignistic: {e}"
                );
            }
        }
        let ds = ds_result.ok();

        // Reuse the novelty gate's already-generated vector when we have
        // one (avoids a second OpenAI call for the same content). Only the
        // gate's own embedder-failure path (`pending_embedding = None`)
        // falls back to `embed_and_store`'s independent generate-and-store.
        let embedded = if let Some(pgvec) = pending_embedding.take() {
            match ClaimRepository::store_embedding(&server.pool, claim_uuid, &pgvec).await {
                Ok(stored) => stored,
                Err(e) => {
                    tracing::warn!(claim_id = %claim_uuid, "novelty-gate embedding store failed: {e}");
                    false
                }
            }
        } else {
            server
                .embedder
                .embed_and_store(claim_uuid, &params.content)
                .await
        };

        // Stage anything the write-time contradiction scan flagged
        // (backlog 6ed02d04). Placement is load-bearing on BOTH sides:
        //   - AFTER `create_claim_idempotent` and the embedding store, because
        //     `match_candidates.claim_a/claim_b` are FKs into `claims(id)` —
        //     enqueuing earlier is a constraint violation, not a warning.
        //   - INSIDE `was_created`, because a resubmit's claim was already
        //     scanned when it was first written; re-staging would just retry an
        //     insert that `ON CONFLICT DO NOTHING` will refuse anyway.
        // Best-effort by construction: `enqueue` never returns an error, so a
        // review queue that is down cannot fail a submission.
        if !contradiction_signals.is_empty() {
            possible_contradictions = crate::tools::contradiction_scan::enqueue(
                &server.pool,
                claim_uuid,
                &contradiction_signals,
            )
            .await
            .into_iter()
            .map(|id| id.to_string())
            .collect();
        }

        let final_truth = ds
            .as_ref()
            .map(|d| d.pignistic_prob.clamp(0.01, 0.99))
            .unwrap_or(raw_truth);

        (final_truth, ds, embedded)
    } else {
        // Resubmit (Option B): verb-edges already emitted above. Skip
        // update_trace_id (canonical trace immutable), skip DS auto-wire
        // (canonical truth set on first create), skip embed (canonical
        // embedding already exists). Report canonical truth, not raw.
        (claim.truth_value.value(), None, false)
    };

    success_json(&SubmitClaimResponse {
        claim_id: claim_uuid.to_string(),
        truth_value: final_truth,
        content_hash: ContentHasher::to_hex(&content_hash),
        embedded,
        belief: ds.as_ref().map(|d| d.belief),
        plausibility: ds.as_ref().map(|d| d.plausibility),
        pignistic_prob: ds.as_ref().map(|d| d.pignistic_prob),
        frame_id: ds.as_ref().map(|d| d.frame_id.to_string()),
        possible_contradictions,
    })
}

pub async fn query_claims(
    server: &EpiGraphMcpFull,
    params: QueryClaimsParams,
    requester: Option<Uuid>,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let min = params.min_truth.unwrap_or(0.0);
    let max = params.max_truth.unwrap_or(1.0);

    // Filter by truth range in SQL (before LIMIT) so matching claims outside
    // the most-recent `limit` rows are still reachable (bug 5a55a48e).
    //
    // `current_only` defaults to false, preserving the historical page contents
    // (superseded rows ARE returned — locked in by query_claims_labels_test).
    // That default is safe now that each row reports its own `is_current` /
    // `supersedes`: a caller who wants live-only asks for it, and the sibling
    // `query_claims_by_label` defaults the same way (bug a85ee585).
    let claims =
        ClaimRepository::list_by_truth_range(&server.pool, min, max, params.current_only, limit, 0)
            .await
            .map_err(internal_error)?;

    // Redact PRIVATE content the requester cannot read (A3 §7.5). Build a
    // per-id access map and look each claim's decision up BY ITS OWN ID rather
    // than positionally zipping the batch result. The lookup fails closed
    // (`unwrap_or(Redacted)`), so a future reorder — or any id the batch helper
    // fails to return — redacts rather than leaks. This is a durable runtime
    // guard, not a debug-only tripwire.
    let ids: Vec<Uuid> = claims.iter().map(|c| c.id.as_uuid()).collect();
    let access_map: std::collections::HashMap<Uuid, ContentAccess> =
        batch_check_content_access(&server.pool, &ids, requester)
            .await
            .into_iter()
            .collect();

    // Populate labels via a single batch round-trip for all returned ids
    // (backlog babd5904: this handler previously hardcoded `labels: Vec::new()`
    // while get_claim on the same id returned them). Batch fetch avoids the
    // N+1 fan-out of per-claim get_labels calls; the helper does NOT filter on
    // is_current so superseded rows (which list_by_truth_range returns) keep
    // their labels, matching get_labels' label source. A missing id → no labels.
    let labels_map = ClaimRepository::labels_by_ids(&server.pool, &ids)
        .await
        .map_err(internal_error)?;

    let results: Vec<ClaimResponse> = claims
        .into_iter()
        .map(|c| {
            let id = c.id.as_uuid();
            let access = access_map
                .get(&id)
                .copied()
                .unwrap_or(ContentAccess::Redacted);
            let (content, content_hash) =
                crate::tools::redaction::redact_content(access, &c.content, &c.content_hash);
            ClaimResponse {
                id: id.to_string(),
                content,
                truth_value: c.truth_value.value(),
                agent_id: c.agent_id.as_uuid().to_string(),
                content_hash,
                created_at: c.created_at.to_rfc3339(),
                labels: labels_map.get(&id).cloned().unwrap_or_default(),
                // Forward the row's REAL retirement state. These were hardcoded
                // `true` / `None`, so a superseded claim serialised identically
                // to a live one while `get_claim` on the same id reported the
                // truth — the two tools contradicted each other (bug a85ee585).
                // Matches query_claims_by_label's forwarding exactly.
                is_current: c.is_current,
                supersedes: c.supersedes.map(|s| s.as_uuid().to_string()),
            }
        })
        .collect();

    success_json(&results)
}

pub async fn get_claim(
    server: &EpiGraphMcpFull,
    params: GetClaimParams,
    requester: Option<Uuid>,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let claim_id = ClaimId::from_uuid(id);

    // Resolve the optional (frame, perspective) lens up front (both-or-neither,
    // parse, existence) so a bad lens fails fast before any belief compute.
    let lens = crate::tools::lens::resolve_lens(
        params.frame_id.as_deref(),
        params.perspective_id.as_deref(),
    )?;
    if let Some((frame_id, perspective_id)) = lens {
        crate::tools::lens::validate_lens_exists(&server.pool, frame_id, perspective_id).await?;
    }

    let (claim, labels) = ClaimRepository::get_by_id_with_labels(&server.pool, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;
    let access = check_content_access(&server.pool, claim.id.as_uuid(), requester).await;
    let (content, content_hash) =
        crate::tools::redaction::redact_content(access, &claim.content, &claim.content_hash);
    // Cached CDST classification ('supported' | 'contradicted' |
    // 'not_enough_info' | null). Flattened onto the standard claim response so
    // existing `ClaimResponse` consumers are unaffected.
    let classification = ClaimRepository::get_classification(&server.pool, id)
        .await
        .map_err(internal_error)?;

    // Additive lensed belief: compute the claim's belief under the chosen lens.
    // Frame/perspective existence is already validated, so a compute failure
    // here is a genuine internal error (single-claim tool → propagate, no
    // page-degrade semantics).
    let lensed_belief = match lens {
        Some((frame_id, perspective_id)) => {
            let interval = epigraph_engine::belief_query::get_perspective_belief(
                &server.pool,
                id,
                frame_id,
                perspective_id,
            )
            .await
            .map_err(|e| match e {
                epigraph_engine::BeliefQueryError::FrameNotFound(fid) => {
                    invalid_params(format!("frame {fid} not found"))
                }
                // Unreachable in practice — the claim row was fetched above —
                // but mapping it keeps the engine's not-found signal from
                // degrading into a 500 if that ordering ever changes.
                epigraph_engine::BeliefQueryError::ClaimNotFound(cid) => {
                    invalid_params(format!("claim {cid} not found"))
                }
                epigraph_engine::BeliefQueryError::ParseMasses(msg) => {
                    invalid_params(format!("invalid mass function: {msg}"))
                }
                other => internal_error(other),
            })?;
            Some(LensedBelief::from_interval(
                frame_id,
                perspective_id,
                &interval,
            ))
        }
        None => None,
    };

    // Writer-supplied free-text prose ABOUT the claim — a sibling field of
    // `content` in exactly the sense redaction.rs warns about (a redacted row
    // must not leak its content through a neighbouring field). Gate it on the
    // SAME `access` decision that gates content, and skip the read entirely
    // when redacted: no round-trip, no oracle.
    let confidence_declaration = match access {
        ContentAccess::Full => ClaimRepository::get_confidence_declaration(&server.pool, claim_id)
            .await
            .map_err(internal_error)?,
        ContentAccess::Redacted => None,
    };

    #[derive(serde::Serialize)]
    struct GetClaimResponse {
        #[serde(flatten)]
        claim: ClaimResponse,
        classification: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        lensed_belief: Option<LensedBelief>,
        // Omitted (never `null`) when absent, so a claim with no declaration
        // serialises byte-identically to before this field existed.
        #[serde(skip_serializing_if = "Option::is_none")]
        confidence_declaration: Option<serde_json::Value>,
    }

    success_json(&GetClaimResponse {
        claim: ClaimResponse {
            id: claim.id.as_uuid().to_string(),
            content,
            truth_value: claim.truth_value.value(),
            agent_id: claim.agent_id.as_uuid().to_string(),
            content_hash,
            created_at: claim.created_at.to_rfc3339(),
            labels,
            is_current: claim.is_current,
            supersedes: claim.supersedes.map(|s| s.as_uuid().to_string()),
        },
        classification,
        lensed_belief,
        confidence_declaration,
    })
}

pub async fn verify_claim(
    server: &EpiGraphMcpFull,
    params: VerifyClaimParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let claim = ClaimRepository::get_by_id(&server.pool, ClaimId::from_uuid(id))
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;

    // Verify content hash
    let computed_hash = ContentHasher::hash(claim.content.as_bytes());
    let hash_matches = computed_hash == claim.content_hash;

    // Verify signature
    let signature_valid = match claim.signature {
        Some(sig) => {
            epigraph_crypto::SignatureVerifier::verify(&claim.public_key, &claim.content_hash, &sig)
                .unwrap_or(false)
        }
        None => false,
    };

    success_json(&VerifyResponse {
        claim_id: id.to_string(),
        signature_valid,
        hash_matches,
        truth_value: claim.truth_value.value(),
    })
}

pub async fn update_with_evidence(
    server: &EpiGraphMcpFull,
    params: UpdateWithEvidenceParams,
) -> Result<CallToolResult, McpError> {
    // Reject unexpanded shell syntax up front, mirroring `submit_claim`.
    // `ClaimRepository::update_labels` already guards its `add` slice, but it
    // runs *after* the evidence row and DS recomputation have been written, and
    // its `DbError` was mapped through `internal_error` — a 500, which agents
    // retry. Checking here fails the call before any write, and `map_db_error`
    // turns `DbError::InvalidData` into `invalid_params` so the caller is told
    // to fix the label rather than to try again.
    epigraph_db::reject_shell_expansion(&params.labels).map_err(map_db_error)?;

    // Two addressing modes, exactly one required: id-mode (`claim_id`) or
    // name-mode (`canonical_name` + `step_index`), the latter resolved through
    // the same `executes`-edge walk `report_hierarchical_outcome` uses (#352).
    let claim_id = if !params.claim_id.trim().is_empty() {
        if params.canonical_name.is_some() || params.step_index.is_some() {
            return Err(invalid_params(
                "provide EITHER claim_id OR (canonical_name + step_index), not both",
            ));
        }
        parse_uuid(params.claim_id.trim())?
    } else if let (Some(name), Some(idx)) = (params.canonical_name.as_deref(), params.step_index) {
        epigraph_db::WorkflowRepository::resolve_step_claim(&server.pool, name, idx, true)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| {
                invalid_params(format!(
                    "no step at index {idx} of workflow '{name}' (unknown workflow or index out of range)"
                ))
            })?
    } else {
        return Err(invalid_params(
            "provide a claim to update: either `claim_id`, or both `canonical_name` and `step_index`",
        ));
    };
    let evidence_type = parse_evidence_type(&params.evidence_type, params.source_url.as_deref())
        .map_err(invalid_params)?;

    let claim = ClaimRepository::get_by_id(&server.pool, ClaimId::from_uuid(claim_id))
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {claim_id} not found")))?;

    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    // Create evidence
    let evidence_hash = ContentHasher::hash(params.evidence_data.as_bytes());
    let mut evidence = Evidence::new(
        agent_id_typed,
        pub_key,
        evidence_hash,
        evidence_type,
        Some(params.evidence_data),
        ClaimId::from_uuid(claim_id),
    );
    evidence.signature = Some(server.signer.sign(&evidence_hash));

    EvidenceRepository::create(&server.pool, &evidence)
        .await
        .map_err(internal_error)?;

    let before = claim.truth_value.value();
    let strength = params.strength.clamp(0.0, 1.0);

    // Capture pre-combination pignistic to detect the counterintuitive-but-correct
    // case where SUPPORTING evidence lowers belief (Task 3.6, backlog 3b60a785).
    // Compare pignistic-vs-pignistic. `get_belief_columns` reads the persisted
    // `pignistic_prob` column (distinct from `truth_value`; see claim.rs docs).
    // It is NULL for a claim with no prior DS state — in that case fall back to
    // `truth_value` (`before`), which is the belief the fresh BBA is combined
    // against. The monotonicity clamp in `auto_wire_ds_update` bounds BetP below
    // by the prior column value for supports=true, so the warning is only ever
    // reachable on the NULL-column (no-prior-DS-state) path.
    let pre_pignistic =
        ClaimRepository::get_belief_columns(&server.pool, ClaimId::from_uuid(claim_id))
            .await
            .map_err(internal_error)?
            .and_then(|c| c.pignistic_prob);

    // Load type_weight from calibration (replaces deleted evidence_weight())
    // I-3: use helper that checks CALIBRATION_PATH env var before relative path
    let weight = load_evidence_type_weight(&params.evidence_type);

    // CDST update (primary — errors propagated, not swallowed)
    // C-1: pass evidence UUID as perspective_id so each evidence gets its own BBA row
    let ds = ds_auto::auto_wire_ds_update(
        &server.pool,
        claim_id,
        agent_id,
        strength,
        weight, // from calibration.toml (C1 fix: single weight source)
        params.supports,
        Some(&params.evidence_type),
        Some(evidence.id.as_uuid()), // C-1: evidence UUID prevents BBA upsert overwrite
    )
    .await
    .map_err(internal_error)?;

    // Derive truth_value from CDST pignistic probability
    let after_truth = TruthValue::clamped(ds.pignistic_prob);
    ClaimRepository::update_truth_value(&server.pool, ClaimId::from_uuid(claim_id), after_truth)
        .await
        .map_err(internal_error)?;

    // Additive label merge on the dedup-match write, mirroring submit_claim's
    // and memorize's dedup-hit behavior: labels union into the claim's
    // existing array (ClaimRepository::update_labels dedupes via
    // array_agg(DISTINCT ...)), never overwriting labels from the claim's
    // original creation cycle. Fixes backlog f14592cb: run-tag labels (e.g.
    // norcal-rfp-2026-07-05) were previously dropped on every call because
    // UpdateWithEvidenceParams had no labels field at all.
    if !params.labels.is_empty() {
        ClaimRepository::update_labels(&server.pool, claim_id, &params.labels, &[])
            .await
            .map_err(internal_error)?;
    }

    // Warn when SUPPORTING evidence lowered the pignistic probability. Compare
    // pignistic-to-pignistic; when the claim had no prior DS state the column is
    // NULL, so fall back to the truth_value the fresh BBA combined against.
    let pre_belief = pre_pignistic.unwrap_or(before);
    let warning = (params.supports && ds.pignistic_prob < pre_belief).then(|| {
        "Supporting evidence decreased belief — the new evidence has high \
         ignorance mass relative to the prior; this is mathematically correct \
         DS combination, not a bug."
            .to_string()
    });

    success_json(&UpdateResponse {
        claim_id: claim_id.to_string(),
        truth_before: before,
        truth_after: after_truth.value(),
        evidence_id: evidence.id.as_uuid().to_string(),
        belief: Some(ds.belief),
        plausibility: Some(ds.plausibility),
        pignistic_prob: Some(ds.pignistic_prob),
        warning,
    })
}

/// Per-row authorization for MCP tools that mutate an existing claim.
///
/// Mirrors `epigraph_api::middleware::scopes::require_owner_or_admin`
/// (the HTTP layer's check on PATCH `/api/v1/claims/:id/labels`) but
/// scoped to the MCP entry path. Two callers, two policies:
///
/// - **HTTP (`auth = Some(_)`):** allow if the token carries
///   `claims:admin` OR the caller's principal (`owner_id` falling back
///   to `client_id`) equals `target_agent_id`. This is the path that
///   unblocks cross-agent backlog retirement for admin-scope holders
///   (backlog item `a4cc08a6`).
/// - **stdio (`auth = None`):** the MCP server has no per-request
///   identity, so degrade to comparing the claim's author against the
///   server's own signer agent. Preserves the legacy behavior for
///   non-HTTP callers without re-opening the cross-agent abuse vector.
pub(crate) async fn require_owner_or_admin(
    server: &EpiGraphMcpFull,
    auth: Option<&epigraph_auth::AuthContext>,
    target_agent_id: uuid::Uuid,
) -> Result<(), McpError> {
    if let Some(auth) = auth {
        if auth.has_scope("claims:admin") {
            return Ok(());
        }
        let principal = auth.owner_id.unwrap_or(auth.client_id);
        if principal == target_agent_id {
            return Ok(());
        }
        return Err(McpError {
            code: rmcp::model::ErrorCode::INVALID_PARAMS,
            message: format!(
                "claim is owned by agent {target_agent_id}; \
                 caller principal {principal} cannot retire it \
                 (requires claims:admin scope or ownership)"
            )
            .into(),
            data: None,
        });
    }

    let caller_agent = server.agent_id().await?;
    if caller_agent == target_agent_id {
        return Ok(());
    }
    Err(McpError {
        code: rmcp::model::ErrorCode::INVALID_PARAMS,
        message: format!(
            "claim is owned by agent {target_agent_id}; \
             caller agent {caller_agent} cannot retire it \
             (no AuthContext on this transport — claims:admin scope only honored over HTTP)"
        )
        .into(),
        data: None,
    })
}

/// Upper bound on `closure_basis` entries accepted by `resolve_backlog_item`.
///
/// Each id costs two sequential round-trips — one `get_by_id` existence check
/// before any write, plus one `create_if_not_exists` (itself a two-statement
/// transaction) after. The cap bounds the worst case at ~48 statements on a
/// verb that already does far more; raise it only with that arithmetic in mind.
const MAX_CLOSURE_BASIS: usize = 16;

/// Parse and normalize the caller's `closure_basis` strings. Pure — no DB.
///
/// Rejects (rather than silently drops) three things, because each one means
/// the caller believes something false about the closure they are recording:
/// more than [`MAX_CLOSURE_BASIS`] entries, a malformed UUID, and the item
/// being resolved appearing as its own justification.
///
/// De-duplicates while preserving first-seen order, so the stored
/// `closure_basis` property and the emitted edges are deterministic for a
/// given input. Empty input yields an empty vector — the zero-cost path every
/// pre-existing caller takes.
fn parse_closure_basis(raw: &[String], original_id: Uuid) -> Result<Vec<Uuid>, McpError> {
    if raw.len() > MAX_CLOSURE_BASIS {
        return Err(invalid_params(format!(
            "closure_basis accepts at most {MAX_CLOSURE_BASIS} entries, got {}",
            raw.len()
        )));
    }
    let mut out: Vec<Uuid> = Vec::with_capacity(raw.len());
    for (i, s) in raw.iter().enumerate() {
        let id = Uuid::parse_str(s.trim())
            .map_err(|e| invalid_params(format!("closure_basis[{i}] is not a valid UUID: {e}")))?;
        if id == original_id {
            return Err(invalid_params(format!(
                "closure_basis[{i}] is the backlog item being resolved ({original_id}); \
                 an item is not evidence for its own closure"
            )));
        }
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// Split a validated basis list into the ids that may legally receive an edge
/// and human-readable warnings for the ids that may not. Pure — no DB.
///
/// The one skipped case is the resolution claim itself. That is not
/// hypothetical: `submit_claim` dedups on content hash, so re-filing an
/// identical resolution hands back a pre-existing claim id, which a caller may
/// legitimately also be citing as basis. `edges_no_self_loop`
/// (`migrations/001_initial_schema.sql:772`) rejects a claim→claim self edge,
/// so filtering here turns a constraint violation into a reported skip.
fn closure_basis_edge_targets(basis: &[Uuid], resolution_id: Uuid) -> (Vec<Uuid>, Vec<String>) {
    let mut targets = Vec::with_capacity(basis.len());
    let mut warnings = Vec::new();
    for id in basis {
        if *id == resolution_id {
            warnings.push(format!(
                "closure_basis entry {id} is the resolution claim itself; \
                 skipped the self-edge (recorded in the closure_basis property only)"
            ));
        } else {
            targets.push(*id);
        }
    }
    (targets, warnings)
}

/// The `properties` fragment stashed on the resolution claim. Pure — no DB.
///
/// Merged with jsonb `||` by `patch_claim_atomic_conn`, so it must set exactly
/// one top-level key: anything else in the object would clobber unrelated
/// properties on the claim.
fn closure_basis_properties(basis: &[Uuid]) -> serde_json::Value {
    serde_json::json!({
        "closure_basis": basis.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

/// Merge `{"closure_basis": [...]}` into the resolution claim's properties.
///
/// Mirrors `patch_claim`'s transaction shape. Note the merge is
/// last-writer-wins: because `submit_claim` dedups on content hash, calling
/// `resolve_backlog_item` twice with identical `resolution_content` patches the
/// *same* claim, and the jsonb `||` replaces the key outright while the edges
/// from the first call remain. A second call with a shorter basis list
/// therefore leaves the property narrower than the edges.
async fn stash_closure_basis(
    pool: &epigraph_db::PgPool,
    resolution_id: Uuid,
    basis: &[Uuid],
) -> Result<(), DbError> {
    let mut tx = pool.begin().await?;
    ClaimRepository::patch_claim_atomic_conn(
        &mut tx,
        ClaimId::from_uuid(resolution_id),
        &PatchClaimInput {
            properties: Some(closure_basis_properties(basis)),
            ..PatchClaimInput::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// One-call backlog-item retirement.
///
/// Submits a resolution claim via the canonical `submit_claim` pipeline
/// (full lifecycle: idempotent create + Evidence + ReasoningTrace +
/// DERIVED_FROM/HAS_TRACE/AUTHORED edges + DS auto-wire + embedding +
/// label patch), then PATCHes the original claim's labels with
/// `add=["resolved"]`. The original keeps `is_current=true` and
/// `supersedes=None` — retirement is label-side, not lineage-side.
///
/// Partial-failure semantics: if the label PATCH on the original fails
/// after the resolution claim is created, returns an error including
/// the `resolution_claim_id` so the reconciler can back-fill.
pub async fn resolve_backlog_item(
    server: &EpiGraphMcpFull,
    params: crate::types::ResolveBacklogItemParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let original_id = parse_uuid(&params.original_id)?;
    let original_claim_id = ClaimId::from_uuid(original_id);
    let basis_ids =
        parse_closure_basis(params.closure_basis.as_deref().unwrap_or(&[]), original_id)?;

    // Confirm the target exists; we do NOT require the "backlog" label —
    // a stricter precondition belongs to the call site (HTTP filters /
    // operator UI) rather than the verb.
    let original = ClaimRepository::get_by_id(&server.pool, original_claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {original_id} not found")))?;

    // Authorization: mirror PATCH /api/v1/claims/:id/labels'
    // `require_owner_or_admin` middleware. With an HTTP `AuthContext`
    // available (propagated into rmcp's `RequestContext::extensions` by
    // `server::call_tool`), allow when the caller has `claims:admin` or
    // when their principal (`owner_id` falling back to `client_id`)
    // matches the claim's `agent_id`. With no auth (stdio transport),
    // fall back to the legacy agent-equality check against the server's
    // own signer agent — preserves backward compat for non-HTTP callers.
    let target_agent = original.agent_id.as_uuid();
    require_owner_or_admin(server, auth, target_agent).await?;

    // Existence-check every closure basis id. Ordering is load-bearing twice
    // over: after the auth check, so an unauthorized caller cannot use this
    // verb to probe which claim ids exist; and before any write, so a typo'd
    // basis UUID fails the whole call instead of leaving a resolution claim
    // behind. (`edges_validate_refs`,
    // `migrations/001_initial_schema.sql:3263`, would also reject a dangling
    // ref — but only after the resolution claim and the label patch landed.)
    for (i, basis) in basis_ids.iter().enumerate() {
        if ClaimRepository::get_by_id(&server.pool, ClaimId::from_uuid(*basis))
            .await
            .map_err(internal_error)?
            .is_none()
        {
            return Err(invalid_params(format!(
                "closure_basis[{i}]: claim {basis} not found"
            )));
        }
    }

    // 1. Submit the resolution claim via the canonical pipeline.
    let methodology = params
        .methodology
        .unwrap_or_else(|| "expert_elicitation".to_string());
    let resolution_content = format!("Resolves {}: {}", original_id, params.resolution_content);
    let submit_params = crate::types::SubmitClaimParams {
        content: resolution_content,
        methodology,
        evidence_data: format!(
            "Operational resolution of backlog claim {}. Filed via resolve_backlog_item.",
            original_id
        ),
        evidence_type: "testimonial".to_string(),
        confidence: 0.8,
        source_url: None,
        reasoning: Some(format!(
            "Backlog claim {original_id} retired by agent assertion via resolve_backlog_item."
        )),
        labels: vec!["resolved".to_string()],
        // Resolution claims are operational provenance records, not
        // epistemic content competing for novelty against the corpus —
        // never suppress or flag them via the semantic gate.
        novelty_threshold: Some(0.0),
        // Not declared here. The hardcoded `confidence: 0.8` above is itself a
        // textbook bare scalar and deserves a scope, but dogfooding it is a
        // separate decision from adding the field — left as its own item.
        confidence_scope: None,
        known_issues: Vec::new(),
    };
    let submit_result = submit_claim(server, submit_params).await?;
    let resolution_id = extract_submit_claim_id(&submit_result)?;

    // 2. PATCH the original's labels: add "resolved", keep "backlog".
    //    Best-effort: if this fails the resolution claim already exists,
    //    return a partial-success error so the reconciler can back-fill.
    let after_labels = match ClaimRepository::update_labels(
        &server.pool,
        original_id,
        &["resolved".to_string()],
        &[],
    )
    .await
    {
        Ok(labels) => labels,
        Err(e) => {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INTERNAL_ERROR,
                message: format!(
                    "resolution claim {resolution_id} created but failed to patch original {original_id}: {e}"
                )
                .into(),
                data: Some(serde_json::json!({
                    "resolution_claim_id": resolution_id,
                    "original_id": original_id.to_string(),
                })),
            });
        }
    };

    // 3. Record WHY the item could be closed. Deliberately AFTER the label
    //    patch and deliberately best-effort: at this point the item is already
    //    correctly retired, so a lost provenance edge must not turn a
    //    successful retirement into an error the caller retries — a retry would
    //    file a second resolution claim. Same rule CLAUDE.md applies to
    //    post-commit embedding ("best-effort, warn on failure, never block the
    //    write") and the same shape as submit_claim's best-effort edges.
    //    `create_if_not_exists` is idempotent on (source, target,
    //    relationship), so re-running is safe.
    let mut warnings: Vec<String> = Vec::new();
    let mut edges_created = 0usize;
    if !basis_ids.is_empty() {
        let resolution_uuid = Uuid::parse_str(&resolution_id).map_err(internal_error)?;
        if let Err(e) = stash_closure_basis(&server.pool, resolution_uuid, &basis_ids).await {
            tracing::warn!(
                resolution_id = %resolution_uuid,
                "closure_basis property patch failed: {e}"
            );
            warnings.push(format!("closure_basis property patch failed: {e}"));
        }
        let (targets, mut skipped) = closure_basis_edge_targets(&basis_ids, resolution_uuid);
        warnings.append(&mut skipped);
        for basis in &targets {
            // `source -> target` reads "source RELATIONSHIP target"
            // (`link_epistemic` module docs), so basis -> resolution says
            // "basis justifies resolution" — the direction that is true.
            //
            // "justifies" is deliberately absent from `edge_to_factor_type`
            // (migrations/011; trigger last rewritten in migrations/038), so
            // `auto_create_factor_from_edge` hits `IF ft IS NULL THEN RETURN
            // NEW` and the edge is belief-inert — correct for an operational
            // provenance record. It is likewise absent from
            // `link_epistemic::EPISTEMIC_RELATIONSHIPS`,
            // `epigraph_db::EPISTEMIC_RELATIONSHIPS` and
            // `EXPANSION_RELATIONSHIPS`. Do not add it to any of them: giving
            // "justifies" a factor mapping later would retroactively animate
            // every historical closure edge.
            match EdgeRepository::create_if_not_exists(
                &server.pool,
                *basis,
                "claim",
                resolution_uuid,
                "claim",
                "justifies",
                Some(serde_json::json!({
                    "written_by": "resolve_backlog_item",
                    "backlog_item_id": original_id.to_string(),
                })),
                None,
                None,
            )
            .await
            {
                Ok((_, true)) => edges_created += 1,
                Ok((_, false)) => {}
                Err(e) => {
                    tracing::warn!(
                        source = %basis,
                        target = %resolution_uuid,
                        "justifies edge failed: {e}"
                    );
                    warnings.push(format!(
                        "justifies edge {basis} -> {resolution_uuid} failed: {e}"
                    ));
                }
            }
        }
    }

    success_json(&serde_json::json!({
        "resolution_claim_id": resolution_id,
        "original_id": original_id.to_string(),
        "original_labels": after_labels,
        "closure_basis": basis_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "justifies_edges_created": edges_created,
        "warnings": warnings,
    }))
}

/// Pull `claim_id` out of a `submit_claim` response. Mirrors the
/// `first_text` helper in `tests/common/mod.rs` (the proven shape for
/// pattern-matching `CallToolResult.content` in this rmcp version).
fn extract_submit_claim_id(result: &CallToolResult) -> Result<String, McpError> {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .ok_or_else(|| internal_error("submit_claim returned no text content"))?;
    let parsed: serde_json::Value = serde_json::from_str(text).map_err(internal_error)?;
    parsed
        .get("claim_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| internal_error("submit_claim response missing claim_id"))
}

pub async fn update_labels(
    server: &EpiGraphMcpFull,
    params: crate::types::UpdateLabelsParams,
) -> Result<CallToolResult, McpError> {
    if params.add.is_empty() && params.remove.is_empty() {
        return Err(invalid_params("must specify at least one of add/remove"));
    }
    let id = parse_uuid(&params.claim_id)?;
    let labels = ClaimRepository::update_labels(&server.pool, id, &params.add, &params.remove)
        .await
        .map_err(map_db_error)?;
    success_json(&serde_json::json!({ "claim_id": id, "labels": labels }))
}

pub async fn patch_claim(
    server: &EpiGraphMcpFull,
    params: crate::types::PatchClaimParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let trace = match &params.trace_id {
        Some(s) => Some(parse_uuid(s)?),
        None => None,
    };
    if trace.is_none()
        && params.properties.is_none()
        && params.add_labels.is_empty()
        && params.remove_labels.is_empty()
    {
        return Err(invalid_params(
            "at least one of trace_id/properties/add_labels/remove_labels required",
        ));
    }
    let mut tx = server.pool.begin().await.map_err(internal_error)?;
    let diff = ClaimRepository::patch_claim_atomic_conn(
        &mut tx,
        ClaimId::from_uuid(id),
        &PatchClaimInput {
            trace_id: trace,
            properties: params.properties.clone(),
            add_labels: params.add_labels.clone(),
            remove_labels: params.remove_labels.clone(),
        },
    )
    .await
    .map_err(map_db_error)?;
    tx.commit().await.map_err(internal_error)?;
    success_json(&serde_json::json!({
        "claim_id": id,
        "after_labels": diff.after_labels,
        "after_properties": diff.after_props,
        "after_trace": diff.after_trace,
    }))
}

pub async fn query_undecomposed_claims(
    server: &EpiGraphMcpFull,
    params: crate::types::QueryUndecomposedClaimsParams,
    requester: Option<Uuid>,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 1000);
    let offset = params.offset.unwrap_or(0).max(0);

    let claims = ClaimRepository::list_undecomposed(&server.pool, limit, offset)
        .await
        .map_err(internal_error)?;

    // Apply partition-aware content redaction so private/community-partitioned
    // claims are not exposed to requesters who don't own them (parity with
    // query_claims and get_claim — security finding: this path previously
    // bypassed the check_content_access / batch_check_content_access layer).
    let ids: Vec<Uuid> = claims.iter().map(|c| c.id.as_uuid()).collect();
    let access_map: std::collections::HashMap<Uuid, ContentAccess> =
        batch_check_content_access(&server.pool, &ids, requester)
            .await
            .into_iter()
            .collect();

    let results: Vec<ClaimResponse> = claims
        .into_iter()
        .map(|c| {
            let id = c.id.as_uuid();
            let access = access_map
                .get(&id)
                .copied()
                .unwrap_or(ContentAccess::Redacted);
            let (content, content_hash) =
                crate::tools::redaction::redact_content(access, &c.content, &c.content_hash);
            ClaimResponse {
                id: id.to_string(),
                content,
                truth_value: c.truth_value.value(),
                agent_id: c.agent_id.as_uuid().to_string(),
                content_hash,
                created_at: c.created_at.to_rfc3339(),
                labels: Vec::new(),
                is_current: true,
                supersedes: None,
            }
        })
        .collect();

    success_json(&results)
}

#[cfg(test)]
mod tests {
    use super::{
        build_confidence_declaration, closure_basis_edge_targets, closure_basis_properties,
        parse_closure_basis, parse_methodology, MAX_CLOSURE_BASIS, MAX_CONFIDENCE_SCOPE_CHARS,
        MAX_KNOWN_ISSUES, MAX_KNOWN_ISSUE_CHARS,
    };
    use epigraph_core::Methodology;
    use epigraph_engine::calibration::CalibrationConfig;

    /// The canonical accepted string for every [`Methodology`] variant.
    ///
    /// The `match` is exhaustive **on purpose**: adding a tenth variant to
    /// `Methodology` breaks this file at compile time, forcing whoever adds it
    /// to also give it a route in through the MCP write surface. Three variants
    /// (`Abductive`, `Extraction`, `VisualInspection`) sat unreachable from
    /// `parse_methodology` precisely because nothing enforced this.
    const fn canonical_token(m: Methodology) -> &'static str {
        match m {
            Methodology::Deductive => "deductive_logic",
            Methodology::Inductive => "inductive_generalization",
            Methodology::Abductive => "abductive",
            Methodology::Instrumental => "instrumental",
            Methodology::Extraction => "extraction",
            Methodology::BayesianInference => "bayesian_inference",
            Methodology::VisualInspection => "visual_inspection",
            Methodology::FormalProof => "formal_proof",
            Methodology::Heuristic => "expert_elicitation",
        }
    }

    const ALL_METHODOLOGIES: [Methodology; 9] = [
        Methodology::Deductive,
        Methodology::Inductive,
        Methodology::Abductive,
        Methodology::Instrumental,
        Methodology::Extraction,
        Methodology::BayesianInference,
        Methodology::VisualInspection,
        Methodology::FormalProof,
        Methodology::Heuristic,
    ];

    #[test]
    fn every_methodology_variant_is_reachable_from_the_mcp_surface() {
        for m in ALL_METHODOLOGIES {
            let token = canonical_token(m);
            assert_eq!(
                parse_methodology(token),
                Ok(m),
                "Methodology::{m:?} has no accepted string on the submit_claim \
                 surface — an agent can never record a claim under it"
            );
        }
    }

    #[test]
    fn direct_observation_is_an_accepted_methodology() {
        // BL-9: the dominant evidence mode for an engineering defect is "I ran
        // it and watched it fail". Every one of these was rejected outright.
        // Instrumental is the repo's own answer: calibration.toml
        // [methodology_aliases] maps `experimental_observation = "instrumental"`.
        for s in [
            "direct_observation",
            "observation",
            "observational",
            "experimental_observation",
            "Direct-Observation",
        ] {
            assert_eq!(
                parse_methodology(s),
                Ok(Methodology::Instrumental),
                "{s:?} must be accepted as direct observation"
            );
        }
    }

    #[test]
    fn meta_analysis_is_an_inductive_generalization_not_a_formal_proof() {
        for s in ["meta_analysis", "meta-analysis", "meta"] {
            assert_eq!(
                parse_methodology(s),
                Ok(Methodology::Inductive),
                "{s:?} must resolve to an inductive generalization over studies"
            );
        }
        // The concrete harm of the old mapping, stated on the single scale it
        // lives on: FormalProof (1.2) is the highest trust modifier in the
        // system, above Deductive (1.1). A statistical synthesis of prior
        // studies must not outrank deductive logic — calibration.toml ranks
        // meta_analysis 0.80 BELOW deductive_logic 0.85.
        let meta = parse_methodology("meta_analysis").expect("meta_analysis parses");
        assert!(
            meta.weight_modifier() < Methodology::Deductive.weight_modifier(),
            "meta-analysis weight {} must be below deductive logic's {}",
            meta.weight_modifier(),
            Methodology::Deductive.weight_modifier()
        );
    }

    #[test]
    fn previously_unreachable_variants_now_parse() {
        assert_eq!(parse_methodology("abductive"), Ok(Methodology::Abductive));
        assert_eq!(parse_methodology("extraction"), Ok(Methodology::Extraction));
        assert_eq!(
            parse_methodology("visual_inspection"),
            Ok(Methodology::VisualInspection)
        );
        // FormalProof lost its only (mis-mapped) route when meta_analysis was
        // retargeted; it must keep one under its own name.
        assert_eq!(
            parse_methodology("formal_proof"),
            Ok(Methodology::FormalProof)
        );
    }

    /// Drift guard, mirroring `tests/evidence_type_vocab.rs`: a methodology the
    /// DS calibrator has a tuned profile for must not be rejected by the write
    /// surface that produces the claims it calibrates.
    #[test]
    fn the_calibrated_methodology_vocabulary_is_accepted() {
        let cal =
            CalibrationConfig::from_workspace_root().expect("load workspace calibration.toml");

        // Non-vacuity. `from_workspace_root()` does NOT error when
        // calibration.toml is unreadable — it silently returns
        // `default_for_phase2_fallback()`, whose maps are all EMPTY, which
        // would make both loops below iterate zero times and pass trivially.
        assert!(
            cal.methodology_profiles.contains_key("observational"),
            "calibration.toml did not load (empty fallback) — this test would \
             otherwise pass vacuously"
        );
        assert!(
            cal.methodology_aliases
                .contains_key("experimental_observation"),
            "calibration.toml aliases did not load — this test would otherwise \
             pass vacuously"
        );

        for key in cal
            .methodology_profiles
            .keys()
            .filter(|k| k.as_str() != "default")
        {
            assert!(
                parse_methodology(key).is_ok(),
                "calibration.toml [methodology_profiles] has a tuned profile for \
                 {key:?} but the MCP submit_claim surface rejects it"
            );
        }
        for alias in cal.methodology_aliases.keys() {
            assert!(
                parse_methodology(alias).is_ok(),
                "calibration.toml [methodology_aliases] accepts {alias:?} but the \
                 MCP submit_claim surface rejects it"
            );
        }
    }

    #[test]
    fn the_five_correct_pre_existing_mappings_are_preserved() {
        // BL-9 changed exactly one existing arm (meta_analysis). These five are
        // load-bearing for already-stored traces and must not move.
        assert_eq!(
            parse_methodology("bayesian_inference"),
            Ok(Methodology::BayesianInference)
        );
        assert_eq!(
            parse_methodology("deductive_logic"),
            Ok(Methodology::Deductive)
        );
        assert_eq!(
            parse_methodology("inductive_generalization"),
            Ok(Methodology::Inductive)
        );
        // `resolve_backlog_item` defaults to this string on every backlog
        // retirement; calibration ranks expert_elicitation lowest (0.45 support
        // / 0.45 ignorance) and Heuristic is the lowest weight (0.5).
        assert_eq!(
            parse_methodology("expert_elicitation"),
            Ok(Methodology::Heuristic)
        );
        // Agrees with the sibling mapping `ingestion::methodology_from_planned`,
        // which maps "statistical" | "instrumental" | "computational" the same way.
        assert_eq!(
            parse_methodology("statistical_analysis"),
            Ok(Methodology::Instrumental)
        );
    }

    #[test]
    fn an_unknown_methodology_is_still_rejected() {
        assert!(parse_methodology("vibes").is_err());
        assert!(parse_methodology("").is_err());
    }

    // ── build_confidence_declaration ──
    //
    // The function is pure — no clock, no pool — so every case below runs
    // without a database. All of them assert on the returned patch, which is
    // exactly the value handed to `merge_properties`.

    /// The default path: a caller who sends neither field produces no patch at
    /// all, so `submit_claim` performs NO properties write and the stored row
    /// is byte-identical to one written before this feature existed.
    #[test]
    fn no_declaration_leaves_properties_untouched() {
        assert_eq!(build_confidence_declaration(None, &[]), Ok(None));
    }

    /// A scope is trimmed, and — the guard that matters — the patch has exactly
    /// ONE top-level key. `merge_properties` is a shallow `||`, so a second
    /// top-level key here would be able to clobber `level` / `event` /
    /// `methodology` on a claim that already carries them.
    #[test]
    fn a_declared_scope_is_trimmed_and_nested_under_one_properties_key() {
        let patch = build_confidence_declaration(Some("  pg15 only "), &[])
            .expect("a well-formed scope is accepted")
            .expect("a declared scope produces a patch");

        assert_eq!(
            patch.pointer("/confidence_declaration/scope"),
            Some(&serde_json::json!("pg15 only"))
        );

        let top = patch.as_object().expect("the patch is a JSON object");
        assert_eq!(
            top.keys().collect::<Vec<_>>(),
            vec!["confidence_declaration"],
            "the patch must carry exactly one top-level key or the shallow `||` \
             merge can clobber a sibling properties key"
        );
    }

    /// Issues stand alone without a scope, keep their submitted order, and do
    /// not conjure a null `scope` key.
    #[test]
    fn known_issues_keep_their_order_and_stand_alone_without_a_scope() {
        let issues = vec![
            "single run, n=1".to_string(),
            "macOS only".to_string(),
            "no concurrency test".to_string(),
        ];
        let patch = build_confidence_declaration(None, &issues)
            .expect("well-formed issues are accepted")
            .expect("declared issues produce a patch");

        assert_eq!(
            patch.pointer("/confidence_declaration/known_issues"),
            Some(&serde_json::json!([
                "single run, n=1",
                "macOS only",
                "no concurrency test"
            ]))
        );
        assert!(
            patch.pointer("/confidence_declaration/scope").is_none(),
            "an undeclared scope must be ABSENT, not null: {patch}"
        );
    }

    /// An empty scope is a caller mistake, not a declaration of "no conditions".
    /// Rejecting it keeps a meaningless `scope: ""` out of the graph.
    #[test]
    fn an_empty_or_whitespace_only_scope_is_rejected_rather_than_stored() {
        for bad in ["", "   ", "\n\t"] {
            assert!(
                build_confidence_declaration(Some(bad), &[]).is_err(),
                "scope {bad:?} must be rejected"
            );
        }
    }

    /// A bad entry names its index, so a caller with 20 issues can find the one
    /// that failed without bisecting.
    #[test]
    fn an_empty_known_issue_is_rejected_and_names_its_index() {
        let issues = vec!["ok".to_string(), "  ".to_string()];
        let err = build_confidence_declaration(None, &issues)
            .expect_err("a whitespace-only issue must be rejected");
        assert!(
            err.contains("known_issues[1]"),
            "the error must name the offending index; got {err}"
        );
    }

    /// Bounds are counted in `chars()`, never bytes. A 2000-char scope of
    /// two-byte characters is 4000 bytes and must still be accepted; byte
    /// counting would reject it, and byte SLICING would panic mid-character.
    #[test]
    fn the_character_bounds_are_counted_in_chars_not_bytes() {
        let at_scope_limit = "é".repeat(MAX_CONFIDENCE_SCOPE_CHARS);
        assert!(
            at_scope_limit.len() > MAX_CONFIDENCE_SCOPE_CHARS,
            "multi-byte"
        );
        assert!(build_confidence_declaration(Some(&at_scope_limit), &[]).is_ok());

        let over_scope_limit = "é".repeat(MAX_CONFIDENCE_SCOPE_CHARS + 1);
        assert!(build_confidence_declaration(Some(&over_scope_limit), &[]).is_err());

        let at_issue_limit = vec!["é".repeat(MAX_KNOWN_ISSUE_CHARS)];
        assert!(build_confidence_declaration(None, &at_issue_limit).is_ok());

        let over_issue_limit = vec!["é".repeat(MAX_KNOWN_ISSUE_CHARS + 1)];
        assert!(build_confidence_declaration(None, &over_issue_limit).is_err());
    }

    #[test]
    fn more_known_issues_than_the_bound_are_rejected() {
        let at_limit: Vec<String> = (0..MAX_KNOWN_ISSUES)
            .map(|i| format!("issue {i}"))
            .collect();
        assert!(build_confidence_declaration(None, &at_limit).is_ok());

        let over_limit: Vec<String> = (0..=MAX_KNOWN_ISSUES)
            .map(|i| format!("issue {i}"))
            .collect();
        assert!(build_confidence_declaration(None, &over_limit).is_err());
    }

    // ---- closure_basis (resolve_backlog_item) --------------------------
    //
    // All pure. The DB-side facts these stand in for — the `justifies` edge
    // insert, the belief-inert trigger, the jsonb `||` merge — cannot be
    // exercised here; see the module doc comments for where each is argued
    // from in `migrations/`.

    /// A `uuid` distinct per `n`, so order assertions below are meaningful.
    fn test_uuid(n: u8) -> uuid::Uuid {
        uuid::Uuid::from_bytes([n; 16])
    }

    #[test]
    fn closure_basis_defaults_to_empty_when_omitted() {
        // The zero-cost path every pre-existing caller takes: no basis, no
        // existence checks, no edges, no property patch.
        let original = test_uuid(1);
        assert!(parse_closure_basis(&[], original).unwrap().is_empty());
    }

    #[test]
    fn closure_basis_rejects_a_malformed_uuid() {
        let original = test_uuid(1);
        let raw = vec![test_uuid(2).to_string(), "not-a-uuid".to_string()];
        let err = parse_closure_basis(&raw, original).expect_err("malformed uuid must be rejected");
        // The index is what lets the caller find the offending entry.
        assert!(
            err.message.contains("closure_basis[1]"),
            "message must name the offending index: {}",
            err.message
        );
    }

    #[test]
    fn closure_basis_rejects_the_item_being_resolved() {
        // Hard error, not a silent drop: citing the item as its own
        // justification means the caller believes something false about the
        // closure they are recording.
        let original = test_uuid(1);
        let raw = vec![test_uuid(2).to_string(), original.to_string()];
        let err =
            parse_closure_basis(&raw, original).expect_err("self-justification must be rejected");
        assert!(
            err.message.contains("its own closure"),
            "message must explain the rejection: {}",
            err.message
        );
    }

    #[test]
    fn closure_basis_deduplicates_and_preserves_first_seen_order() {
        // Determinism is load-bearing: the stored property and the emitted
        // edges must both be a function of the input alone.
        let original = test_uuid(1);
        let (a, b) = (test_uuid(2), test_uuid(3));
        let raw = vec![a.to_string(), b.to_string(), a.to_string()];
        assert_eq!(parse_closure_basis(&raw, original).unwrap(), vec![a, b]);
    }

    #[test]
    fn closure_basis_rejects_more_entries_than_the_cap() {
        let original = test_uuid(0);
        let at_limit: Vec<String> = (1..=MAX_CLOSURE_BASIS)
            .map(|i| test_uuid(u8::try_from(i).unwrap()).to_string())
            .collect();
        assert_eq!(
            parse_closure_basis(&at_limit, original).unwrap().len(),
            MAX_CLOSURE_BASIS
        );

        let over_limit: Vec<String> = (1..=MAX_CLOSURE_BASIS + 1)
            .map(|i| test_uuid(u8::try_from(i).unwrap()).to_string())
            .collect();
        assert!(parse_closure_basis(&over_limit, original).is_err());
    }

    #[test]
    fn closure_basis_edge_targets_skips_the_resolution_itself() {
        // Pure-logic stand-in for the `edges_no_self_loop` CHECK
        // (migrations/001_initial_schema.sql:772), which cannot be exercised
        // without a database. Reachable in production because `submit_claim`
        // dedups on content hash.
        let (a, r) = (test_uuid(2), test_uuid(9));
        let (targets, warnings) = closure_basis_edge_targets(&[a, r], r);
        assert_eq!(targets, vec![a]);
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains(&r.to_string()),
            "warning must name the skipped id: {}",
            warnings[0]
        );
    }

    #[test]
    fn closure_basis_properties_serializes_uuids_as_strings() {
        let (a, b) = (test_uuid(2), test_uuid(3));
        let props = closure_basis_properties(&[a, b]);
        // Exactly one top-level key: the jsonb `||` merge replaces whole
        // top-level keys, so a second key here would clobber unrelated
        // properties on the resolution claim.
        let obj = props.as_object().expect("object");
        assert_eq!(obj.len(), 1);
        assert_eq!(
            props["closure_basis"],
            serde_json::json!([a.to_string(), b.to_string()])
        );
        // Hyphenated lowercase, the form `Uuid::parse_str` round-trips.
        assert_eq!(props["closure_basis"][0].as_str().unwrap(), a.to_string());
    }
}
