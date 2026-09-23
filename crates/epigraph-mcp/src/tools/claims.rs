#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{db_caller_error, internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, ClaimId, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput,
    TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::PatchClaimInput;
use epigraph_db::{ClaimRepository, EvidenceRepository, ReasoningTraceRepository};
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

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn submit_claim(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    mut params: SubmitClaimParams,
) -> Result<CallToolResult, McpError> {
    let methodology = parse_methodology(&params.methodology).map_err(invalid_params)?;
    let evidence_type = parse_evidence_type(&params.evidence_type, params.source_url.as_deref())
        .map_err(invalid_params)?;

    // Label validation runs HERE — before any write — not at the
    // `ClaimRepository::update_labels` call further down. The repo layer
    // refuses unexpanded shell syntax either way (backlog f6310444), but that
    // call happens AFTER `create_claim_idempotent` has already persisted the
    // claim, so a guard there returns an error while leaving an ORPHAN claim
    // behind: a row with none of the labels the caller asked for, and nothing
    // marking it as the residue of a failed submission. That is the same
    // "guard after the write" shape this branch's own HTTP tests assert must
    // not happen (they check the 400 AND `COUNT(*) = 0`).
    //
    // `batch_submit_claims` delegates here per entry, so this also bounds a
    // bad label's blast radius to its own index instead of leaving one orphan
    // per rejected row.
    epigraph_db::reject_unexpanded_labels(&params.labels).map_err(db_caller_error)?;

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
        ClaimRepository::find_by_content_hash_and_agent(&mut conn, viewer, &content_hash, agent_id)
            .await
            .map_err(internal_error)?
            .is_some()
    };
    let mut pending_embedding: Option<String> = None;
    if !is_exact_resubmit {
        let novelty_threshold = params
            .novelty_threshold
            .unwrap_or(crate::tools::novelty_gate::DEFAULT_NOVELTY_THRESHOLD);
        if let Some((decision, pgvec)) = crate::tools::novelty_gate::decide(
            &server.pool,
            viewer,
            server.embedder.as_ref(),
            &params.content,
            novelty_threshold,
        )
        .await
        {
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
                let existing = ClaimRepository::get_by_id(
                    &server.pool,
                    viewer,
                    ClaimId::from_uuid(existing_id),
                )
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
                });
            }
            // Insert / InsertFlagged: stash the already-generated,
            // pgvector-formatted embedding so the was_created branch below
            // can store it directly instead of paying for a second
            // embedding call via embed_and_store.
            pending_embedding = Some(pgvec);
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

    // ── THE ONE TRANSACTION THIS SUBMISSION RUNS IN ─────────────────────
    //
    // Claim + labels + Trace + Evidence + the two verb-edges + `update_trace_id`
    // all run on ONE connection stamped from the AUTHOR's viewer. Two defects
    // are closed by the same construction, which is why it is one change:
    //
    // 1. **42501.** Nothing on the MCP path stamped the session GUCs migration
    //    077's policies read, so `epigraph_writable_groups` was `{}` and the
    //    `reasoning_traces` INSERT was refused — on a connection where the claim
    //    INSERT had already been admitted by an orphan `claims_privacy` policy.
    // 2. **Non-atomic writes.** Every step used to take its own pool checkout,
    //    so a refused trace left a COMMITTED claim with no trace, no evidence
    //    and no AUTHORED edge, and returned an error carrying no claim id — the
    //    caller could not even find what it had created.
    //
    // Follows `epigraph-api/src/routes/groups.rs::rotate_key`'s "why the whole
    // body runs on `ScopedPool::begin_as`"; this is that pattern, not a new one.
    //
    // WHAT IS DELIBERATELY *OUTSIDE* IT, below the commit: the DS auto-wire and
    // the embedding. The embedding is CLAUDE.md's policy (best-effort,
    // post-commit, warn on failure, never block the write). The DS auto-wire is
    // a larger conversion — it writes `claim_frames` / `mass_functions` through
    // a pool-bound helper — and it also READS the claim back, which a sibling
    // connection cannot do before this transaction commits. It therefore stays
    // post-commit and stays warn-only; `claim_frames` / `mass_functions` remain
    // in the unstamped-write blast radius until that conversion lands.
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, agent_id, "submit_claim").await?;

    // Idempotent canonical claim create + AUTHORED verb-edge.
    let (claim, was_created) =
        crate::claim_helper::create_claim_idempotent(&mut tx, viewer, &claim, "submit_claim")
            .await?;
    let claim_uuid = claim.id.as_uuid();

    // Already validated above, before the claim write. This call can now only
    // fail for server-side reasons; `db_caller_error` keeps those
    // INTERNAL_ERROR while still reporting a caller-caused `InvalidData`
    // correctly if a future label rule is added to the repo layer. Inside the
    // transaction, so a rejected label no longer leaves a labelled-nothing claim.
    if !params.labels.is_empty() {
        ClaimRepository::update_labels_conn(&mut tx, claim_uuid, &params.labels, &[])
            .await
            .map_err(db_caller_error)?;
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

    // Persist Trace + Evidence on every submission. In the transaction: a
    // refusal here now rolls the claim back instead of committing it as an
    // orphan.
    ReasoningTraceRepository::create(&mut *tx, &trace, claim.id)
        .await
        .map_err(internal_error)?;
    EvidenceRepository::create(&mut *tx, &evidence_with_sig)
        .await
        .map_err(internal_error)?;

    // Verb-edges: every submission references its own Evidence + Trace.
    // Emitted on both branches per the architecture doc's "re-occurrence
    // = new edge" rule (S3a Task 6, fix #1).
    // The was_created marker on properties lets queries distinguish
    // first-create from resubmit edges.
    //
    // SAVEPOINT-wrapped rather than `let _ =`: inside a transaction a failed
    // INSERT aborts everything that follows, so a swallowed edge error would
    // surface at COMMIT as `current transaction is aborted` with the real cause
    // lost. `emit_verb_edge_best_effort` keeps the architecture doc's
    // best-effort policy without that trade.
    //
    // Note: the API handler at routes/claims.rs still follows the pre-S3a
    // skip-on-resubmit rule. Aligning the API to MCP's accumulating semantics is
    // spec backlog item #10.
    crate::claim_helper::emit_verb_edge_best_effort(
        &mut tx,
        claim_uuid,
        "claim",
        evidence_with_sig.id.as_uuid(),
        "evidence",
        "DERIVED_FROM",
        Some(serde_json::json!({"was_created": was_created})),
        "submit_claim",
    )
    .await?;
    crate::claim_helper::emit_verb_edge_best_effort(
        &mut tx,
        claim_uuid,
        "claim",
        trace.id.as_uuid(),
        "trace",
        "HAS_TRACE",
        Some(serde_json::json!({"was_created": was_created})),
        "submit_claim",
    )
    .await?;

    // A resubmit whose canonical claim has NO `trace_id` is a PRE-EXISTING
    // ORPHAN — the residue of a submission that committed the claim and then
    // lost its trace to the 42501. `was_created` is false for it, so the old
    // code skipped `update_trace_id` and returned bare HTTP success forever: the
    // retry a caller performs precisely to repair the row could not repair it.
    // This submission already wrote a fresh Trace and Evidence above, so linking
    // them is the repair. Gated on `trace_id.is_none()` alone, never widened to
    // every resubmit: relinking a claim that already has a canonical trace would
    // rewrite settled provenance.
    let needs_trace_link = was_created || claim.trace_id.is_none();
    if needs_trace_link {
        ClaimRepository::update_trace_id_conn(&mut tx, claim.id, trace.id)
            .await
            .map_err(internal_error)?;
    }

    // COMMIT. Everything below this line is post-commit and best-effort.
    tx.commit().await.map_err(internal_error)?;

    // DS auto-wire: FIRST-CREATE ONLY, and that asymmetry with the embed below is
    // deliberate. Re-running it on an existing claim would combine the same mass
    // into the same frame twice, so a resubmit must not; re-embedding a claim that
    // has no vector is idempotent and is the only way a repaired orphan becomes
    // recallable again.
    let ds = if was_created {
        let ds_result = ds_auto::auto_wire_ds_for_claim(
            &server.pool,
            viewer,
            claim_uuid,
            agent_id,
            ds_auto::DsAutoInput {
                confidence,
                weight,
                supports: true,
                evidence_type: Some(&params.evidence_type),
            },
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
        ds_result.ok()
    } else {
        // Resubmit (Option B): verb-edges already emitted above, and the canonical
        // trace stays as it is unless the claim had none (the orphan-repair arm
        // above). No DS: canonical truth was set on first create.
        None
    };

    // EMBEDDING. Gated on `was_created` OR "the canonical row is missing its
    // vector", never on `was_created` alone.
    //
    // `was_created` alone is what made the orphan repair half a repair. A
    // production orphan committed its claim and lost its trace to the 42501
    // BEFORE this post-commit embed ran, so it carries `is_current = true` AND
    // `embedding IS NULL` — CLAUDE.md's `live_missing` violation. The retry that
    // repairs its provenance took the `was_created == false` branch, which
    // returned `{"embedded": false}` with HTTP success and a comment asserting
    // "canonical embedding already exists". For that row the comment was false
    // and the claim stayed invisible to `recall()` forever.
    //
    // `claim_text_if_embedding_missing` is the gate rather than a bare
    // `embedding IS NULL` read because the embedded population excludes
    // telemetry and sealed rows — see `EMBEDDABLE_POPULATION` in
    // `epigraph-db/src/repos/claim.rs`. A read failure means we cannot tell, and
    // the conservative answer is not to embed (the maintenance backfill
    // enumerates the same population and will pick it up).
    let embed_text: Option<String> = if was_created {
        Some(params.content.clone())
    } else {
        match ClaimRepository::claim_text_if_embedding_missing(&server.pool, viewer, claim_uuid)
            .await
        {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!(
                    claim_id = %claim_uuid,
                    "could not read whether the canonical claim still needs an embedding; \
                     skipping the repair embed: {e}"
                );
                None
            }
        }
    };

    // The store runs on an AUTHOR-STAMPED connection, not on `server.pool`: the
    // `UPDATE claims SET embedding` is governed by `claims_tenancy`'s WITH CHECK
    // and is refused on an unstamped session, silently, because the embed is
    // best-effort. See `claim_helper::embed_claim_author_stamped` for the
    // measurement and for why the provider call stays outside the transaction.
    //
    // Both arms go through it: the novelty gate's already-generated vector when
    // there is one (no second OpenAI call), and a fresh `generate` otherwise —
    // the gate's own embedder-failure path and the repair arm, where the
    // exact-resubmit shortcut means the gate never ran. The previous fallback,
    // `McpEmbedder::embed_and_store`, stores through the embedder's OWN
    // unstamped pool and is therefore refused in exactly the same way.
    let embedded = match embed_text {
        None => false,
        Some(text) => {
            crate::claim_helper::embed_claim_author_stamped(
                server,
                agent_id,
                claim_uuid,
                &text,
                pending_embedding.take(),
                "submit_claim",
            )
            .await
        }
    };

    // A resubmit reports the CANONICAL truth, not this submission's raw value.
    let final_truth = if was_created {
        ds.as_ref()
            .map(|d| d.pignistic_prob.clamp(0.01, 0.99))
            .unwrap_or(raw_truth)
    } else {
        claim.truth_value.value()
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
    })
}

pub async fn query_claims(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: QueryClaimsParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let min = params.min_truth.unwrap_or(0.0);
    let max = params.max_truth.unwrap_or(1.0);

    // Retirement state defaults to current-only. This tool is used as an
    // assessment-queue proxy (`query_claims(max_truth=0.4)`), and returning
    // superseded/refuted claims made already-resolved work resurface every
    // cycle (backlog a85ee585). `Some(false)` still yields superseded rows for
    // callers that want them; the schema documents that omission means
    // current-only.
    let is_current = params.is_current.or(Some(true));

    // Filter by truth range AND retirement state in SQL (before LIMIT) so
    // matching claims outside the most-recent `limit` rows are still reachable
    // (bug 5a55a48e) and excluded rows don't consume the limit budget.
    let claims =
        ClaimRepository::list_by_truth_range(&server.pool, viewer, min, max, is_current, limit, 0)
            .await
            .map_err(internal_error)?;

    // No per-id access map. `list_by_truth_range` is spliced with `viewer`, so
    // a claim this caller may not read is not in `claims`. The map existed to
    // fail closed on an id the batch helper skipped — a hazard created by
    // doing the check in a second pass keyed by id, which no longer happens.
    let ids: Vec<Uuid> = claims.iter().map(|c| c.id.as_uuid()).collect();

    // Populate labels via a single batch round-trip for all returned ids
    // (backlog babd5904: this handler previously hardcoded `labels: Vec::new()`
    // while get_claim on the same id returned them). Batch fetch avoids the
    // N+1 fan-out of per-claim get_labels calls; the helper does NOT filter on
    // is_current, so an explicit `is_current=false` request keeps its labels,
    // matching get_labels' label source. A missing id → no labels.
    let labels_map = ClaimRepository::labels_by_ids(&server.pool, viewer, &ids)
        .await
        .map_err(internal_error)?;

    let results: Vec<ClaimResponse> = claims
        .into_iter()
        .map(|c| {
            let id = c.id.as_uuid();
            ClaimResponse {
                id: id.to_string(),
                content: c.content.clone(),
                truth_value: c.truth_value.value(),
                agent_id: c.agent_id.as_uuid().to_string(),
                content_hash: ContentHasher::to_hex(&c.content_hash),
                created_at: c.created_at.to_rfc3339(),
                labels: labels_map.get(&id).cloned().unwrap_or_default(),
                // The row's real retirement state, not a hardcoded `true` /
                // `None` (backlog a85ee585) — `list_by_truth_range` now
                // projects both columns.
                is_current: c.is_current,
                supersedes: c.supersedes.map(|s| s.as_uuid().to_string()),
            }
        })
        .collect();

    success_json(&results)
}

pub async fn get_claim(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetClaimParams,
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
        crate::tools::lens::validate_lens_exists(&server.pool, viewer, frame_id, perspective_id)
            .await?;
    }

    let (claim, labels) = ClaimRepository::get_by_id_with_labels(&server.pool, viewer, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;
    // The `ok_or_else` above is now the ONLY outcome for a claim this viewer
    // cannot read: `get_by_id_with_labels` filters, and the redaction pass that
    // used to turn an already-fetched row into `("[REDACTED]", "")` is gone. A
    // private claim and a nonexistent uuid therefore produce the same error.
    let content = claim.content.clone();
    let content_hash = ContentHasher::to_hex(&claim.content_hash);
    // Cached CDST classification ('supported' | 'contradicted' |
    // 'not_enough_info' | null). Flattened onto the standard claim response so
    // existing `ClaimResponse` consumers are unaffected.
    let classification = ClaimRepository::get_classification(&server.pool, viewer, id)
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
                viewer,
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

    #[derive(serde::Serialize)]
    struct GetClaimResponse {
        #[serde(flatten)]
        claim: ClaimResponse,
        classification: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        lensed_belief: Option<LensedBelief>,
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
    })
}

/// Report the crypto state of a claim: does the body still match its stored
/// digest, and did a known key sign that digest.
///
/// # The integrity answer is three-valued, deliberately
///
/// `claims.content_hash` is not `blake3(content)` on every row. The canonical
/// Tier-1 document pipeline binds
/// `compound_content_hash(blake3(text), artifact_seed)` on every thesis,
/// section and paragraph node so that migration 013's
/// `UNIQUE (content_hash, agent_id)` cannot collapse two papers' "Introduction"
/// rows (`epigraph_ingest::common::plan::PlannedClaim::content_hash` is the
/// contract; `epigraph_mcp::tools::ingestion` binds it verbatim). For that class
/// `blake3(content) != stored` holds on *untampered* rows, and the seed is not
/// carried on the claim, so the comparison decides nothing — reported as
/// [`HashCheck::NotApplicable`] rather than as a mismatch.
///
/// The seed is deliberately NOT guessed back. `verify_claim` was filed as
/// theatre (backlog `49c17386`) for asserting certainty it did not have;
/// recomputing a compound digest from an inferred seed would reintroduce
/// exactly that, one level deeper.
pub async fn verify_claim(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: VerifyClaimParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let claim_id = ClaimId::from_uuid(id);
    let claim = ClaimRepository::get_by_id(&server.pool, viewer, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;

    // Integrity: BLAKE3 over the body vs. the digest STORED on the row.
    //
    // `ClaimRepository::get_by_id` projects `claims.content_hash` (backlog
    // `49c17386`). It used to inherit `claim_from_row`'s placeholder, which was
    // itself `ContentHasher::hash(content)` — so this comparison ran a value
    // against itself, the answer was unconditionally "matches", and a claim
    // whose body had been mutated without rewriting its digest verified clean.
    let computed_hash = ContentHasher::hash(claim.content.as_bytes());
    let hash_check = if computed_hash == claim.content_hash {
        HashCheck::Match
    } else {
        // The digest is not blake3(body). Two very different causes, and only
        // one of them is tampering. Classify by how the row was WRITTEN — the
        // predicate lives next to the writer that creates the class.
        //
        // Second query, on this branch only: the matching case needs no
        // `properties` read at all, so the common path is unchanged.
        let properties = ClaimRepository::get_properties(&server.pool, viewer, claim_id)
            .await
            .map_err(internal_error)?
            .unwrap_or(serde_json::Value::Null);
        if epigraph_ingest::document::stored_content_hash_is_seed_scoped(&properties) {
            HashCheck::NotApplicable
        } else {
            HashCheck::Mismatch
        }
    };

    // Authenticity: the stored Ed25519 signature over the stored digest,
    // checked against the SIGNER's public key (resolved by `get_by_id` through
    // `claims.signer_id -> agents.public_key`). Previously `public_key` was
    // hardcoded `[0u8; 32]` and `signature` hardcoded `None`, so this check
    // could never pass for any claim.
    //
    // `signed` keeps "no signature to check" distinguishable from "signature
    // present and rejected" — both of which report `signature_valid = false`.
    let signed = claim.signature.is_some();
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
        signed,
        hash_check,
        hash_matches: match hash_check {
            HashCheck::Match => Some(true),
            HashCheck::Mismatch => Some(false),
            // `null`, never `false`: see `VerifyResponse::hash_matches`.
            HashCheck::NotApplicable => None,
        },
        truth_value: claim.truth_value.value(),
    })
}

pub async fn update_with_evidence(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: UpdateWithEvidenceParams,
) -> Result<CallToolResult, McpError> {
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
        epigraph_db::WorkflowRepository::resolve_step_claim(&server.pool, viewer, name, idx, true)
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

    // Same placement rule as `submit_claim`: validate the caller's labels
    // before anything is written. The additive label merge at the bottom of
    // this function runs AFTER the Evidence insert, the DS/BBA wiring and the
    // truth_value update, so a rejection there would move the claim's belief
    // on the strength of a submission the caller was told had failed.
    epigraph_db::reject_unexpanded_labels(&params.labels).map_err(db_caller_error)?;

    let claim = ClaimRepository::get_by_id(&server.pool, viewer, ClaimId::from_uuid(claim_id))
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

    // ── THE EVIDENCE WRITE IS DELIBERATELY *NOT* STAMPED YET ────────────
    //
    // `evidence` is tier-A under migration 077's strict
    // `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))`, so on this
    // unstamped pool the INSERT is refused on a cleanly-migrated schema — MEASURED
    // as `new row violates row-level security policy for table "evidence"`. It is
    // this tool's FIRST write, so today that refusal is also its whole outcome:
    // the call fails and **nothing is written**.
    //
    // A revision of this branch DID stamp it, and that change was MEASURED to be a
    // regression rather than an improvement. The reason is that stamping this one
    // INSERT cannot make the tool whole: migration 046 gives
    // `mass_functions.evidence_id` a FK to `evidence(id)`, and `ds_auto`'s wiring
    // below runs on a SIBLING pool connection that cannot see an uncommitted row,
    // so a stamped evidence INSERT has to COMMIT ON ITS OWN before the DS wiring
    // can reference it. The DS wiring is itself unconverted (it writes
    // `claim_frames`, which has no orphan `*_privacy` policy), so on a clean
    // schema it is refused immediately afterwards — with the evidence row already
    // committed.
    //
    // The two configurations, measured with the real binary on a role with
    // `rolbypassrls = false`:
    //
    // * CONFIG B (prod-faithful, `evidence_privacy` present): the INSERT is
    //   admitted either way, so the stamp changes nothing here at all.
    // * CONFIG A (clean 001→head): unstamped fails at `evidence` having written
    //   nothing; stamped commits the evidence row and then drops the wire at
    //   `claim_frames`.
    //
    // So the stamp buys nothing on either configuration today, and on CONFIG A it
    // converts a clean refusal into a committed row whose BBA never lands.
    //
    // ONE PREMISE OF THIS ARGUMENT WEAKENED WHEN THE DS WIRING BELOW BECAME
    // BEST-EFFORT, and it is recorded here rather than quietly acted on. The
    // earlier form of the argument leant on RETRY AMPLIFICATION: `Evidence::new`
    // mints a fresh `EvidenceId` (a v4 UUID) and `EvidenceRepository::create` has
    // NO `ON CONFLICT`, so every agent retry of a call *certain to fail* appended
    // another evidence row for the same assertion. With the wire best-effort, a
    // stamped INSERT on CONFIG A would no longer report failure, so there would be
    // no retry to amplify — the residue would be one evidence row per submission
    // with `belief_wired: false`, which is exactly CONFIG B's behaviour today.
    // What survives untouched is the ATOMICITY half: a stamp here would still
    // commit evidence on its own connection, ahead of the truth/label unit below,
    // for no gain on either configuration. Re-deciding the stamp is D2's call and
    // needs its own measurement; this change does not pre-empt it. Its sibling in
    // `submit_ds_evidence` was KEPT for a different reason — `assign_claim` is
    // `ON CONFLICT … DO UPDATE` and `store_with_perspective` upserts, so a retry
    // there re-states rather than accumulates.
    //
    // This site therefore converts WITH the DS wiring (D2), in the one commit that
    // can put evidence → BBA → truth_value → labels in a single stamped unit, and
    // not before. `crates/epigraph-mcp/tests/residual_unstamped_writes.rs` carries
    // it in the residual register so it cannot be forgotten.
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
        ClaimRepository::get_belief_columns(&server.pool, viewer, ClaimId::from_uuid(claim_id))
            .await
            .map_err(internal_error)?
            .and_then(|c| c.pignistic_prob);

    // Load type_weight from calibration (replaces deleted evidence_weight())
    // I-3: use helper that checks CALIBRATION_PATH env var before relative path
    let weight = load_evidence_type_weight(&params.evidence_type);

    // ── CDST UPDATE — BEST-EFFORT, EXACTLY AS IN `submit_claim` ─────────
    //
    // This used to be `.map_err(internal_error)?`, i.e. FATAL, and that made the
    // tool report total failure for a call that had PARTLY SUCCEEDED: the
    // evidence INSERT above has already committed on its own connection (it has
    // to — `mass_functions.evidence_id` FKs `evidence(id)` and the wiring below
    // runs on a SIBLING pool connection that cannot see an uncommitted row), and
    // it stays committed when the wiring fails. So the caller was handed an error
    // for work the database had kept.
    //
    // `submit_claim` treats the IDENTICAL failure of the IDENTICAL helper as
    // best-effort (`tracing::warn!` + `ds_result.ok()`, see the comment above its
    // own transaction). Two tools disagreeing about whether one helper's failure
    // is fatal is not a policy, it is a discrepancy; this aligns the outlier with
    // the canonical path rather than inventing a third behaviour.
    //
    // WHY BEST-EFFORT IS THE RIGHT SIDE OF THAT ALIGNMENT. `claim_frames` /
    // `mass_functions` are written through the pool-bound `ds_auto` helper, which
    // is still unconverted for migration 077's tenancy stamp, so on a
    // cleanly-migrated schema this wiring is refused on EVERY call — measured in
    // production as `new row violates row-level security policy for table
    // "claim_frames"`, with `mass_functions`' last successful write on
    // 2026-09-22. Making that refusal fatal does not protect anything: the
    // evidence is already committed either way, and the only difference is
    // whether the agent can proceed.
    //
    // RECOVERY PATH, AND ITS LIMIT — which of the two applies is `bba_stored`.
    //
    // * BBA stored, late step failed: the operator binary
    //   `recompute_claim_belief` (a `[[bin]]` in the `epigraph-cli` package —
    //   `cargo run -p epigraph-cli --bin recompute_claim_belief -- --stdin` — not
    //   an `epigraph-cli` subcommand) draws its connection from
    //   `MaintenancePool::connect`, so it is not bound by this tool's pool, and
    //   recomputes the cached DS columns per frame from the claim's STORED
    //   `mass_functions`. It writes no `truth_value`
    //   (`MassFunctionRepository::update_claim_belief` sets only the DS
    //   columns), so `claims.truth_value` stays stale until the next successful
    //   wire on the claim. It is specifically NOT the `recompute_beliefs` MCP
    //   tool — that one is hard-disabled by
    //   `crate::maintenance::maintenance_tools_run_on_the_maintenance_connection()
    //   -> false` and refuses by construction, so naming it as the remedy would
    //   send an operator at a door that is welded shut.
    // * No BBA stored, first step failed — production's `claim_frames` refusal:
    //   there is nothing for that binary to recompute from, and no existing tool
    //   mints a BBA from an `evidence` row. Re-submitting is NOT a recovery: an
    //   identical re-submit is refused by `evidence_content_hash_claim_unique
    //   UNIQUE (content_hash, claim_id)` (the hash is over `evidence_data`), so
    //   the BBA-less row blocks it; a re-worded one is admitted as a SECOND
    //   evidence row for the same assertion, leaving the original BBA-less. Both
    //   measured in `update_with_evidence_ds_wiring_is_best_effort.rs`. The
    //   `evidence_id` in the response is the handle for a future
    //   BBA-from-evidence repair, and for de-duplicating the original row.
    //
    // AND IT IS DISCLOSED, NOT SWALLOWED. Returning bare success here would be
    // the silent-failure mode this codebase has been bitten by repeatedly, so the
    // response carries `belief_wired: false` (the same contract
    // `link_epistemic` already publishes) and the belief numbers below are held
    // honest: see the response construction at the end of this function.
    //
    // NOT A CONVERSION. `ds_auto` and `edge_factor` stay exactly as they are —
    // converting them is a separate unit, and when it lands the `Err` arm here
    // stops being reachable in normal operation and `belief_wired` becomes
    // permanently `true`. This change is confined to what happens WHEN it fails.
    //
    // C-1: pass evidence UUID as perspective_id so each evidence gets its own BBA row
    //
    // The STAGED form is used so the response can say whether this submission's
    // BBA was persisted before the failure (`bba_stored`). The two outcomes need
    // opposite recoveries and are otherwise indistinguishable to the caller —
    // `truth_after == truth_before` and the measures are absent in both.
    let (ds, ds_failure) = match ds_auto::auto_wire_ds_update_staged(
        &server.pool,
        viewer,
        claim_id,
        agent_id,
        strength,
        weight, // from calibration.toml (C1 fix: single weight source)
        params.supports,
        Some(&params.evidence_type),
        Some(evidence.id.as_uuid()), // C-1: evidence UUID prevents BBA upsert overwrite
    )
    .await
    {
        Ok(ds) => (Some(ds), None),
        Err(f) => {
            // Same message shape and same fields as `submit_claim`'s warn, so one
            // log query finds every dropped wire regardless of which tool dropped it.
            tracing::warn!(
                claim_id = %claim_id,
                bba_stored = f.bba_stored,
                "ds auto-wire failed: {}",
                f.error
            );
            (None, Some(f))
        }
    };

    // ── THE TWO CLAIM UPDATES, IN ONE AUTHOR-STAMPED TRANSACTION ────────
    //
    // Both are `UPDATE claims`, so both are governed by `claims_tenancy`'s
    // `WITH CHECK` and both were refused on the unstamped pool. They share a
    // transaction because they are one decision about one row: the belief this
    // submission produced, and the labels it was submitted under. Splitting them
    // is how a successful truth update with dropped labels happens — the shape
    // backlog f14592cb reported for the labels themselves.
    //
    // AFTER the DS wiring, necessarily: `after_truth` is derived from
    // `ds.pignistic_prob`, so there is nothing to write until the recompute has
    // run. The label merge stays in the same unit rather than moving earlier,
    // because a label rejection must not leave the claim's belief moved on the
    // strength of a submission the caller was told had failed — the placement rule
    // the caller-label validation at the top of this function already follows.
    //
    // WHY THIS ONE IS STAMPED WHILE THE EVIDENCE INSERT ABOVE IS NOT, which is
    // otherwise an inconsistency a reader is right to challenge: these are the
    // tool's LAST writes, so a self-committing stamped unit here opens no orphan
    // window — there is nothing after it that can fail with them half-landed. The
    // evidence INSERT is the FIRST write and is followed by an unconverted step
    // that is certain to fail on a clean schema, so stamping it would have
    // committed a row the call then reports as failed, and retries would
    // accumulate.
    //
    // REACHABILITY, RE-MEASURED AFTER THE DS WIRING ABOVE BECAME BEST-EFFORT.
    // It used to be true that "neither reaches execution on either
    // configuration", because a refused wire aborted the whole tool. It is no
    // longer: on CONFIG B (prod-faithful) the evidence INSERT is admitted, the
    // wire is dropped with a warn, and this block now RUNS — committing the label
    // merge with `update_truth_value_conn` skipped, per the note directly below.
    // On CONFIG A the evidence INSERT is still refused first, so this block is
    // still unreached there. MEASURED on both via `scripts/e2e/probe-tools.sh`
    // (real binary, `epigraph_app`, `rolbypassrls = false`), with a `labels`
    // argument so the merge is observable: CONFIG B `uwe_labelled` 0 → 1 across
    // the fix; CONFIG A 0 on both binaries, refused at `evidence`.
    //
    // AND WHEN IT DOES BECOME REACHABLE IT WILL SERVE ONLY CLAIMS THIS SERVER'S
    // GROUP OWNS. The stamp carries `server.agent_id()`'s writable set, and
    // `claims_tenancy`'s `WITH CHECK` asks about the ROW's `owner_group_id` — the
    // TARGET claim's group, not the evidence author's. So `update_with_evidence`
    // against another agent's claim stays refused on a cleanly-migrated schema,
    // exactly as `update_labels` does. That residual is pinned on the non-bypassing
    // role by `epigraph-db/tests/tool_write_tables_require_a_stamp.rs::
    // relabelling_a_foreign_groups_claim_is_refused_on_a_stamped_app_session` and
    // its `…_lands_when_the_session_carries_the_claims_own_group` pair; the same
    // statement holds for `challenge_claim` and `submit_ds_evidence`, and each
    // states it at its own site. It is a tenancy-model decision, not a defect here.
    // ── AND WHEN THE WIRING DROPPED, THE LABEL MERGE STILL RUNS ─────────
    //
    // `after_truth` is `None` exactly when the wiring failed, because its value
    // is DERIVED from `ds.pignistic_prob` — with no completed combination there
    // is no new truth to write (even when this submission's BBA was stored before
    // a late step failed), and writing the old one back would be a lie dressed as
    // an update.
    //
    // The label merge is NOT gated on the same condition, and that separation is
    // deliberate. Gating the whole block on "the wiring succeeded" would drop
    // every submitted label on the DS-failure path, which is precisely backlog
    // f14592cb (run-tag labels silently lost on every call) reintroduced through
    // a different door — and a silent loss is the failure mode this change exists
    // to remove, not one it may trade for. The two facts are independently true:
    // the labels were submitted and accepted, the belief was not computed. So the
    // transaction still opens, still carries the author stamp, and commits
    // whichever of the two writes actually has something to say.
    let after_truth = ds.as_ref().map(|d| TruthValue::clamped(d.pignistic_prob));
    {
        let mut tx =
            crate::claim_helper::begin_author_stamped_tx(server, agent_id, "update_with_evidence")
                .await?;
        if let Some(after_truth) = after_truth {
            ClaimRepository::update_truth_value_conn(
                &mut tx,
                ClaimId::from_uuid(claim_id),
                after_truth,
            )
            .await
            .map_err(internal_error)?;
        }

        // Additive label merge on the dedup-match write, mirroring submit_claim's
        // and memorize's dedup-hit behavior: labels union into the claim's
        // existing array (ClaimRepository::update_labels dedupes via
        // array_agg(DISTINCT ...)), never overwriting labels from the claim's
        // original creation cycle. Fixes backlog f14592cb: run-tag labels (e.g.
        // norcal-rfp-2026-07-05) were previously dropped on every call because
        // UpdateWithEvidenceParams had no labels field at all.
        if !params.labels.is_empty() {
            ClaimRepository::update_labels_conn(&mut tx, claim_id, &params.labels, &[])
                .await
                .map_err(db_caller_error)?;
        }
        tx.commit().await.map_err(internal_error)?;
    }

    // Warn when SUPPORTING evidence lowered the pignistic probability. Compare
    // pignistic-to-pignistic; when the claim had no prior DS state the column is
    // NULL, so fall back to the truth_value the fresh BBA combined against.
    //
    // Only ever computed on the wired path. This warning is a statement about a
    // COMBINATION that happened ("supporting evidence decreased belief"); with no
    // combination there is nothing it could be true or false about, and
    // `pre_pignistic` on its own is a stale column read, not a delta.
    let pre_belief = pre_pignistic.unwrap_or(before);
    let warning = ds.as_ref().and_then(|d| {
        (params.supports && d.pignistic_prob < pre_belief).then(|| {
            "Supporting evidence decreased belief — the new evidence has high \
             ignorance mass relative to the prior; this is mathematically correct \
             DS combination, not a bug."
                .to_string()
        })
    });

    // ── THE RESPONSE, WITH THE BELIEF NUMBERS HELD HONEST ───────────────
    //
    // `evidence_id` is reported unconditionally because the evidence row is
    // committed unconditionally — that half genuinely succeeded and the caller
    // needs the id to find it.
    //
    // Everything DS-derived is reported only when the wire COMPLETED — a stored
    // BBA with no completed combination (a late-step failure) yields no measures:
    //
    // * `truth_after` falls back to `before` — the claim's truth_value was not
    //   updated, so before and after really are equal. Reporting the persisted
    //   `pignistic_prob` column here instead would manufacture a delta out of a
    //   previous call's state.
    // * `belief` / `plausibility` / `pignistic_prob` are `None`, and their
    //   `skip_serializing_if` makes them ABSENT from the JSON rather than `null`
    //   or stale. A consumer that reads them gets this submission's measures or
    //   nothing; it never gets someone else's.
    // * `belief_wired` is the flag that makes the above legible instead of
    //   ambiguous: `false` says "`claims.truth_value` and the cached belief
    //   columns were not updated by this call", so an unchanged `truth_after`
    //   cannot be misread as "the evidence had no effect on a claim that WAS
    //   recomputed". It does NOT say no BBA landed — that is `bba_stored`.
    // * `bba_stored` / `ds_wire_error` say WHICH failure it was. A late-step
    //   failure has already persisted this submission's BBA (framed reads that
    //   recompute live from stored BBAs reflect it, and the next successful wire
    //   combines it); a first-step failure has not. The error text is the same
    //   string the tool used to return as its -32603 message, so reporting it
    //   discloses nothing the old contract did not.
    success_json(&UpdateResponse {
        claim_id: claim_id.to_string(),
        truth_before: before,
        truth_after: after_truth.map_or(before, |t| t.value()),
        evidence_id: evidence.id.as_uuid().to_string(),
        belief_wired: ds.is_some(),
        bba_stored: ds_failure.as_ref().map_or(true, |f| f.bba_stored),
        ds_wire_error: ds_failure.map(|f| f.error),
        belief: ds.as_ref().map(|d| d.belief),
        plausibility: ds.as_ref().map(|d| d.plausibility),
        pignistic_prob: ds.as_ref().map(|d| d.pignistic_prob),
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
///   non-HTTP callers without re-opening the cross-agent abuse vector —
///   *provided* that signer agent is a stable identity. When it is not,
///   see the `signer_identity_declared` arm below.
///
/// ## The undeclared-signer arm
///
/// The stdio comparison presumes the server HAS an identity worth
/// comparing against. `main::select_signer` rung 4 (`--agent-key` and
/// `--agent-model` both absent) hands back `AgentSigner::generate()` — a
/// fresh random keypair per process, which `agent_id()` then registers as
/// a brand-new `agents` row that has authored nothing. Against such a
/// signer `caller_agent == target_agent_id` cannot hold for any claim not
/// written during this same process lifetime: the check is not "owner
/// only", it is deny-always, and the message it emitted pointed at a
/// remedy (`claims:admin` over HTTP) the caller had no way to reach.
///
/// This is the configuration epiclaw agent containers run — the
/// agent-runner spawns `epigraph-mcp --database-url <url>` over stdio with
/// no key — so cross-agent supersede/retire was permanently unreachable
/// for every agent in the fleet.
///
/// Granting the operation there does not widen the trust boundary:
///
/// - A stdio server is spoken to only by the process that spawned it, and
///   that process supplied `--database-url`, so it already holds
///   unmediated write access to every row this gate protects.
/// - `patch_claim` and `update_labels` (`crate::tools::claims`) take no
///   `AuthContext` and perform no ownership check at all, so arbitrary
///   cross-agent label/property mutation is already available on this
///   transport.
/// - The strictly *looser* deployment already permits it: a
///   `--listen unix:… --allow-unauthenticated-http` listener gets
///   `auth::unauthenticated_context()`, which carries every scope in
///   `SCOPE_MAP` including `claims:admin`. Refusing stdio while allowing
///   an unauthenticated socket inverts the two postures.
/// - No remotely reachable path arrives here with `auth = None`:
///   `main::check_listen_auth_mode` refuses a TCP listener that has
///   neither `--jwt-secret` nor (unix-only) `--allow-unauthenticated-http`.
///
/// A server WITH a declared signer keeps the strict behavior unchanged.
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

    if !server.signer_identity_declared {
        // Undecidable, not denied — see the doc comment. Warned rather than
        // silent: this is the one arm that mutates another agent's claim with
        // no credential presented, so the journal must be able to show which
        // pairs it covered.
        tracing::warn!(
            target_agent = %target_agent_id,
            caller_agent = %caller_agent,
            "cross-agent claim mutation allowed on an unauthenticated transport: this server \
             has no declared signer identity (--agent-key / --agent-model absent), so the \
             owner-equality fallback is undecidable. Pass --agent-key to restore strict \
             ownership enforcement."
        );
        return Ok(());
    }

    Err(McpError {
        code: rmcp::model::ErrorCode::INVALID_PARAMS,
        message: format!(
            "claim is owned by agent {target_agent_id}; \
             caller agent {caller_agent} cannot retire it. This transport carries no \
             AuthContext, and {caller_agent} is this server's declared signer identity \
             (--agent-key / --agent-model), so ownership is enforced against it. Use an \
             authenticated HTTP listener with a claims:admin token, or run this server \
             under the owning agent's key."
        )
        .into(),
        data: None,
    })
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
    viewer: &epigraph_db::visibility::Viewer,
    params: crate::types::ResolveBacklogItemParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let original_id = parse_uuid(&params.original_id)?;
    let original_claim_id = ClaimId::from_uuid(original_id);

    // Confirm the target exists; we do NOT require the "backlog" label —
    // a stricter precondition belongs to the call site (HTTP filters /
    // operator UI) rather than the verb.
    let original = ClaimRepository::get_by_id(&server.pool, viewer, original_claim_id)
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

    // Resolve the closure basis BEFORE anything is created.
    //
    // Ordering is the load-bearing decision here: a bad or unreadable basis id
    // discovered AFTER `submit_claim` would leave an orphan resolution claim
    // with no edges — and, once the label patch ran, an item that looks closed
    // with no recorded basis at all, which is the exact failure this parameter
    // exists to prevent.
    //
    // The existence check goes through the caller's `viewer`, the same read
    // `original` above uses. That is deliberate and is the tenancy property of
    // this feature: a caller cannot point a `justifies` edge at a claim they
    // cannot see, and an invisible basis is REFUSED rather than silently
    // dropped. Silently dropping would be worse than either alternative — it
    // would record a closure whose basis set is quietly smaller than the one
    // the caller asked for.
    let mut basis_ids: Vec<uuid::Uuid> = Vec::with_capacity(params.basis_claim_ids.len());
    for raw in &params.basis_claim_ids {
        let basis_uuid = parse_uuid(raw)?;
        if basis_uuid == original_id {
            return Err(invalid_params(format!(
                "basis claim {basis_uuid} is the backlog item being resolved; a closure \
                 cannot be its own justification"
            )));
        }
        ClaimRepository::get_by_id(&server.pool, viewer, ClaimId::from_uuid(basis_uuid))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| {
                invalid_params(format!("basis claim {basis_uuid} not found or not visible"))
            })?;
        if !basis_ids.contains(&basis_uuid) {
            basis_ids.push(basis_uuid);
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
    };
    let submit_result = submit_claim(server, viewer, submit_params).await?;
    let resolution_id = extract_submit_claim_id(&submit_result)?;

    // 2. Record the closure basis as `resolution -justifies-> basis` edges,
    //    BEFORE the label patch. Ordering again: the item must not read as
    //    closed until its basis is on the graph, because a closure with a
    //    `resolved` label and no basis is precisely the un-reopenable state
    //    this records against.
    //
    //    `create_if_not_exists` keys on (source, target, relationship), so a
    //    retried call re-asserts rather than duplicating.
    let resolution_uuid = parse_uuid(&resolution_id)?;
    let mut basis_edge_ids: Vec<String> = Vec::with_capacity(basis_ids.len());
    for basis_uuid in &basis_ids {
        // Direction is `basis -justifies-> resolution`, NOT the reverse. Two
        // reasons, and the second is the load-bearing one:
        //   1. It is the correct English reading — the basis justifies the
        //      resolution, not the other way round.
        //   2. `EdgeRepository::list_current_claim_targets`, which
        //      `retraction_cascade` uses to enumerate downstream work, takes a
        //      `source_id` and walks `WHERE e.source_id = $1`. With the basis on
        //      the TARGET side, retracting a basis could never reach the
        //      resolution that rested on it.
        // NOTE this alone does NOT make the closure defeasible — see the
        // `basis_claim_ids` doc in types.rs. `sheaf::restriction_kind_with_profile`
        // does not name "justifies", so it takes the `_ => Neutral` arm, and
        // `auto_wire_edge_if_epistemic` short-circuits on Neutral, so the edge
        // carries no BBA and the cascade's BBA filter skips it regardless of
        // direction. This direction is a precondition for a future fix, not the
        // fix itself.
        let (row, _was_created) = epigraph_db::EdgeRepository::create_if_not_exists(
            &server.pool,
            *basis_uuid,
            "claim",
            resolution_uuid,
            "claim",
            JUSTIFIES_RELATIONSHIP,
            Some(serde_json::json!({
                "via": "resolve_backlog_item",
                "closure_of": original_id.to_string(),
            })),
            None,
            None,
        )
        .await
        .map_err(|e| McpError {
            code: rmcp::model::ErrorCode::INTERNAL_ERROR,
            message: format!(
                "resolution claim {resolution_id} created but failed to record basis \
                 {basis_uuid}: {e}"
            )
            .into(),
            data: Some(serde_json::json!({
                "resolution_claim_id": resolution_id,
                "original_id": original_id.to_string(),
            })),
        })?;
        basis_edge_ids.push(row.id.to_string());
    }

    // 3. PATCH the original's labels: add "resolved", keep "backlog".
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

    success_json(&serde_json::json!({
        "resolution_claim_id": resolution_id,
        "original_id": original_id.to_string(),
        "original_labels": after_labels,
        "basis_claim_ids": basis_ids.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
        "basis_edge_ids": basis_edge_ids,
    }))
}

/// Relationship byte string for a closure-basis edge: resolution → basis.
///
/// LOWERCASE, and the same literal on both surfaces. `epigraph-api`'s
/// `is_valid_relationship` matches `VALID_RELATIONSHIPS` case-sensitively and
/// carries both spellings of several names (`DERIVED_FROM` and `derived_from`),
/// so a mismatch here would make an edge this tool writes unreachable through
/// `POST /api/v1/edges`. Lowercase matches the claim→claim cluster it belongs
/// with: `alternative_of`, `asserts`, `decomposes_to`.
pub const JUSTIFIES_RELATIONSHIP: &str = "justifies";

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

/// The one label that carries RETIREMENT semantics.
///
/// Exact byte string on purpose: it must be the same literal the canonical
/// open-backlog query filters on
/// (`query_claims_by_label(labels=["backlog"], exclude_labels=["resolved"])`,
/// `CLAUDE.md`). A case variant such as `Resolved` is deliberately NOT gated,
/// because it does not retire anything either — `exclude_labels` would not
/// match it, so the claim stays visible in every backlog query.
pub(crate) const RETIREMENT_LABEL: &str = "resolved";

/// Apply `resolve_backlog_item`'s ownership gate to a free-form label mutation,
/// but ONLY when it touches [`RETIREMENT_LABEL`] and ONLY on a transport that
/// carries an `AuthContext` (issue #374).
///
/// ## The asymmetry this closes
///
/// `resolve_backlog_item`, `supersede_claim` and `mark_duplicate` all call
/// [`require_owner_or_admin`]; `update_labels` and `patch_claim` called nothing,
/// while being able to achieve the same *observable* effect — adding `resolved`
/// to a claim removes it from every open-backlog query, without the resolution
/// claim or the `Resolves <id>: ` trail the gated verb exists to create. A
/// caller refused by the gated path was nudged toward the unaudited one. The
/// reporter's own session relabelled 161 claims it did not own over the same
/// token that `resolve_backlog_item` then refused.
///
/// ## Why only the `resolved` label
///
/// A blanket `require_owner_or_admin` on these two tools would gate cross-agent
/// taxonomy maintenance, which is legitimate and high-volume. `resolved` is the
/// one label with retirement semantics; the rest are free-form vocabulary.
/// Both directions are gated: *removing* `resolved` un-retires a claim, which is
/// the same authority as retiring it.
///
/// ## Why only the authenticated transport — and what stays open
///
/// `auth = None` means stdio, and stdio is NOT a trust boundary here: the
/// process that spawned the server handed it `--database-url`, so it already
/// holds unmediated write access to every row this gate protects (the same
/// argument [`require_owner_or_admin`]'s doc comment makes for its own stdio
/// arm). Gating it would also break a live, documented workflow rather than an
/// abuse: `epiclaw-host`'s baked `release/epiclaw/CLAUDE.md` instructs every
/// scheduled agent to retire cross-agent backlog items with exactly
/// `update_labels(original_id, add=["resolved"])`, because `resolve_backlog_item`
/// refuses them.
///
/// That refusal is real and was **re-measured, not assumed**: the epiclaw
/// agent-runner exports `EPIGRAPH_AGENT_MODEL` /
/// `EPIGRAPH_AGENT_SYSTEM_PROMPT_HASH` (`agent-runner/src/index.ts`,
/// `agentIdentityEnv`), so `main::select_signer` takes rung 1 and
/// `signer_identity_declared` is **true** for the fleet — the
/// warn-and-allow `!signer_identity_declared` arm does not cover them. Gating
/// stdio here would therefore leave those agents with no way to retire a
/// backlog item at all.
///
/// So this closes the remotely-reachable half and leaves the local half as it
/// was. The stdio bypass remains open by design until the sanctioned path is
/// reachable for the fleet; issue #374 stays open for that half.
async fn gate_retirement_label(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    claim_id: Uuid,
    add: &[String],
    remove: &[String],
) -> Result<(), McpError> {
    let touches_retirement = add
        .iter()
        .chain(remove.iter())
        .any(|l| l == RETIREMENT_LABEL);
    if !touches_retirement {
        return Ok(());
    }
    let Some(auth) = auth else {
        return Ok(());
    };

    // Only fetched on the gated path, so the common label mutation keeps its
    // single round-trip. This also means a `resolved` mutation now reports
    // "claim not found" for a missing id where it previously fell through to a
    // repo-layer no-op — deliberate: the gate cannot decide ownership of a row
    // it cannot read.
    //
    // Read with the CALLER's own authority, not a maintenance viewer: this is
    // an ownership gate, and a principal who cannot see the row cannot own it.
    // A viewer-invisible claim therefore takes the same "not found" branch as a
    // nonexistent one, which is the behaviour the paragraph above describes.
    // Viewer is supplied by the caller (acquired in server.rs). Acquiring it
    // here instead would break `tool_viewer_coverage`'s location ratchet, which
    // asserts `request_viewer(` appears under src/tools/ only in viewer.rs.
    let claim = ClaimRepository::get_by_id(&server.pool, viewer, ClaimId::from_uuid(claim_id))
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {claim_id} not found")))?;

    require_owner_or_admin(server, Some(auth), claim.agent_id.as_uuid()).await
}

pub async fn update_labels(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: crate::types::UpdateLabelsParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    if params.add.is_empty() && params.remove.is_empty() {
        return Err(invalid_params("must specify at least one of add/remove"));
    }
    let id = parse_uuid(&params.claim_id)?;
    gate_retirement_label(server, viewer, auth, id, &params.add, &params.remove).await?;
    // `db_caller_error`, not `internal_error`: a label refused by
    // `reject_unexpanded_labels` is the caller's input, not a server fault. The
    // repo layer refuses it inside the same statement that would have written
    // it, so nothing is persisted — only the reported code was wrong here.
    //
    // Author-stamped, because this is an `UPDATE claims` and `claims_tenancy`'s
    // WITH CHECK refuses it on an unstamped session. The stamp is the MCP
    // server's own agent, which is what makes the SANCTIONED case work: the
    // stdio ownership gate above degrades to "the claim's author is this server's
    // agent", so the row is owned by the group this session can write. A
    // `claims:admin` HTTP caller relabelling ANOTHER agent's claim is still
    // refused on a cleanly-migrated schema, because the row is owned by that
    // agent's group and no viewer this process can resolve carries write
    // authority there — the same residual `challenge_claim` carries, and a
    // tenancy-model question rather than a stamping one.
    let mut tx = crate::claim_helper::begin_author_stamped_tx(
        server,
        server.agent_id().await?,
        "update_labels",
    )
    .await?;
    let labels = ClaimRepository::update_labels_conn(&mut tx, id, &params.add, &params.remove)
        .await
        .map_err(db_caller_error)?;
    tx.commit().await.map_err(internal_error)?;
    success_json(&serde_json::json!({ "claim_id": id, "labels": labels }))
}

pub async fn patch_claim(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: crate::types::PatchClaimParams,
    auth: Option<&epigraph_auth::AuthContext>,
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
    // Same gate as `update_labels`: `patch_claim` also accepts
    // `add_labels`/`remove_labels`, so leaving it ungated would just move the
    // bypass one tool over (issue #374).
    gate_retirement_label(
        server,
        viewer,
        auth,
        id,
        &params.add_labels,
        &params.remove_labels,
    )
    .await?;
    // STILL UNSTAMPED, and named here rather than left silent. This transaction
    // is ATOMIC but carries no tenancy context, so `patch_claim_atomic_conn`'s
    // `UPDATE claims` is refused by `claims_tenancy`'s `WITH CHECK` on a session
    // whose writable set is `{}` — the same refusal the `update_labels` tool
    // above was converted out of.
    //
    // It is not converted with it because the fix is a REPOSITORY SIGNATURE
    // CHANGE, not a call-site one: `patch_claim_atomic_conn` takes a
    // `&mut sqlx::Transaction`, which `ScopedTx` is not (it derefs to
    // `PgConnection`), so the parameter has to become a connection — with an
    // `epigraph-api` caller to move and a `visibility_lint` register entry to
    // write, since a `&mut PgConnection` parameter is exactly what that lint's
    // connection scanner reads.
    //
    // Recorded because this site escaped the residual-write inventory
    // altogether: it takes no `&server.pool` ARGUMENT — it calls
    // `server.pool.begin()` — so an argument-shaped scan cannot see it. Its
    // sibling `update_labels`, two functions up, was in that inventory.
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
    .map_err(db_caller_error)?;
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
    viewer: &epigraph_db::visibility::Viewer,
    params: crate::types::QueryUndecomposedClaimsParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 1000);
    let offset = params.offset.unwrap_or(0).max(0);

    let claims = ClaimRepository::list_undecomposed(&server.pool, viewer, limit, offset)
        .await
        .map_err(internal_error)?;

    // `list_undecomposed` is spliced with `viewer`. This path once bypassed the
    // redaction layer entirely — a finding fixed by adding a second pass; the
    // durable fix is that the read itself filters, so there is no second pass
    // left to forget.
    let results: Vec<ClaimResponse> = claims
        .into_iter()
        .map(|c| {
            let id = c.id.as_uuid();
            ClaimResponse {
                id: id.to_string(),
                content: c.content.clone(),
                truth_value: c.truth_value.value(),
                agent_id: c.agent_id.as_uuid().to_string(),
                content_hash: ContentHasher::to_hex(&c.content_hash),
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
    use super::parse_methodology;
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
}
