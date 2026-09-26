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
    params: SubmitClaimParams,
) -> Result<CallToolResult, McpError> {
    success_json(&submit_claim_response(server, viewer, params).await?)
}

/// `submit_claim` as a typed response rather than a serialized tool result.
///
/// `batch_submit_claims` calls this per entry and returns each entry's FULL
/// response (backlog 73657204). It used to call [`submit_claim`] and re-parse
/// the JSON text for `claim_id` alone, discarding truth_value, content_hash,
/// embedded and the whole Dempster-Shafer block for every batch entry.
pub(crate) async fn submit_claim_response(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SubmitClaimParams,
) -> Result<SubmitClaimResponse, McpError> {
    let sub = match prepare_submission(server, viewer, params).await? {
        PreparedSubmission::Existing(response) => return Ok(*response),
        PreparedSubmission::Fresh(sub) => *sub,
    };
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, sub.agent_id, "submit_claim").await?;
    let written = write_submission(&mut tx, server, viewer, &sub, "submit_claim").await?;
    // COMMIT. Everything after this line is post-commit and best-effort.
    tx.commit().await.map_err(internal_error)?;
    finish_submission(server, viewer, sub, written, "submit_claim").await
}

/// The `deduplicated` block for a `submit_claim` answered with an existing
/// claim (backlog a3e63a12). Each list is what the path in question ACTUALLY
/// does with the input, read off the code below, not what one might expect:
///
/// * [`DedupBy::NoveltyGate`] — `prepare_submission` returns before any
///   transaction opens. Nothing of this call is written: not its wording, not
///   its labels, not an evidence row, not a trace.
/// * [`DedupBy::ContentHash`] — `write_submission` still runs in full on the
///   existing claim: `update_labels_conn` UNIONS the labels in; a new Evidence
///   row (evidence_data, evidence_type, and source_url serialized into the
///   evidence type) and a new ReasoningTrace (methodology, reasoning,
///   confidence) are written and linked by DERIVED_FROM / HAS_TRACE edges. The
///   trace becomes the claim's canonical trace only if it had none. The DS
///   auto-wire is skipped (`was_created` is false), so none of it moves the
///   existing belief. `novelty_threshold` is never consulted: the exact-content
///   pre-check skips the gate. `source_url` is written nowhere for `empirical`
///   evidence, whose evidence type has no URL slot (`parse_evidence_type`) —
///   true of a fresh insert as well.
///
/// Only supplied inputs are listed; see `types::Deduplicated`. On a
/// novelty-gate hit `novelty_threshold` is the input that DECIDED the hit, so
/// it is listed in neither.
fn dedup_block(by: DedupBy, existing_claim_id: Uuid, params: &SubmitClaimParams) -> Deduplicated {
    let mut applied: Vec<&'static str> = Vec::new();
    let mut discarded: Vec<&'static str> = Vec::new();
    let url_has_a_slot = !params.evidence_type.eq_ignore_ascii_case("empirical");
    match by {
        DedupBy::NoveltyGate => {
            discarded.extend(["content", "methodology", "evidence_data", "evidence_type"]);
            discarded.push("confidence");
            if params.source_url.is_some() {
                discarded.push("source_url");
            }
            if params.reasoning.is_some() {
                discarded.push("reasoning");
            }
            if !params.labels.is_empty() {
                discarded.push("labels");
            }
        }
        DedupBy::ContentHash => {
            applied.extend([
                "methodology",
                "evidence_data",
                "evidence_type",
                "confidence",
            ]);
            if params.source_url.is_some() {
                if url_has_a_slot {
                    applied.push("source_url");
                } else {
                    discarded.push("source_url");
                }
            }
            if params.reasoning.is_some() {
                applied.push("reasoning");
            }
            if !params.labels.is_empty() {
                applied.push("labels");
            }
            if params.novelty_threshold.is_some() {
                discarded.push("novelty_threshold");
            }
        }
    }
    Deduplicated {
        by,
        existing_claim_id: existing_claim_id.to_string(),
        inputs_applied: applied,
        inputs_discarded: discarded,
    }
}

/// What [`prepare_submission`] decided.
enum PreparedSubmission {
    /// The novelty gate matched an existing claim: this is the response, and
    /// nothing is to be written.
    Existing(Box<SubmitClaimResponse>),
    /// A submission to write.
    Fresh(Box<Submission>),
}

/// Everything [`write_submission`] and [`finish_submission`] need, computed once
/// by [`prepare_submission`] before any transaction opens.
struct Submission {
    params: SubmitClaimParams,
    agent_id: Uuid,
    agent_id_typed: AgentId,
    pub_key: [u8; 32],
    confidence: f64,
    weight: f64,
    raw_truth: f64,
    claim: Claim,
    content_hash: [u8; 32],
    methodology: Methodology,
    evidence_type: EvidenceType,
    pending_embedding: Option<String>,
}

/// What [`write_submission`] wrote.
struct WrittenSubmission {
    claim: Claim,
    was_created: bool,
    ds: Option<ds_auto::DsAutoResult>,
}

/// Phase 1 of a submission: validation, the signed [`Claim`], and the write-side
/// novelty gate. Nothing is written.
///
/// # Why a submission is three phases
///
/// `submit_claim` is also the first write of `resolve_backlog_item`, and that tool
/// must commit its resolution claim, its `justifies` edges and the original's
/// `resolved` label as ONE fact. It used to call `submit_claim` whole, which
/// committed the resolution claim on its own transaction before the edges and
/// the label patch ran, so a failure after it left a resolution claim for an item
/// still reading as open. Splitting the pipeline lets that caller run
/// [`write_submission`] on its own transaction and share one code path with
/// `submit_claim` rather than a copy of it.
async fn prepare_submission(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    mut params: SubmitClaimParams,
) -> Result<PreparedSubmission, McpError> {
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
                return Ok(PreparedSubmission::Existing(Box::new(
                    SubmitClaimResponse {
                        claim_id: existing_id.to_string(),
                        truth_value: existing.truth_value.value(),
                        content_hash: ContentHasher::to_hex(&existing.content_hash),
                        embedded: false,
                        belief: None,
                        plausibility: None,
                        pignistic_prob: None,
                        frame_id: None,
                        // The caller is TOLD this is not an insert, and that
                        // every input it sent was dropped (backlog a3e63a12).
                        deduplicated: Some(dedup_block(DedupBy::NoveltyGate, existing_id, &params)),
                    },
                )));
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

    Ok(PreparedSubmission::Fresh(Box::new(Submission {
        params,
        agent_id,
        agent_id_typed,
        pub_key,
        confidence,
        weight,
        raw_truth,
        claim,
        content_hash,
        methodology,
        evidence_type,
        pending_embedding,
    })))
}

/// Phase 2 of a submission: every write, on the caller's author-stamped
/// transaction. See the comment at the top of the body for why they share one.
/// The caller COMMITs.
async fn write_submission(
    conn: &mut sqlx::PgConnection,
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    sub: &Submission,
    tool_name: &'static str,
) -> Result<WrittenSubmission, McpError> {
    let Submission {
        params,
        agent_id,
        agent_id_typed,
        pub_key,
        confidence,
        weight,
        claim,
        methodology,
        evidence_type,
        ..
    } = sub;
    let (agent_id, agent_id_typed, pub_key, confidence, weight) =
        (*agent_id, *agent_id_typed, *pub_key, *confidence, *weight);
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
    // The DS auto-wire is INSIDE it too (see below, before COMMIT). Only the
    // embedding is deliberately outside, below the commit: that is CLAUDE.md's
    // policy (best-effort, post-commit, warn on failure, never block the write),
    // and a provider round trip must not hold a transaction open.

    // Idempotent canonical claim create + AUTHORED verb-edge.
    let (claim, was_created) =
        crate::claim_helper::create_claim_idempotent(&mut *conn, viewer, claim, tool_name).await?;
    let claim_uuid = claim.id.as_uuid();

    // Already validated above, before the claim write. This call can now only
    // fail for server-side reasons; `db_caller_error` keeps those
    // INTERNAL_ERROR while still reporting a caller-caused `InvalidData`
    // correctly if a future label rule is added to the repo layer. Inside the
    // transaction, so a rejected label no longer leaves a labelled-nothing claim.
    if !params.labels.is_empty() {
        ClaimRepository::update_labels_conn(&mut *conn, claim_uuid, &params.labels, &[])
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
        evidence_type.clone(),
        Some(params.evidence_data.clone()),
        claim.id,
    );
    let evidence_with_sig = {
        let mut e = evidence;
        e.signature = Some(server.signer.sign(&evidence_hash));
        e
    };

    let explanation = params.reasoning.clone().unwrap_or_else(|| {
        format!(
            "Claim submitted via MCP with {} methodology",
            params.methodology
        )
    });
    let trace = ReasoningTrace::new(
        agent_id_typed,
        pub_key,
        *methodology,
        vec![TraceInput::Evidence {
            id: evidence_with_sig.id,
        }],
        confidence,
        explanation,
    );

    // Persist Trace + Evidence on every submission. In the transaction: a
    // refusal here now rolls the claim back instead of committing it as an
    // orphan.
    ReasoningTraceRepository::create(&mut *conn, &trace, claim.id)
        .await
        .map_err(internal_error)?;
    EvidenceRepository::create(&mut *conn, &evidence_with_sig)
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
        &mut *conn,
        claim_uuid,
        "claim",
        evidence_with_sig.id.as_uuid(),
        "evidence",
        "DERIVED_FROM",
        Some(serde_json::json!({"was_created": was_created})),
        tool_name,
    )
    .await?;
    crate::claim_helper::emit_verb_edge_best_effort(
        &mut *conn,
        claim_uuid,
        "claim",
        trace.id.as_uuid(),
        "trace",
        "HAS_TRACE",
        Some(serde_json::json!({"was_created": was_created})),
        tool_name,
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
        ClaimRepository::update_trace_id_conn(&mut *conn, claim.id, trace.id)
            .await
            .map_err(internal_error)?;
    }

    // DS auto-wire: FIRST-CREATE ONLY, and that asymmetry with the embed below is
    // deliberate. Re-running it on an existing claim would combine the same mass
    // into the same frame twice, so a resubmit must not; re-embedding a claim that
    // has no vector is idempotent and is the only way a repaired orphan becomes
    // recallable again.
    //
    // IN THIS TRANSACTION, BEFORE COMMIT, AND A FAILURE FAILS THE SUBMISSION.
    // `claim_frames`, `mass_functions`, the cached-belief `UPDATE claims` and the
    // `truth_value` derived from the pignistic land with the claim or not at all.
    // It used to run post-commit and warn-only, so a wiring failure returned
    // success with `belief: null` over a committed claim that had no BBA: partial
    // state behind a success response. See
    // `claim_helper::wire_ds_for_new_claim_in_tx` for why that is now safe to make
    // fatal, and why retrying is safe.
    let ds = if was_created {
        Some(
            crate::claim_helper::wire_ds_for_new_claim_in_tx(
                &mut *conn,
                viewer,
                agent_id,
                claim_uuid,
                ds_auto::DsAutoInput {
                    confidence,
                    weight,
                    supports: true,
                    evidence_type: Some(&params.evidence_type),
                },
                /* persist_truth_from_pignistic */ true,
                tool_name,
            )
            .await?,
        )
    } else {
        // Resubmit (Option B): verb-edges already emitted above, and the canonical
        // trace stays as it is unless the claim had none (the orphan-repair arm
        // above). No DS: canonical truth was set on first create.
        None
    };

    Ok(WrittenSubmission {
        claim,
        was_created,
        ds,
    })
}

/// Phase 3 of a submission, after COMMIT: the best-effort embedding (CLAUDE.md's
/// policy) and the response.
async fn finish_submission(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    sub: Submission,
    written: WrittenSubmission,
    tool_name: &'static str,
) -> Result<SubmitClaimResponse, McpError> {
    let Submission {
        params,
        agent_id,
        raw_truth,
        content_hash,
        mut pending_embedding,
        ..
    } = sub;
    let WrittenSubmission {
        claim,
        was_created,
        ds,
    } = written;
    let claim_uuid = claim.id.as_uuid();

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
                tool_name,
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

    Ok(SubmitClaimResponse {
        claim_id: claim_uuid.to_string(),
        truth_value: final_truth,
        content_hash: ContentHasher::to_hex(&content_hash),
        embedded,
        belief: ds.as_ref().map(|d| d.belief),
        plausibility: ds.as_ref().map(|d| d.plausibility),
        pignistic_prob: ds.as_ref().map(|d| d.pignistic_prob),
        frame_id: ds.as_ref().map(|d| d.frame_id.to_string()),
        // `was_created` from the idempotent create, not the read-only
        // pre-check: it is what decided whether DS ran, and it also covers a
        // concurrent writer landing the same content between the two.
        deduplicated: (!was_created)
            .then(|| dedup_block(DedupBy::ContentHash, claim_uuid, &params)),
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

    // Filter by the BELIEF SCORE range AND retirement state in SQL (before
    // LIMIT) so matching claims outside the most-recent `limit` rows are still
    // reachable (bug 5a55a48e) and excluded rows don't consume the limit
    // budget. The score is the DS pignistic probability when the claim has a
    // DS cache, else `truth_value` — the same score `recall`'s `min_truth`
    // gates on (GitHub #395). This used to filter the stale authored
    // `truth_value`, so a refuted claim (BetP 0.18, `truth_value` 0.78) never
    // entered a `max_truth=0.4` assessment queue.
    let claims =
        ClaimRepository::list_by_belief_range(&server.pool, viewer, min, max, is_current, limit, 0)
            .await
            .map_err(internal_error)?;

    // No per-id access map. `list_by_belief_range` is spliced with `viewer`, so
    // a claim this caller may not read is not in `claims`. The map existed to
    // fail closed on an id the batch helper skipped — a hazard created by
    // doing the check in a second pass keyed by id, which no longer happens.
    let ids: Vec<Uuid> = claims.iter().map(|(c, _)| c.id.as_uuid()).collect();

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
        .map(|(c, score)| {
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
                // `None` (backlog a85ee585) — `list_by_belief_range`
                // projects both columns.
                is_current: c.is_current,
                supersedes: c.supersedes.map(|s| s.as_uuid().to_string()),
                // What min_truth / max_truth were compared against.
                belief_score: Some(score),
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
            belief_score: None,
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

    // HISTORY, kept short because the next block supersedes it: before D2 this
    // evidence INSERT was deliberately left UNSTAMPED. Stamped on its own it
    // would have had to self-commit (migration 046's
    // `mass_functions.evidence_id -> evidence(id)` FK, with the DS wiring on a
    // sibling connection), and the still-unconverted DS wiring then failed at
    // `claim_frames` — a committed evidence row whose BBA never landed. MEASURED
    // on the pre-branch binary, CONFIG B: `update_with_evidence` ->
    // "assign_claim: ... policy for table \"claim_frames\"" with the evidence
    // row committed.
    //
    // (An earlier form of this note also called that orphan a RETRY AMPLIFIER —
    // "`Evidence::new` mints a fresh v4 UUID and `EvidenceRepository::create`
    // has no `ON CONFLICT`, so each retry appends another row". #497 measured
    // that premise wrong for an IDENTICAL retry: `content_hash` is
    // `blake3(evidence_data)` and migration 001's
    // `evidence_content_hash_claim_unique UNIQUE (content_hash, claim_id)`
    // refuses it as "Duplicate entity already exists". Only a RE-WORDED retry
    // adds a row. That makes a committed BBA-less row WORSE, not better: it
    // blocks the identical re-submission that would land the contribution.)
    //
    // ── D2: evidence -> BBA -> truth_value -> labels, ONE STAMPED UNIT ──
    //
    // THE OBJECTION ABOVE IS ANSWERED BY THE TRANSACTION, NOT WAIVED. It said
    // stamping this INSERT alone "converts a clean refusal into a committed
    // orphan". That is true of a SELF-COMMITTING stamped INSERT. Here the INSERT
    // joins the transaction that also carries the DS wiring, the truth write and
    // the label merge: if any of them fails, nothing is committed, so there is
    // no BBA-less row left behind to refuse the identical re-submission — the
    // caller's retry of the same `evidence_data` is the recovery, and it is
    // pinned in `tests/update_with_evidence_ds_wiring_failure_is_atomic.rs`.
    //
    // AND THE FK ORDERING THAT FORCED THE SPLIT DISSOLVES. Migration 046 gives
    // `mass_functions.evidence_id` a foreign key to `evidence(id)`, which is why
    // the evidence row had to exist before `auto_wire_ds_update` could reference
    // it. A foreign key is checked at statement time against the CURRENT
    // transaction's snapshot, not at commit, so an uncommitted evidence row in
    // this same transaction satisfies it. The two writes no longer need separate
    // commits to be orderable.
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, agent_id, "update_with_evidence")
            .await?;

    EvidenceRepository::create(&mut *tx, &evidence)
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
        ClaimRepository::get_belief_columns(&mut *tx, viewer, ClaimId::from_uuid(claim_id))
            .await
            .map_err(internal_error)?
            .and_then(|c| c.pignistic_prob);

    // Load type_weight from calibration (replaces deleted evidence_weight())
    // I-3: use helper that checks CALIBRATION_PATH env var before relative path
    let weight = load_evidence_type_weight(&params.evidence_type);

    // ── CDST UPDATE — A FAILURE IS A RETURNED ERROR THAT ROLLS EVERYTHING BACK ──
    //
    // #497 ("update_with_evidence best-effort") made this failure non-fatal and
    // disclosed it as `belief_wired: false`. That was right FOR ITS TREE: there
    // the evidence INSERT had already self-committed on the unstamped pool, the
    // wiring ran on a sibling pool connection and was refused in production
    // (`new row violates row-level security policy for table "claim_frames"`),
    // so a fatal error reported total failure for a call whose evidence row the
    // database had kept.
    //
    // Neither premise survives D2. The wiring runs on THIS stamped transaction,
    // so the production refusal it was working around is the thing D2 removes,
    // and the evidence row is uncommitted until everything below succeeds. A
    // failure here therefore leaves NOTHING behind — no evidence, no BBA, no
    // truth write, no labels — and an error is now the complete and truthful
    // answer. Swallowing it instead would commit exactly the BBA-less evidence
    // row the note above explains is worse than nothing (it blocks the identical
    // re-submit via `evidence_content_hash_claim_unique`). The error text keeps
    // the failing step as its prefix (`assign_claim:`, `store BBA:`,
    // `update_claim_belief:`, …), so the caller still learns WHICH step failed,
    // which is the part of #497's disclosure that still has a referent.
    //
    // `submit_claim` still treats its own DS wiring as best-effort, and that is
    // not a discrepancy: there the CLAIM is the primary write and it has already
    // committed in its own transaction before the wire runs, so the claim
    // exists either way. Here the evidence row IS the submission, and it is in
    // the same unit as its BBA.
    //
    // C-1: pass evidence UUID as perspective_id so each evidence gets its own BBA row
    let ds = ds_auto::auto_wire_ds_update(
        &mut tx,
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
    .map_err(|e| {
        // Logged as well as returned. `internal_error` only builds the
        // `McpError`, so without this a dropped wire here would never reach
        // the server log. #497 added this warn so that one log query
        // ("ds auto-wire failed") finds every dropped wire, whichever tool
        // dropped it; `submit_claim`'s path emits the same prefix with the same
        // `claim_id`/`tool` fields. The wording differs because the outcome
        // does: here the whole submission is rolled back.
        tracing::warn!(
            claim_id = %claim_id,
            tool = "update_with_evidence",
            "ds auto-wire failed: {e}. Rolled back; nothing from this submission was stored"
        );
        internal_error(e)
    })?;

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
    // IT SERVES ONLY CLAIMS THIS SERVER'S
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
    let after_truth = TruthValue::clamped(ds.pignistic_prob);
    {
        ClaimRepository::update_truth_value_conn(
            &mut tx,
            ClaimId::from_uuid(claim_id),
            after_truth,
        )
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
            ClaimRepository::update_labels_conn(&mut tx, claim_id, &params.labels, &[])
                .await
                .map_err(db_caller_error)?;
        }
        tx.commit().await.map_err(internal_error)?;
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

    // `belief_wired` / `bba_stored` / `ds_wire_error` are #497's response fields,
    // kept because clients may already read them. Under D2 a success response is
    // only reachable when the whole unit committed, so they are constant here:
    // the wire landed (`true`), this submission's BBA is persisted (`true`, which
    // #497 defines as always true when `belief_wired` is), and there is no wire
    // error to report. A failed wire never reaches this line — it is the `?`
    // above, with everything rolled back.
    success_json(&UpdateResponse {
        claim_id: claim_id.to_string(),
        truth_before: before,
        truth_after: after_truth.value(),
        evidence_id: evidence.id.as_uuid().to_string(),
        belief_wired: true,
        bba_stored: true,
        ds_wire_error: None,
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
///
/// ## The operator arm (migration 107)
///
/// Added BESIDE every branch above, never in place of one. It asks two
/// DIFFERENT questions, one per side, and uses a different definer read for
/// each (`migrations/107_operator_link.sql` section 5):
///
/// - `author_op(target)` = `AgentRepository::operator_of_author` — "whose are
///   this author's claims?", from the `operator_links` record alone, RETIRED
///   links included, no membership consulted. Used ONLY for the target.
/// - `actor_op(caller)` = `AgentRepository::operator_actor` — "may this agent
///   act for an operator?": a not-retired record, a live `writer`/`admin`
///   membership, the operator's own personal group. Used ONLY for the caller.
///
/// With `caller` = the server's own agent on stdio and `auth.agent_id` over
/// HTTP, the arm allows exactly:
///
/// - `caller == author_op(target)` — the operator acting on its linked agents'
///   claims, retired ones included (over HTTP this is the operator's own
///   `auth.agent_id`);
/// - `actor_op(caller) == author_op(target)`, both present — an agent acting
///   for the operator on another of its agents' claims, e.g. a job whose model
///   was bumped and so runs under a new identity, over its retired
///   predecessor's claims. **stdio only.** Operated agents are stdio-only
///   (token issuance refuses them), but that is enforced at MINT, so a token
///   minted BEFORE the agent was linked would otherwise carry the actor arm
///   onto HTTP until it expired (stage-2 review). Over HTTP only the operator
///   acting directly is admitted.
///
/// A retired identity is never an actor, so it owns nothing through this arm
/// (its key may be exposed). An operator's OWN directly authored claims are
/// not reachable from its agents here: `author_op(operator)` is `None`.
///
/// ### What this arm does NOT reach: claims written through a shared HTTP signer
///
/// The rule is keyed on the claim's AUTHOR (`claims.agent_id`). Claims an
/// operator writes through the shared HTTP MCP servers (`epigraph-mcp-auth` /
/// `-http`) are authored by that server's ONE signer agent, not by the
/// operator's own agent id, so they are outside it: no link names the signer
/// as operated (an HTTP listener refuses to start, and refuses every call, while
/// its signer has any link — `operator::refuse_operated_http_signer`,
/// `operator::refuse_linked_http_signer`). Do NOT close that gap by walking the
/// signer's `OPERATED_BY` auth-lineage edges: `record_auth_lineage` writes one
/// for every OAuth caller and REST `create_edge` accepts `OPERATED_BY` from any
/// `edges:write` caller, so those edges are forgeable and would make every
/// caller an owner of every HTTP-authored claim. Extending ownership to
/// HTTP-authored claims needs its own design.
///
/// It is keyed on AUTHORS, never on the claim's owner group. "The owner group is
/// writable by the caller" would be the wrong generalisation: most pre-tenancy
/// claims are world-owned, and an agent's writable set would make it an owner
/// of everything. `None == None` never matches — an unlinked caller and an
/// unlinked target share no operator.
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
        // Between the principal check and the denial, deliberately: every
        // ALLOW above is unchanged. One visible difference on the DENY path: a
        // failed operator lookup (e.g. a database without migration 107) now
        // returns an internal error instead of the ownership denial text — the
        // gate does not decide on an answer it did not get.
        if let Some(caller) = auth.agent_id {
            // `allow_actor = false`: operated agents are stdio-only.
            if operator_arm_allows(server, caller, target_agent_id, false).await? {
                return Ok(());
            }
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

    // The operator arm runs AFTER the undeclared-signer arm, so that arm is
    // byte-for-byte the pre-107 behaviour — including when the operator lookup
    // fails (e.g. a database without migration 107), where it still warns and
    // allows instead of returning an internal error. The order changes no
    // decision: an undeclared (random, per-process) signer can be neither
    // operated (`operator::check_operator_transport` refuses it) nor anyone's
    // operator.
    if operator_arm_allows(server, caller_agent, target_agent_id, true).await? {
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

/// The operator arm of [`require_owner_or_admin`]; see its doc for the rule.
///
/// The TARGET side reads `AgentRepository::operator_of_author` and the CALLER
/// side `AgentRepository::operator_actor` (migration 107's two definer reads).
/// Swapping either is a defect: an author read on the caller side would let a
/// retired identity — whose key may be exposed — act for its operator, and an
/// actor read on the target side would take the operator's ownership of a
/// retired or revoked agent's claims away. A lookup failure is an error, not a
/// `false`: the gate must not quietly decide ownership without the answer it
/// asked for.
///
/// `allow_actor` is `false` on the HTTP transport: there only `caller ==
/// author_op(target)` (the operator itself) is admitted, never the actor arm.
async fn operator_arm_allows(
    server: &EpiGraphMcpFull,
    caller: uuid::Uuid,
    target: uuid::Uuid,
    allow_actor: bool,
) -> Result<bool, McpError> {
    let Some(target_op) =
        epigraph_db::AgentRepository::operator_of_author_pool(&server.pool, target)
            .await
            .map_err(internal_error)?
            .map(|a| a.operator_id)
    else {
        // An author with no link record has no operator for anyone to share.
        return Ok(false);
    };
    let reason = if caller == target_op {
        "caller is the operator of the claim's author"
    } else if allow_actor
        && epigraph_db::AgentRepository::operator_actor_pool(&server.pool, caller)
            .await
            .map_err(internal_error)?
            .is_some_and(|l| l.operator_id == target_op)
    {
        "caller acts for the operator of the claim's author"
    } else {
        return Ok(false);
    };
    tracing::info!(
        caller = %caller,
        target_agent = %target,
        operator = %target_op,
        reason,
        "claim ownership granted through an operator link"
    );
    Ok(true)
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
/// # All-or-nothing, on ONE author-stamped transaction
///
/// The resolution claim, its `justifies` edges and the original's `resolved`
/// label commit together, or nothing does. It used to call `submit_claim`
/// whole, which committed the resolution claim on its own transaction and then
/// wrote the edges and the label patch on the unstamped pool. A failure there
/// returned an error carrying a `resolution_claim_id` for the reconciler to
/// back-fill, over a committed resolution for an item still reading as open:
/// partial state by contract. The label PATCH is an `UPDATE claims` that
/// `claims_tenancy`'s WITH CHECK refuses on an unstamped session, so on a
/// cleanly-migrated schema that partial state was the normal outcome.
///
/// The stamp is `server.agent_id()`'s, the author of the resolution claim, as
/// for every other MCP write. The label PATCH therefore succeeds for an item
/// owned by that agent's group, which is the item the stdio ownership gate
/// admits. A `claims:admin` HTTP caller retiring ANOTHER agent's item is
/// refused on a cleanly-migrated schema with nothing written: carrying the
/// caller's admin authority into a group this process cannot write is the
/// cross-agent ownership question (#374), not a stamping one. Only the
/// embedding of the resolution claim runs after COMMIT, best-effort.
pub async fn resolve_backlog_item(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: crate::types::ResolveBacklogItemParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let original_id = parse_uuid(&params.original_id)?;
    let original_claim_id = ClaimId::from_uuid(original_id);

    // THE GATE READS RUN ON A STAMPED TRANSACTION, not the unstamped pool, and
    // it is a separate one from the write transaction below. The transaction is
    // needed because on an unstamped session `claims_tenancy`'s USING admits only
    // public rows, so a group-private original or basis read "not found" even for
    // its own author: the gate refused the one population the write stamp
    // exists to admit. It is SEPARATE because the submission's first phase can
    // call the embedding provider (the novelty gate), and a provider round trip
    // must not hold a transaction open. This one only reads; dropping it rolls
    // back nothing.
    let mut gate_tx = crate::claim_helper::begin_author_stamped_tx(
        server,
        server.agent_id().await?,
        "resolve_backlog_item",
    )
    .await?;

    // Confirm the target exists; we do NOT require the "backlog" label —
    // a stricter precondition belongs to the call site (HTTP filters /
    // operator UI) rather than the verb.
    let original = ClaimRepository::get_by_id(&mut *gate_tx, viewer, original_claim_id)
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
        ClaimRepository::get_by_id(&mut *gate_tx, viewer, ClaimId::from_uuid(basis_uuid))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| {
                invalid_params(format!("basis claim {basis_uuid} not found or not visible"))
            })?;
        if !basis_ids.contains(&basis_uuid) {
            basis_ids.push(basis_uuid);
        }
    }
    drop(gate_tx);

    // 1. The resolution claim, through the canonical pipeline's first phase
    //    (validation + signing). Nothing is written yet.
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
    let sub = match prepare_submission(server, viewer, submit_params).await? {
        PreparedSubmission::Fresh(sub) => *sub,
        // Unreachable at `novelty_threshold = 0.0`: no distance is below zero,
        // so the gate never returns an existing claim for a resolution. Refused
        // rather than trusted, because following it would retire the item
        // against a claim this call did not write.
        PreparedSubmission::Existing(_) => {
            return Err(internal_error(
                "resolve_backlog_item: the novelty gate returned an existing claim for a \
                 resolution at threshold 0.0; refusing to retire the item against a claim this \
                 call did not write. Nothing was written.",
            ))
        }
    };

    // THE ONE TRANSACTION. Resolution claim, `justifies` edges and the label
    // PATCH all run on it; see the function doc.
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, sub.agent_id, "resolve_backlog_item")
            .await?;

    // RE-DECIDE THE GATE ON THE WRITE TRANSACTION. The reads above ran on
    // `gate_tx`, which is gone, and `prepare_submission` may have spent a
    // provider round trip since. An original reassigned, or a basis privatized
    // or deleted, inside that window would otherwise still be written against.
    // So the original and every basis are read again through the caller's
    // viewer, on the transaction the writes run on, and the ownership check is
    // re-run against the author read HERE (review finding, atomicity-authz).
    // Both reads are cheap point lookups; the gate above stays, because it is
    // what refuses a bad request BEFORE the provider call.
    let original_now = ClaimRepository::get_by_id(&mut *tx, viewer, original_claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| {
            invalid_params(format!(
                "claim {original_id} is no longer visible; nothing was written"
            ))
        })?;
    if original_now.agent_id.as_uuid() != target_agent {
        require_owner_or_admin(server, auth, original_now.agent_id.as_uuid()).await?;
    }
    for basis_uuid in &basis_ids {
        ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(*basis_uuid))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| {
                invalid_params(format!(
                    "basis claim {basis_uuid} is no longer visible; nothing was written"
                ))
            })?;
    }

    let written = write_submission(&mut tx, server, viewer, &sub, "submit_claim").await?;
    let resolution_uuid = written.claim.id.as_uuid();
    let resolution_id = resolution_uuid.to_string();

    // 2. Record the closure basis as `basis -justifies-> resolution` edges,
    //    BEFORE the label patch. The item must not read as closed until its
    //    basis is on the graph, because a closure with a `resolved` label and
    //    no basis is precisely the un-reopenable state this records against.
    //    Now that both are in one transaction the order is also what a reader
    //    of this function sees, not a partial-failure guarantee.
    //
    //    `create_if_not_exists_conn` keys on (source, target, relationship), so
    //    a retried call re-asserts rather than duplicating.
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
        //
        // TENANCY. 070's trigger owns the edge by its endpoints: world-owned
        // when both are public (the resolution claim is public), otherwise the
        // private basis's group. A private basis is readable here only if it is
        // this agent's own (the viewer check above), so its edge lands in a group
        // this stamp can write.
        let (row, _was_created) = epigraph_db::EdgeRepository::create_if_not_exists_conn(
            &mut tx,
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
        .map_err(|e| {
            internal_error(format!(
                "resolve_backlog_item: could not record basis {basis_uuid}: {e}. Nothing was \
                 written: the resolution claim was rolled back with it."
            ))
        })?;
        basis_edge_ids.push(row.id.to_string());
    }

    // 3. PATCH the original's labels: add "resolved", keep "backlog". In the
    //    same transaction: a refusal here rolls back the resolution claim and
    //    its edges, so an item is never left open beside a resolution of it.
    let after_labels =
        ClaimRepository::update_labels_conn(&mut tx, original_id, &["resolved".to_string()], &[])
            .await
            .map_err(|e| {
                internal_error(format!(
            "resolve_backlog_item: could not label {original_id} resolved: {e}. Nothing was \
             written: the resolution claim and its basis edges were rolled back with it."
        ))
            })?;

    tx.commit().await.map_err(internal_error)?;

    // After COMMIT, best-effort: the resolution claim's embedding, exactly as
    // `submit_claim` does it. Its response is not returned; this tool's is.
    let _ = finish_submission(server, viewer, sub, written, "submit_claim").await;

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
    conn: &mut sqlx::PgConnection,
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
    //
    // On the caller's STAMPED connection, not the unstamped pool. An unstamped
    // session's `claims_tenancy` USING admits only public rows, so a
    // group-private claim read "not found" here even for its own author. The
    // gate then refused the one population the stamp below exists to admit.
    let claim = ClaimRepository::get_by_id(&mut *conn, viewer, ClaimId::from_uuid(claim_id))
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
    // The gate reads on the SAME stamped transaction; a refusal drops `tx`, which
    // rolls back, so nothing is written.
    gate_retirement_label(
        server,
        &mut tx,
        viewer,
        auth,
        id,
        &params.add,
        &params.remove,
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
    // ONE TRANSACTION, STAMPED FROM THE MCP SERVER'S OWN AGENT, and every read
    // and write below runs on it.
    //
    // This was `server.pool.begin()`: atomic, but carrying no tenancy context,
    // so on a cleanly-migrated schema `claims_tenancy`'s `WITH CHECK` refused
    // `patch_claim_atomic_conn`'s UPDATE. That session's writable set is `{}`.
    // It was not converted with `update_labels` because
    // `patch_claim_atomic_conn` took a `&mut sqlx::Transaction`, which a
    // `ScopedTx` is not. It now takes the connection a `ScopedTx` derefs to.
    //
    // THE STAMP IS `server.agent_id()`'s, the same as `update_labels`, and for
    // the same reason. Every claim this MCP process writes is authored by that
    // agent and owned by its group, so that is the population the stamp admits.
    // A claim owned by another agent's group is refused loudly (`42501` from the
    // UPDATE, or not-found from the row lock). Nothing is written, because the
    // refusal aborts this transaction and it is never committed. Whether a
    // `claims:admin` caller should carry write authority into a group this
    // process cannot write is the cross-agent ownership question (#374), not a
    // stamping one.
    let mut tx = crate::claim_helper::begin_author_stamped_tx(
        server,
        server.agent_id().await?,
        "patch_claim",
    )
    .await?;

    // The CALLER's read authority, on the same transaction. Before this,
    // `patch_claim` checked caller visibility only on the retirement-label path
    // below. A caller could patch the trace or properties of a claim it could not
    // read, as long as it named the id. That is the MCP twin of the HTTP
    // write-path gap (backlog 30c29c52). An invisible claim is reported as not
    // found, exactly like a missing one.
    let target = ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(id))
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;

    // OWNERSHIP OF THE WHOLE PATCH on the authenticated transport, as the HTTP
    // twin (`PATCH /api/v1/claims/:id`, `require_owner_or_admin`) requires. The
    // write runs under the SERVER agent's stamp, so without this an HTTP caller
    // who could merely READ a server-authored claim could rewrite its trace and
    // properties with the server's write authority (batch H-a review,
    // atomicity-authz). Only when `auth` is present: on stdio the caller IS the
    // process that holds the DSN, and a cross-agent patch there is the
    // #374 stdio half, left open by design (see `gate_retirement_label`).
    if auth.is_some() {
        require_owner_or_admin(server, auth, target.agent_id.as_uuid()).await?;
    }

    // Same gate as `update_labels`: `patch_claim` also accepts
    // `add_labels`/`remove_labels`, so leaving it ungated would just move the
    // bypass one tool over (issue #374).
    gate_retirement_label(
        server,
        &mut tx,
        viewer,
        auth,
        id,
        &params.add_labels,
        &params.remove_labels,
    )
    .await?;
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
                belief_score: None,
            }
        })
        .collect();

    success_json(&results)
}

#[cfg(test)]
mod tests {
    // Nested in `tests` because `tests/no_inline_sql_in_tools.rs` requires the first
    // `#[cfg(test)]` in a tools file to introduce `mod tests` and be the last item.
    mod dedup_block_tests {
        //! The novelty-gate arm of `dedup_block` cannot be reached through
        //! `EpiGraphMcpFull` in a test process (its embedder hard-codes OpenAI; see
        //! `tests/novelty_gate_test.rs`), so its list is pinned here. The
        //! content-hash arm is additionally measured end-to-end in
        //! `tests/dedup_response_signal.rs`.
        use super::super::dedup_block;
        use crate::types::{DedupBy, SubmitClaimParams};

        fn params() -> SubmitClaimParams {
            SubmitClaimParams {
                content: "c".into(),
                methodology: "direct_observation".into(),
                evidence_data: "e".into(),
                evidence_type: "logical".into(),
                confidence: 0.5,
                source_url: Some("u".into()),
                reasoning: Some("r".into()),
                labels: vec!["l".into()],
                novelty_threshold: Some(0.1),
            }
        }

        #[test]
        fn a_novelty_gate_hit_discards_every_supplied_input() {
            let d = dedup_block(DedupBy::NoveltyGate, uuid::Uuid::nil(), &params());
            assert!(d.inputs_applied.is_empty(), "{d:?}");
            for want in [
                "content",
                "methodology",
                "evidence_data",
                "evidence_type",
                "confidence",
                "source_url",
                "reasoning",
                "labels",
            ] {
                assert!(d.inputs_discarded.contains(&want), "{want}: {d:?}");
            }
            assert!(
                !d.inputs_discarded.contains(&"novelty_threshold"),
                "the threshold decided the hit; it was not discarded: {d:?}"
            );
        }

        #[test]
        fn unsupplied_inputs_are_listed_nowhere() {
            let mut p = params();
            p.source_url = None;
            p.reasoning = None;
            p.labels.clear();
            p.novelty_threshold = None;
            for by in [DedupBy::NoveltyGate, DedupBy::ContentHash] {
                let d = dedup_block(by, uuid::Uuid::nil(), &p);
                for absent in ["source_url", "reasoning", "labels", "novelty_threshold"] {
                    assert!(
                        !d.inputs_applied.contains(&absent)
                            && !d.inputs_discarded.contains(&absent),
                        "{absent} listed for {by:?}: {d:?}"
                    );
                }
            }
        }
    }

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
