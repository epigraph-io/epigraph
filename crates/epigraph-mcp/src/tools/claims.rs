#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
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
use epigraph_db::{ClaimRepository, EdgeRepository, EvidenceRepository, ReasoningTraceRepository};
use uuid::Uuid;

fn parse_methodology(s: &str) -> Result<Methodology, String> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "bayesian_inference" | "bayesian" => Ok(Methodology::BayesianInference),
        "deductive_logic" | "deductive" => Ok(Methodology::Deductive),
        "inductive_generalization" | "inductive" => Ok(Methodology::Inductive),
        "expert_elicitation" | "expert" => Ok(Methodology::Heuristic),
        "statistical_analysis" | "statistical" => Ok(Methodology::Instrumental),
        "meta_analysis" | "meta" => Ok(Methodology::FormalProof),
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
    mut params: SubmitClaimParams,
) -> Result<CallToolResult, McpError> {
    let methodology = parse_methodology(&params.methodology).map_err(invalid_params)?;
    let evidence_type = parse_evidence_type(&params.evidence_type, params.source_url.as_deref())
        .map_err(invalid_params)?;

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
    if !is_exact_resubmit {
        let novelty_threshold = params
            .novelty_threshold
            .unwrap_or(crate::tools::novelty_gate::DEFAULT_NOVELTY_THRESHOLD);
        if let Some((decision, pgvec)) = crate::tools::novelty_gate::decide(
            &server.pool,
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

    // Idempotent canonical claim create + AUTHORED verb-edge.
    let (claim, was_created) =
        crate::claim_helper::create_claim_idempotent(&server.pool, &claim, "submit_claim").await?;
    let claim_uuid = claim.id.as_uuid();

    if !params.labels.is_empty() {
        ClaimRepository::update_labels(&server.pool, claim_uuid, &params.labels, &[])
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
    let claims = ClaimRepository::list_by_truth_range(&server.pool, min, max, limit, 0)
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
                is_current: true,
                supersedes: None,
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

    let claim = ClaimRepository::get_by_id(&server.pool, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;
    let labels = ClaimRepository::get_labels(&server.pool, claim_id)
        .await
        .map_err(internal_error)?;
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
    let claim_id = parse_uuid(&params.claim_id)?;
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

    success_json(&UpdateResponse {
        claim_id: claim_id.to_string(),
        truth_before: before,
        truth_after: after_truth.value(),
        evidence_id: evidence.id.as_uuid().to_string(),
        belief: Some(ds.belief),
        plausibility: Some(ds.plausibility),
        pignistic_prob: Some(ds.pignistic_prob),
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

    success_json(&serde_json::json!({
        "resolution_claim_id": resolution_id,
        "original_id": original_id.to_string(),
        "original_labels": after_labels,
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
        .map_err(internal_error)?;
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
    .map_err(internal_error)?;
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
