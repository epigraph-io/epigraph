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
use epigraph_db::PatchClaimInput;
use epigraph_db::{ClaimRepository, EdgeRepository, EvidenceRepository, ReasoningTraceRepository};

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
    params: SubmitClaimParams,
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

        let embedded = server
            .embedder
            .embed_and_store(claim_uuid, &params.content)
            .await;

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
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    // Use list with search for now (min/max truth filtering done post-query)
    let claims = ClaimRepository::list(&server.pool, limit, 0, None)
        .await
        .map_err(internal_error)?;

    let min = params.min_truth.unwrap_or(0.0);
    let max = params.max_truth.unwrap_or(1.0);

    let results: Vec<ClaimResponse> = claims
        .into_iter()
        .filter(|c| {
            let tv = c.truth_value.value();
            tv >= min && tv <= max
        })
        .map(|c| ClaimResponse {
            id: c.id.as_uuid().to_string(),
            content: c.content.clone(),
            truth_value: c.truth_value.value(),
            agent_id: c.agent_id.as_uuid().to_string(),
            content_hash: ContentHasher::to_hex(&c.content_hash),
            created_at: c.created_at.to_rfc3339(),
            labels: Vec::new(),
            is_current: true,
            supersedes: None,
        })
        .collect();

    success_json(&results)
}

pub async fn get_claim(
    server: &EpiGraphMcpFull,
    params: GetClaimParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let claim_id = ClaimId::from_uuid(id);
    let claim = ClaimRepository::get_by_id(&server.pool, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;
    let labels = ClaimRepository::get_labels(&server.pool, claim_id)
        .await
        .map_err(internal_error)?;

    success_json(&ClaimResponse {
        id: claim.id.as_uuid().to_string(),
        content: claim.content.clone(),
        truth_value: claim.truth_value.value(),
        agent_id: claim.agent_id.as_uuid().to_string(),
        content_hash: ContentHasher::to_hex(&claim.content_hash),
        created_at: claim.created_at.to_rfc3339(),
        labels,
        is_current: claim.is_current,
        supersedes: claim.supersedes.map(|s| s.as_uuid().to_string()),
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
    // `require_owner_or_admin` middleware. The HTTP route's check is
    // (claims:admin OR auth.owner_id/client_id == claim.agent_id). The
    // rmcp tool_router macro does NOT forward the request's `AuthContext`
    // into per-tool handlers — only `Parameters<T>` is passed. So we
    // cannot read the caller's scopes here (admin override) or their
    // owner/client UUID. Per Component 2 of the backlog-retirement spec
    // ("Calls existing HTTP routes…"), HTTP forwarding would be cleaner
    // but requires a bearer token the MCP server doesn't hold unless the
    // caller passes one.
    //
    // Coarse fallback: compare the claim's author against the server's
    // own signer agent. This blocks the most common abuse (a token with
    // claims:write retiring a claim authored by a different signer) but
    // it does NOT distinguish multiple human/agent callers that share
    // the same MCP-server signer. Follow-up: plumb AuthContext through
    // rmcp's Extension<T> pattern at the tool-handler boundary so this
    // can check has_scope("claims:admin") and auth.owner_id properly.
    let caller_agent = server.agent_id().await?;
    let target_agent = original.agent_id.as_uuid();
    if caller_agent != target_agent {
        return Err(McpError {
            code: rmcp::model::ErrorCode::INVALID_PARAMS,
            message: format!(
                "claim {original_id} is owned by agent {target_agent}; \
                 caller agent {caller_agent} cannot retire it (claims:admin scope \
                 override not yet plumbed into MCP tool handlers)"
            )
            .into(),
            data: None,
        });
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
