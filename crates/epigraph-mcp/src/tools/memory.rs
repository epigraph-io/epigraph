#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput, TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::{ClaimRepository, EvidenceRepository, ReasoningTraceRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn memorize(
    server: &EpiGraphMcpFull,
    params: MemorizeParams,
) -> Result<CallToolResult, McpError> {
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();
    let confidence = params.confidence.unwrap_or(0.7).clamp(0.0, 1.0);
    let tags = params.tags.unwrap_or_default();

    // Testimonial weight = 0.6x
    let raw_truth = (confidence * 0.6).clamp(0.01, 0.99);
    let truth_value = TruthValue::clamped(raw_truth);

    let mut claim = Claim::new(params.content.clone(), agent_id_typed, pub_key, truth_value);
    let claim_uuid = claim.id.as_uuid();
    claim.content_hash = ContentHasher::hash(params.content.as_bytes());
    claim.signature = Some(server.signer.sign(&claim.content_hash));

    // Tag-based evidence content
    let evidence_text = if tags.is_empty() {
        "Memory stored via MCP memorize tool".to_string()
    } else {
        format!("Memory [{}] stored via MCP memorize tool", tags.join(", "))
    };
    let evidence_hash = ContentHasher::hash(evidence_text.as_bytes());
    let mut evidence = Evidence::new(
        agent_id_typed,
        pub_key,
        evidence_hash,
        EvidenceType::Testimony {
            source: "mcp-memorize".to_string(),
            testified_at: chrono::Utc::now(),
            verification: None,
        },
        Some(evidence_text),
        claim.id,
    );
    evidence.signature = Some(server.signer.sign(&evidence_hash));

    let trace = ReasoningTrace::new(
        agent_id_typed,
        pub_key,
        Methodology::Heuristic,
        vec![TraceInput::Evidence { id: evidence.id }],
        confidence,
        format!("Memory stored via memorize tool. Tags: {}", tags.join(", ")),
    );

    ClaimRepository::create(&server.pool, &claim)
        .await
        .map_err(internal_error)?;
    ReasoningTraceRepository::create(&server.pool, &trace, claim.id)
        .await
        .map_err(internal_error)?;
    EvidenceRepository::create(&server.pool, &evidence)
        .await
        .map_err(internal_error)?;
    ClaimRepository::update_trace_id(&server.pool, claim.id, trace.id)
        .await
        .map_err(internal_error)?;

    // DS auto-wire (best-effort, testimonial weight = 0.6)
    let ds = match ds_auto::auto_wire_ds_for_claim(
        &server.pool,
        claim_uuid,
        agent_id,
        confidence,
        0.6,
        true,
        None, // evidence_type: Task 4 will populate
    )
    .await
    {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::warn!(claim_id = %claim_uuid, "ds auto-wire memorize failed: {e}");
            None
        }
    };

    let embedded = server
        .embedder
        .embed_and_store(claim_uuid, &params.content)
        .await;

    success_json(&MemorizeResponse {
        claim_id: claim_uuid.to_string(),
        truth_value: raw_truth,
        embedded,
        tags,
        belief: ds.as_ref().map(|d| d.belief),
        plausibility: ds.as_ref().map(|d| d.plausibility),
        pignistic_prob: ds.as_ref().map(|d| d.pignistic_prob),
    })
}

pub async fn recall(
    server: &EpiGraphMcpFull,
    params: RecallParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50) as usize;
    let min_truth = params.min_truth.unwrap_or(0.3);

    let lib_results = epigraph_engine::recall(
        &server.pool,
        server.embedder.as_ref(),
        &params.query,
        limit,
        min_truth,
    )
    .await
    .map_err(internal_error)?;

    // Shape into the MCP response type (RecallResult is defined in crate::types).
    let results: Vec<RecallResult> = lib_results
        .into_iter()
        .map(|r| RecallResult {
            claim_id: r.claim_id,
            content: r.content,
            truth_value: r.truth_value,
            similarity: r.similarity,
        })
        .collect();

    success_json(&results)
}
