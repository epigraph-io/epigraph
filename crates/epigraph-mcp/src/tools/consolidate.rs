//! `consolidate_claims` MCP tool (backlog 44b19521 / design F1).
//!
//! N→1 memory consolidation. The caller supplies the synthesized content —
//! the server never invokes an LLM, matching `epigraph-ingest-executor`'s
//! division of labour (agent-side synthesis, server-side storage).

use rmcp::model::{CallToolResult, Content};
use serde::Serialize;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::ConsolidateClaimsParams;

use epigraph_db::{ClaimRepository, ConsolidateMode};

#[derive(Debug, Serialize)]
struct ConsolidateResponse {
    merged_claim_id: String,
    superseded_ids: Vec<String>,
    edges_migrated: u64,
    edges_deduped: u64,
    embedded: bool,
    /// `true` when an identical merged claim by this agent already existed and
    /// was returned rather than inserted twice.
    already_existed: bool,
}

pub async fn consolidate_claims(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ConsolidateClaimsParams,
) -> Result<CallToolResult, McpError> {
    let acting_agent_id = server.agent_id().await?;

    let source_ids = params
        .source_claim_ids
        .iter()
        .map(|s| parse_uuid(s))
        .collect::<Result<Vec<_>, _>>()?;

    let mode = ConsolidateMode::parse(&params.mode).map_err(|bad| {
        invalid_params(format!("unknown mode {bad:?}; want merge|abstract|rewrite"))
    })?;

    // Default confidence: the strongest source discounted slightly, so a merge
    // never claims more certainty than its best input.
    let merged_truth = match params.confidence {
        Some(c) => c.clamp(0.0, 1.0),
        None => {
            let mut best: f64 = 0.0;
            for id in &source_ids {
                if let Ok(Some(c)) = ClaimRepository::get_by_id(
                    &server.pool,
                    viewer,
                    epigraph_core::ClaimId::from_uuid(*id),
                )
                .await
                {
                    best = best.max(c.truth_value.value());
                }
            }
            (best * 0.95).clamp(0.0, 1.0)
        }
    };

    let result = ClaimRepository::consolidate(
        &server.pool,
        &source_ids,
        &params.merged_content,
        merged_truth,
        mode,
        &params.reason,
        acting_agent_id,
    )
    .await
    .map_err(|e| match e {
        // The cross-group refusal (PR-16, plan §4.6) is a CLIENT error: the
        // caller asked for a merge whose sources span two owner groups, and
        // the answer is "pick sources within one group", not "the server
        // failed". `internal_error` would render it as INTERNAL_ERROR and an
        // agent would retry it forever. The HTTP twin is 409
        // (`DbError::Conflict` -> `ApiError::Conflict`); INVALID_PARAMS is the
        // nearest JSON-RPC code that carries the message to the caller.
        epigraph_db::DbError::Conflict { ref reason } => invalid_params(reason.clone()),
        other => internal_error(other),
    })?;

    // Post-commit embedding, best-effort: warn but never fail the merge (the
    // CLAUDE.md write-path invariant). Skipped on the idempotent return, where
    // nothing new was written.
    let embedded = if result.already_existed {
        false
    } else {
        match server
            .embedder
            .embed_and_store(result.merged_id, &params.merged_content)
            .await
        {
            true => true,
            false => {
                tracing::warn!(
                    claim_id = %result.merged_id,
                    "consolidate: merged claim embedding failed; claim is stored but not semantically recallable yet"
                );
                false
            }
        }
    };

    let response = ConsolidateResponse {
        merged_claim_id: result.merged_id.to_string(),
        superseded_ids: result.superseded.iter().map(ToString::to_string).collect(),
        edges_migrated: result.edges_migrated,
        edges_deduped: result.edges_deduped,
        embedded,
        already_existed: result.already_existed,
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&response).map_err(internal_error)?,
    )]))
}
