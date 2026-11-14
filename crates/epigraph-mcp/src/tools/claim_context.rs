//! MCP `claim_context` (backlog `0720d208`): one claim's structural context
//! BY ID, the twin of `GET /api/v1/claims/:id/context`.
//!
//! The body is `epigraph_engine::claim_context::load`'s, the function the
//! route calls, so the two surfaces return one shape and one set of
//! visibility rules. `recall_with_context` attaches a smaller structural
//! block to text-search hits; this is the lookup for a claim you already have
//! the id of.

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::ClaimContextParams;

pub async fn claim_context(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ClaimContextParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    // Refused before any statement, so a refusal cannot depend on whether
    // the caller may read the root.
    let mode = epigraph_engine::claim_context::validate(
        params.list.as_deref(),
        params.after.as_deref(),
        params.limit,
    )
    .map_err(invalid_params)?;

    // One viewer-stamped connection for every statement, so the root check,
    // the lists and their totals describe the same corpus.
    let mut read = server.read_as(viewer, "claim_context").await?;
    let body = epigraph_engine::claim_context::load(&mut read, viewer, id, mode)
        .await
        .map_err(internal_error)?
        // `get_claim`'s refusal: a claim this caller cannot read and a uuid
        // that names nothing are the same error.
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;
    read.commit().await.map_err(internal_error)?;

    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}
