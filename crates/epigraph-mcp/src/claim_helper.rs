//! Idempotent claim creation + AUTHORED verb-edge emission for MCP-layer
//! writers. See docs/architecture/noun-claims-and-verb-edges.md and
//! docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md.

use epigraph_core::Claim;
use epigraph_db::{ClaimRepository, EdgeRepository};
use serde_json::json;
use sqlx::PgPool;

use crate::errors::{internal_error, McpError};

/// Idempotently create a claim by `(content_hash, agent_id)` and emit an
/// AUTHORED verb-edge marking the submission lifecycle event.
///
/// Mirrors the API handler's pattern at routes/claims.rs:444-576: dedup
/// inside a connection scope via `ClaimRepository::create_or_get`, then
/// fire-and-forget the AUTHORED edge on the pool after the connection is
/// released. AUTHORED failure is logged via `tracing::warn!` but never
/// propagated — orphan claims are tolerated per the architecture doc's
/// atomicity policy. Each submission emits a distinct AUTHORED edge
/// regardless of `was_created`, because each submission is an authorship
/// verb-event.
///
/// # Errors
/// Returns the underlying `McpError::internal_error` if `pool.acquire()`
/// or `ClaimRepository::create_or_get` fail. AUTHORED edge failure is
/// not returned (logged + swallowed).
pub async fn create_claim_idempotent(
    pool: &PgPool,
    claim: &Claim,
    tool_name: &'static str,
) -> Result<(Claim, bool), McpError> {
    let mut conn = pool.acquire().await.map_err(internal_error)?;
    let (claim, was_created) = ClaimRepository::create_or_get(&mut conn, claim)
        .await
        .map_err(internal_error)?;
    drop(conn);

    if let Err(e) = EdgeRepository::create(
        pool,
        claim.agent_id.as_uuid(),
        "agent",
        claim.id.as_uuid(),
        "claim",
        "AUTHORED",
        Some(json!({"tool": tool_name, "was_created": was_created})),
        None,
        None,
    )
    .await
    {
        tracing::warn!(
            claim_id = %claim.id.as_uuid(),
            tool = tool_name,
            error = %e,
            "AUTHORED verb-edge emit failed; claim row persisted as orphan"
        );
    }

    Ok((claim, was_created))
}
