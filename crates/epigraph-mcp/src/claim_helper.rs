//! Idempotent claim creation + AUTHORED verb-edge emission for MCP-layer
//! writers. See docs/architecture/noun-claims-and-verb-edges.md and
//! docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md.

use epigraph_core::Claim;
use epigraph_db::{ClaimRepository, EdgeRepository};
use serde_json::json;
use sqlx::PgPool;

use crate::errors::{internal_error, invalid_params, McpError};

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
/// or `ClaimRepository::create_or_get` fail, except that a collision with a
/// row the caller cannot read is `invalid_params` carrying
/// `ClaimRepository::CONTENT_COLLISION_REASON`. AUTHORED edge failure is
/// not returned (logged + swallowed).
pub async fn create_claim_idempotent(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim: &Claim,
    tool_name: &'static str,
) -> Result<(Claim, bool), McpError> {
    let mut conn = pool.acquire().await.map_err(internal_error)?;
    // Tenancy declaration (PR-16). Every MCP writer that reaches this helper
    // (`submit_claim`, `memorize`, `batch_submit_claims`) posts a claim
    // authored by the calling principal and carries no visibility parameter, so
    // the declaration is the author's own personal group, publicly visible.
    // Giving those tools a `visibility` argument is the write-side gate's work,
    // not this PR's; when it arrives, this is the single place it lands for all
    // three.
    let decl = ClaimRepository::default_decl_for_author(&mut conn, claim.agent_id.into())
        .await
        .map_err(internal_error)?;
    // A `Conflict` is a `(content_hash, agent_id)` collision with a row the
    // caller cannot read (plan §8.5, item 21). Here the author IS the caller,
    // so it is reached only by a self-authored claim that has since become
    // invisible to its author — moved into a group the author is not in, or a
    // revoked membership. It carries a fixed literal naming nothing, and is
    // answered as invalid params with that literal rather than as an internal
    // error: the request is what collides, and nothing failed.
    let (claim, was_created) = ClaimRepository::create_or_get(&mut conn, viewer, claim, decl)
        .await
        .map_err(|e| match e {
            epigraph_db::DbError::Conflict { reason } => invalid_params(reason),
            e => internal_error(e),
        })?;
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

    // Note: the durable `claim.created` event for this submission is emitted
    // inside `ClaimRepository::create_strict` (which `create_or_get` calls on
    // the success branch). Centralizing the emit at the repository boundary
    // ensures all writers — submit_claim, ingest_paper, ingest_workflow,
    // batch ingestion, API conventions — produce the event, not just the
    // MCP submit_claim path. See claim.rs::create_strict for the emit site
    // and crates/epigraph-db/src/repos/event.rs::publish_or_log_conn for
    // the transactional sink.

    Ok((claim, was_created))
}
