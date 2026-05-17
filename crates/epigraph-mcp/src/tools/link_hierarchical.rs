//! `link_hierarchical` — cross-tier structural edge creation between claims.
//!
//! Counterpart to the new `POST /api/v1/edges/hierarchical` HTTP endpoint.
//! Bypasses HTTP and goes directly through `EdgeRepository::create_if_not_exists`
//! so per-chapter ingest wiring (e.g. chapter thesis → book thesis,
//! chapter[N] → chapter[N+1]) can continue from a Claude Code session even
//! when the API binary is unavailable.
//!
//! Tight contract — narrower than the generic `POST /api/v1/edges` route:
//! - both endpoints must be existing claims (`source_type` / `target_type`
//!   are always `"claim"` and not caller-controllable),
//! - `relationship` must be one of `HIERARCHICAL_RELATIONSHIPS`,
//! - the call is idempotent on `(source, target, relationship)`.
//!
//! Intentionally side-effect-free vs the generic POST: no DS recomputation,
//! no factor inserts, no `edge.added` event, no provenance. These structural
//! edges carry no evidential semantics and the matching `ingest_document`
//! flow treats them the same way.

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{LinkHierarchicalParams, LinkHierarchicalResponse};

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, EdgeRepository};

/// Allowed relationship strings — mirror of
/// `epigraph_api::routes::edges::HIERARCHICAL_RELATIONSHIPS`. Kept as a local
/// constant so the MCP crate does not take a code dep on the API crate.
pub const HIERARCHICAL_RELATIONSHIPS: &[&str] =
    &["decomposes_to", "section_follows", "continues_argument"];

fn is_hierarchical_relationship(s: &str) -> bool {
    HIERARCHICAL_RELATIONSHIPS.contains(&s)
}

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn link_hierarchical(
    server: &EpiGraphMcpFull,
    params: LinkHierarchicalParams,
) -> Result<CallToolResult, McpError> {
    do_link_hierarchical(server, params).await
}

/// Core wiring logic factored out so integration tests can call it directly
/// without round-tripping through the rmcp dispatch layer. Mirrors the
/// `do_ingest_document` factoring in `tools/ingestion.rs`.
pub async fn do_link_hierarchical(
    server: &EpiGraphMcpFull,
    params: LinkHierarchicalParams,
) -> Result<CallToolResult, McpError> {
    let source_id = parse_uuid(&params.source_claim_id)?;
    let target_id = parse_uuid(&params.target_claim_id)?;

    // Tight allow-list — narrower than VALID_RELATIONSHIPS on purpose. New
    // entries must come from `HIERARCHICAL_RELATIONSHIPS`.
    if !is_hierarchical_relationship(&params.relationship) {
        return Err(invalid_params(format!(
            "invalid relationship '{}'. Valid hierarchical types: {}",
            params.relationship,
            HIERARCHICAL_RELATIONSHIPS.join(", "),
        )));
    }

    // No self-loops — both endpoints are claims so equal UUIDs always loop.
    if source_id == target_id {
        return Err(invalid_params(
            "self-loops are not allowed (source and target are the same claim)",
        ));
    }

    let pool = &server.pool;

    // Verify both claims exist via the repo layer (per CLAUDE.md, SQL stays
    // in epigraph-db). Disambiguate which side is missing so the caller can
    // fix the right end of the link.
    if ClaimRepository::get_by_id(pool, ClaimId::from_uuid(source_id))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!(
            "source_claim_id {source_id} not found"
        )));
    }
    if ClaimRepository::get_by_id(pool, ClaimId::from_uuid(target_id))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!(
            "target_claim_id {target_id} not found"
        )));
    }

    let (edge_row, was_created) = EdgeRepository::create_if_not_exists(
        pool,
        source_id,
        "claim",
        target_id,
        "claim",
        &params.relationship,
        params.properties.clone(),
        None,
        None,
    )
    .await
    .map_err(internal_error)?;

    success_json(&LinkHierarchicalResponse {
        edge_id: edge_row.id.to_string(),
        created: was_created,
    })
}
