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
    viewer: &epigraph_db::visibility::Viewer,
    params: LinkHierarchicalParams,
) -> Result<CallToolResult, McpError> {
    do_link_hierarchical(server, viewer, params).await
}

/// Core wiring logic factored out so integration tests can call it directly
/// without round-tripping through the rmcp dispatch layer. Mirrors the
/// `do_ingest_document` factoring in `tools/ingestion.rs`.
pub async fn do_link_hierarchical(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
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

    // ONE TRANSACTION, STAMPED FROM THE MCP SERVER'S OWN AGENT. The two
    // existence reads and the INSERT all run on it.
    //
    // The INSERT used to run on the unstamped pool. `edges_tenancy`'s WITH CHECK
    // then admitted only what its static arm admits: an edge between two PUBLIC
    // claims, which 070's BEFORE trigger makes world-owned. An edge touching a
    // group-private claim is owned by that claim's group, and on a
    // cleanly-migrated schema it was refused. Production admitted it only through
    // the orphan `edges_privacy` policy that R3 drops.
    //
    // The READS move too, and they are what make the stamp able to succeed. On
    // an unstamped session `claims_tenancy`'s USING admits only public rows, so a
    // group-private endpoint read "not found" before the INSERT was reached.
    // Converting only the INSERT would have been a conversion its own target
    // population could never reach.
    //
    // THE STAMP IS `server.agent_id()`'s, as for every other MCP write: the edge
    // is owned by an endpoint's group, and the population this admits is the
    // server agent's own claims. An endpoint in another agent's private group is
    // refused loudly by the WITH CHECK (or, for a co-owned edge, by RETURNING's
    // intersection read) and nothing is written. Whether a caller should carry
    // write authority into a group this process cannot write is the cross-agent
    // ownership question (#374), not a stamping one.
    let mut tx = crate::claim_helper::begin_author_stamped_tx(
        server,
        server.agent_id().await?,
        "link_hierarchical",
    )
    .await?;

    // Verify both claims exist via the repo layer (per CLAUDE.md, SQL stays
    // in epigraph-db). Disambiguate which side is missing so the caller can
    // fix the right end of the link.
    if ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(source_id))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!(
            "source_claim_id {source_id} not found"
        )));
    }
    if ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(target_id))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!(
            "target_claim_id {target_id} not found"
        )));
    }

    let (edge_row, was_created) = EdgeRepository::create_if_not_exists_conn(
        &mut tx,
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
    tx.commit().await.map_err(internal_error)?;

    success_json(&LinkHierarchicalResponse {
        edge_id: edge_row.id.to_string(),
        created: was_created,
    })
}
