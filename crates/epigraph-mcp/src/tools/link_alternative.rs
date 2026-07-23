//! `link_alternative` — promote two claims into a mutually-exclusive
//! `alternative_of` pair.
//!
//! Closes the loop `suggest_alternative_sets` documents: it proposes candidate
//! pairs and its own docstring says *"operator promotes by submitting an
//! explicit alternative_of edge"*, but no other MCP tool could write one —
//! `link_epistemic` rejects the relationship (its allow-list is the seven
//! belief-affecting relations) and `link_hierarchical` only takes structural
//! types. This tool writes the symmetric edge directly through the repo layer.
//!
//! Contract:
//! - both endpoints must be existing claims (`source_type`/`target_type` are
//!   always `"claim"` and not caller-controllable),
//! - the edge is **symmetric**: `{claim_a, claim_b}` is one edge regardless of
//!   order (migration 042's `edges_alternative_of_symmetric_uniq`), so the call
//!   is idempotent on the unordered pair,
//! - deliberately inert like `link_hierarchical`: no DS re-wire, no factor
//!   inserts, no `edge.added` event. The belief effect of an alternative set is
//!   realized later by CDST BP's max-plausibility combine over the
//!   `alternative_set` view (see `crates/epigraph-engine/src/cdst_bp.rs`), not
//!   at write time.

use rmcp::model::*;
use serde_json::{Map, Value};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{LinkAlternativeParams, LinkAlternativeResponse};

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, EdgeRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn link_alternative(
    server: &EpiGraphMcpFull,
    params: LinkAlternativeParams,
) -> Result<CallToolResult, McpError> {
    do_link_alternative(server, params).await
}

/// Core wiring logic factored out so integration tests can call it directly
/// without round-tripping through the rmcp dispatch layer. Mirrors the
/// `do_link_hierarchical` factoring in `tools/link_hierarchical.rs`.
pub async fn do_link_alternative(
    server: &EpiGraphMcpFull,
    params: LinkAlternativeParams,
) -> Result<CallToolResult, McpError> {
    let a = parse_uuid(&params.claim_a)?;
    let b = parse_uuid(&params.claim_b)?;

    // No self-loops — a claim cannot be its own alternative, and equal UUIDs
    // would also trip the symmetric index's LEAST==GREATEST degenerate key.
    if a == b {
        return Err(invalid_params(
            "self-loops are not allowed (claim_a and claim_b are the same claim)",
        ));
    }

    let pool = &server.pool;

    // Verify both claims exist via the repo layer (SQL stays in epigraph-db per
    // CLAUDE.md). Disambiguate which side is missing so the caller can fix the
    // right end of the pair.
    if ClaimRepository::get_by_id(pool, ClaimId::from_uuid(a))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!("claim_a {a} not found")));
    }
    if ClaimRepository::get_by_id(pool, ClaimId::from_uuid(b))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!("claim_b {b} not found")));
    }

    // Fold the optional context into the edge properties. Validate a supplied
    // target_claim_id so a typo'd UUID surfaces here rather than being silently
    // persisted on the edge.
    let mut props = Map::new();
    if let Some(t) = &params.target_claim_id {
        let tid = parse_uuid(t)?;
        if ClaimRepository::get_by_id(pool, ClaimId::from_uuid(tid))
            .await
            .map_err(internal_error)?
            .is_none()
        {
            return Err(invalid_params(format!("target_claim_id {tid} not found")));
        }
        props.insert(
            "target_claim_id".to_string(),
            Value::String(tid.to_string()),
        );
    }
    if let Some(r) = &params.rationale {
        props.insert("rationale".to_string(), Value::String(r.clone()));
    }

    let (edge_id, created) = EdgeRepository::create_symmetric_if_absent_returning(
        pool,
        a,
        b,
        "alternative_of",
        Value::Object(props),
    )
    .await
    .map_err(internal_error)?;

    success_json(&LinkAlternativeResponse {
        edge_id: edge_id.to_string(),
        created,
    })
}
