//! `GET /api/v1/claims/:id/provenance-chain` — the HTTP surface of
//! [`epigraph_db::ProvenanceChainRepository::chain`], the claim→claim
//! derivation walk that MCP `get_provenance_chain` exposes.
//!
//! It is NOT a view of `GET /api/v1/claims/:id/provenance`
//! (`routes::edges::claim_provenance`): that one walks claim → reasoning trace
//! → evidence, this one walks claim → ancestor claim. Both are rendered, as
//! separate sections.
//!
//! Two things differ from the MCP tool deliberately:
//!
//! - **404 on a missing root.** The repo's recursive CTE always seeds `root`,
//!   so a nonexistent claim comes back as an empty success. Over HTTP that is
//!   indistinguishable from "this claim derives from nothing", so the handler
//!   turns "root not among the hydrated nodes" into `NotFound`.
//! - **Per-node redaction.** MCP does not redact this walk (a known leak,
//!   filed as a backlog item); every HTTP read of claim content does.
//!
//! The module is `#[cfg(feature = "db")]` as a whole and is registered only in
//! the db router, so no `cfg(not(db))` stub is needed.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::access_control::{batch_content_access, ContentAccess};
use crate::errors::ApiError;
use crate::state::AppState;

/// Default traversal depth when `max_depth` is absent, matching MCP
/// `get_provenance_chain`. The repo clamps to `1..=8`; the handler clamps
/// first so an out-of-range value is answered, not rejected.
const DEFAULT_MAX_DEPTH: u32 = 4;
const MIN_MAX_DEPTH: u32 = 1;
const MAX_MAX_DEPTH: u32 = 8;

#[derive(Debug, Deserialize)]
pub struct ProvenanceChainQuery {
    /// Deliberately `u32`, not `u8`: axum rejects an out-of-range `u8` with a
    /// plain-text 400 before the handler runs, and this route clamps instead.
    #[serde(default)]
    pub max_depth: Option<u32>,
    /// Comma-separated relationship names filtering the default traversal set.
    /// Absent or empty means the default set (`PROVENANCE_INCOMING` +
    /// `PROVENANCE_OUTGOING`); repeated query keys are not supported by
    /// `serde_urlencoded`, which is why this is a `String`.
    #[serde(default)]
    pub relationships: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChainNode {
    pub id: Uuid,
    /// `"[REDACTED]"` when the requester may not read this claim.
    pub content: String,
    pub truth_value: f64,
    pub labels: Vec<String>,
    pub is_current: bool,
    /// Fewest hops from the root at which this claim was reached.
    pub depth: i32,
    pub redacted: bool,
}

#[derive(Debug, Serialize)]
pub struct ChainEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

/// Named `ProvenanceChainResponse`, not `ProvenanceChain`: `routes::edges`
/// already exports a `ProvenanceChain` for the evidence-side route, and
/// `epigraph_db::ProvenanceChain` is a third.
#[derive(Debug, Serialize)]
pub struct ProvenanceChainResponse {
    pub root: Uuid,
    /// Topologically ordered, evidence first and the conclusion last.
    pub nodes: Vec<ChainNode>,
    pub edges: Vec<ChainEdge>,
    pub truncated: bool,
    pub cycles: Vec<Vec<Uuid>>,
}

/// Split a comma-separated `relationships` parameter.
///
/// `None` (absent, blank, or only separators) means "no filter", i.e. the
/// repo's default traversal set — not "filter to nothing".
fn parse_relationships(raw: Option<&str>) -> Option<Vec<String>> {
    let names: Vec<String> = raw?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// `GET /api/v1/claims/:id/provenance-chain`
pub async fn claim_provenance_chain(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<ProvenanceChainQuery>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
) -> Result<Json<ProvenanceChainResponse>, ApiError> {
    let pool = &state.db_pool;

    // SECURITY: the requester comes from the validated bearer only; this route
    // takes no `agent_id` query parameter precisely because it would be spoofable.
    let requester = auth_ctx
        .as_ref()
        .and_then(|axum::Extension(ctx)| ctx.agent_id.or(Some(ctx.client_id)));

    let max_depth = params
        .max_depth
        .unwrap_or(DEFAULT_MAX_DEPTH)
        .clamp(MIN_MAX_DEPTH, MAX_MAX_DEPTH) as u8;
    let relationships = parse_relationships(params.relationships.as_deref());

    let chain = epigraph_db::ProvenanceChainRepository::chain(
        pool,
        claim_id,
        max_depth,
        relationships.as_deref(),
    )
    .await?;

    // The root is always reached at depth 0 and is never dropped by the node
    // cap, so its absence from `nodes` means hydration found no such claim.
    if !chain.nodes.iter().any(|n| n.id == claim_id) {
        return Err(ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        });
    }

    let node_ids: Vec<Uuid> = chain.nodes.iter().map(|n| n.id).collect();
    let access = batch_content_access(pool, &node_ids, requester).await;

    let nodes = chain
        .nodes
        .into_iter()
        .map(|n| {
            // An id missing from the map would be a bug in the batch check;
            // treat it the way the check itself fails — closed.
            let redacted = access
                .get(&n.id)
                .copied()
                .unwrap_or(ContentAccess::Redacted)
                == ContentAccess::Redacted;
            let mut content = n.content;
            if redacted {
                crate::access_control::redact_claim_content(&mut content);
            }
            ChainNode {
                id: n.id,
                content,
                truth_value: n.truth_value,
                labels: n.labels,
                is_current: n.is_current,
                depth: n.depth,
                redacted,
            }
        })
        .collect();

    // Edges are kept even when they touch a redacted node: the shape of the
    // derivation is not the secret, the text is.
    let edges = chain
        .edges
        .into_iter()
        .map(|e| ChainEdge {
            source: e.source,
            target: e.target,
            relationship: e.relationship,
        })
        .collect();

    Ok(Json(ProvenanceChainResponse {
        root: chain.root,
        nodes,
        edges,
        truncated: chain.truncated,
        cycles: chain.cycles,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationships_absent_or_blank_means_default_set() {
        assert_eq!(parse_relationships(None), None);
        assert_eq!(parse_relationships(Some("")), None);
        assert_eq!(parse_relationships(Some("   ")), None);
        // Only separators: still the default set, never an empty filter.
        assert_eq!(parse_relationships(Some(",,")), None);
    }

    #[test]
    fn relationships_are_split_and_trimmed() {
        assert_eq!(
            parse_relationships(Some(" supports , supersedes ")),
            Some(vec!["supports".to_string(), "supersedes".to_string()])
        );
    }
}
