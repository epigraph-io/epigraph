//! `GET /api/v1/claims/:id/provenance-chain` — the HTTP surface of
//! [`epigraph_db::ProvenanceChainRepository::chain_conn`], the claim→claim
//! derivation walk that MCP `get_provenance_chain` exposes.
//!
//! It is NOT a view of `GET /api/v1/claims/:id/provenance`
//! (`routes::edges::claim_provenance`): that one walks claim → reasoning trace
//! → evidence, this one walks claim → ancestor claim. Both are rendered, as
//! separate sections.
//!
//! One thing differs from the MCP tool deliberately: **404 on a missing root.**
//! The repo's recursive CTE always seeds `root`, so a claim that does not exist
//! comes back as an empty success. Over HTTP that is indistinguishable from
//! "this claim derives from nothing", so the handler turns "root not among the
//! hydrated nodes" into `NotFound` — and, because hydration is viewer-filtered,
//! a claim the viewer may not read takes exactly the same branch and produces
//! exactly the same body.
//!
//! This handler applies no access pass of its own. Both halves of the walk are
//! filtered in the repo: an edge the viewer cannot see does not extend the
//! frontier, and a claim the viewer cannot read is absent from `nodes` — and,
//! since the repo retains edges against the hydrated node set, absent from
//! `edges` too. An ancestor that is not there is not there; there is no
//! placeholder node and no blanked field.
//!
//! All SQL lives in `epigraph_db::ProvenanceChainRepository`.
//!
//! The module is `#[cfg(feature = "db")]` as a whole and is registered only in
//! the db router, so no `cfg(not(db))` stub is needed.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
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
    /// The claim's text. Always the real text: a claim the viewer may not read
    /// is absent from `nodes` entirely rather than present with this field
    /// blanked.
    pub content: String,
    pub truth_value: f64,
    pub labels: Vec<String>,
    pub is_current: bool,
    /// Fewest hops from the root at which this claim was reached.
    pub depth: i32,
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
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<ProvenanceChainQuery>,
) -> Result<Json<ProvenanceChainResponse>, ApiError> {
    let max_depth = params
        .max_depth
        .unwrap_or(DEFAULT_MAX_DEPTH)
        .clamp(MIN_MAX_DEPTH, MAX_MAX_DEPTH) as u8;
    let relationships = parse_relationships(params.relationships.as_deref());

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "claim_provenance_chain",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let chain = epigraph_db::ProvenanceChainRepository::chain_conn(
        &mut read,
        &viewer,
        claim_id,
        max_depth,
        relationships.as_deref(),
    )
    .await?;

    crate::routes::finish_scoped_read(read, "claim_provenance_chain").await?;

    // The root is always reached at depth 0 and is never dropped by the node
    // cap, so its absence from `nodes` means hydration found no such claim —
    // because there is none, or because this viewer may not read it. The two
    // are the same answer on purpose.
    if !chain.nodes.iter().any(|n| n.id == claim_id) {
        return Err(ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        });
    }

    let nodes = chain
        .nodes
        .into_iter()
        .map(|n| ChainNode {
            id: n.id,
            content: n.content,
            truth_value: n.truth_value,
            labels: n.labels,
            is_current: n.is_current,
            depth: n.depth,
        })
        .collect();

    // Every edge here names two nodes that are in `nodes`: the repo retains the
    // edge set against the hydrated nodes, not against the walk. An edge whose
    // far endpoint is invisible would otherwise hand the caller that claim's
    // uuid and the relationship it stands in — a disclosure with no content
    // attached, which is still a disclosure.
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
