//! `get_provenance_chain` MCP tool (backlog 3216b086 / design F2).
//!
//! Distinct from the existing `get_provenance`, which emits a PROV-O JSON-LD
//! document over `LineageRepository`. This tool answers the narrower
//! compositional-reasoning question — "what derivation supports this
//! conclusion, in order" — in a single call, so an agent no longer has to run
//! `recall` → `get_neighborhood` per node → `get_claim` per neighbour to
//! reconstruct a chain.

use rmcp::model::{CallToolResult, Content};
use serde::Serialize;

use crate::errors::{internal_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::GetProvenanceChainParams;

use epigraph_db::ProvenanceChainRepository;

#[derive(Debug, Serialize)]
struct ChainNode {
    id: String,
    content: String,
    truth_value: f64,
    labels: Vec<String>,
    is_current: bool,
    depth: i32,
}

#[derive(Debug, Serialize)]
struct ChainEdge {
    source: String,
    target: String,
    relationship: String,
}

#[derive(Debug, Serialize)]
struct ChainResponse {
    root: String,
    /// Topologically ordered: evidence first, the conclusion last.
    nodes: Vec<ChainNode>,
    edges: Vec<ChainEdge>,
    /// `true` when the depth bound or the 500-node cap cut the walk short.
    truncated: bool,
    /// Cycles encountered, as node paths. Reported rather than errored — a
    /// cyclic derivation is a data-quality signal the caller should see.
    cycles: Vec<Vec<String>>,
}

pub async fn get_provenance_chain(
    server: &EpiGraphMcpFull,
    params: GetProvenanceChainParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let max_depth = params.max_depth.unwrap_or(4);

    let chain = ProvenanceChainRepository::chain(
        &server.pool,
        claim_id,
        max_depth,
        params.relationships.as_deref(),
    )
    .await
    .map_err(internal_error)?;

    let response = ChainResponse {
        root: chain.root.to_string(),
        nodes: chain
            .nodes
            .into_iter()
            .map(|n| ChainNode {
                id: n.id.to_string(),
                content: n.content,
                truth_value: n.truth_value,
                labels: n.labels,
                is_current: n.is_current,
                depth: n.depth,
            })
            .collect(),
        edges: chain
            .edges
            .into_iter()
            .map(|e| ChainEdge {
                source: e.source.to_string(),
                target: e.target.to_string(),
                relationship: e.relationship,
            })
            .collect(),
        truncated: chain.truncated,
        cycles: chain
            .cycles
            .into_iter()
            .map(|c| c.into_iter().map(|id| id.to_string()).collect())
            .collect(),
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&response).map_err(internal_error)?,
    )]))
}
