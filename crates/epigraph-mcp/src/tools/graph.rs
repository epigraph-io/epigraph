#![allow(clippy::wildcard_imports)]

use std::collections::{HashSet, VecDeque};

use rmcp::model::*;

use crate::errors::{internal_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, EdgeRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// `(valid_to, retracted)` for the response. `retracted` is "the validity
/// interval has closed", the complement of `EDGE_IN_FORCE`; a future-dated
/// `valid_to` is reported but is not retracted.
fn retraction_flags(
    valid_to: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> (Option<String>, bool) {
    (
        valid_to.map(|t| t.to_rfc3339()),
        valid_to.is_some_and(|t| t <= now),
    )
}

/// Outgoing edges of `node` for a display / traversal read.
///
/// Edge removal is a retraction, so the default read is
/// [`EdgeRepository::get_by_source_in_force`]: a deleted edge is neither shown
/// nor followed. `include_retracted` opts into the unfiltered structural read,
/// whose rows the callers flag via [`retraction_flags`]. The choice is made at
/// the READ, not by filtering the result, so a hidden edge can never widen a
/// traversal frontier. See `docs/architecture/edge-retraction-tiers.md`.
async fn outgoing(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    node: uuid::Uuid,
    include_retracted: bool,
) -> Result<Vec<epigraph_db::repos::edge::EdgeRow>, epigraph_db::DbError> {
    if include_retracted {
        EdgeRepository::get_by_source(&server.pool, viewer, node, "claim").await
    } else {
        EdgeRepository::get_by_source_in_force(&server.pool, viewer, node, "claim").await
    }
}

/// Incoming twin of [`outgoing`].
async fn incoming(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    node: uuid::Uuid,
    include_retracted: bool,
) -> Result<Vec<epigraph_db::repos::edge::EdgeRow>, epigraph_db::DbError> {
    if include_retracted {
        EdgeRepository::get_by_target(&server.pool, viewer, node, "claim").await
    } else {
        EdgeRepository::get_by_target_in_force(&server.pool, viewer, node, "claim").await
    }
}

pub async fn get_neighborhood(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetNeighborhoodParams,
) -> Result<CallToolResult, McpError> {
    let node_id = parse_uuid(&params.node_id)?;
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let direction = params.direction.as_deref().unwrap_or("both");
    let include_retracted = params.include_retracted.unwrap_or(false);
    let now = chrono::Utc::now();

    let mut edges = Vec::new();

    if direction == "outgoing" || direction == "both" {
        let out = outgoing(server, viewer, node_id, include_retracted)
            .await
            .map_err(internal_error)?;
        for e in out {
            if let Some(ref rel_filter) = params.relationship {
                if e.relationship != *rel_filter {
                    continue;
                }
            }
            let (valid_to, retracted) = retraction_flags(e.valid_to, now);
            edges.push(NeighborhoodEdge {
                edge_id: e.id.to_string(),
                source_id: e.source_id.to_string(),
                source_type: e.source_type,
                target_id: e.target_id.to_string(),
                target_type: e.target_type,
                relationship: e.relationship,
                valid_to,
                retracted,
            });
        }
    }

    if direction == "incoming" || direction == "both" {
        let inc = incoming(server, viewer, node_id, include_retracted)
            .await
            .map_err(internal_error)?;
        for e in inc {
            if let Some(ref rel_filter) = params.relationship {
                if e.relationship != *rel_filter {
                    continue;
                }
            }
            let (valid_to, retracted) = retraction_flags(e.valid_to, now);
            edges.push(NeighborhoodEdge {
                edge_id: e.id.to_string(),
                source_id: e.source_id.to_string(),
                source_type: e.source_type,
                target_id: e.target_id.to_string(),
                target_type: e.target_type,
                relationship: e.relationship,
                valid_to,
                retracted,
            });
        }
    }

    edges.truncate(limit as usize);

    success_json(&NeighborhoodResponse {
        node_id: node_id.to_string(),
        edge_count: edges.len(),
        edges,
    })
}

pub async fn traverse(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: TraverseParams,
) -> Result<CallToolResult, McpError> {
    let start_id = parse_uuid(&params.start_id)?;
    let max_depth = params.max_depth.unwrap_or(2).clamp(1, 4) as i32;
    let node_limit = params.limit.unwrap_or(50).clamp(1, 100) as usize;
    let min_truth = params.min_truth.unwrap_or(0.0);
    let include_retracted = params.include_retracted.unwrap_or(false);
    let now = chrono::Utc::now();

    let mut visited: HashSet<uuid::Uuid> = HashSet::new();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut queue: VecDeque<(uuid::Uuid, i32)> = VecDeque::new();
    let mut depth_reached = 0;

    queue.push_back((start_id, 0));
    visited.insert(start_id);

    while let Some((current_id, depth)) = queue.pop_front() {
        if nodes.len() >= node_limit {
            break;
        }
        depth_reached = depth_reached.max(depth);

        // Try to get claim info for label/truth
        let (label, truth) =
            match ClaimRepository::get_by_id(&server.pool, viewer, ClaimId::from_uuid(current_id))
                .await
            {
                Ok(Some(claim)) => (
                    Some(claim.content.chars().take(100).collect::<String>()),
                    Some(claim.truth_value.value()),
                ),
                _ => (None, None),
            };

        // Filter by min_truth
        if let Some(tv) = truth {
            if tv < min_truth {
                continue;
            }
        }

        nodes.push(TraverseNode {
            id: current_id.to_string(),
            node_type: if truth.is_some() {
                "claim".to_string()
            } else {
                "unknown".to_string()
            },
            label,
            truth_value: truth,
            depth,
        });

        if depth < max_depth {
            // Outgoing edges. In-force only unless the caller opted in, and
            // chosen at the read: a retracted edge must not reach `queue`,
            // or it would decide which nodes are reached and how `node_limit`
            // truncates even though it is never shown.
            let out = outgoing(server, viewer, current_id, include_retracted)
                .await
                .unwrap_or_default();

            for e in out {
                if let Some(ref rel_filter) = params.relationship {
                    if e.relationship != *rel_filter {
                        continue;
                    }
                }

                let (valid_to, retracted) = retraction_flags(e.valid_to, now);
                edges.push(TraverseEdge {
                    source_id: e.source_id.to_string(),
                    target_id: e.target_id.to_string(),
                    relationship: e.relationship,
                    valid_to,
                    retracted,
                });

                if visited.insert(e.target_id) {
                    queue.push_back((e.target_id, depth + 1));
                }
            }
        }
    }

    success_json(&TraverseResponse {
        start_id: start_id.to_string(),
        nodes,
        edges,
        depth_reached,
    })
}
