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

pub async fn get_neighborhood(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetNeighborhoodParams,
) -> Result<CallToolResult, McpError> {
    let node_id = parse_uuid(&params.node_id)?;
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let direction = params.direction.as_deref().unwrap_or("both");

    // The node's REAL endpoint type(s), read from the viewer-filtered edges
    // (backlog cdd8d097). The repo reads below key on `(id, type)`, and this
    // tool used to pass the literal "claim", so a paper, workflow or agent node
    // returned 0 edges.
    let node_types = EdgeRepository::endpoint_types(&server.pool, viewer, node_id)
        .await
        .map_err(internal_error)?;

    let mut edges = Vec::new();
    let keep = |rel: &str| match params.relationship.as_deref() {
        Some(filter) => filter == rel,
        None => true,
    };

    if direction == "outgoing" || direction == "both" {
        for node_type in &node_types {
            let outgoing = EdgeRepository::get_by_source(&server.pool, viewer, node_id, node_type)
                .await
                .map_err(internal_error)?;
            edges.extend(
                outgoing
                    .into_iter()
                    .filter(|e| keep(&e.relationship))
                    .map(neighborhood_edge),
            );
        }
    }

    if direction == "incoming" || direction == "both" {
        for node_type in &node_types {
            let incoming = EdgeRepository::get_by_target(&server.pool, viewer, node_id, node_type)
                .await
                .map_err(internal_error)?;
            edges.extend(
                incoming
                    .into_iter()
                    .filter(|e| keep(&e.relationship))
                    .map(neighborhood_edge),
            );
        }
    }

    edges.truncate(limit as usize);

    success_json(&NeighborhoodResponse {
        node_id: node_id.to_string(),
        node_types,
        edge_count: edges.len(),
        edges,
    })
}

fn neighborhood_edge(e: epigraph_db::EdgeRow) -> NeighborhoodEdge {
    NeighborhoodEdge {
        edge_id: e.id.to_string(),
        source_id: e.source_id.to_string(),
        source_type: e.source_type,
        target_id: e.target_id.to_string(),
        target_type: e.target_type,
        relationship: e.relationship,
    }
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

    let mut visited: HashSet<uuid::Uuid> = HashSet::new();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    // Each queued node carries the endpoint type(s) it is known by (backlog
    // aedde855). A node reached over an edge takes that edge's `target_type`;
    // the start node's are read from its visible edges. The walk used to
    // expand every node with `get_by_source(.., "claim")`, so it could neither
    // leave a paper or workflow node nor type one as anything but 'unknown'.
    let mut queue: VecDeque<(uuid::Uuid, i32, Vec<String>)> = VecDeque::new();
    let mut depth_reached = 0;

    let start_types = EdgeRepository::endpoint_types(&server.pool, viewer, start_id)
        .await
        .unwrap_or_default();
    queue.push_back((start_id, 0, start_types));
    visited.insert(start_id);

    while let Some((current_id, depth, node_types)) = queue.pop_front() {
        if nodes.len() >= node_limit {
            break;
        }
        depth_reached = depth_reached.max(depth);

        // Label/truth come from the claims table, so only a claim has them. A
        // node with no known type (no visible edges: an isolated start node) is
        // still probed as a claim, as before.
        let may_be_claim = node_types.is_empty() || node_types.iter().any(|t| t == "claim");
        let (label, truth) = if may_be_claim {
            match ClaimRepository::get_by_id(&server.pool, viewer, ClaimId::from_uuid(current_id))
                .await
            {
                Ok(Some(claim)) => (
                    Some(claim.content.chars().take(100).collect::<String>()),
                    Some(claim.truth_value.value()),
                ),
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        // Filter by min_truth — on the Dempster-Shafer pignistic probability,
        // NOT on `claims.truth_value` (backlog 14b98adc). No DS write path
        // refreshes `truth_value`, so a node thoroughly refuted by epistemic
        // edges kept clearing a caller's gate at its pre-edge authored value.
        //
        // Resolved per node rather than batched because the walk is a BFS: the
        // frontier is not known until the node ahead of it has been expanded.
        // This is the same shape as the `get_by_id` above, so it adds at most
        // one query per visited node (capped at `node_limit` = 100) — and it is
        // skipped entirely on the DEFAULT path, where `min_truth` is 0.0 and
        // the comparison cannot drop anything whichever column it reads.
        let belief_score = match truth {
            Some(tv) if min_truth > 0.0 => {
                let resolved = ClaimRepository::effective_belief_batch(
                    &server.pool,
                    viewer,
                    std::slice::from_ref(&current_id),
                )
                .await
                .unwrap_or_default()
                .get(&current_id)
                .copied()
                // Absent key (or a failed lookup) == invisible / deleted
                // mid-walk. Fall back to the truth_value already in hand,
                // matching pre-fix behaviour.
                .unwrap_or(tv);
                Some(resolved)
            }
            other => other,
        };
        if let Some(score) = belief_score {
            if score < min_truth {
                continue;
            }
        }

        nodes.push(TraverseNode {
            id: current_id.to_string(),
            node_type: if truth.is_some() {
                "claim".to_string()
            } else {
                // The recorded endpoint type ('paper', 'workflow', 'agent',
                // ...). 'unknown' only when none is visible.
                node_types
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string())
            },
            label,
            truth_value: truth,
            // What `min_truth` was compared against: the DS pignistic
            // probability, or `truth_value` when the node carries no DS cache
            // (and always, on the default `min_truth = 0.0` path, where the
            // lookup is skipped because it could not change the outcome).
            belief_score,
            depth,
        });

        if depth < max_depth {
            // Outgoing edges under every type this node is known by. A node
            // with no known type is expanded as a claim, the previous
            // behaviour for exactly that case.
            let expand_as: Vec<String> = if node_types.is_empty() {
                vec!["claim".to_string()]
            } else {
                node_types
            };
            for node_type in &expand_as {
                let outgoing =
                    EdgeRepository::get_by_source(&server.pool, viewer, current_id, node_type)
                        .await
                        .unwrap_or_default();

                for e in outgoing {
                    if let Some(ref rel_filter) = params.relationship {
                        if e.relationship != *rel_filter {
                            continue;
                        }
                    }

                    edges.push(TraverseEdge {
                        source_id: e.source_id.to_string(),
                        target_id: e.target_id.to_string(),
                        relationship: e.relationship,
                    });

                    if visited.insert(e.target_id) {
                        queue.push_back((e.target_id, depth + 1, vec![e.target_type]));
                    }
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
