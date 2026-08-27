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
    params: GetNeighborhoodParams,
) -> Result<CallToolResult, McpError> {
    let node_id = parse_uuid(&params.node_id)?;
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let direction = params.direction.as_deref().unwrap_or("both");

    let mut edges = Vec::new();

    if direction == "outgoing" || direction == "both" {
        // `list_filtered` NULL-guards every predicate, so passing `None` for
        // both entity-type columns matches edges incident to a node of ANY
        // type. `get_by_source(.., "claim")` constrained `source_type`, which
        // is the type of the node being looked up — so a `paper --asserts-->
        // claim` edge (what every ingestion path writes) matched zero rows and
        // the tool silently reported `edge_count: 0`.
        let outgoing = EdgeRepository::list_filtered(
            &server.pool,
            Some(node_id),
            None,
            params.relationship.as_deref(),
            None,
            None,
            limit,
        )
        .await
        .map_err(internal_error)?;
        for e in outgoing {
            edges.push(NeighborhoodEdge {
                edge_id: e.id.to_string(),
                source_id: e.source_id.to_string(),
                source_type: e.source_type,
                target_id: e.target_id.to_string(),
                target_type: e.target_type,
                relationship: e.relationship,
            });
        }
    }

    if direction == "incoming" || direction == "both" {
        // This half bound the TARGET's type, so it already resolved
        // `paper --asserts--> claim` when the *claim* was the node. Dropping
        // the constraint widens it to non-claim nodes (`agent --authored-->
        // paper`) without regressing that claim-side path.
        let incoming = EdgeRepository::list_filtered(
            &server.pool,
            None,
            Some(node_id),
            params.relationship.as_deref(),
            None,
            None,
            limit,
        )
        .await
        .map_err(internal_error)?;
        for e in incoming {
            edges.push(NeighborhoodEdge {
                edge_id: e.id.to_string(),
                source_id: e.source_id.to_string(),
                source_type: e.source_type,
                target_id: e.target_id.to_string(),
                target_type: e.target_type,
                relationship: e.relationship,
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
    params: TraverseParams,
) -> Result<CallToolResult, McpError> {
    let start_id = parse_uuid(&params.start_id)?;
    let max_depth = params.max_depth.unwrap_or(2).clamp(1, 4) as i32;
    let node_limit = params.limit.unwrap_or(50).clamp(1, 100) as usize;
    let min_truth = params.min_truth.unwrap_or(0.0);

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
            match ClaimRepository::get_by_id(&server.pool, ClaimId::from_uuid(current_id)).await {
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
            // Get outgoing edges. Unconstrained on entity type for the same
            // reason as `get_neighborhood`: BFS from a paper terminated at
            // depth 0 while `source_type = 'claim'` was hardcoded.
            let outgoing = EdgeRepository::list_filtered(
                &server.pool,
                Some(current_id),
                None,
                params.relationship.as_deref(),
                None,
                None,
                node_limit as i64,
            )
            .await
            .unwrap_or_default();

            for e in outgoing {
                edges.push(TraverseEdge {
                    source_id: e.source_id.to_string(),
                    target_id: e.target_id.to_string(),
                    relationship: e.relationship,
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
