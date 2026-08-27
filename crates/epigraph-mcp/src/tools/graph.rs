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

/// Per-node fan-out bound for `traverse`'s BFS edge fetch.
///
/// Deliberately NOT the tool's `node_limit`. The two budgets are not
/// interchangeable, and conflating them silently under-reports:
///
/// * `list_filtered` applies its `LIMIT` in SQL, i.e. BEFORE `min_truth` is
///   evaluated in Rust below.
/// * A target under `min_truth` hits `continue` WITHOUT being pushed to
///   `nodes`, so it never consumes node budget — the `nodes.len() >=
///   node_limit` break cannot fire on its account, and the BFS instead drains
///   its already-truncated queue.
///
/// So sizing the edge fetch off the node budget drops *qualifying*
/// neighbours: `traverse(min_truth > 0)` on a node whose fan-out exceeds
/// `limit` loses nodes it would otherwise return. `edges.valid_from` has no
/// column default (migrations/001_initial_schema.sql:765), so the
/// `ORDER BY valid_from DESC NULLS LAST, id` degenerates to
/// `gen_random_uuid()` id order and *which* neighbours vanish is effectively
/// random. Regression pinned by `tests/graph_traverse_fan_out_bound.rs`.
///
/// This constant is a memory guard against a pathological hub, not a semantic
/// knob: no caller-supplied value can shrink it, and at 10x the largest
/// accepted `limit` (100) it cannot interact with the node budget. A node with
/// fan-out above it still has its tail cut — the pre-63e4ddd `get_by_source`
/// had no `LIMIT` at all — but that trade buys a bounded response and is two
/// orders of magnitude away from the budgets a caller can actually set.
const MAX_EDGES_PER_NODE: i64 = 1_000;

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
            //
            // Bounded by `MAX_EDGES_PER_NODE`, NOT by `node_limit` — see that
            // constant for why the node budget is the wrong bound here.
            let outgoing = EdgeRepository::list_filtered(
                &server.pool,
                Some(current_id),
                None,
                params.relationship.as_deref(),
                None,
                None,
                MAX_EDGES_PER_NODE,
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
