use axum::{extract::State, Json};
use serde::Deserialize;

use crate::errors::ApiError;
use crate::query_parser::{parse_gql, EdgeDirection, GqlQuery, Operator, ReturnClause, Value};
use crate::routes::edges::FullGraphResponse;
use crate::state::AppState;
#[cfg(feature = "db")]
use epigraph_db::{
    GqlColumn, GqlCondition, GqlDirection, GqlNodeTable, GqlOp, GqlValue, GqlWalk,
    GraphViewRepository,
};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct GraphQueryRequest {
    pub query: String,
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
}

#[cfg(feature = "db")]
pub async fn execute_graph_query(
    // PR-07: added. `load_subgraph` now requires a `Viewer`; this handler
    // previously had only the fail-open `auth_ctx` and passed no viewer at all,
    // so both of its subgraph loads returned unfiltered claim content.
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<GraphQueryRequest>,
) -> Result<Json<FullGraphResponse>, ApiError> {
    // 1. Parse GQL
    let ast: GqlQuery = parse_gql(&request.query).map_err(|e| ApiError::ValidationError {
        field: "query".to_string(),
        reason: format!("Failed to parse Cypher/GQL: {}", e),
    })?;

    // 2. We only support returning the entire matched set for now to feed the UI
    if !matches!(
        ast.return_clause,
        ReturnClause::All | ReturnClause::Variables(_)
    ) {
        return Err(ApiError::ValidationError {
            field: "RETURN".to_string(),
            reason: "Only RETURN * or returning variable lists is supported in MVP".to_string(),
        });
    }

    let limit = ast.limit.unwrap_or(200).min(1000) as i64;

    // Node constraints
    let node_var = &ast.match_clause.source_node.variable;
    let node_type = ast
        .match_clause
        .source_node
        .label
        .clone()
        .unwrap_or_else(|| "claim".to_string());

    // Determine Table (allowlist — no user strings enter table names)
    let node_table = match node_type.to_lowercase().as_str() {
        "claim" | "claims" => GqlNodeTable::Claims,
        "evidence" => GqlNodeTable::Evidence,
        "agent" | "agents" => GqlNodeTable::Agents,
        "trace" | "traces" | "reasoning_traces" | "reasoning_trace" => {
            GqlNodeTable::ReasoningTraces
        }
        _ => {
            return Err(ApiError::ValidationError {
                field: "label".to_string(),
                reason: format!("Unknown node label: {}", node_type),
            })
        }
    };

    // WHERE conditions on the anchor node. Column names come from a fixed
    // mapping or a validated property name; every number and string is bound
    // by the repo layer.
    let mut conditions: Vec<GqlCondition> = Vec::new();
    if let Some(where_c) = &ast.where_clause {
        for c in where_c
            .conditions
            .iter()
            .filter(|c| c.variable == *node_var)
        {
            let op = match c.operator {
                Operator::Eq => GqlOp::Eq,
                Operator::Gt => GqlOp::Gt,
                Operator::Lt => GqlOp::Lt,
                Operator::Gte => GqlOp::Gte,
                Operator::Lte => GqlOp::Lte,
            };
            let column = if c.property == "truth_value" {
                GqlColumn::TruthValue
            } else if c.property == "confidence" {
                GqlColumn::Confidence
            } else {
                // property names come from parser (alphanumeric + underscore only)
                // but validate defensively
                if !c
                    .property
                    .chars()
                    .all(|ch| ch.is_alphanumeric() || ch == '_')
                {
                    return Err(ApiError::ValidationError {
                        field: "property".to_string(),
                        reason: format!("Invalid property name: {}", c.property),
                    });
                }
                GqlColumn::Property(c.property.clone())
            };
            let value = match &c.value {
                Value::Number(n) => GqlValue::Number(*n),
                Value::String(s) => GqlValue::Text(s.clone()),
                Value::Boolean(b) => GqlValue::Bool(*b),
            };
            conditions.push(GqlCondition { column, op, value });
        }
    }

    // The anchor rows are taken newest first, `id` as the tie-breaker, so the
    // LIMIT window is a total order (backlog 2aacb390).
    let pool = &state.db_pool;

    let walk = match &ast.match_clause.edge {
        Some(edge) => {
            // Validate relationship type against allowlist
            if let Some(rt) = &edge.rel_type {
                const VALID_RELS: &[&str] = &[
                    "supports",
                    "contradicts",
                    "derives_from",
                    "refines",
                    "analogous",
                    "authored",
                    "asserts",
                    "variant_of",
                    "produced",
                    "cites",
                ];
                if !VALID_RELS.contains(&rt.as_str()) {
                    return Err(ApiError::ValidationError {
                        field: "relationship".to_string(),
                        reason: format!(
                            "Unknown relationship type: {}. Valid: {:?}",
                            rt, VALID_RELS
                        ),
                    });
                }
            }
            Some(GqlWalk {
                relationship: edge.rel_type.as_deref(),
                direction: match edge.direction {
                    EdgeDirection::Outgoing => GqlDirection::Outgoing,
                    EdgeDirection::Incoming => GqlDirection::Incoming,
                    EdgeDirection::Any => GqlDirection::Any,
                },
                min_hops: edge.min_hops,
                max_hops: edge.max_hops.min(4), // Safety cap
            })
        }
        None => None,
    };

    // The selection AND the walk are read through the viewer (backlog
    // 4815dcf7): the anchor table and every `edges` hop carry the predicate,
    // so neither a property predicate nor a traversal reaches past what the
    // caller can read, and the LIMIT window counts only readable rows.
    let node_ids = GraphViewRepository::graph_query_node_ids(
        pool,
        &viewer,
        node_table,
        &conditions,
        limit,
        walk,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: if walk.is_some() {
            format!("Graph Query Error: {}", e)
        } else {
            format!("Query Error: {}", e)
        },
    })?;

    if node_ids.is_empty() {
        return Ok(Json(FullGraphResponse {
            nodes: vec![],
            edges: vec![],
            total_nodes: 0,
            total_edges: 0,
        }));
    }

    // No `apply_partition_filter`: `load_subgraph` is spliced with
    // `&viewer`, so a claim node the caller may not read is not in `resp`.
    let resp = super::graph_query_utils::load_subgraph(pool, &viewer, node_ids).await?;
    Ok(resp)
}

#[cfg(not(feature = "db"))]
pub async fn execute_graph_query(
    State(_state): State<AppState>,
    Json(_request): Json<GraphQueryRequest>,
) -> Result<Json<FullGraphResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}
