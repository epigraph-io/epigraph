use axum::{extract::State, Json};
use serde::Deserialize;

use crate::access_control::{check_content_access, ContentAccess};
use crate::errors::ApiError;
use crate::query_parser::{parse_gql, EdgeDirection, GqlQuery, Operator, ReturnClause, Value};
use crate::routes::edges::FullGraphResponse;
use crate::state::AppState;
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
        "claim" | "claims" => "claims",
        "evidence" => "evidence",
        "agent" | "agents" => "agents",
        "trace" | "traces" | "reasoning_traces" | "reasoning_trace" => "reasoning_traces",
        _ => {
            return Err(ApiError::ValidationError {
                field: "label".to_string(),
                reason: format!("Unknown node label: {}", node_type),
            })
        }
    };

    // Build WHERE clause with bind parameters ($1, $2, ...)
    // All user-supplied values go through bind() — no string interpolation.
    let mut where_fragments: Vec<String> = Vec::new();
    let mut bind_strings: Vec<String> = Vec::new();
    let mut bind_numbers: Vec<(usize, f64)> = Vec::new(); // (param_index, value)
    let mut param_idx = 0usize;

    if let Some(where_c) = &ast.where_clause {
        let conditions: Vec<_> = where_c
            .conditions
            .iter()
            .filter(|c| c.variable == *node_var)
            .collect();

        for c in conditions {
            let op = match c.operator {
                Operator::Eq => "=",
                Operator::Gt => ">",
                Operator::Lt => "<",
                Operator::Gte => ">=",
                Operator::Lte => "<=",
            };

            // Column mapping: only known columns allowed (no user strings in column names)
            let column = if c.property == "truth_value" {
                "truth_value".to_string()
            } else if c.property == "confidence" {
                "(properties->>'confidence')::float8".to_string()
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
                format!("properties->>'{}'", c.property)
            };

            param_idx += 1;
            match &c.value {
                Value::Number(n) => {
                    where_fragments.push(format!("{} {} ${}", column, op, param_idx));
                    bind_numbers.push((param_idx, *n));
                }
                Value::String(s) => {
                    where_fragments.push(format!("{} {} ${}", column, op, param_idx));
                    bind_strings.push(s.clone());
                }
                Value::Boolean(b) => {
                    // Booleans are safe to inline (only true/false from parser)
                    where_fragments.push(format!("{} {} {}", column, op, b));
                    param_idx -= 1; // no bind needed
                }
            }
        }
    }

    let where_sql = if where_fragments.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_fragments.join(" AND "))
    };

    // Helper: bind all accumulated parameters to a query
    // Since sqlx doesn't support heterogeneous dynamic binding easily,
    // we use float parameters for all bound values (numbers stay as-is,
    // strings use a separate text query path).
    let pool = &state.db_pool;

    if let Some(edge) = &ast.match_clause.edge {
        // Validate relationship type against allowlist
        let rel_filter = if let Some(rt) = &edge.rel_type {
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
                    reason: format!("Unknown relationship type: {}. Valid: {:?}", rt, VALID_RELS),
                });
            }
            format!("AND e.relationship = '{}'", rt)
        } else {
            String::new()
        };

        let direction_filter = match edge.direction {
            EdgeDirection::Outgoing => "e.source_id = p.id",
            EdgeDirection::Incoming => "e.target_id = p.id",
            EdgeDirection::Any => "(e.source_id = p.id OR e.target_id = p.id)",
        };

        let max_hops = edge.max_hops.min(4); // Safety cap
        let min_hops = edge.min_hops;

        let sql = format!(
            r#"
            WITH RECURSIVE paths(id, depth) AS (
                (SELECT id, 0
                FROM {node_table}
                {where_sql}
                LIMIT {limit})
                UNION
                SELECT
                    CASE WHEN e.source_id = p.id THEN e.target_id ELSE e.source_id END,
                    p.depth + 1
                FROM edges e
                JOIN paths p ON {direction_filter}
                WHERE p.depth < {max_hops}
                {rel_filter}
            )
            SELECT DISTINCT id FROM paths WHERE depth >= {min_hops};
            "#,
        );

        #[derive(sqlx::FromRow)]
        struct IdRow {
            id: Uuid,
        }

        // Build dynamic query with bound parameters
        let mut query = sqlx::query_as::<_, IdRow>(&sql);
        let mut str_idx = 0;
        for i in 1..=param_idx {
            if let Some((_, n)) = bind_numbers.iter().find(|(idx, _)| *idx == i) {
                query = query.bind(*n);
            } else {
                query = query.bind(&bind_strings[str_idx]);
                str_idx += 1;
            }
        }

        let path_nodes: Vec<IdRow> =
            query
                .fetch_all(pool)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Graph Query Error: {}", e),
                })?;

        let node_ids: Vec<Uuid> = path_nodes.into_iter().map(|r| r.id).collect();

        if node_ids.is_empty() {
            return Ok(Json(FullGraphResponse {
                nodes: vec![],
                edges: vec![],
                total_nodes: 0,
                total_edges: 0,
            }));
        }

        let mut resp = super::graph_query_utils::load_subgraph(pool, node_ids).await?;
        apply_partition_filter(pool, &mut resp, request.agent_id).await;
        Ok(resp)
    } else {
        let sql = format!(
            "SELECT id FROM {} {} LIMIT {}",
            node_table, where_sql, limit
        );

        #[derive(sqlx::FromRow)]
        struct IdRow {
            id: Uuid,
        }

        let mut query = sqlx::query_as::<_, IdRow>(&sql);
        let mut str_idx = 0;
        for i in 1..=param_idx {
            if let Some((_, n)) = bind_numbers.iter().find(|(idx, _)| *idx == i) {
                query = query.bind(*n);
            } else {
                query = query.bind(&bind_strings[str_idx]);
                str_idx += 1;
            }
        }

        let matches: Vec<IdRow> =
            query
                .fetch_all(pool)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Query Error: {}", e),
                })?;

        let node_ids: Vec<Uuid> = matches.into_iter().map(|r| r.id).collect();
        if node_ids.is_empty() {
            return Ok(Json(FullGraphResponse {
                nodes: vec![],
                edges: vec![],
                total_nodes: 0,
                total_edges: 0,
            }));
        }

        let mut resp = super::graph_query_utils::load_subgraph(pool, node_ids).await?;
        apply_partition_filter(pool, &mut resp, request.agent_id).await;
        Ok(resp)
    }
}

/// Redact content of claim nodes that the requester cannot access.
#[cfg(feature = "db")]
async fn apply_partition_filter(
    pool: &sqlx::PgPool,
    resp: &mut Json<FullGraphResponse>,
    requester_agent_id: Option<Uuid>,
) {
    for node in &mut resp.nodes {
        if node.entity_type == "claim" {
            let access = check_content_access(pool, node.id, requester_agent_id).await;
            if access == ContentAccess::Redacted {
                node.label = "[REDACTED]".to_string();
            }
        }
    }
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
