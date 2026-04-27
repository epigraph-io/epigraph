//! Cluster-level graph endpoints driven by the `claim_themes` table.
//!
//! - `GET /api/v1/graph/overview` — list themes as supernodes for the high-level view
//! - `GET /api/v1/graph/clusters/:id/expand` — claim-level subgraph for one theme
//! - `GET /api/v1/graph/neighborhood` — n-hop subgraph around a single claim

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;

#[cfg(feature = "db")]
use sqlx::Row;

const SUPERNODE_LIMIT: i64 = 200;
const CLUSTER_EDGE_LIMIT: i64 = 1_000;
const DEFAULT_BUDGET: i64 = 200;
const MAX_BUDGET: i64 = 1_000;
const DEFAULT_HOPS: i32 = 1;
const MAX_HOPS: i32 = 3;
const NODE_EDGE_LIMIT: i64 = 5_000;

/// Claim-level edge relationships exposed to the graph view.
/// Covers the dominant relationship types in the corpus (hierarchical
/// decomposition, corroboration, support/contradiction, refinement, etc.)
/// plus their case variants. Anything not on this list (e.g. `same_source`,
/// `produced`, `CONTAINS`) is omitted to keep the subgraph readable.
const GRAPH_EDGE_RELATIONSHIPS: &[&str] = &[
    "decomposes_to",
    "CORROBORATES",
    "corroborates",
    "continues_argument",
    "refines",
    "REFINES",
    "supports",
    "SUPPORTS",
    "refutes",
    "contradicts",
    "CONTRADICTS",
    "relates_to",
    "RELATES_TO",
    "supersedes",
    "derived_from",
    "DERIVED_FROM",
    "derives_from",
    "same_as",
    "analogous",
    "asserts",
    "enables",
];

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct Supernode {
    pub cluster_id: String,
    pub label: String,
    pub size: i64,
    pub mean_betp: Option<f64>,
    pub dominant_type: Option<String>,
    pub dominant_frame_id: Option<Uuid>,
}

#[derive(Serialize)]
pub struct ClusterEdge {
    pub a: String,
    pub b: String,
    pub weight: i64,
}

#[derive(Serialize)]
pub struct OverviewResponse {
    pub run_id: Option<String>,
    pub generated_at: Option<String>,
    pub degraded: bool,
    pub supernodes: Vec<Supernode>,
    pub cluster_edges: Vec<ClusterEdge>,
}

#[derive(Serialize)]
pub struct GraphNodeDto {
    pub id: Uuid,
    pub label: String,
    pub entity_type: String,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
    pub cluster_id: Option<Uuid>,
    pub conflict_k: Option<f64>,
}

#[derive(Serialize)]
pub struct GraphEdgeDto {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

#[derive(Serialize)]
pub struct ClusterSubgraphResponse {
    pub cluster_id: String,
    pub truncated: bool,
    pub total_size: i64,
    pub nodes: Vec<GraphNodeDto>,
    pub edges: Vec<GraphEdgeDto>,
}

#[derive(Deserialize)]
pub struct BudgetQuery {
    pub budget: Option<i64>,
}

#[derive(Deserialize)]
pub struct NeighborhoodQuery {
    pub node_id: Uuid,
    pub hops: Option<i32>,
    pub budget: Option<i64>,
}

// ---------------------------------------------------------------------------
// Handlers (db feature)
// ---------------------------------------------------------------------------

/// `GET /api/v1/graph/overview`
#[cfg(feature = "db")]
pub async fn graph_overview(
    State(state): State<AppState>,
) -> Result<Json<OverviewResponse>, ApiError> {
    let pool = &state.db_pool;

    let supernode_rows = sqlx::query(
        r#"
        SELECT
            ct.id,
            ct.label,
            ct.claim_count::bigint AS claim_count,
            AVG(c.pignistic_prob) AS mean_betp
        FROM claim_themes ct
        LEFT JOIN claims c ON c.theme_id = ct.id AND c.is_current = true
        WHERE ct.claim_count > 0
        GROUP BY ct.id, ct.label, ct.claim_count
        ORDER BY ct.claim_count DESC
        LIMIT $1
        "#,
    )
    .bind(SUPERNODE_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Theme overview query failed: {}", e),
    })?;

    let supernodes: Vec<Supernode> = supernode_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            Supernode {
                cluster_id: id.to_string(),
                label: r.get("label"),
                size: r.get("claim_count"),
                mean_betp: r.try_get("mean_betp").ok(),
                dominant_type: Some("claim".to_string()),
                dominant_frame_id: None,
            }
        })
        .collect();

    let degraded = supernodes.is_empty();

    let cluster_edges: Vec<ClusterEdge> = if degraded {
        Vec::new()
    } else {
        let edge_rows = sqlx::query(
            r#"
            SELECT
                LEAST(cs.theme_id, ct.theme_id)::text AS a,
                GREATEST(cs.theme_id, ct.theme_id)::text AS b,
                COUNT(*)::bigint AS weight
            FROM edges e
            JOIN claims cs ON cs.id = e.source_id
            JOIN claims ct ON ct.id = e.target_id
            WHERE e.source_type = 'claim'
              AND e.target_type = 'claim'
              AND cs.theme_id IS NOT NULL
              AND ct.theme_id IS NOT NULL
              AND cs.theme_id <> ct.theme_id
              AND e.relationship = ANY($1::text[])
            GROUP BY a, b
            ORDER BY weight DESC
            LIMIT $2
            "#,
        )
        .bind(GRAPH_EDGE_RELATIONSHIPS)
        .bind(CLUSTER_EDGE_LIMIT)
        .fetch_all(pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Cluster edge aggregation failed: {}", e),
        })?;

        edge_rows
            .into_iter()
            .map(|r| ClusterEdge {
                a: r.get("a"),
                b: r.get("b"),
                weight: r.get("weight"),
            })
            .collect()
    };

    Ok(Json(OverviewResponse {
        run_id: None,
        generated_at: None,
        degraded,
        supernodes,
        cluster_edges,
    }))
}

/// `GET /api/v1/graph/clusters/:id/expand?budget=N`
#[cfg(feature = "db")]
pub async fn expand_cluster(
    State(state): State<AppState>,
    Path(cluster_id): Path<Uuid>,
    Query(params): Query<BudgetQuery>,
) -> Result<Json<ClusterSubgraphResponse>, ApiError> {
    let pool = &state.db_pool;
    let budget = params.budget.unwrap_or(DEFAULT_BUDGET).clamp(1, MAX_BUDGET);

    let total_size: i64 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT claim_count FROM claim_themes WHERE id = $1), 0)::bigint",
    )
    .bind(cluster_id)
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Theme size lookup failed: {}", e),
    })?;

    let node_rows = sqlx::query(
        r#"
        SELECT id, content, pignistic_prob, theme_id
        FROM claims
        WHERE theme_id = $1 AND is_current = true
        ORDER BY pignistic_prob DESC NULLS LAST, created_at DESC
        LIMIT $2
        "#,
    )
    .bind(cluster_id)
    .bind(budget)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Cluster claim fetch failed: {}", e),
    })?;

    let nodes: Vec<GraphNodeDto> = node_rows
        .into_iter()
        .map(|r| {
            let content: String = r.get("content");
            GraphNodeDto {
                id: r.get("id"),
                label: truncate_label(&content, 120),
                entity_type: "claim".to_string(),
                pignistic_prob: r.try_get("pignistic_prob").ok(),
                frame_id: None,
                cluster_id: r.try_get("theme_id").ok(),
                conflict_k: None,
            }
        })
        .collect();

    let node_ids: Vec<Uuid> = nodes.iter().map(|n| n.id).collect();
    let edges = fetch_subgraph_edges(pool, &node_ids).await?;

    Ok(Json(ClusterSubgraphResponse {
        cluster_id: cluster_id.to_string(),
        truncated: (nodes.len() as i64) < total_size,
        total_size,
        nodes,
        edges,
    }))
}

/// `GET /api/v1/graph/neighborhood?node_id=...&hops=N&budget=N`
#[cfg(feature = "db")]
pub async fn graph_neighborhood(
    State(state): State<AppState>,
    Query(params): Query<NeighborhoodQuery>,
) -> Result<Json<ClusterSubgraphResponse>, ApiError> {
    let pool = &state.db_pool;
    let hops = params.hops.unwrap_or(DEFAULT_HOPS).clamp(1, MAX_HOPS);
    let budget = params.budget.unwrap_or(DEFAULT_BUDGET).clamp(1, MAX_BUDGET);

    // Recursive BFS through claim↔claim edges, bounded by hops + budget.
    let id_rows = sqlx::query(
        r#"
        WITH RECURSIVE walk(id, depth) AS (
            SELECT $1::uuid, 0
            UNION
            SELECT
                CASE WHEN e.source_id = w.id THEN e.target_id ELSE e.source_id END,
                w.depth + 1
            FROM walk w
            JOIN edges e ON (e.source_id = w.id OR e.target_id = w.id)
            WHERE w.depth < $2
              AND e.source_type = 'claim'
              AND e.target_type = 'claim'
              AND e.relationship = ANY($3::text[])
        )
        SELECT DISTINCT id FROM walk LIMIT $4
        "#,
    )
    .bind(params.node_id)
    .bind(hops)
    .bind(GRAPH_EDGE_RELATIONSHIPS)
    .bind(budget)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Neighborhood walk failed: {}", e),
    })?;

    let mut node_ids: Vec<Uuid> = id_rows.iter().map(|r| r.get("id")).collect();
    // The recursive CTE's LIMIT can drop the seed node when many neighbors exist.
    // Ensure the starting node is always present so edges back to it render.
    if !node_ids.contains(&params.node_id) {
        node_ids.insert(0, params.node_id);
    }

    let nodes = if node_ids.is_empty() {
        Vec::new()
    } else {
        let rows = sqlx::query(
            r#"
            SELECT id, content, pignistic_prob, theme_id
            FROM claims
            WHERE id = ANY($1::uuid[])
            "#,
        )
        .bind(&node_ids)
        .fetch_all(pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Neighborhood claim hydration failed: {}", e),
        })?;

        rows.into_iter()
            .map(|r| {
                let content: String = r.get("content");
                GraphNodeDto {
                    id: r.get("id"),
                    label: truncate_label(&content, 120),
                    entity_type: "claim".to_string(),
                    pignistic_prob: r.try_get("pignistic_prob").ok(),
                    frame_id: None,
                    cluster_id: r.try_get("theme_id").ok(),
                    conflict_k: None,
                }
            })
            .collect()
    };

    let edges = fetch_subgraph_edges(pool, &node_ids).await?;
    let total_size = nodes.len() as i64;

    Ok(Json(ClusterSubgraphResponse {
        cluster_id: params.node_id.to_string(),
        truncated: (nodes.len() as i64) >= budget,
        total_size,
        nodes,
        edges,
    }))
}

#[cfg(feature = "db")]
async fn fetch_subgraph_edges(
    pool: &sqlx::PgPool,
    node_ids: &[Uuid],
) -> Result<Vec<GraphEdgeDto>, ApiError> {
    if node_ids.is_empty() {
        return Ok(Vec::new());
    }

    let rows = sqlx::query(
        r#"
        SELECT source_id, target_id, relationship
        FROM edges
        WHERE source_type = 'claim'
          AND target_type = 'claim'
          AND source_id = ANY($1::uuid[])
          AND target_id = ANY($1::uuid[])
          AND relationship = ANY($2::text[])
        LIMIT $3
        "#,
    )
    .bind(node_ids)
    .bind(GRAPH_EDGE_RELATIONSHIPS)
    .bind(NODE_EDGE_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Subgraph edge query failed: {}", e),
    })?;

    Ok(rows
        .into_iter()
        .map(|r| GraphEdgeDto {
            source: r.get("source_id"),
            target: r.get("target_id"),
            relationship: r.get("relationship"),
        })
        .collect())
}

fn truncate_label(content: &str, max: usize) -> String {
    let trimmed = content.trim();
    if trimmed.chars().count() <= max {
        trimmed.to_string()
    } else {
        let mut out: String = trimmed.chars().take(max).collect();
        out.push('…');
        out
    }
}

// ---------------------------------------------------------------------------
// no-db stubs (keep build green when feature = "db" is off)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "db"))]
pub async fn graph_overview(
    State(_): State<AppState>,
) -> Result<Json<OverviewResponse>, ApiError> {
    Ok(Json(OverviewResponse {
        run_id: None,
        generated_at: None,
        degraded: true,
        supernodes: Vec::new(),
        cluster_edges: Vec::new(),
    }))
}

#[cfg(not(feature = "db"))]
pub async fn expand_cluster(
    State(_): State<AppState>,
    Path(cluster_id): Path<Uuid>,
    Query(_): Query<BudgetQuery>,
) -> Result<Json<ClusterSubgraphResponse>, ApiError> {
    Ok(Json(ClusterSubgraphResponse {
        cluster_id: cluster_id.to_string(),
        truncated: false,
        total_size: 0,
        nodes: Vec::new(),
        edges: Vec::new(),
    }))
}

#[cfg(not(feature = "db"))]
pub async fn graph_neighborhood(
    State(_): State<AppState>,
    Query(params): Query<NeighborhoodQuery>,
) -> Result<Json<ClusterSubgraphResponse>, ApiError> {
    Ok(Json(ClusterSubgraphResponse {
        cluster_id: params.node_id.to_string(),
        truncated: false,
        total_size: 0,
        nodes: Vec::new(),
        edges: Vec::new(),
    }))
}
