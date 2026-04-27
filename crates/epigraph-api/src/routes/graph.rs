//! /api/v1/graph/{overview, clusters/:id/expand, neighborhood} — read-only
//! endpoints over the latest successful clustering run.

use axum::{extract::{Path, Query, State}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Serialize)]
pub struct OverviewResponse {
    pub run_id: Option<Uuid>,
    pub generated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub degraded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
    pub supernodes: Vec<Supernode>,
    pub cluster_edges: Vec<ClusterEdgeOut>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Supernode {
    pub cluster_id: Uuid,
    pub label: String,
    pub size: i32,
    pub mean_betp: Option<f64>,
    pub dominant_type: Option<String>,
    pub dominant_frame_id: Option<Uuid>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ClusterEdgeOut {
    pub a: Uuid,
    pub b: Uuid,
    pub weight: i32,
}

#[derive(Debug, Deserialize)]
pub struct OverviewParams {
    #[serde(default)]
    pub color_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExpandResponse {
    pub cluster_id: Uuid,
    pub truncated: bool,
    pub total_size: i64,
    pub nodes: Vec<NodeOut>,
    pub edges: Vec<EdgeOut>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct NodeOut {
    pub id: Uuid,
    pub label: String,
    pub entity_type: String,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
    pub cluster_id: Option<Uuid>,
    pub conflict_k: Option<f64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EdgeOut {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

#[derive(Debug, Deserialize)]
pub struct ExpandParams {
    #[serde(default = "default_budget")]
    pub budget: i64,
}
const fn default_budget() -> i64 { 200 }

#[derive(Debug, Deserialize)]
pub struct NeighborhoodParams {
    pub node_id: Uuid,
    #[serde(default = "default_hops")]
    pub hops: i64,
    #[serde(default = "default_budget")]
    pub budget: i64,
}
const fn default_hops() -> i64 { 1 }

pub async fn overview(
    State(state): State<AppState>,
    Query(_params): Query<OverviewParams>,
) -> Result<Json<OverviewResponse>, (axum::http::StatusCode, String)> {
    let pool: &PgPool = &state.db_pool;
    let latest: Option<(Uuid, chrono::DateTime<chrono::Utc>, bool)> = sqlx::query_as(
        "SELECT run_id, completed_at, degraded
         FROM graph_cluster_runs
         ORDER BY completed_at DESC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(internal)?;
    let Some((run_id, generated_at, degraded)) = latest else {
        return Ok(Json(OverviewResponse {
            run_id: None,
            generated_at: None,
            degraded: false,
            status: Some("no_clusters_computed"),
            supernodes: vec![],
            cluster_edges: vec![],
        }));
    };
    let supernodes: Vec<Supernode> = sqlx::query_as::<_, Supernode>(
        "SELECT id AS cluster_id, label, size, mean_betp, dominant_type, dominant_frame_id
         FROM graph_clusters
         WHERE run_id = $1
         ORDER BY size DESC",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    let cluster_edges: Vec<ClusterEdgeOut> = sqlx::query_as::<_, ClusterEdgeOut>(
        "SELECT cluster_a AS a, cluster_b AS b, weight
         FROM cluster_edges
         WHERE run_id = $1",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    Ok(Json(OverviewResponse {
        run_id: Some(run_id),
        generated_at: Some(generated_at),
        degraded,
        status: None,
        supernodes,
        cluster_edges,
    }))
}

pub async fn expand(
    State(state): State<AppState>,
    Path(cluster_id): Path<Uuid>,
    Query(params): Query<ExpandParams>,
) -> Result<Json<ExpandResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    let pool: &PgPool = &state.db_pool;
    let latest_run: Option<(Uuid,)> = sqlx::query_as(
        "SELECT run_id FROM graph_cluster_runs ORDER BY completed_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(internal)?;
    let Some((run_id,)) = latest_run else {
        return Err((StatusCode::NOT_FOUND, "no completed run".into()));
    };
    let cluster_exists: Option<(i64,)> = sqlx::query_as(
        "SELECT size::bigint FROM graph_clusters WHERE id = $1 AND run_id = $2",
    )
    .bind(cluster_id)
    .bind(run_id)
    .fetch_optional(pool)
    .await
    .map_err(internal)?;
    let Some((total_size,)) = cluster_exists else {
        return Err((StatusCode::NOT_FOUND, "cluster not in latest run".into()));
    };

    let budget = params.budget.max(1);
    // Re-use the canonical list from epigraph-jobs rather than duplicating it.
    let rel_list: Vec<&str> = epigraph_jobs::cluster_graph::runner::EPISTEMIC_RELATIONSHIPS.to_vec();
    let nodes: Vec<NodeOut> = sqlx::query_as::<_, NodeOut>(
        "WITH degree AS (
            SELECT m.claim_id, COUNT(e.*) AS deg
            FROM claim_cluster_membership m
            LEFT JOIN edges e ON (e.source_id = m.claim_id OR e.target_id = m.claim_id)
                              AND e.relationship = ANY($3)
            WHERE m.cluster_id = $1 AND m.run_id = $2
            GROUP BY m.claim_id
        )
        SELECT c.id,
               COALESCE(c.content, c.id::text) AS label,
               'claim'::text AS entity_type,
               c.pignistic_prob,
               (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1) AS frame_id,
               $1::uuid AS cluster_id,
               NULL::float8 AS conflict_k
        FROM degree d
        JOIN claims c ON c.id = d.claim_id
        ORDER BY d.deg DESC NULLS LAST, c.pignistic_prob DESC NULLS LAST
        LIMIT $4",
    )
    .bind(cluster_id)
    .bind(run_id)
    .bind(rel_list.clone())
    .bind(budget)
    .fetch_all(pool)
    .await
    .map_err(internal)?;

    let node_ids: Vec<Uuid> = nodes.iter().map(|n| n.id).collect();
    let edges: Vec<EdgeOut> = sqlx::query_as::<_, EdgeOut>(
        "SELECT source_id AS source, target_id AS target, relationship
         FROM edges
         WHERE source_id = ANY($1) AND target_id = ANY($1) AND relationship = ANY($2)",
    )
    .bind(&node_ids)
    .bind(rel_list)
    .fetch_all(pool)
    .await
    .map_err(internal)?;

    Ok(Json(ExpandResponse {
        cluster_id,
        truncated: total_size > nodes.len() as i64,
        total_size,
        nodes,
        edges,
    }))
}

pub async fn neighborhood(
    State(state): State<AppState>,
    Query(params): Query<NeighborhoodParams>,
) -> Result<Json<ExpandResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    let pool: &PgPool = &state.db_pool;
    let hops = params.hops.clamp(1, 2);
    let budget = params.budget.max(1);
    let rel_list: Vec<&str> = epigraph_jobs::cluster_graph::runner::EPISTEMIC_RELATIONSHIPS.to_vec();

    let nodes: Vec<NodeOut> = sqlx::query_as::<_, NodeOut>(
        r#"
        WITH RECURSIVE bfs(id, depth) AS (
            SELECT $1::uuid, 0
            UNION
            SELECT CASE WHEN e.source_id = b.id THEN e.target_id ELSE e.source_id END,
                   b.depth + 1
            FROM bfs b
            JOIN edges e
              ON (e.source_id = b.id OR e.target_id = b.id)
             AND e.relationship = ANY($3)
            WHERE b.depth < $2
        )
        SELECT DISTINCT
               c.id,
               COALESCE(c.content, c.id::text) AS label,
               'claim'::text AS entity_type,
               c.pignistic_prob,
               (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1) AS frame_id,
               NULL::uuid AS cluster_id,
               NULL::float8 AS conflict_k
        FROM bfs b JOIN claims c ON c.id = b.id
        LIMIT $4
        "#,
    )
    .bind(params.node_id)
    .bind(hops)
    .bind(rel_list.clone())
    .bind(budget)
    .fetch_all(pool)
    .await
    .map_err(internal)?;

    if nodes.is_empty() {
        return Err((StatusCode::NOT_FOUND, "seed node not found".into()));
    }

    let ids: Vec<Uuid> = nodes.iter().map(|n| n.id).collect();
    let edges: Vec<EdgeOut> = sqlx::query_as::<_, EdgeOut>(
        "SELECT source_id AS source, target_id AS target, relationship
         FROM edges
         WHERE source_id = ANY($1) AND target_id = ANY($1) AND relationship = ANY($2)",
    )
    .bind(&ids)
    .bind(rel_list)
    .fetch_all(pool)
    .await
    .map_err(internal)?;

    Ok(Json(ExpandResponse {
        cluster_id: Uuid::nil(),
        truncated: false,
        total_size: nodes.len() as i64,
        nodes,
        edges,
    }))
}

fn internal(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
