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

fn internal(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
