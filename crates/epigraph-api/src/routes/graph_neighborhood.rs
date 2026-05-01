//! /api/v1/graph/neighborhoods/:id/expand — compound + atomic modes.
//!
//! Compound mode (this file): nodes are compound claims (those with
//! decomposes_to children inside the neighborhood) plus standalone claims
//! (no decomposes_to in either direction). Edges are induced from atom-level
//! relationships (mass-weighted by `forward_strength`) plus direct
//! compound-compound edges that exist outside the decomposition hierarchy.
//!
//! Atomic mode is implemented in Task 8 — for now `atomic_response` returns
//! an empty placeholder.

use axum::{extract::{Path, Query, State}, Json};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct ExpandParams {
    #[serde(default = "default_budget")] pub budget: i64,
    #[serde(default = "default_mode")] pub mode: String,
}
fn default_budget() -> i64 { 200 }
fn default_mode() -> String { "compound".to_string() }

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum NeighborhoodExpandResponse {
    Compound(CompoundResponse),
    Atomic(AtomicResponse),
}

#[derive(Debug, Serialize)]
pub struct CompoundResponse {
    pub neighborhood_id: Uuid,
    pub truncated: bool,
    pub nodes: Vec<CompoundNode>,
    pub induced_edges: Vec<InducedEdge>,
    pub direct_edges: Vec<DirectEdge>,
}

#[derive(Debug, Serialize)]
pub struct CompoundNode {
    pub id: Uuid,
    pub label: String,
    pub kind: String,           // "compound" | "standalone"
    pub atom_count: i32,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct InducedEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
    pub strength: f64,
    pub atom_edge_count: i32,
}

#[derive(Debug, Serialize)]
pub struct DirectEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

#[derive(Debug, Serialize)]
pub struct AtomicResponse {
    pub neighborhood_id: Uuid,
    pub truncated: bool,
    pub nodes: Vec<AtomicNode>,
    pub edges: Vec<AtomicEdge>,
    pub compound_groups: Vec<CompoundGroup>,
}

#[derive(Debug, Serialize)]
pub struct AtomicNode {
    pub id: Uuid,
    pub label: String,
    pub compound_id: Option<Uuid>,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct AtomicEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

#[derive(Debug, Serialize)]
pub struct CompoundGroup {
    pub compound_id: Uuid,
    pub label: String,
    pub member_atom_ids: Vec<Uuid>,
}

pub async fn expand(
    State(state): State<AppState>,
    Path(neighborhood_id): Path<Uuid>,
    Query(params): Query<ExpandParams>,
) -> Result<Json<NeighborhoodExpandResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    let pool: &PgPool = &state.db_pool;
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM graph_neighborhoods WHERE id = $1 \
         AND run_id = (SELECT run_id FROM graph_cluster_runs ORDER BY completed_at DESC LIMIT 1)"
    ).bind(neighborhood_id).fetch_optional(pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "neighborhood not found in latest run".into()));
    }

    match params.mode.as_str() {
        "atomic" => Ok(Json(NeighborhoodExpandResponse::Atomic(
            atomic_response(pool, neighborhood_id, params.budget).await?
        ))),
        _ => Ok(Json(NeighborhoodExpandResponse::Compound(
            compound_response(pool, neighborhood_id, params.budget).await?
        ))),
    }
}

async fn compound_response(pool: &PgPool, neighborhood_id: Uuid, _budget: i64)
    -> Result<CompoundResponse, (axum::http::StatusCode, String)>
{
    let nodes: Vec<CompoundNode> = sqlx::query_as::<_, (Uuid, String, String, i32, Option<f64>, Option<Uuid>)>(
        r#"
        WITH atoms AS (
            SELECT m.claim_id
            FROM claim_neighborhood_membership m
            WHERE m.neighborhood_id = $1
        ),
        compound_to_atoms AS (
            SELECT e.source_id AS compound_id, e.target_id AS atom_id
            FROM edges e
            JOIN atoms a ON a.claim_id = e.target_id
            WHERE e.relationship = 'decomposes_to'
        ),
        compound_nodes AS (
            SELECT cta.compound_id AS id, COUNT(*)::int AS atom_count
            FROM compound_to_atoms cta
            GROUP BY cta.compound_id
        ),
        standalone_nodes AS (
            SELECT a.claim_id AS id
            FROM atoms a
            WHERE NOT EXISTS (SELECT 1 FROM edges e WHERE e.target_id = a.claim_id AND e.relationship = 'decomposes_to')
              AND NOT EXISTS (SELECT 1 FROM edges e WHERE e.source_id = a.claim_id AND e.relationship = 'decomposes_to')
        )
        SELECT c.id, COALESCE(c.content, c.id::text) AS label, 'compound'::text AS kind,
               cn.atom_count, c.pignistic_prob,
               (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1) AS frame_id
        FROM compound_nodes cn JOIN claims c ON c.id = cn.id
        UNION ALL
        SELECT c.id, COALESCE(c.content, c.id::text), 'standalone'::text, 0, c.pignistic_prob,
               (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1)
        FROM standalone_nodes s JOIN claims c ON c.id = s.id
        "#,
    )
    .bind(neighborhood_id)
    .fetch_all(pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(|(id, label, kind, atom_count, pp, fid)| CompoundNode { id, label, kind, atom_count, pignistic_prob: pp, frame_id: fid })
    .collect();

    let induced_edges: Vec<InducedEdge> = sqlx::query_as::<_, (Uuid, Uuid, String, f64, i32)>(
        r#"
        WITH atoms AS (
            SELECT m.claim_id FROM claim_neighborhood_membership m WHERE m.neighborhood_id = $1
        ),
        atom_to_compound AS (
            SELECT e.target_id AS atom_id, e.source_id AS compound_id
            FROM edges e JOIN atoms a ON a.claim_id = e.target_id
            WHERE e.relationship = 'decomposes_to'
        )
        SELECT a2c_s.compound_id AS source,
               a2c_t.compound_id AS target,
               e.relationship,
               SUM(ft.forward_strength)::double precision AS strength,
               COUNT(*)::int AS atom_edge_count
        FROM edges e
        JOIN atoms a_s ON a_s.claim_id = e.source_id
        JOIN atoms a_t ON a_t.claim_id = e.target_id
        JOIN atom_to_compound a2c_s ON a2c_s.atom_id = e.source_id
        JOIN atom_to_compound a2c_t ON a2c_t.atom_id = e.target_id
        LEFT JOIN LATERAL edge_to_factor_type(e.relationship) ft ON true
        WHERE a2c_s.compound_id <> a2c_t.compound_id
          AND e.relationship <> 'decomposes_to'
          AND ft.forward_strength > 0
        GROUP BY 1, 2, 3
        "#,
    )
    .bind(neighborhood_id)
    .fetch_all(pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(|(source, target, relationship, strength, atom_edge_count)| InducedEdge { source, target, relationship, strength, atom_edge_count })
    .collect();

    let direct_edges: Vec<DirectEdge> = sqlx::query_as::<_, (Uuid, Uuid, String)>(
        r#"
        WITH neighborhood_compounds AS (
            SELECT DISTINCT e.source_id AS id
            FROM edges e
            JOIN claim_neighborhood_membership m ON m.claim_id = e.target_id
            WHERE m.neighborhood_id = $1 AND e.relationship = 'decomposes_to'
        ),
        neighborhood_standalones AS (
            SELECT m.claim_id AS id
            FROM claim_neighborhood_membership m
            WHERE m.neighborhood_id = $1
              AND NOT EXISTS (SELECT 1 FROM edges e WHERE e.source_id = m.claim_id AND e.relationship = 'decomposes_to')
              AND NOT EXISTS (SELECT 1 FROM edges e WHERE e.target_id = m.claim_id AND e.relationship = 'decomposes_to')
        ),
        compound_universe AS (
            SELECT id FROM neighborhood_compounds UNION SELECT id FROM neighborhood_standalones
        )
        SELECT e.source_id, e.target_id, e.relationship
        FROM edges e
        JOIN compound_universe a ON a.id = e.source_id
        JOIN compound_universe b ON b.id = e.target_id
        LEFT JOIN LATERAL edge_to_factor_type(e.relationship) ft ON true
        WHERE e.relationship <> 'decomposes_to'
          AND ft.forward_strength > 0
        "#,
    )
    .bind(neighborhood_id)
    .fetch_all(pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(|(source, target, relationship)| DirectEdge { source, target, relationship })
    .collect();

    Ok(CompoundResponse { neighborhood_id, truncated: false, nodes, induced_edges, direct_edges })
}

async fn atomic_response(pool: &PgPool, neighborhood_id: Uuid, _budget: i64)
    -> Result<AtomicResponse, (axum::http::StatusCode, String)>
{
    let nodes: Vec<AtomicNode> = sqlx::query_as::<_, (Uuid, String, Option<Uuid>, Option<f64>, Option<Uuid>)>(
        r#"
        SELECT c.id,
               COALESCE(c.content, c.id::text) AS label,
               (SELECT e.source_id FROM edges e
                WHERE e.target_id = c.id AND e.relationship = 'decomposes_to' LIMIT 1) AS compound_id,
               c.pignistic_prob,
               (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1) AS frame_id
        FROM claim_neighborhood_membership m
        JOIN claims c ON c.id = m.claim_id
        WHERE m.neighborhood_id = $1
        "#,
    )
    .bind(neighborhood_id).fetch_all(pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(|(id, label, compound_id, pp, fid)| AtomicNode { id, label, compound_id, pignistic_prob: pp, frame_id: fid })
    .collect();

    let edges: Vec<AtomicEdge> = sqlx::query_as::<_, (Uuid, Uuid, String)>(
        r#"
        SELECT e.source_id, e.target_id, e.relationship
        FROM edges e
        JOIN claim_neighborhood_membership ms ON ms.claim_id = e.source_id AND ms.neighborhood_id = $1
        JOIN claim_neighborhood_membership mt ON mt.claim_id = e.target_id AND mt.neighborhood_id = $1
        LEFT JOIN LATERAL edge_to_factor_type(e.relationship) ft ON true
        WHERE e.relationship <> 'decomposes_to'
          AND ft.forward_strength > 0
        "#,
    )
    .bind(neighborhood_id).fetch_all(pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(|(source, target, relationship)| AtomicEdge { source, target, relationship })
    .collect();

    let compound_groups: Vec<CompoundGroup> = sqlx::query_as::<_, (Uuid, String, Vec<Uuid>)>(
        r#"
        SELECT e.source_id AS compound_id,
               COALESCE(c.content, c.id::text) AS label,
               array_agg(e.target_id ORDER BY e.target_id) AS member_atom_ids
        FROM edges e
        JOIN claims c ON c.id = e.source_id
        JOIN claim_neighborhood_membership m ON m.claim_id = e.target_id AND m.neighborhood_id = $1
        WHERE e.relationship = 'decomposes_to'
        GROUP BY 1, 2
        "#,
    )
    .bind(neighborhood_id).fetch_all(pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(|(compound_id, label, member_atom_ids)| CompoundGroup { compound_id, label, member_atom_ids })
    .collect();

    Ok(AtomicResponse { neighborhood_id, truncated: false, nodes, edges, compound_groups })
}
