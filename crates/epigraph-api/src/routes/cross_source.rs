//! GET /api/v1/claims/:id/cross_source_matches (T20).
//!
//! Returns two arrays for the given claim:
//! - `corroborates`: claim→claim edges with relationship `CORROBORATES`, either
//!   direction.
//! - `pending`: `match_candidates` rows in `status = 'pending'`. Promoted /
//!   rejected rows are intentionally omitted — the UI surface for those is
//!   either the CORROBORATES edge itself or admin tooling.
//!
//! 404 when the claim doesn't exist. 200 with empty arrays when it exists
//! but has no matches.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

// Cross-source matches reads two tables (edges, match_candidates) via raw
// sqlx. Local helpers fold sqlx errors into ApiError::DatabaseError so the
// existing DbError → ApiError bridge isn't bypassed silently.
fn map_sqlx<T>(r: Result<T, sqlx::Error>) -> Result<T, ApiError> {
    r.map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })
}

#[derive(Serialize)]
pub struct CorroboratesEdge {
    pub edge_id: String,
    pub source_id: String,
    pub target_id: String,
    pub properties: serde_json::Value,
}

#[derive(Serialize)]
pub struct PendingCandidate {
    pub id: String,
    pub claim_a: String,
    pub claim_b: String,
    pub score: f32,
    pub features: serde_json::Value,
    pub verifier_verdict: Option<String>,
    pub verifier_rationale: Option<String>,
    pub matcher_run_id: Option<String>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct CrossSourceMatchesResponse {
    pub claim_id: String,
    pub corroborates: Vec<CorroboratesEdge>,
    pub pending: Vec<PendingCandidate>,
}

#[cfg(feature = "db")]
pub async fn get_cross_source_matches(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<CrossSourceMatchesResponse>, ApiError> {
    // 404 if the claim doesn't exist. Using count(*) so we don't pay for the
    // full row hydration we'd get from ClaimRepository::get_by_id.
    let exists: (i64,) = map_sqlx(
        sqlx::query_as("SELECT COUNT(*)::bigint FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&state.db_pool)
            .await,
    )?;
    if exists.0 == 0 {
        return Err(ApiError::NotFound {
            entity: "claim".to_string(),
            id: claim_id.to_string(),
        });
    }

    let edge_rows: Vec<(Uuid, Uuid, Uuid, serde_json::Value)> = map_sqlx(
        sqlx::query_as(
            "SELECT id, source_id, target_id, properties FROM edges
             WHERE relationship = 'CORROBORATES'
               AND (source_id = $1 OR target_id = $1)",
        )
        .bind(claim_id)
        .fetch_all(&state.db_pool)
        .await,
    )?;
    let corroborates: Vec<CorroboratesEdge> = edge_rows
        .into_iter()
        .map(|(id, src, tgt, properties)| CorroboratesEdge {
            edge_id: id.to_string(),
            source_id: src.to_string(),
            target_id: tgt.to_string(),
            properties,
        })
        .collect();

    let repo = epigraph_db::MatchCandidateRepo::new(state.db_pool.clone());
    let candidate_rows = map_sqlx(repo.list_for_claim(claim_id).await)?;
    let pending: Vec<PendingCandidate> = candidate_rows
        .into_iter()
        .filter(|r| r.status == "pending")
        .map(|r| PendingCandidate {
            id: r.id.to_string(),
            claim_a: r.claim_a.to_string(),
            claim_b: r.claim_b.to_string(),
            score: r.score,
            features: r.features,
            verifier_verdict: r.verifier_verdict,
            verifier_rationale: r.verifier_rationale,
            matcher_run_id: r.matcher_run_id.map(|u| u.to_string()),
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(CrossSourceMatchesResponse {
        claim_id: claim_id.to_string(),
        corroborates,
        pending,
    }))
}

#[cfg(not(feature = "db"))]
pub async fn get_cross_source_matches(
    State(_state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<CrossSourceMatchesResponse>, ApiError> {
    Ok(Json(CrossSourceMatchesResponse {
        claim_id: claim_id.to_string(),
        corroborates: Vec::new(),
        pending: Vec::new(),
    }))
}
