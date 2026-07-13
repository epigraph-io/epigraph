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

use axum::extract::Query;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use std::collections::HashMap;
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

#[derive(serde::Deserialize)]
pub struct ListCandidatesQuery {
    pub status: Option<String>,
    pub limit: i64,
}

#[derive(Serialize)]
pub struct PendingCandidateOut {
    pub id: String,
    pub claim_a: String,
    pub claim_a_excerpt: String,
    pub claim_b: String,
    pub claim_b_excerpt: String,
    pub score: f32,
    pub verifier_verdict: Option<String>,
    pub verifier_rationale: Option<String>,
    pub created_at: String,
}

fn excerpt(content: Option<&String>) -> String {
    match content {
        Some(c) => {
            let trimmed: String = c.chars().take(200).collect();
            if c.chars().count() > 200 {
                format!("{trimmed}…")
            } else {
                trimmed
            }
        }
        None => "(claim not found)".to_string(),
    }
}

#[cfg(feature = "db")]
pub async fn list_candidates(
    State(state): State<AppState>,
    Query(q): Query<ListCandidatesQuery>,
) -> Result<Json<Vec<PendingCandidateOut>>, ApiError> {
    let status_ref = match q.status.as_deref() {
        Some(s @ ("pending" | "promoted" | "rejected" | "stale")) => Some(s),
        Some(other) => {
            return Err(ApiError::BadRequest {
                message: format!(
                    "status must be one of pending|promoted|rejected|stale, got {other}"
                ),
            });
        }
        None => None,
    };

    let repo = epigraph_db::MatchCandidateRepo::new(state.db_pool.clone());
    let rows = map_sqlx(repo.list(status_ref, q.limit).await)?;

    let mut claim_ids: Vec<Uuid> = Vec::with_capacity(rows.len() * 2);
    for r in &rows {
        claim_ids.push(r.claim_a);
        claim_ids.push(r.claim_b);
    }
    claim_ids.sort_unstable();
    claim_ids.dedup();

    let content_rows: Vec<(Uuid, String)> = map_sqlx(
        sqlx::query_as("SELECT id, content FROM claims WHERE id = ANY($1)")
            .bind(&claim_ids)
            .fetch_all(&state.db_pool)
            .await,
    )?;
    let content_by_id: HashMap<Uuid, String> = content_rows.into_iter().collect();

    let out = rows
        .into_iter()
        .map(|r| PendingCandidateOut {
            id: r.id.to_string(),
            claim_a_excerpt: excerpt(content_by_id.get(&r.claim_a)),
            claim_a: r.claim_a.to_string(),
            claim_b_excerpt: excerpt(content_by_id.get(&r.claim_b)),
            claim_b: r.claim_b.to_string(),
            score: r.score,
            verifier_verdict: r.verifier_verdict,
            verifier_rationale: r.verifier_rationale,
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(out))
}

#[cfg(not(feature = "db"))]
pub async fn list_candidates(
    State(_state): State<AppState>,
    Query(_q): Query<ListCandidatesQuery>,
) -> Result<Json<Vec<PendingCandidateOut>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[derive(serde::Deserialize)]
pub struct DecideCandidateRequest {
    pub verdict: String,
}

#[cfg(feature = "db")]
pub async fn decide_candidate(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(req): Json<DecideCandidateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "decide_candidate requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    let repo = epigraph_db::MatchCandidateRepo::new(state.db_pool.clone());
    let row = map_sqlx(repo.get(id).await)?;

    if row.status != "pending" {
        return Err(ApiError::Conflict {
            reason: format!("candidate {id} already decided (status={})", row.status),
        });
    }

    match req.verdict.as_str() {
        "promote" => {
            let all_current = epigraph_db::ClaimRepository::are_all_current(
                &state.db_pool,
                &[row.claim_a, row.claim_b],
            )
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;
            if !all_current {
                return Err(ApiError::BadRequest {
                    message: format!(
                        "cannot promote candidate {id}: both claims must be current \
                         (is_current=true)"
                    ),
                });
            }

            repo.set_status(id, "promoted", auth.agent_id)
                .await
                .map_err(|e| ApiError::DatabaseError {
                    message: e.to_string(),
                })?;

            let props = serde_json::json!({
                "candidate_id": id,
                "score": row.score,
                "features": row.features,
                "verifier_verdict": row.verifier_verdict,
                "decided_by": auth.agent_id,
                "source": "cross_source_matcher",
            });
            epigraph_db::EdgeRepository::create_symmetric_if_absent(
                &state.db_pool,
                row.claim_a,
                row.claim_b,
                "CORROBORATES",
                props,
            )
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;
        }
        "reject" => {
            repo.set_status(id, "rejected", auth.agent_id)
                .await
                .map_err(|e| ApiError::DatabaseError {
                    message: e.to_string(),
                })?;
        }
        other => {
            return Err(ApiError::BadRequest {
                message: format!("verdict must be 'promote' or 'reject', got {other}"),
            });
        }
    }

    let updated = map_sqlx(repo.get(id).await)?;
    Ok(Json(serde_json::json!({
        "id": updated.id.to_string(),
        "status": updated.status,
    })))
}
