//! Conflict resolution pipeline endpoints (ported from MCP tools).
//!
//! ## Endpoints
//!
//! - `GET  /api/v1/conflicts/scan`               - Scan for high-conflict claim pairs
//! - `POST /api/v1/conflicts/classify`            - Classify a conflict between two claims
//! - `POST /api/v1/conflicts/:a/:b/resolve`       - Resolve a conflict between two claims
//! - `GET  /api/v1/conflicts/silence-check`       - Check for suspiciously silent frames
//! - `POST /api/v1/conflicts/:a/:b/counterfactuals` - Generate counterfactual scenarios
//! - `GET  /api/v1/conflicts/:a/:b/counterfactuals` - Read stored counterfactuals
//! - `GET  /api/v1/learning-events`               - List learning events from resolutions

#[cfg(feature = "db")]
use axum::{
    extract::{Path, Query, State},
    Json,
};
#[cfg(feature = "db")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "db")]
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use sqlx;

// ── Request / Response types ──

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct ScanConflictsQuery {
    pub min_k: Option<f64>,
    pub frame_id: Option<Uuid>,
    pub limit: Option<i64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Serialize)]
pub struct ConflictScanResponse {
    pub high_conflict: Vec<serde_json::Value>,
    pub silence_alarms: Vec<serde_json::Value>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct ClassifyConflictRequest {
    pub claim_a_id: Uuid,
    pub claim_b_id: Uuid,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct ResolveConflictRequest {
    pub winner_id: Uuid,
    pub resolution: String,
    pub lesson: Option<String>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct GenerateCounterfactualsRequest {
    pub scenario_a: serde_json::Value,
    pub scenario_b: serde_json::Value,
    pub discriminating_tests: Option<serde_json::Value>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct LearningEventsQuery {
    pub challenge_id: Option<Uuid>,
    pub claim_id: Option<Uuid>,
    pub search: Option<String>,
    pub limit: Option<i64>,
}

// ── Handlers ──

/// GET /api/v1/conflicts/scan - Scan for high-conflict claim pairs.
#[cfg(feature = "db")]
pub async fn scan_conflicts(
    State(state): State<AppState>,
    Query(params): Query<ScanConflictsQuery>,
) -> Result<Json<ConflictScanResponse>, ApiError> {
    let min_k = params.min_k.unwrap_or(0.3);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    // Scan for high-conflict claims via mass_functions
    let high_conflict: Vec<serde_json::Value> = sqlx::query_as::<_, HighConflictRow>(
        "SELECT mf.claim_id, mf.frame_id, MAX(mf.conflict_k) AS max_k, \
                COUNT(*) AS bba_count, c.content \
         FROM mass_functions mf \
         JOIN claims c ON c.id = mf.claim_id \
         WHERE mf.conflict_k >= $1 \
         GROUP BY mf.claim_id, mf.frame_id, c.content \
         ORDER BY max_k DESC \
         LIMIT $2",
    )
    .bind(min_k)
    .bind(limit)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to scan conflicts: {e}"),
    })?
    .into_iter()
    .map(|r| {
        serde_json::json!({
            "claim_id": r.claim_id,
            "frame_id": r.frame_id,
            "max_k": r.max_k,
            "bba_count": r.bba_count,
            "content": r.content,
        })
    })
    .collect();

    // Scan for silence alarms
    let frame_densities: Vec<FrameDensityRow> = sqlx::query_as(
        "SELECT f.id AS frame_id, f.name AS frame_name, \
                (SELECT COUNT(DISTINCT mf.claim_id) FROM mass_functions mf WHERE mf.frame_id = f.id) AS total_claims, \
                (SELECT COUNT(*) FROM edges e \
                 JOIN mass_functions mf1 ON mf1.claim_id = e.source_id AND mf1.frame_id = f.id \
                 WHERE e.relationship = 'CONTRADICTS') AS contradicts_edges, \
                (SELECT COUNT(DISTINCT mf2.source_agent_id) FROM mass_functions mf2 \
                 WHERE mf2.frame_id = f.id AND mf2.source_agent_id IS NOT NULL) AS distinct_sources \
         FROM frames f LIMIT 100",
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to scan frame densities: {e}"),
    })?;

    let silence_alarms: Vec<serde_json::Value> = frame_densities
        .iter()
        .filter(|fd| fd.total_claims >= 20 && fd.distinct_sources >= 2)
        .filter(|fd| {
            let rate = if fd.total_claims > 0 {
                fd.contradicts_edges as f64 / fd.total_claims as f64
            } else {
                0.0
            };
            rate < 0.02
        })
        .map(|fd| {
            serde_json::json!({
                "frame_id": fd.frame_id,
                "frame_name": fd.frame_name,
                "total_claims": fd.total_claims,
                "contradicts_edges": fd.contradicts_edges,
                "distinct_sources": fd.distinct_sources,
            })
        })
        .collect();

    Ok(Json(ConflictScanResponse {
        high_conflict,
        silence_alarms,
    }))
}

/// POST /api/v1/conflicts/classify - Classify the conflict between two claims.
#[cfg(feature = "db")]
pub async fn classify_conflict(
    State(state): State<AppState>,
    Json(request): Json<ClassifyConflictRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Fetch both claims
    let claim_a =
        epigraph_db::ClaimRepository::get_by_id(&state.db_pool, request.claim_a_id.into())
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to fetch claim A: {e}"),
            })?
            .ok_or(ApiError::NotFound {
                entity: "claim".into(),
                id: request.claim_a_id.to_string(),
            })?;

    let claim_b =
        epigraph_db::ClaimRepository::get_by_id(&state.db_pool, request.claim_b_id.into())
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to fetch claim B: {e}"),
            })?
            .ok_or(ApiError::NotFound {
                entity: "claim".into(),
                id: request.claim_b_id.to_string(),
            })?;

    // Basic classification based on truth values and content
    let truth_diff = (claim_a.truth_value.value() - claim_b.truth_value.value()).abs();
    let conflict_type = if truth_diff > 0.5 {
        "strong_contradiction"
    } else if truth_diff > 0.2 {
        "moderate_disagreement"
    } else {
        "minor_tension"
    };

    Ok(Json(serde_json::json!({
        "claim_a": {
            "id": request.claim_a_id,
            "content": claim_a.content,
            "truth_value": claim_a.truth_value.value(),
        },
        "claim_b": {
            "id": request.claim_b_id,
            "content": claim_b.content,
            "truth_value": claim_b.truth_value.value(),
        },
        "conflict_type": conflict_type,
        "truth_difference": truth_diff,
    })))
}

/// POST /api/v1/conflicts/:a/:b/resolve - Resolve a conflict.
#[cfg(feature = "db")]
pub async fn resolve_conflict(
    State(state): State<AppState>,
    Path((claim_a_id, claim_b_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<ResolveConflictRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Create a challenge record for the resolution
    let challenge_id = epigraph_db::ChallengeRepository::create(
        &state.db_pool,
        if request.winner_id == claim_a_id {
            claim_b_id
        } else {
            claim_a_id
        },
        None,
        "contradicting_evidence",
        &request.resolution,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create challenge: {e}"),
    })?;

    // Mark it as resolved immediately
    epigraph_db::ChallengeRepository::update_state(
        &state.db_pool,
        challenge_id,
        "accepted",
        None,
        Some(&serde_json::json!({
            "winner_id": request.winner_id,
            "resolution": request.resolution,
        })),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to update challenge state: {e}"),
    })?;

    // Record learning event if lesson provided
    if let Some(ref lesson) = request.lesson {
        let _ = epigraph_db::LearningEventRepository::insert(
            &state.db_pool,
            challenge_id,
            Some(claim_a_id),
            Some(claim_b_id),
            &request.resolution,
            lesson,
            None,
        )
        .await;
    }

    // Emit event
    let _ = epigraph_db::EventRepository::insert(
        &state.db_pool,
        "conflict.resolved",
        None,
        &serde_json::json!({
            "claim_a_id": claim_a_id,
            "claim_b_id": claim_b_id,
            "winner_id": request.winner_id,
            "challenge_id": challenge_id,
        }),
    )
    .await;

    Ok(Json(serde_json::json!({
        "challenge_id": challenge_id,
        "claim_a_id": claim_a_id,
        "claim_b_id": claim_b_id,
        "winner_id": request.winner_id,
        "state": "accepted",
    })))
}

/// GET /api/v1/conflicts/silence-check - Check for suspiciously silent frames.
#[cfg(feature = "db")]
pub async fn silence_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let frame_densities: Vec<FrameDensityRow> = sqlx::query_as(
        "SELECT f.id AS frame_id, f.name AS frame_name, \
                (SELECT COUNT(DISTINCT mf.claim_id) FROM mass_functions mf WHERE mf.frame_id = f.id) AS total_claims, \
                (SELECT COUNT(*) FROM edges e \
                 JOIN mass_functions mf1 ON mf1.claim_id = e.source_id AND mf1.frame_id = f.id \
                 WHERE e.relationship = 'CONTRADICTS') AS contradicts_edges, \
                (SELECT COUNT(DISTINCT mf2.source_agent_id) FROM mass_functions mf2 \
                 WHERE mf2.frame_id = f.id AND mf2.source_agent_id IS NOT NULL) AS distinct_sources \
         FROM frames f LIMIT 100",
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to scan frame densities: {e}"),
    })?;

    let alarms: Vec<serde_json::Value> = frame_densities
        .iter()
        .filter(|fd| fd.total_claims >= 20 && fd.distinct_sources >= 2)
        .filter(|fd| {
            let rate = if fd.total_claims > 0 {
                fd.contradicts_edges as f64 / fd.total_claims as f64
            } else {
                0.0
            };
            rate < 0.02
        })
        .map(|fd| {
            let rate = if fd.total_claims > 0 {
                fd.contradicts_edges as f64 / fd.total_claims as f64
            } else {
                0.0
            };
            serde_json::json!({
                "frame_id": fd.frame_id,
                "frame_name": fd.frame_name,
                "total_claims": fd.total_claims,
                "contradicts_edges": fd.contradicts_edges,
                "distinct_sources": fd.distinct_sources,
                "conflict_rate": rate,
                "alarm": "suspicious_silence",
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "alarms": alarms,
        "total": alarms.len(),
    })))
}

/// POST /api/v1/conflicts/:a/:b/counterfactuals - Store counterfactual scenarios.
#[cfg(feature = "db")]
pub async fn store_counterfactuals(
    State(state): State<AppState>,
    Path((claim_a_id, claim_b_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<GenerateCounterfactualsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = epigraph_db::CounterfactualRepository::store(
        &state.db_pool,
        None,
        claim_a_id,
        claim_b_id,
        &request.scenario_a,
        &request.scenario_b,
        request.discriminating_tests.as_ref(),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to store counterfactuals: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "counterfactual_id": id,
        "claim_a_id": claim_a_id,
        "claim_b_id": claim_b_id,
    })))
}

/// GET /api/v1/conflicts/:a/:b/counterfactuals - Read stored counterfactuals.
#[cfg(feature = "db")]
pub async fn get_counterfactuals(
    State(state): State<AppState>,
    Path((claim_a_id, claim_b_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rows = epigraph_db::CounterfactualRepository::get_for_claims(
        &state.db_pool,
        claim_a_id,
        claim_b_id,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch counterfactuals: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "counterfactuals": rows,
        "total": rows.len(),
    })))
}

/// GET /api/v1/learning-events - List learning events from resolutions.
#[cfg(feature = "db")]
pub async fn list_learning_events(
    State(state): State<AppState>,
    Query(params): Query<LearningEventsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 500);

    let events = epigraph_db::LearningEventRepository::list(
        &state.db_pool,
        params.challenge_id,
        params.claim_id,
        params.search.as_deref(),
        limit,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to list learning events: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "learning_events": events,
        "total": events.len(),
    })))
}

// ── Internal row types ──

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct HighConflictRow {
    claim_id: Uuid,
    frame_id: Uuid,
    max_k: Option<f64>,
    bba_count: i64,
    content: String,
}

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct FrameDensityRow {
    frame_id: Uuid,
    frame_name: String,
    total_claims: i64,
    contradicts_edges: i64,
    distinct_sources: i64,
}
