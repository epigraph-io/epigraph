//! Activity management API for PROV-O provenance tracking
//!
//! - `POST /api/v1/activities` — Create a new activity (protected)
//! - `GET /api/v1/activities/:id` — Get an activity by ID (public)
//! - `PUT /api/v1/activities/:id/complete` — Mark an activity as completed (protected)

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateActivityRequest {
    pub activity_type: String,
    pub agent_id: Option<Uuid>,
    pub description: Option<String>,
    #[serde(default)]
    pub properties: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ActivityResponse {
    pub id: Uuid,
    pub activity_type: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub agent_id: Option<Uuid>,
    pub description: Option<String>,
    pub properties: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct CompleteActivityRequest {
    #[serde(default)]
    pub properties: Option<serde_json::Value>,
}

const VALID_ACTIVITY_TYPES: &[&str] = &["extraction", "ingestion", "reasoning", "experiment"];

// =============================================================================
// HANDLERS (db feature)
// =============================================================================

/// Create a new activity record.
///
/// `POST /api/v1/activities`
#[cfg(feature = "db")]
pub async fn create_activity(
    State(state): State<AppState>,
    Json(request): Json<CreateActivityRequest>,
) -> Result<(StatusCode, Json<ActivityResponse>), ApiError> {
    if !VALID_ACTIVITY_TYPES.contains(&request.activity_type.as_str()) {
        return Err(ApiError::ValidationError {
            field: "activity_type".to_string(),
            reason: format!(
                "Invalid activity_type '{}'. Valid types: {}",
                request.activity_type,
                VALID_ACTIVITY_TYPES.join(", ")
            ),
        });
    }

    let pool = &state.db_pool;
    let started_at = chrono::Utc::now();
    let properties = request.properties;

    let id = epigraph_db::ActivityRepository::create(
        pool,
        &request.activity_type,
        started_at,
        request.agent_id,
        request.description.as_deref(),
        properties.clone(),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ActivityResponse {
            id,
            activity_type: request.activity_type,
            started_at: started_at.to_rfc3339(),
            ended_at: None,
            agent_id: request.agent_id,
            description: request.description,
            properties,
        }),
    ))
}

/// Get an activity by ID.
///
/// `GET /api/v1/activities/:id`
#[cfg(feature = "db")]
pub async fn get_activity(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ActivityResponse>, ApiError> {
    let pool = &state.db_pool;

    let row = epigraph_db::ActivityRepository::get_by_id(pool, id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "activity".to_string(),
            id: id.to_string(),
        })?;

    Ok(Json(ActivityResponse {
        id: row.id,
        activity_type: row.activity_type,
        started_at: row.started_at.to_rfc3339(),
        ended_at: row.ended_at.map(|t| t.to_rfc3339()),
        agent_id: row.agent_id,
        description: row.description,
        properties: row.properties,
    }))
}

/// Mark an activity as completed.
///
/// `PUT /api/v1/activities/:id/complete`
#[cfg(feature = "db")]
pub async fn complete_activity(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<CompleteActivityRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pool = &state.db_pool;
    let ended_at = chrono::Utc::now();

    epigraph_db::ActivityRepository::complete(pool, id, ended_at, request.properties).await?;

    Ok(Json(serde_json::json!({
        "id": id,
        "ended_at": ended_at.to_rfc3339(),
        "status": "completed"
    })))
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn create_activity(
    Json(_request): Json<CreateActivityRequest>,
) -> Result<(StatusCode, Json<ActivityResponse>), ApiError> {
    let id = Uuid::new_v4();
    Ok((
        StatusCode::CREATED,
        Json(ActivityResponse {
            id,
            activity_type: "ingestion".to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            ended_at: None,
            agent_id: None,
            description: None,
            properties: serde_json::json!({}),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn get_activity(Path(id): Path<Uuid>) -> Result<Json<ActivityResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "activity".to_string(),
        id: id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn complete_activity(
    Path(id): Path<Uuid>,
    Json(_request): Json<CompleteActivityRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "id": id,
        "ended_at": chrono::Utc::now().to_rfc3339(),
        "status": "completed"
    })))
}
