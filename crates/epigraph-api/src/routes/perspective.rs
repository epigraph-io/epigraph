//! Perspective endpoints
//!
//! Public (GET):
//! - `GET /api/v1/perspectives` — list perspectives
//! - `GET /api/v1/perspectives/:id` — get perspective detail
//! - `GET /api/v1/agents/:id/perspectives` — list perspectives for an agent
//!
//! Protected (POST):
//! - `POST /api/v1/perspectives` — create a perspective

use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use axum::extract::State;
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request to create a new perspective
#[derive(Debug, Deserialize)]
pub struct CreatePerspectiveRequest {
    pub name: String,
    pub description: Option<String>,
    pub owner_agent_id: Option<Uuid>,
    #[serde(default = "default_perspective_type")]
    pub perspective_type: String,
    #[serde(default)]
    pub frame_ids: Vec<Uuid>,
    #[serde(default = "default_extraction_method")]
    pub extraction_method: String,
    #[serde(default = "default_confidence_calibration")]
    pub confidence_calibration: f64,
}

fn default_perspective_type() -> String {
    "analytical".to_string()
}

fn default_extraction_method() -> String {
    "ai_generated".to_string()
}

fn default_confidence_calibration() -> f64 {
    0.5
}

/// Response for a perspective
#[derive(Debug, Serialize)]
pub struct PerspectiveResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub owner_agent_id: Option<Uuid>,
    pub perspective_type: Option<String>,
    pub frame_ids: Option<Vec<Uuid>>,
    pub extraction_method: Option<String>,
    pub confidence_calibration: Option<f64>,
    pub created_at: String,
}

/// Query parameters for listing perspectives
#[derive(Debug, Deserialize)]
pub struct ListPerspectivesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

// =============================================================================
// HANDLERS (db feature)
// =============================================================================

/// Create a new perspective
///
/// `POST /api/v1/perspectives`
#[cfg(feature = "db")]
pub async fn create_perspective(
    State(state): State<AppState>,
    Json(request): Json<CreatePerspectiveRequest>,
) -> Result<(StatusCode, Json<PerspectiveResponse>), ApiError> {
    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    if !(0.0..=1.0).contains(&request.confidence_calibration) {
        return Err(ApiError::ValidationError {
            field: "confidence_calibration".to_string(),
            reason: "Must be in [0, 1]".to_string(),
        });
    }

    let pool = &state.db_pool;
    let row = epigraph_db::PerspectiveRepository::create(
        pool,
        &request.name,
        request.description.as_deref(),
        request.owner_agent_id,
        Some(&request.perspective_type),
        &request.frame_ids,
        Some(&request.extraction_method),
        Some(request.confidence_calibration),
    )
    .await?;

    // Materialize PERSPECTIVE_OF edge (agent → perspective) if owner specified
    if let Some(agent_id) = request.owner_agent_id {
        let _ = epigraph_db::EdgeRepository::create(
            pool,
            row.id,
            "perspective",
            agent_id,
            "agent",
            "PERSPECTIVE_OF",
            None,
            None,
            None,
        )
        .await;
    }

    Ok((StatusCode::CREATED, Json(perspective_to_response(row))))
}

/// List all perspectives
///
/// `GET /api/v1/perspectives`
#[cfg(feature = "db")]
pub async fn list_perspectives(
    State(state): State<AppState>,
    Query(params): Query<ListPerspectivesQuery>,
) -> Result<Json<Vec<PerspectiveResponse>>, ApiError> {
    let pool = &state.db_pool;
    let rows = epigraph_db::PerspectiveRepository::list(pool, params.limit, params.offset).await?;

    Ok(Json(
        rows.into_iter().map(perspective_to_response).collect(),
    ))
}

/// Get a perspective by ID
///
/// `GET /api/v1/perspectives/:id`
#[cfg(feature = "db")]
pub async fn get_perspective(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PerspectiveResponse>, ApiError> {
    let pool = &state.db_pool;
    let row = epigraph_db::PerspectiveRepository::get_by_id(pool, id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "perspective".to_string(),
            id: id.to_string(),
        })?;

    Ok(Json(perspective_to_response(row)))
}

/// List perspectives for an agent
///
/// `GET /api/v1/agents/:id/perspectives`
#[cfg(feature = "db")]
pub async fn agent_perspectives(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
    Query(params): Query<ListPerspectivesQuery>,
) -> Result<Json<Vec<PerspectiveResponse>>, ApiError> {
    let pool = &state.db_pool;
    let rows = epigraph_db::PerspectiveRepository::list_by_agent(
        pool,
        agent_id,
        params.limit,
        params.offset,
    )
    .await?;

    Ok(Json(
        rows.into_iter().map(perspective_to_response).collect(),
    ))
}

#[cfg(feature = "db")]
fn perspective_to_response(row: epigraph_db::PerspectiveRow) -> PerspectiveResponse {
    PerspectiveResponse {
        id: row.id,
        name: row.name,
        description: row.description,
        owner_agent_id: row.owner_agent_id,
        perspective_type: row.perspective_type,
        frame_ids: row.frame_ids,
        extraction_method: row.extraction_method,
        confidence_calibration: row.confidence_calibration,
        created_at: row.created_at.to_rfc3339(),
    }
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn create_perspective(
    Json(request): Json<CreatePerspectiveRequest>,
) -> Result<(StatusCode, Json<PerspectiveResponse>), ApiError> {
    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(PerspectiveResponse {
            id: Uuid::new_v4(),
            name: request.name,
            description: request.description,
            owner_agent_id: request.owner_agent_id,
            perspective_type: Some(request.perspective_type),
            frame_ids: Some(request.frame_ids),
            extraction_method: Some(request.extraction_method),
            confidence_calibration: Some(request.confidence_calibration),
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn list_perspectives(
    Query(_params): Query<ListPerspectivesQuery>,
) -> Result<Json<Vec<PerspectiveResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn get_perspective(Path(id): Path<Uuid>) -> Result<Json<PerspectiveResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "perspective".to_string(),
        id: id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn agent_perspectives(
    Path(_agent_id): Path<Uuid>,
    Query(_params): Query<ListPerspectivesQuery>,
) -> Result<Json<Vec<PerspectiveResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_perspective_request_defaults() {
        let req: CreatePerspectiveRequest = serde_json::from_str(r#"{"name":"test"}"#).unwrap();
        assert_eq!(req.name, "test");
        assert_eq!(req.perspective_type, "analytical");
        assert_eq!(req.extraction_method, "ai_generated");
        assert!((req.confidence_calibration - 0.5).abs() < f64::EPSILON);
        assert!(req.frame_ids.is_empty());
    }

    #[test]
    fn list_perspectives_query_defaults() {
        let q: ListPerspectivesQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
    }
}
