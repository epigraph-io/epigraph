//! Context endpoints
//!
//! Public (GET):
//! - `GET /api/v1/contexts` — list all contexts
//! - `GET /api/v1/contexts/:id` — get context detail
//! - `GET /api/v1/contexts/active` — list currently active contexts
//! - `GET /api/v1/frames/:id/contexts` — list contexts applicable to a frame
//!
//! Protected (POST):
//! - `POST /api/v1/contexts` — create a context

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

/// Request to create a new context
#[derive(Debug, Deserialize)]
pub struct CreateContextRequest {
    pub name: String,
    pub context_type: String,
    pub description: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    #[serde(default)]
    pub applicable_frame_ids: Vec<Uuid>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    #[serde(default = "default_modifier_type")]
    pub modifier_type: String,
}

fn default_modifier_type() -> String {
    "filter".to_string()
}

/// Response for a context
#[derive(Debug, Serialize)]
pub struct ContextResponse {
    pub id: Uuid,
    pub name: String,
    pub context_type: String,
    pub description: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub applicable_frame_ids: Option<Vec<Uuid>>,
    pub parameters: Option<serde_json::Value>,
    pub modifier_type: Option<String>,
    pub created_at: String,
}

/// Query parameters for listing contexts
#[derive(Debug, Deserialize)]
pub struct ListContextsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

// =============================================================================
// HELPERS
// =============================================================================

#[cfg(feature = "db")]
fn context_to_response(row: epigraph_db::ContextRow) -> ContextResponse {
    ContextResponse {
        id: row.id,
        name: row.name,
        context_type: row.context_type,
        description: row.description,
        valid_from: row.valid_from.map(|t| t.to_rfc3339()),
        valid_until: row.valid_until.map(|t| t.to_rfc3339()),
        applicable_frame_ids: row.applicable_frame_ids,
        parameters: row.parameters,
        modifier_type: row.modifier_type,
        created_at: row.created_at.to_rfc3339(),
    }
}

// =============================================================================
// HANDLERS (db feature)
// =============================================================================

/// Create a new context
///
/// `POST /api/v1/contexts`
#[cfg(feature = "db")]
pub async fn create_context(
    State(state): State<AppState>,
    Json(request): Json<CreateContextRequest>,
) -> Result<(StatusCode, Json<ContextResponse>), ApiError> {
    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    if request.context_type.is_empty() {
        return Err(ApiError::ValidationError {
            field: "context_type".to_string(),
            reason: "context_type is required".to_string(),
        });
    }

    let valid_types = ["temporal", "domain", "experimental"];
    if !valid_types.contains(&request.context_type.as_str()) {
        return Err(ApiError::ValidationError {
            field: "context_type".to_string(),
            reason: format!("Must be one of: {}", valid_types.join(", ")),
        });
    }

    let valid_from = request
        .valid_from
        .as_deref()
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|_| ApiError::ValidationError {
                    field: "valid_from".to_string(),
                    reason: "Must be a valid RFC 3339 datetime".to_string(),
                })
        })
        .transpose()?;

    let valid_until = request
        .valid_until
        .as_deref()
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|_| ApiError::ValidationError {
                    field: "valid_until".to_string(),
                    reason: "Must be a valid RFC 3339 datetime".to_string(),
                })
        })
        .transpose()?;

    let pool = &state.db_pool;
    let row = epigraph_db::ContextRepository::create(
        pool,
        &request.name,
        &request.context_type,
        request.description.as_deref(),
        valid_from,
        valid_until,
        &request.applicable_frame_ids,
        request.parameters.as_ref(),
        Some(&request.modifier_type),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(context_to_response(row))))
}

/// List all contexts
///
/// `GET /api/v1/contexts`
#[cfg(feature = "db")]
pub async fn list_contexts(
    State(state): State<AppState>,
    Query(params): Query<ListContextsQuery>,
) -> Result<Json<Vec<ContextResponse>>, ApiError> {
    let pool = &state.db_pool;
    let rows = epigraph_db::ContextRepository::list(pool, params.limit, params.offset).await?;
    Ok(Json(rows.into_iter().map(context_to_response).collect()))
}

/// Get a context by ID
///
/// `GET /api/v1/contexts/:id`
#[cfg(feature = "db")]
pub async fn get_context(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ContextResponse>, ApiError> {
    let pool = &state.db_pool;
    let row = epigraph_db::ContextRepository::get_by_id(pool, id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "context".to_string(),
            id: id.to_string(),
        })?;
    Ok(Json(context_to_response(row)))
}

/// List currently active contexts
///
/// `GET /api/v1/contexts/active`
#[cfg(feature = "db")]
pub async fn list_active_contexts(
    State(state): State<AppState>,
) -> Result<Json<Vec<ContextResponse>>, ApiError> {
    let pool = &state.db_pool;
    let rows = epigraph_db::ContextRepository::list_active(pool).await?;
    Ok(Json(rows.into_iter().map(context_to_response).collect()))
}

/// List contexts applicable to a frame
///
/// `GET /api/v1/frames/:id/contexts`
#[cfg(feature = "db")]
pub async fn frame_contexts(
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
) -> Result<Json<Vec<ContextResponse>>, ApiError> {
    let pool = &state.db_pool;
    let rows = epigraph_db::ContextRepository::list_for_frame(pool, frame_id).await?;
    Ok(Json(rows.into_iter().map(context_to_response).collect()))
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn create_context(
    Json(request): Json<CreateContextRequest>,
) -> Result<(StatusCode, Json<ContextResponse>), ApiError> {
    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(ContextResponse {
            id: Uuid::new_v4(),
            name: request.name,
            context_type: request.context_type,
            description: request.description,
            valid_from: request.valid_from,
            valid_until: request.valid_until,
            applicable_frame_ids: Some(request.applicable_frame_ids),
            parameters: request.parameters,
            modifier_type: Some(request.modifier_type),
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn list_contexts(
    Query(_params): Query<ListContextsQuery>,
) -> Result<Json<Vec<ContextResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn get_context(Path(id): Path<Uuid>) -> Result<Json<ContextResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "context".to_string(),
        id: id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn list_active_contexts() -> Result<Json<Vec<ContextResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn frame_contexts(
    Path(_frame_id): Path<Uuid>,
) -> Result<Json<Vec<ContextResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_context_request_defaults() {
        let req: CreateContextRequest =
            serde_json::from_str(r#"{"name":"test","context_type":"temporal"}"#).unwrap();
        assert_eq!(req.name, "test");
        assert_eq!(req.context_type, "temporal");
        assert_eq!(req.modifier_type, "filter");
        assert!(req.applicable_frame_ids.is_empty());
        assert!(req.parameters.is_none());
    }

    #[test]
    fn list_contexts_query_defaults() {
        let q: ListContextsQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn context_response_serializes() {
        let resp = ContextResponse {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            context_type: "temporal".to_string(),
            description: None,
            valid_from: None,
            valid_until: None,
            applicable_frame_ids: Some(vec![]),
            parameters: None,
            modifier_type: Some("filter".to_string()),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("temporal"));
    }
}
