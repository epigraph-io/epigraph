//! Community endpoints
//!
//! Public (GET):
//! - `GET /api/v1/communities` — list communities
//! - `GET /api/v1/communities/:id` — get community with members
//!
//! Protected (POST/DELETE):
//! - `POST /api/v1/communities` — create a community
//! - `POST /api/v1/communities/:id/members` — add perspective member
//! - `DELETE /api/v1/communities/:id/members/:perspective_id` — remove member

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

/// Request to create a new community
#[derive(Debug, Deserialize)]
pub struct CreateCommunityRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_governance_type")]
    pub governance_type: String,
    #[serde(default = "default_ownership_type")]
    pub ownership_type: String,
    /// Optional mass override: frame_id → mass assignments.
    /// When set, community-scoped belief for that frame uses this instead of combining member BBAs.
    pub mass_override: Option<serde_json::Value>,
}

fn default_governance_type() -> String {
    "open".to_string()
}

fn default_ownership_type() -> String {
    "public".to_string()
}

/// Request to add a member to a community
#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub perspective_id: Uuid,
}

/// Response for a community
#[derive(Debug, Serialize)]
pub struct CommunityResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub governance_type: Option<String>,
    pub ownership_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mass_override: Option<serde_json::Value>,
    pub created_at: String,
}

/// Response for a community with members
#[derive(Debug, Serialize)]
pub struct CommunityDetailResponse {
    pub community: CommunityResponse,
    pub member_count: usize,
    pub members: Vec<CommunityMemberEntry>,
}

/// A member entry in a community detail response
#[derive(Debug, Serialize)]
pub struct CommunityMemberEntry {
    pub perspective_id: Uuid,
    pub name: String,
    pub owner_agent_id: Option<Uuid>,
}

/// Query parameters for listing communities
#[derive(Debug, Deserialize)]
pub struct ListCommunitiesQuery {
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

/// Create a new community
///
/// `POST /api/v1/communities`
#[cfg(feature = "db")]
pub async fn create_community(
    State(state): State<AppState>,
    Json(request): Json<CreateCommunityRequest>,
) -> Result<(StatusCode, Json<CommunityResponse>), ApiError> {
    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    let pool = &state.db_pool;
    let row = epigraph_db::CommunityRepository::create(
        pool,
        &request.name,
        request.description.as_deref(),
        Some(&request.governance_type),
        Some(&request.ownership_type),
    )
    .await?;

    // Emit community.formed event
    let event_store = super::events::global_event_store();
    event_store
        .push(
            "community.formed".to_string(),
            None,
            serde_json::json!({
                "community_id": row.id,
                "name": row.name,
                "governance_type": request.governance_type,
            }),
        )
        .await;

    Ok((StatusCode::CREATED, Json(community_to_response(row))))
}

/// List all communities
///
/// `GET /api/v1/communities`
#[cfg(feature = "db")]
pub async fn list_communities(
    State(state): State<AppState>,
    Query(params): Query<ListCommunitiesQuery>,
) -> Result<Json<Vec<CommunityResponse>>, ApiError> {
    let pool = &state.db_pool;
    let rows = epigraph_db::CommunityRepository::list(pool, params.limit, params.offset).await?;

    Ok(Json(rows.into_iter().map(community_to_response).collect()))
}

/// Get a community by ID with members
///
/// `GET /api/v1/communities/:id`
#[cfg(feature = "db")]
pub async fn get_community(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CommunityDetailResponse>, ApiError> {
    let pool = &state.db_pool;

    let row = epigraph_db::CommunityRepository::get_by_id(pool, id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "community".to_string(),
            id: id.to_string(),
        })?;

    let members = epigraph_db::CommunityRepository::get_members(pool, id).await?;

    let member_entries: Vec<CommunityMemberEntry> = members
        .into_iter()
        .map(|p| CommunityMemberEntry {
            perspective_id: p.id,
            name: p.name,
            owner_agent_id: p.owner_agent_id,
        })
        .collect();

    Ok(Json(CommunityDetailResponse {
        community: community_to_response(row),
        member_count: member_entries.len(),
        members: member_entries,
    }))
}

/// Add a perspective member to a community
///
/// `POST /api/v1/communities/:id/members`
#[cfg(feature = "db")]
pub async fn add_member(
    State(state): State<AppState>,
    Path(community_id): Path<Uuid>,
    Json(request): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let pool = &state.db_pool;

    // Verify community exists
    epigraph_db::CommunityRepository::get_by_id(pool, community_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "community".to_string(),
            id: community_id.to_string(),
        })?;

    // Verify perspective exists
    epigraph_db::PerspectiveRepository::get_by_id(pool, request.perspective_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "perspective".to_string(),
            id: request.perspective_id.to_string(),
        })?;

    epigraph_db::CommunityRepository::add_member(pool, community_id, request.perspective_id)
        .await?;

    // Materialize MEMBER_OF edge (perspective → community)
    let _ = epigraph_db::EdgeRepository::create(
        pool,
        request.perspective_id,
        "perspective",
        community_id,
        "community",
        "MEMBER_OF",
        None,
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Remove a perspective member from a community
///
/// `DELETE /api/v1/communities/:id/members/:perspective_id`
#[cfg(feature = "db")]
pub async fn remove_member(
    State(state): State<AppState>,
    Path((community_id, perspective_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let pool = &state.db_pool;

    let removed =
        epigraph_db::CommunityRepository::remove_member(pool, community_id, perspective_id).await?;

    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound {
            entity: "community_member".to_string(),
            id: format!("{community_id}/{perspective_id}"),
        })
    }
}

#[cfg(feature = "db")]
fn community_to_response(row: epigraph_db::CommunityRow) -> CommunityResponse {
    CommunityResponse {
        id: row.id,
        name: row.name,
        description: row.description,
        governance_type: row.governance_type,
        ownership_type: row.ownership_type,
        mass_override: row.mass_override,
        created_at: row.created_at.to_rfc3339(),
    }
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn create_community(
    Json(request): Json<CreateCommunityRequest>,
) -> Result<(StatusCode, Json<CommunityResponse>), ApiError> {
    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(CommunityResponse {
            id: Uuid::new_v4(),
            name: request.name,
            description: request.description,
            governance_type: Some(request.governance_type),
            ownership_type: Some(request.ownership_type),
            mass_override: request.mass_override,
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn list_communities(
    Query(_params): Query<ListCommunitiesQuery>,
) -> Result<Json<Vec<CommunityResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn get_community(
    Path(id): Path<Uuid>,
) -> Result<Json<CommunityDetailResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "community".to_string(),
        id: id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn add_member(
    Path(_community_id): Path<Uuid>,
    Json(_request): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Community membership requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn remove_member(
    Path((_community_id, _perspective_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Community membership requires database".to_string(),
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_community_request_defaults() {
        let req: CreateCommunityRequest =
            serde_json::from_str(r#"{"name":"test_community"}"#).unwrap();
        assert_eq!(req.name, "test_community");
        assert_eq!(req.governance_type, "open");
        assert_eq!(req.ownership_type, "public");
        assert!(req.description.is_none());
    }

    #[test]
    fn list_communities_query_defaults() {
        let q: ListCommunitiesQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn add_member_request_parses() {
        let id = Uuid::new_v4();
        let json = format!(r#"{{"perspective_id":"{}"}}"#, id);
        let req: AddMemberRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.perspective_id, id);
    }
}
