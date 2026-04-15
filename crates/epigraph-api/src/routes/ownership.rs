//! Ownership & partition endpoints (§3 Ownership/Privacy Layer)
//!
//! Public (GET):
//! - `GET /api/v1/ownership/:node_id` — get ownership info for a node
//! - `GET /api/v1/agents/:id/owned-nodes` — list nodes owned by an agent
//!
//! Protected (POST/PUT):
//! - `POST /api/v1/ownership` — assign ownership partition
//! - `PUT /api/v1/ownership/:node_id` — update partition type

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

/// Request to assign ownership of a node.
///
/// For `community` partitions, pass `community_id` to specify which community
/// gates access. The `owner_id` must still be a valid agent UUID (FK constraint).
#[derive(Debug, Deserialize)]
pub struct AssignOwnershipRequest {
    pub node_id: Uuid,
    pub node_type: String,
    #[serde(default = "default_partition")]
    pub partition_type: String,
    pub owner_id: Uuid,
    /// For community partitions: the community UUID that gates read access.
    pub community_id: Option<Uuid>,
}

fn default_partition() -> String {
    "public".to_string()
}

/// Request to update the partition type of a node
#[derive(Debug, Deserialize)]
pub struct UpdatePartitionRequest {
    pub partition_type: String,
}

/// Response for ownership info
#[derive(Debug, Serialize)]
pub struct OwnershipResponse {
    pub node_id: Uuid,
    pub node_type: String,
    pub partition_type: String,
    pub owner_id: Uuid,
    pub encryption_key_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Query parameters for listing owned nodes
#[derive(Debug, Deserialize)]
pub struct OwnedNodesQuery {
    pub node_type: Option<String>,
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

/// Assign ownership of a node to an agent
///
/// `POST /api/v1/ownership`
#[cfg(feature = "db")]
pub async fn assign_ownership(
    State(state): State<AppState>,
    Json(request): Json<AssignOwnershipRequest>,
) -> Result<(StatusCode, Json<OwnershipResponse>), ApiError> {
    let pool = &state.db_pool;

    let row = epigraph_db::OwnershipRepository::assign_with_community(
        pool,
        request.node_id,
        &request.node_type,
        &request.partition_type,
        request.owner_id,
        request.community_id,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(ownership_to_response(row))))
}

/// Get ownership info for a node
///
/// `GET /api/v1/ownership/:node_id`
#[cfg(feature = "db")]
pub async fn get_ownership(
    State(state): State<AppState>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<OwnershipResponse>, ApiError> {
    let pool = &state.db_pool;

    let row = epigraph_db::OwnershipRepository::get(pool, node_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "ownership".to_string(),
            id: node_id.to_string(),
        })?;

    Ok(Json(ownership_to_response(row)))
}

/// List nodes owned by an agent
///
/// `GET /api/v1/agents/:id/owned-nodes`
#[cfg(feature = "db")]
pub async fn owned_nodes(
    State(state): State<AppState>,
    Path(owner_id): Path<Uuid>,
    Query(params): Query<OwnedNodesQuery>,
) -> Result<Json<Vec<OwnershipResponse>>, ApiError> {
    let pool = &state.db_pool;

    let rows = epigraph_db::OwnershipRepository::get_for_owner(
        pool,
        owner_id,
        params.node_type.as_deref(),
        params.limit,
        params.offset,
    )
    .await?;

    Ok(Json(rows.into_iter().map(ownership_to_response).collect()))
}

/// Update the partition type of a node
///
/// `PUT /api/v1/ownership/:node_id`
#[cfg(feature = "db")]
pub async fn update_partition(
    State(state): State<AppState>,
    Path(node_id): Path<Uuid>,
    Json(request): Json<UpdatePartitionRequest>,
) -> Result<Json<OwnershipResponse>, ApiError> {
    let pool = &state.db_pool;

    let row =
        epigraph_db::OwnershipRepository::update_partition(pool, node_id, &request.partition_type)
            .await?
            .ok_or(ApiError::NotFound {
                entity: "ownership".to_string(),
                id: node_id.to_string(),
            })?;

    Ok(Json(ownership_to_response(row)))
}

#[cfg(feature = "db")]
fn ownership_to_response(row: epigraph_db::OwnershipRow) -> OwnershipResponse {
    OwnershipResponse {
        node_id: row.node_id,
        node_type: row.node_type,
        partition_type: row.partition_type,
        owner_id: row.owner_id,
        encryption_key_id: row.encryption_key_id,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn assign_ownership(
    Json(request): Json<AssignOwnershipRequest>,
) -> Result<(StatusCode, Json<OwnershipResponse>), ApiError> {
    Ok((
        StatusCode::CREATED,
        Json(OwnershipResponse {
            node_id: request.node_id,
            node_type: request.node_type,
            partition_type: request.partition_type,
            owner_id: request.owner_id,
            encryption_key_id: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn get_ownership(Path(node_id): Path<Uuid>) -> Result<Json<OwnershipResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "ownership".to_string(),
        id: node_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn owned_nodes(
    Path(_owner_id): Path<Uuid>,
    Query(_params): Query<OwnedNodesQuery>,
) -> Result<Json<Vec<OwnershipResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn update_partition(
    Path(node_id): Path<Uuid>,
    Json(_request): Json<UpdatePartitionRequest>,
) -> Result<Json<OwnershipResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "ownership".to_string(),
        id: node_id.to_string(),
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_ownership_request_defaults() {
        let req: AssignOwnershipRequest = serde_json::from_str(&format!(
            r#"{{"node_id":"{}","node_type":"claim","owner_id":"{}"}}"#,
            Uuid::new_v4(),
            Uuid::new_v4()
        ))
        .unwrap();
        assert_eq!(req.partition_type, "public");
        assert_eq!(req.node_type, "claim");
    }

    #[test]
    fn update_partition_request_parses() {
        let req: UpdatePartitionRequest =
            serde_json::from_str(r#"{"partition_type":"private"}"#).unwrap();
        assert_eq!(req.partition_type, "private");
    }

    #[test]
    fn owned_nodes_query_defaults() {
        let q: OwnedNodesQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
        assert!(q.node_type.is_none());
    }

    #[test]
    fn ownership_response_serializes() {
        let resp = OwnershipResponse {
            node_id: Uuid::new_v4(),
            node_type: "claim".to_string(),
            partition_type: "public".to_string(),
            owner_id: Uuid::new_v4(),
            encryption_key_id: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("partition_type"));
        assert!(json.contains("public"));
    }
}
