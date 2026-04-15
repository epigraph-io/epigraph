//! Group management endpoints for encrypted subgraphs
//!
//! Protected (POST/DELETE):
//! - `POST /api/v1/groups` — create a group (returns group_id + metadata only)
//! - `POST /api/v1/groups/:id/members` — add member (ECDH key exchange)
//! - `DELETE /api/v1/groups/:id/members/:agent_id` — remove member
//! - `POST /api/v1/groups/:id/rotate-key` — rotate epoch key
//!
//! Public (GET):
//! - `GET /api/v1/groups/:id` — group info with member count

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use epigraph_db::{GroupKeyEpochRepository, GroupMembershipRepository, GroupRepository};
// rotate_group_key (from epigraph-privacy) is an enterprise extension.
// The rotate_key handler lives in the epigraph-enterprise repo.
// To add it here: add epigraph-privacy as a dep, enable the enterprise feature,
// and re-implement the handler calling rotate_group_key from that crate.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request to create a new encrypted group
#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    /// Human-readable group name
    pub name: String,
    /// Creator's Ed25519 public key (hex-encoded, 32 bytes)
    pub creator_public_key: String,
    /// Optional PRE public key for proxy re-encryption (hex-encoded)
    pub pre_public_key: Option<String>,
}

/// Response after creating a group (metadata only — keys generated client-side)
#[derive(Debug, Serialize)]
pub struct CreateGroupResponse {
    pub group_id: Uuid,
    /// DID key identifier for the group
    pub did_key: String,
    /// Starting epoch number
    pub epoch: u32,
}

/// Request to add a member to a group
#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    /// Agent UUID to add
    pub agent_id: Uuid,
    /// Member's wrapped key share (hex-encoded encrypted payload)
    pub wrapped_key_share: String,
    /// Role: "admin", "member", or "reader"
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "member".to_string()
}

/// Response after adding a member
#[derive(Debug, Serialize)]
pub struct AddMemberResponse {
    pub membership_id: Uuid,
    pub group_id: Uuid,
    pub agent_id: Uuid,
    pub role: String,
    pub epoch: i32,
}

/// Response for group info
#[derive(Debug, Serialize)]
pub struct GroupInfoResponse {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub did_key: String,
    pub public_key: String,
    pub current_epoch: Option<i32>,
    pub member_count: usize,
    pub created_at: String,
}

/// Response after key rotation
#[derive(Debug, Serialize)]
pub struct RotateKeyResponse {
    pub group_id: Uuid,
    pub new_epoch: u32,
    /// New epoch key (hex-encoded) — caller must re-wrap for all members
    pub new_epoch_key: String,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Create a new encrypted group.
///
/// Persists group metadata and epoch-0 row only — no key material is generated
/// or stored server-side. The client generates the base key and epoch key
/// locally in the `--init-group` CLI ceremony.
///
/// Any authenticated agent may create a group; the caller becomes its creator.
pub async fn create_group(
    State(state): State<AppState>,
    axum::Extension(auth_ctx): axum::Extension<crate::middleware::bearer::AuthContext>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<CreateGroupResponse>), ApiError> {
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest {
            message: "Group name cannot be empty".to_string(),
        });
    }

    let public_key_bytes =
        hex::decode(&req.creator_public_key).map_err(|e| ApiError::BadRequest {
            message: format!("Invalid hex public key: {e}"),
        })?;

    if public_key_bytes.len() != 32 {
        return Err(ApiError::BadRequest {
            message: format!(
                "Public key must be 32 bytes, got {}",
                public_key_bytes.len()
            ),
        });
    }

    let pre_public_key_bytes = req
        .pre_public_key
        .as_deref()
        .map(hex::decode)
        .transpose()
        .map_err(|e| ApiError::BadRequest {
            message: format!("Invalid hex PRE public key: {e}"),
        })?;

    let group_id = Uuid::new_v4();
    let did_key = format!("did:key:{}", hex::encode(&public_key_bytes));

    // Persist group (metadata only — no key material)
    GroupRepository::create(
        &state.db_pool,
        group_id,
        Some(req.name.trim()),
        &did_key,
        &public_key_bytes,
        pre_public_key_bytes.as_deref(),
    )
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to create group: {e}"),
    })?;

    // Create epoch-0 entry (no wrapped key — client holds the key)
    GroupKeyEpochRepository::create_epoch(&state.db_pool, group_id, 0, None)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to create key epoch: {e}"),
        })?;

    tracing::info!(
        group_id = %group_id,
        creator_agent_id = ?auth_ctx.agent_id,
        "Created encrypted group (metadata only)"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateGroupResponse {
            group_id,
            did_key,
            epoch: 0,
        }),
    ))
}

/// Add a member to a group.
///
/// The caller must have already wrapped the group base key for the new member
/// using ECDH key exchange (`wrap_key_for_member`).
///
/// # Authorization
/// Caller must be an admin or creator of the group.
pub async fn add_member(
    State(state): State<AppState>,
    axum::Extension(auth_ctx): axum::Extension<crate::middleware::bearer::AuthContext>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<AddMemberResponse>), ApiError> {
    crate::middleware::group_authz::require_group_admin(&auth_ctx, group_id, &state.db_pool)
        .await?;

    // Verify group exists
    let group = GroupRepository::get_by_id(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query group: {e}"),
        })?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Group".to_string(),
            id: group_id.to_string(),
        })?;

    // Validate role
    let valid_roles = ["admin", "member", "reader"];
    if !valid_roles.contains(&req.role.as_str()) {
        return Err(ApiError::BadRequest {
            message: format!(
                "Invalid role '{}'. Must be one of: {}",
                req.role,
                valid_roles.join(", ")
            ),
        });
    }

    // Decode wrapped key share
    let wrapped_key_bytes =
        hex::decode(&req.wrapped_key_share).map_err(|e| ApiError::BadRequest {
            message: format!("Invalid hex wrapped_key_share: {e}"),
        })?;

    // Get current epoch
    let active_epoch = GroupKeyEpochRepository::get_active_epoch(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query active epoch: {e}"),
        })?;

    let epoch = active_epoch.map(|e| e.epoch).unwrap_or(0);

    // Persist membership
    let membership_id = GroupMembershipRepository::add_member(
        &state.db_pool,
        group_id,
        req.agent_id,
        &wrapped_key_bytes,
        epoch,
        &req.role,
    )
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to add member: {e}"),
    })?;

    tracing::info!(
        group_id = %group_id,
        agent_id = %req.agent_id,
        role = %req.role,
        "Added member to group"
    );

    // Suppress unused variable warning for group row (used for existence check)
    let _ = group;

    Ok((
        StatusCode::CREATED,
        Json(AddMemberResponse {
            membership_id,
            group_id,
            agent_id: req.agent_id,
            role: req.role,
            epoch,
        }),
    ))
}

/// Remove a member from a group (revoke access).
///
/// # Authorization
/// Caller must be an admin or creator of the group.
pub async fn remove_member(
    State(state): State<AppState>,
    axum::Extension(auth_ctx): axum::Extension<crate::middleware::bearer::AuthContext>,
    Path((group_id, agent_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::group_authz::require_group_admin(&auth_ctx, group_id, &state.db_pool)
        .await?;

    // Verify group exists
    GroupRepository::get_by_id(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query group: {e}"),
        })?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Group".to_string(),
            id: group_id.to_string(),
        })?;

    // Revoke membership
    GroupMembershipRepository::remove_member(&state.db_pool, group_id, agent_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to remove member: {e}"),
        })?;

    tracing::info!(
        group_id = %group_id,
        agent_id = %agent_id,
        "Removed member from group"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Get group info including member count.
pub async fn get_group(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupInfoResponse>, ApiError> {
    let group = GroupRepository::get_by_id(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query group: {e}"),
        })?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Group".to_string(),
            id: group_id.to_string(),
        })?;

    let members = GroupMembershipRepository::get_members(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query members: {e}"),
        })?;

    let active_epoch = GroupKeyEpochRepository::get_active_epoch(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query active epoch: {e}"),
        })?;

    Ok(Json(GroupInfoResponse {
        id: group.id,
        display_name: group.display_name,
        did_key: group.did_key,
        public_key: hex::encode(&group.public_key),
        current_epoch: active_epoch.map(|e| e.epoch),
        member_count: members.len(),
        created_at: group.created_at.to_rfc3339(),
    }))
}

// rotate_key handler is in the epigraph-enterprise repo.
// See: epigraph-enterprise/crates/epigraph-api-enterprise/src/routes/groups.rs
