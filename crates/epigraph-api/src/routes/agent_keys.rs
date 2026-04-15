//! Key management endpoints for agent keys
//!
//! Provides HTTP endpoints for listing, rotating, and revoking agent keys.
//! All write operations require `agents:write` scope; reads require `agents:read`.

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
#[cfg(feature = "db")]
use epigraph_core::AgentId;
#[cfg(feature = "db")]
use epigraph_db::{AgentKeyRepository, AgentKeyRow};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

// =============================================================================
// RESPONSE TYPES
// =============================================================================

/// HTTP response for a single agent key
#[derive(Serialize, Debug)]
pub struct KeyResponse {
    pub id: Uuid,
    pub agent_id: Uuid,
    /// Hex-encoded Ed25519 public key (64 chars)
    pub public_key: String,
    /// "signing", "encryption", or "dual_purpose"
    pub key_type: String,
    /// "active", "pending", "rotated", "revoked", or "expired"
    pub status: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[cfg(feature = "db")]
impl From<AgentKeyRow> for KeyResponse {
    fn from(row: AgentKeyRow) -> Self {
        Self {
            id: row.id,
            agent_id: row.agent_id,
            public_key: hex::encode(&row.public_key),
            key_type: row.key_type,
            status: row.status,
            valid_from: row.valid_from,
            valid_until: row.valid_until,
            created_at: row.created_at,
        }
    }
}

// =============================================================================
// REQUEST TYPES
// =============================================================================

/// Request body for key rotation
#[derive(Deserialize, Debug)]
pub struct RotateKeyRequest {
    /// New Ed25519 public key (hex-encoded, 64 chars)
    pub new_public_key: String,
    /// Signature of the rotation message by the current active key (hex-encoded)
    pub old_key_signature: String,
    /// Signature of the rotation message by the new key (hex-encoded)
    pub new_key_signature: String,
    /// Optional human-readable reason for the rotation
    pub reason: Option<String>,
}

/// Request body for key revocation
#[derive(Deserialize, Debug)]
pub struct RevokeKeyRequest {
    /// Human-readable reason for the revocation
    pub reason: String,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// List all keys for an agent
///
/// GET /api/v1/agents/:id/keys
///
/// Returns all keys (across all statuses) for the given agent,
/// ordered by creation date (newest first).
/// Requires `agents:read` scope when authenticated.
#[cfg(feature = "db")]
pub async fn list_agent_keys(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<KeyResponse>>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["agents:read"])?;
    }

    let agent_id = AgentId::from_uuid(id);

    let rows = AgentKeyRepository::list_by_agent(&state.db_pool, agent_id).await?;

    let keys: Vec<KeyResponse> = rows.into_iter().map(Into::into).collect();

    Ok(Json(keys))
}

/// List all keys for an agent (placeholder — no database)
///
/// GET /api/v1/agents/:id/keys
#[cfg(not(feature = "db"))]
pub async fn list_agent_keys(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> Result<Json<Vec<KeyResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Agent key listing requires database".to_string(),
    })
}

/// Rotate the agent's active signing key
///
/// POST /api/v1/agents/:id/keys/rotate
///
/// Rotates the currently active key for the agent by:
/// 1. Verifying the old key signature over the canonical rotation message
/// 2. Verifying the new key signature over the same message
/// 3. Marking the old key as `rotated`
/// 4. Storing and activating the new key
///
/// Requires `agents:write` scope.
#[cfg(feature = "db")]
pub async fn rotate_agent_key(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<RotateKeyRequest>,
) -> Result<Json<KeyResponse>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["agents:write"])?;
    }

    // Decode the new public key from hex
    let new_key_bytes =
        hex::decode(&request.new_public_key).map_err(|_| ApiError::ValidationError {
            field: "new_public_key".to_string(),
            reason: "Invalid hex encoding".to_string(),
        })?;
    if new_key_bytes.len() != 32 {
        return Err(ApiError::ValidationError {
            field: "new_public_key".to_string(),
            reason: format!(
                "Expected 32 bytes (64 hex chars), got {} bytes",
                new_key_bytes.len()
            ),
        });
    }
    let mut new_key_array = [0u8; 32];
    new_key_array.copy_from_slice(&new_key_bytes);

    // Decode signatures from hex
    let old_sig_bytes =
        hex::decode(&request.old_key_signature).map_err(|_| ApiError::ValidationError {
            field: "old_key_signature".to_string(),
            reason: "Invalid hex encoding".to_string(),
        })?;
    if old_sig_bytes.len() != 64 {
        return Err(ApiError::ValidationError {
            field: "old_key_signature".to_string(),
            reason: format!(
                "Expected 64 bytes (128 hex chars), got {}",
                old_sig_bytes.len()
            ),
        });
    }
    let mut old_sig_array = [0u8; 64];
    old_sig_array.copy_from_slice(&old_sig_bytes);

    let new_sig_bytes =
        hex::decode(&request.new_key_signature).map_err(|_| ApiError::ValidationError {
            field: "new_key_signature".to_string(),
            reason: "Invalid hex encoding".to_string(),
        })?;
    if new_sig_bytes.len() != 64 {
        return Err(ApiError::ValidationError {
            field: "new_key_signature".to_string(),
            reason: format!(
                "Expected 64 bytes (128 hex chars), got {}",
                new_sig_bytes.len()
            ),
        });
    }
    let mut new_sig_array = [0u8; 64];
    new_sig_array.copy_from_slice(&new_sig_bytes);

    let agent_id = AgentId::from_uuid(id);

    // Look up the current active key
    let active_key = AgentKeyRepository::get_active_key(&state.db_pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "ActiveAgentKey".to_string(),
            id: id.to_string(),
        })?;

    // Build the canonical rotation message: "rotate:{agent_uuid_bytes}:{new_public_key_bytes}"
    let mut message = Vec::new();
    message.extend_from_slice(b"rotate:");
    message.extend_from_slice(id.as_bytes());
    message.extend_from_slice(b":");
    message.extend_from_slice(&new_key_array);

    // Verify old key signature (proves current key owner authorizes rotation)
    let old_key_array: [u8; 32] =
        active_key
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::InternalError {
                message: "Stored key has invalid length".to_string(),
            })?;

    use epigraph_crypto::SignatureVerifier;
    let old_sig_valid =
        SignatureVerifier::verify(&old_key_array, &message, &old_sig_array).unwrap_or(false);
    if !old_sig_valid {
        return Err(ApiError::SignatureError {
            reason: "Old key signature is invalid".to_string(),
        });
    }

    // Verify new key signature (proves new key owner controls the key)
    let new_sig_valid =
        SignatureVerifier::verify(&new_key_array, &message, &new_sig_array).unwrap_or(false);
    if !new_sig_valid {
        return Err(ApiError::SignatureError {
            reason: "New key signature is invalid".to_string(),
        });
    }

    // Mark old key as rotated
    AgentKeyRepository::update_status(&state.db_pool, active_key.id, "rotated", None, None).await?;

    // Store the new active key
    let now = Utc::now();
    let new_key_id = Uuid::new_v4();
    let new_key_row = AgentKeyRepository::store(
        &state.db_pool,
        new_key_id,
        agent_id,
        &new_key_array,
        "signing",
        "active",
        now,
        None,
        now,
    )
    .await?;

    Ok(Json(new_key_row.into()))
}

/// Rotate the agent's active signing key (placeholder — no database)
///
/// POST /api/v1/agents/:id/keys/rotate
#[cfg(not(feature = "db"))]
pub async fn rotate_agent_key(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<RotateKeyRequest>,
) -> Result<Json<KeyResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Key rotation requires database".to_string(),
    })
}

/// Revoke a specific key for an agent
///
/// POST /api/v1/agents/:id/keys/:key_id/revoke
///
/// Marks the given key as `revoked` with the provided reason.
/// A revoked key cannot be used for signing or verification.
/// Requires `agents:write` scope.
#[cfg(feature = "db")]
pub async fn revoke_agent_key(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path((id, key_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RevokeKeyRequest>,
) -> Result<Json<KeyResponse>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["agents:write"])?;
    }

    // Look up the key to verify it belongs to this agent
    let key = AgentKeyRepository::get_by_id(&state.db_pool, key_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "AgentKey".to_string(),
            id: key_id.to_string(),
        })?;

    if key.agent_id != id {
        return Err(ApiError::NotFound {
            entity: "AgentKey".to_string(),
            id: key_id.to_string(),
        });
    }

    if key.status == "revoked" {
        return Err(ApiError::BadRequest {
            message: format!("Key {} is already revoked", key_id),
        });
    }

    let updated = AgentKeyRepository::update_status(
        &state.db_pool,
        key_id,
        "revoked",
        Some(request.reason.as_str()),
        Some(id), // revoked_by = the agent themselves (or admin acting on their behalf)
    )
    .await?;

    Ok(Json(updated.into()))
}

/// Revoke a specific key for an agent (placeholder — no database)
///
/// POST /api/v1/agents/:id/keys/:key_id/revoke
#[cfg(not(feature = "db"))]
pub async fn revoke_agent_key(
    State(_state): State<AppState>,
    Path((_id, _key_id)): Path<(Uuid, Uuid)>,
    Json(_request): Json<RevokeKeyRequest>,
) -> Result<Json<KeyResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Key revocation requires database".to_string(),
    })
}
