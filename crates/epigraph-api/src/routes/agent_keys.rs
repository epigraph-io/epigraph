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

/// The caller rule for every agent-key mutation: the caller must be the
/// target agent (`auth.agent_id == agent_id`) or hold `claims:admin`.
///
/// `claims:admin` is read through [`AuthContext::has_scope`], so the admin
/// override holds only while the admin-scope switch (migration 128) is
/// unarmed. Once it is armed, `claims:admin` counts only on an elevated token,
/// and an elevated token carries no `agents:write`, so no HTTP request can use
/// the override; an armed deployment rotates or revokes another agent's key
/// as a maintenance action instead.
///
/// Key rotation and revocation both call this before the hex decode, the
/// key lookup and the signature checks, so a non-owner cannot use those
/// outcomes to probe a mutation target. (The JSON body is deserialized by the
/// extractor before the handler runs; that refusal depends only on the
/// caller's own input. Key rows themselves are not secret:
/// `GET /api/v1/agents/:id/keys` lists them to any `agents:read` holder.)
///
/// [`AuthContext::has_scope`]: crate::middleware::bearer::AuthContext::has_scope
#[cfg(feature = "db")]
fn require_self_or_admin(
    auth: &crate::middleware::bearer::AuthContext,
    agent_id: Uuid,
) -> Result<(), ApiError> {
    if !auth.has_scope("claims:admin") && auth.agent_id != Some(agent_id) {
        return Err(ApiError::Forbidden {
            reason: "can only mutate your own agent record".into(),
        });
    }
    Ok(())
}

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

/// Since migration 161 a `signing` (or `identity-legacy`) key is attested
/// state: the host's identity registration binds it and a maintenance session
/// retires it. On an application session its status change or a new signing
/// row is refused with SQLSTATE 42501 (AK02). Answer that as a 403 naming the
/// right path, not as an opaque 500. Nothing was written: the refusal comes
/// from the first statement of each act.
#[cfg(feature = "db")]
fn attested_key_refusal(e: epigraph_db::DbError) -> ApiError {
    if crate::errors::db_is_insufficient_privilege(&e) {
        ApiError::Forbidden {
            reason: "this is an attested signing key: it is rotated through the host's \
                     identity registration, and revoked by a maintenance session"
                .to_string(),
        }
    } else {
        e.into()
    }
}

/// Rotate the agent's active signing key
///
/// POST /api/v1/agents/:id/keys/rotate
///
/// Rotates the agent's active `signing` key (keys of other types are never
/// touched) by:
/// 1. Verifying the old key signature over the canonical rotation message
/// 2. Verifying the new key signature over the same message
/// 3. Marking the old key as `rotated`, which closes its validity window
///    (`valid_until`, migration 162)
/// 4. Storing and activating the new key, valid from no earlier than the
///    old key's window closed
///
/// Requires `agents:write` scope. Caller must be the target agent
/// (auth.agent_id == :id) or have `claims:admin` (unarmed admin-scope switch
/// only; see `require_self_or_admin`), checked before the hex decode, the key
/// lookup and the signature checks. The old-key signature alone is not an
/// ownership proof: a derived LLM-agent key is computable from public inputs.
///
/// # Errors
///
/// - 400 Bad Request: a field is not valid hex or has the wrong length
/// - 401 Unauthorized: Missing or invalid Bearer token, or the old-key or
///   new-key signature does not verify (`SignatureError`)
/// - 403 Forbidden: Missing scope or caller is not the target agent
/// - 404 Not Found: The agent has no active signing key
/// - 422 Unprocessable Entity: the body does not deserialize (missing field
///   or wrong JSON type); refused by the extractor, the same for every caller
/// - 500 Internal Server Error: the old key left `active` under the request
///   (a concurrent rotation; the status definer refuses with `AK01`)
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
        require_self_or_admin(auth, id)?;
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
    let active_key = AgentKeyRepository::get_active_key(&state.db_pool, agent_id, "signing")
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

    // Mark old key as rotated. Since migration 162 this also closes its
    // validity window (`valid_until`) on the database clock.
    let retired =
        AgentKeyRepository::update_status(&state.db_pool, active_key.id, "rotated", None, None)
            .await
            .map_err(attested_key_refusal)?;

    // Store the new active key. Its window opens no earlier than the old one
    // closed, so the two never overlap even if this host's clock is behind
    // the database's.
    let now = Utc::now();
    let valid_from = retired.valid_until.map_or(now, |closed| closed.max(now));
    let new_key_id = Uuid::new_v4();
    let new_key_row = AgentKeyRepository::store(
        &state.db_pool,
        new_key_id,
        agent_id,
        &new_key_array,
        "signing",
        "active",
        valid_from,
        None,
        now,
    )
    .await
    .map_err(attested_key_refusal)?;

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
/// Marks the given key as `revoked` with the provided reason and closes its
/// validity window (`valid_until`, never moved later; migration 162).
/// A revoked key cannot be used for signing or verification.
/// `revoked_by` records the agent when the agent itself revoked, and nothing
/// on an admin override.
/// Requires `agents:write` scope. Caller must be the target agent
/// (auth.agent_id == :id) or have `claims:admin` (unarmed admin-scope switch
/// only; see `require_self_or_admin`).
///
/// # Errors
///
/// - 400 Bad Request: the key is already revoked
/// - 401 Unauthorized: Missing or invalid Bearer token
/// - 403 Forbidden: Missing scope or caller is not the target agent
/// - 404 Not Found: Agent or key does not exist
/// - 422 Unprocessable Entity: the body does not deserialize
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
        require_self_or_admin(auth, id)?;
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

    // `revoked_by` names the agent only when the agent itself revoked. An
    // admin override records no one: `revoked_by` references `agents(id)` and
    // an admin principal need not have an agents row, so recording it could
    // fail the emergency revoke path; recording the target would be false.
    let caller_is_agent = auth_ctx
        .as_ref()
        .is_some_and(|axum::Extension(auth)| auth.agent_id == Some(id));
    let updated = AgentKeyRepository::update_status(
        &state.db_pool,
        key_id,
        "revoked",
        Some(request.reason.as_str()),
        caller_is_agent.then_some(id),
    )
    .await
    .map_err(attested_key_refusal)?;

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
