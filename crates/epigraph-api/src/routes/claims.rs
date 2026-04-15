use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
#[cfg(feature = "db")]
use base64::Engine;
#[cfg(feature = "db")]
use epigraph_core::EvidenceType;
use epigraph_core::{AgentId, Claim, ClaimId, TraceId, TruthValue};
#[cfg(feature = "db")]
use epigraph_db::ClaimRepository;
#[cfg(feature = "db")]
use epigraph_db::EvidenceRepository;
#[cfg(feature = "db")]
use epigraph_db::{ClaimEncryptionRepository, GroupKeyEpochRepository, GroupMembershipRepository};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::access_control::{check_content_access, ContentAccess};
use crate::{errors::ApiError, state::AppState};
// set_group_context (from epigraph-privacy) is an enterprise extension.
// Add epigraph-privacy as a dep (epigraph-enterprise repo) and enable the enterprise
// feature to restore RLS group context scoping.

// =============================================================================
// PAGINATION CONSTANTS
// =============================================================================

/// Default number of items to return when no limit is specified
pub const DEFAULT_PAGE_LIMIT: i64 = 20;

/// Maximum number of items that can be requested in a single page
pub const MAX_PAGE_LIMIT: i64 = 100;

/// Minimum number of items that can be requested (must be at least 1)
pub const MIN_PAGE_LIMIT: i64 = 1;

/// Default truth value for claims when not explicitly specified
const DEFAULT_INITIAL_TRUTH: f64 = 0.5;

/// Request to create a new claim
#[derive(Deserialize)]
pub struct CreateClaimRequest {
    pub content: String,
    pub agent_id: Uuid,
    /// Reasoning trace ID. Optional — when omitted, the claim is created without a trace link.
    #[serde(default)]
    pub trace_id: Option<Uuid>,
    pub initial_truth: Option<f64>,
    /// Optional hex-encoded BLAKE3 content hash (64 chars). When provided, overrides
    /// the server-computed hash. Used by migration scripts that pre-compute hashes.
    #[serde(default)]
    pub content_hash: Option<String>,
    /// Optional JSONB properties (methodology, section, source_doi, etc.)
    #[serde(default)]
    pub properties: Option<serde_json::Value>,
    /// Optional evidence ID — if provided, creates a DERIVED_FROM edge (claim→evidence)
    pub evidence_id: Option<Uuid>,
    /// Privacy tier: "public" (default), "encrypted_content", or "fully_private"
    #[serde(default)]
    pub privacy_tier: Option<String>,
    /// Group ID — required when privacy_tier is not "public"
    #[serde(default)]
    pub group_id: Option<Uuid>,
    /// Base64-encoded ciphertext (client-encrypted content)
    #[serde(default)]
    pub encrypted_content: Option<String>,
    /// Encryption epoch — must match an active epoch for the group
    #[serde(default)]
    pub encryption_epoch: Option<i32>,
    /// Optional labels to assign on creation (e.g., ["ndi-roadmap", "fet-sensing"])
    #[serde(default)]
    pub labels: Vec<String>,
}

/// Claim response structure
#[derive(Serialize, Debug)]
pub struct ClaimResponse {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub agent_id: Uuid,
    pub trace_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Privacy tier (None = public, omitted from JSON when null)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_tier: Option<String>,
    /// Base64-encoded ciphertext for encrypted claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<String>,
    /// Encryption epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_epoch: Option<i32>,
    /// Group that owns the encrypted claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<Uuid>,
    /// Labels classifying this claim (e.g., "methodology:deductive_logic")
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

impl From<Claim> for ClaimResponse {
    fn from(claim: Claim) -> Self {
        Self {
            id: claim.id.into(),
            content: claim.content,
            truth_value: claim.truth_value.value(),
            agent_id: claim.agent_id.into(),
            trace_id: claim.trace_id.map(Into::into),
            created_at: claim.created_at,
            updated_at: claim.updated_at,
            privacy_tier: None,
            encrypted_content: None,
            encryption_epoch: None,
            group_id: None,
            labels: Vec::new(),
        }
    }
}

/// Pagination query parameters
#[derive(Deserialize, Debug)]
pub struct PaginationParams {
    /// Maximum number of items to return (default: 20, max: 100)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Number of items to skip (default: 0)
    #[serde(default)]
    pub offset: i64,
    /// Optional search string to match against claim content
    #[serde(default)]
    pub search: Option<String>,
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    /// Group ID for RLS context
    #[serde(default)]
    pub group_id: Option<Uuid>,
}

/// Returns the default pagination limit.
///
/// Used by serde when deserializing `PaginationParams` without a limit field.
fn default_limit() -> i64 {
    DEFAULT_PAGE_LIMIT
}

/// Validated pagination parameters ready for database queries.
///
/// Contains bounds-checked limit and offset values.
#[derive(Debug, Clone, Copy)]
pub struct ValidatedPagination {
    /// Number of items to return, clamped to [MIN_PAGE_LIMIT, MAX_PAGE_LIMIT]
    pub limit: i64,
    /// Number of items to skip, guaranteed non-negative
    pub offset: i64,
}

impl ValidatedPagination {
    /// Validate and clamp pagination parameters.
    ///
    /// # Arguments
    /// * `params` - Raw pagination parameters from the request
    ///
    /// # Returns
    /// Validated pagination with bounds-checked values:
    /// - `limit` is clamped to [MIN_PAGE_LIMIT, MAX_PAGE_LIMIT]
    /// - `offset` is clamped to minimum of 0
    ///
    /// # Example
    /// ```rust,ignore
    /// let validated = ValidatedPagination::from_params(&params);
    /// assert!(validated.limit >= MIN_PAGE_LIMIT);
    /// assert!(validated.limit <= MAX_PAGE_LIMIT);
    /// assert!(validated.offset >= 0);
    /// ```
    #[must_use]
    pub fn from_params(params: &PaginationParams) -> Self {
        Self {
            limit: params.limit.clamp(MIN_PAGE_LIMIT, MAX_PAGE_LIMIT),
            offset: params.offset.max(0),
        }
    }
}

/// Paginated list response
#[derive(Serialize, Debug)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Maximum encrypted content size after base64 decode (64 KB)
const MAX_ENCRYPTED_CONTENT_SIZE: usize = 65_536;

/// Validate privacy tier fields on a CreateClaimRequest.
/// Returns the parsed privacy tier string ("public" if omitted).
#[cfg(feature = "db")]
fn validate_privacy_fields(req: &CreateClaimRequest) -> Result<&str, ApiError> {
    let tier = req.privacy_tier.as_deref().unwrap_or("public");

    match tier {
        "public" | "encrypted_content" | "fully_private" => {}
        other => {
            return Err(ApiError::ValidationError {
                field: "privacy_tier".to_string(),
                reason: format!(
                    "Unknown privacy tier '{}'. Must be: public, encrypted_content, fully_private",
                    other
                ),
            });
        }
    }

    if tier != "public" {
        if req.group_id.is_none() {
            return Err(ApiError::ValidationError {
                field: "group_id".to_string(),
                reason: "group_id required for encrypted/private claims".to_string(),
            });
        }
        let enc = req
            .encrypted_content
            .as_deref()
            .ok_or(ApiError::ValidationError {
                field: "encrypted_content".to_string(),
                reason: "encrypted_content required for encrypted/private claims".to_string(),
            })?;
        if enc.len() > MAX_ENCRYPTED_CONTENT_SIZE * 4 / 3 + 4 {
            return Err(ApiError::ValidationError {
                field: "encrypted_content".to_string(),
                reason: format!(
                    "encrypted_content exceeds {} bytes after decode",
                    MAX_ENCRYPTED_CONTENT_SIZE
                ),
            });
        }
        match req.encryption_epoch {
            None => {
                return Err(ApiError::ValidationError {
                    field: "encryption_epoch".to_string(),
                    reason: "encryption_epoch required for encrypted/private claims".to_string(),
                });
            }
            Some(e) if e < 0 => {
                return Err(ApiError::ValidationError {
                    field: "encryption_epoch".to_string(),
                    reason: "encryption_epoch must be >= 0".to_string(),
                });
            }
            _ => {}
        }
    }

    Ok(tier)
}

/// Create a new claim
///
/// POST /claims
///
/// Creates a new claim in the database. The claim must have:
/// - Non-empty content
/// - Valid agent_id (existing agent)
/// - Valid trace_id (existing reasoning trace)
/// - Optional initial_truth in [0.0, 1.0] (defaults to 0.5)
///
/// For encrypted claims (privacy_tier != "public"):
/// - group_id, encrypted_content, and encryption_epoch are required
/// - Agent must be a member of the specified group
/// - encryption_epoch must match the group's active epoch
/// - Claim + encryption metadata are written atomically in a transaction
#[cfg(feature = "db")]
pub async fn create_claim(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    verified_agent: Option<axum::Extension<crate::middleware::auth::VerifiedAgent>>,
    Json(request): Json<CreateClaimRequest>,
) -> Result<Json<ClaimResponse>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    // Validate privacy fields first (needed to know if content check applies)
    let privacy_tier = validate_privacy_fields(&request)?;

    // Validate content is not empty (skip for fully_private — content will be overridden to "[private]")
    if privacy_tier != "fully_private" && request.content.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "content".to_string(),
            reason: "Content cannot be empty".to_string(),
        });
    }

    // If encrypted, validate group membership and epoch
    if privacy_tier != "public" {
        let group_id = request.group_id.unwrap(); // safe: validated above

        // SECURITY: Use ONLY authenticated identity for membership check, never request body
        // Prefer agent_id, fall back to client_id (sub) for human clients
        let caller_agent_id = auth_ctx
            .as_ref()
            .and_then(|axum::Extension(ctx)| ctx.agent_id.or(Some(ctx.client_id)))
            .ok_or_else(|| ApiError::Forbidden {
                reason: "Authentication required to create encrypted claims".to_string(),
            })?;

        // Verify caller is a member of the group
        let is_member =
            GroupMembershipRepository::is_member(&state.db_pool, group_id, caller_agent_id)
                .await
                .map_err(|e| ApiError::DatabaseError {
                    message: format!("Failed to check group membership: {e}"),
                })?;
        if !is_member {
            return Err(ApiError::Forbidden {
                reason: "Agent is not a member of the specified group".to_string(),
            });
        }

        // Verify epoch is active
        let active_epoch = GroupKeyEpochRepository::get_active_epoch(&state.db_pool, group_id)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to query active epoch: {e}"),
            })?;
        let active_epoch_num = match active_epoch {
            Some(e) => e.epoch,
            None => {
                return Err(ApiError::ValidationError {
                    field: "encryption_epoch".to_string(),
                    reason: "No active epoch found for this group".to_string(),
                });
            }
        };
        if request.encryption_epoch.unwrap() != active_epoch_num {
            return Err(ApiError::ValidationError {
                field: "encryption_epoch".to_string(),
                reason: format!(
                    "Epoch {} is not the active epoch (active: {})",
                    request.encryption_epoch.unwrap(),
                    active_epoch_num,
                ),
            });
        }
    }

    // Validate and create truth value
    let initial_truth = request.initial_truth.unwrap_or(DEFAULT_INITIAL_TRUTH);
    let truth_value = TruthValue::new(initial_truth).map_err(|_| ApiError::ValidationError {
        field: "initial_truth".to_string(),
        reason: "Truth value must be between 0.0 and 1.0".to_string(),
    })?;

    // Resolve public key: OAuth2 AuthContext → legacy VerifiedAgent → zero fallback
    let public_key = if let Some(axum::Extension(ctx)) = &auth_ctx {
        if let Some(agent_id) = ctx.agent_id {
            epigraph_db::AgentRepository::get_by_id(&state.db_pool, AgentId::from_uuid(agent_id))
                .await
                .ok()
                .flatten()
                .map(|a| a.public_key)
                .unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        }
    } else if let Some(axum::Extension(va)) = &verified_agent {
        va.public_key
    } else {
        [0u8; 32]
    };

    // For fully_private tier, override content to "[private]" (spec §5)
    let content_for_db = if privacy_tier == "fully_private" {
        "[private]".to_string()
    } else {
        request.content.clone()
    };

    let claim = if let Some(trace_uuid) = request.trace_id {
        Claim::new_with_trace(
            content_for_db,
            AgentId::from_uuid(request.agent_id),
            public_key,
            TraceId::from_uuid(trace_uuid),
            truth_value,
        )
    } else {
        Claim::new(
            content_for_db,
            AgentId::from_uuid(request.agent_id),
            public_key,
            truth_value,
        )
    };

    // Use a transaction for claim + encryption metadata atomicity
    let mut tx = state
        .db_pool
        .begin()
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to begin transaction: {e}"),
        })?;

    // Persist claim
    let created_claim = ClaimRepository::create_with_tx(&mut tx, &claim).await?;
    let claim_uuid = Uuid::from(created_claim.id);

    // Apply optional content_hash override and properties within the same transaction
    if request.content_hash.is_some() || request.properties.is_some() {
        let content_hash_bytes: Option<Vec<u8>> = if let Some(ref hex_hash) = request.content_hash {
            Some(
                hex::decode(hex_hash).map_err(|_| ApiError::ValidationError {
                    field: "content_hash".to_string(),
                    reason: "content_hash must be valid hex (64 chars for BLAKE3)".to_string(),
                })?,
            )
        } else {
            None
        };

        sqlx::query(
            "UPDATE claims SET content_hash = COALESCE($1, content_hash), properties = COALESCE($2, properties) WHERE id = $3"
        )
        .bind(content_hash_bytes.as_deref())
        .bind(&request.properties)
        .bind(claim_uuid)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to set content_hash/properties: {e}"),
        })?;
    }

    // Apply optional labels within the same transaction
    if !request.labels.is_empty() {
        sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
            .bind(&request.labels)
            .bind(claim_uuid)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to set labels: {e}"),
            })?;
    }

    let mut encryption_response = (None, None, None, None);

    if privacy_tier != "public" {
        let group_id = request.group_id.unwrap();
        let epoch = request.encryption_epoch.unwrap();
        let encrypted_bytes = base64::engine::general_purpose::STANDARD
            .decode(request.encrypted_content.as_deref().unwrap())
            .map_err(|e| ApiError::ValidationError {
                field: "encrypted_content".to_string(),
                reason: format!("Invalid base64: {e}"),
            })?;

        if encrypted_bytes.len() > MAX_ENCRYPTED_CONTENT_SIZE {
            return Err(ApiError::ValidationError {
                field: "encrypted_content".to_string(),
                reason: format!(
                    "Decrypted content exceeds {} bytes",
                    MAX_ENCRYPTED_CONTENT_SIZE
                ),
            });
        }

        ClaimEncryptionRepository::insert_conn(
            &mut tx,
            claim_uuid,
            group_id,
            epoch,
            privacy_tier,
            &encrypted_bytes,
            None,
        )
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to insert claim encryption: {e}"),
        })?;

        encryption_response = (
            Some(privacy_tier.to_string()),
            request.encrypted_content.clone(),
            Some(epoch),
            Some(group_id),
        );
    }

    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit transaction: {e}"),
    })?;

    // Materialize edges (best-effort, after commit)
    let _ = epigraph_db::EdgeRepository::create(
        &state.db_pool,
        request.agent_id,
        "agent",
        claim_uuid,
        "claim",
        "AUTHORED",
        None,
        None,
        None,
    )
    .await;

    if let Some(trace_uuid) = request.trace_id {
        let _ = epigraph_db::EdgeRepository::create(
            &state.db_pool,
            claim_uuid,
            "claim",
            trace_uuid,
            "trace",
            "HAS_TRACE",
            None,
            None,
            None,
        )
        .await;
    }

    if let Some(evidence_id) = request.evidence_id {
        let _ = epigraph_db::EdgeRepository::create(
            &state.db_pool,
            claim_uuid,
            "claim",
            evidence_id,
            "evidence",
            "DERIVED_FROM",
            None,
            None,
            None,
        )
        .await;
    }

    let mut response: ClaimResponse = created_claim.into();
    response.privacy_tier = encryption_response.0;
    response.encrypted_content = encryption_response.1;
    response.encryption_epoch = encryption_response.2;
    response.group_id = encryption_response.3;
    response.labels = request.labels;

    // Record provenance chain of custody when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        // Content hash for provenance: BLAKE3 of claim content
        let content_hash = blake3::hash(request.content.as_bytes());
        // Provenance signature placeholder (agent did not sign this request body via Ed25519)
        let provenance_sig: &[u8] = &[];

        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "claim",
            claim_uuid,
            "create",
            content_hash.as_bytes(),
            provenance_sig,
            None,
        )
        .await
        {
            tracing::warn!(
                claim_id = %claim_uuid,
                error = %e,
                "Failed to record provenance for claim creation"
            );
        }
    }

    Ok(Json(response))
}

/// Create a new claim (placeholder - no database)
///
/// POST /claims
///
/// Returns a placeholder response when DB is not enabled.
#[cfg(not(feature = "db"))]
pub async fn create_claim(
    State(_state): State<AppState>,
    Json(request): Json<CreateClaimRequest>,
) -> Result<Json<ClaimResponse>, ApiError> {
    // Validate content is not empty
    if request.content.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "content".to_string(),
            reason: "Content cannot be empty".to_string(),
        });
    }

    // Validate initial_truth if provided
    if let Some(truth) = request.initial_truth {
        if !(0.0..=1.0).contains(&truth) {
            return Err(ApiError::ValidationError {
                field: "initial_truth".to_string(),
                reason: "Truth value must be between 0.0 and 1.0".to_string(),
            });
        }
    }

    // Return placeholder response (no DB available)
    let now = chrono::Utc::now();
    let response = ClaimResponse {
        id: Uuid::new_v4(),
        content: request.content,
        truth_value: request.initial_truth.unwrap_or(DEFAULT_INITIAL_TRUTH),
        agent_id: request.agent_id,
        trace_id: request.trace_id,
        created_at: now,
        updated_at: now,
        privacy_tier: None,
        encrypted_content: None,
        encryption_epoch: None,
        group_id: None,
        labels: Vec::new(),
    };

    Ok(Json(response))
}

/// Query parameters for get_claim (optional agent_id for partition filtering)
#[derive(Deserialize, Debug, Default)]
pub struct GetClaimQuery {
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    /// Group ID for RLS context — enables visibility of fully_private claims
    #[serde(default)]
    pub group_id: Option<Uuid>,
}

/// Get a claim by ID
///
/// GET /claims/:id
///
/// Returns the claim if found, or 404 if not found.
/// If the claim is in a `private` or `community` partition and the requester
/// does not have access, the content field is redacted.
#[cfg(feature = "db")]
pub async fn get_claim(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<GetClaimQuery>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
) -> Result<Json<ClaimResponse>, ApiError> {
    let claim_id = ClaimId::from_uuid(id);

    // If group_id provided, verify caller is a member using authenticated identity
    if let Some(group_id) = params.group_id {
        // SECURITY: Use ONLY authenticated identity, never query-param agent_id
        // Prefer agent_id, fall back to client_id (sub) for human clients
        let caller_agent_id = auth_ctx
            .as_ref()
            .and_then(|axum::Extension(ctx)| ctx.agent_id.or(Some(ctx.client_id)));
        if let Some(agent_id) = caller_agent_id {
            let is_member =
                GroupMembershipRepository::is_member(&state.db_pool, group_id, agent_id)
                    .await
                    .map_err(|e| ApiError::DatabaseError {
                        message: format!("Failed to check group membership: {e}"),
                    })?;
            if !is_member {
                return Err(ApiError::Forbidden {
                    reason: "Agent is not a member of the specified group".to_string(),
                });
            }
        } else {
            return Err(ApiError::Forbidden {
                reason: "Authentication required to access group-scoped claims".to_string(),
            });
        }
    }

    // Set RLS context within a TRANSACTION to scope set_config and prevent pool leak
    let mut tx = state
        .db_pool
        .begin()
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to begin transaction: {e}"),
        })?;
    // enterprise: set_group_context(&mut *tx, params.group_id) — add epigraph-privacy dep to enable

    // Query claim on the same transaction (RLS applied when enterprise feature is active)
    let claim = ClaimRepository::get_by_id_conn(&mut tx, claim_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: id.to_string(),
        })?;

    // Encryption metadata query also within transaction
    let encryption = ClaimEncryptionRepository::get_by_claim_id_conn(&mut tx, id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query claim encryption: {e}"),
        })?;

    // Fetch labels from DB (not part of Claim domain model)
    let labels: Vec<String> = sqlx::query_scalar("SELECT unnest(labels) FROM claims WHERE id = $1")
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();

    // Transaction auto-rolls-back on drop (read-only, no commit needed)
    // This is intentional: dropping resets set_config local settings, preventing pool leak
    drop(tx);

    let mut response: ClaimResponse = claim.into();
    response.labels = labels;

    if let Some(enc) = encryption {
        response.privacy_tier = Some(enc.privacy_tier);
        response.encrypted_content =
            Some(base64::engine::general_purpose::STANDARD.encode(&enc.encrypted_content));
        response.encryption_epoch = Some(enc.epoch);
        response.group_id = Some(enc.group_id);
    }

    let access = check_content_access(&state.db_pool, id, params.agent_id).await;
    if access == ContentAccess::Redacted {
        crate::access_control::redact_claim_content(&mut response.content);
    }

    Ok(Json(response))
}

/// Get a claim by ID (placeholder - no database)
///
/// GET /claims/:id
///
/// Returns a placeholder response when DB is not enabled.
#[cfg(not(feature = "db"))]
pub async fn get_claim(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(_params): Query<GetClaimQuery>,
) -> Result<Json<ClaimResponse>, ApiError> {
    // Return placeholder response (no DB available)
    let now = chrono::Utc::now();
    let response = ClaimResponse {
        id,
        content: "Placeholder claim content".to_string(),
        truth_value: 0.75,
        agent_id: Uuid::new_v4(),
        trace_id: Some(Uuid::new_v4()),
        created_at: now,
        updated_at: now,
        privacy_tier: None,
        encrypted_content: None,
        encryption_epoch: None,
        group_id: None,
        labels: Vec::new(),
    };

    Ok(Json(response))
}

/// List claims with pagination
///
/// GET /claims?limit=20&offset=0
///
/// Returns a paginated list of claims ordered by creation date (newest first).
#[cfg(feature = "db")]
pub async fn list_claims(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
) -> Result<Json<PaginatedResponse<ClaimResponse>>, ApiError> {
    let pagination = ValidatedPagination::from_params(&params);

    // If group_id provided, verify caller is a member using authenticated identity
    if let Some(group_id) = params.group_id {
        // SECURITY: Use ONLY authenticated identity, never query-param agent_id
        // Prefer agent_id, fall back to client_id (sub) for human clients
        let caller_agent_id = auth_ctx
            .as_ref()
            .and_then(|axum::Extension(ctx)| ctx.agent_id.or(Some(ctx.client_id)));
        if let Some(agent_id) = caller_agent_id {
            let is_member =
                GroupMembershipRepository::is_member(&state.db_pool, group_id, agent_id)
                    .await
                    .map_err(|e| ApiError::DatabaseError {
                        message: format!("Failed to check group membership: {e}"),
                    })?;
            if !is_member {
                return Err(ApiError::Forbidden {
                    reason: "Agent is not a member of the specified group".to_string(),
                });
            }
        } else {
            return Err(ApiError::Forbidden {
                reason: "Authentication required to access group-scoped claims".to_string(),
            });
        }
    }

    // Set RLS context within a TRANSACTION to scope set_config and prevent pool leak
    let mut tx = state
        .db_pool
        .begin()
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to begin transaction: {e}"),
        })?;
    // enterprise: set_group_context(&mut *tx, params.group_id) — add epigraph-privacy dep to enable

    // Fetch on the same transaction (RLS applied when enterprise feature is active)
    let claims = ClaimRepository::list_conn(
        &mut tx,
        pagination.limit,
        pagination.offset,
        params.search.as_deref(),
    )
    .await?;
    let total = ClaimRepository::count_conn(&mut tx, params.search.as_deref()).await?;

    let mut items: Vec<ClaimResponse> = claims.into_iter().map(Into::into).collect();

    // Fetch labels for all listed claims in one query
    if !items.is_empty() {
        let claim_ids: Vec<Uuid> = items.iter().map(|i| i.id).collect();
        let label_rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, unnest(labels) FROM claims WHERE id = ANY($1) AND labels != '{}'",
        )
        .bind(&claim_ids)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();

        for item in &mut items {
            item.labels = label_rows
                .iter()
                .filter(|(id, _)| *id == item.id)
                .map(|(_, label)| label.clone())
                .collect();
        }
    }

    // Fetch encryption metadata INSIDE the transaction (RLS context still active)
    if !items.is_empty() {
        for item in &mut items {
            if let Ok(Some(enc)) =
                ClaimEncryptionRepository::get_by_claim_id_conn(&mut tx, item.id).await
            {
                item.privacy_tier = Some(enc.privacy_tier);
                item.encrypted_content =
                    Some(base64::engine::general_purpose::STANDARD.encode(&enc.encrypted_content));
                item.encryption_epoch = Some(enc.epoch);
                item.group_id = Some(enc.group_id);
            }
        }
    }

    // Transaction auto-rolls-back on drop (read-only, no commit needed)
    drop(tx);

    for item in &mut items {
        let access = check_content_access(&state.db_pool, item.id, params.agent_id).await;
        if access == ContentAccess::Redacted {
            crate::access_control::redact_claim_content(&mut item.content);
        }
    }

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit: pagination.limit,
        offset: pagination.offset,
    }))
}

/// List claims with pagination (placeholder - no database)
///
/// GET /claims?limit=20&offset=0
///
/// Returns an empty list when DB is not enabled.
#[cfg(not(feature = "db"))]
pub async fn list_claims(
    State(_state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<ClaimResponse>>, ApiError> {
    let pagination = ValidatedPagination::from_params(&params);

    Ok(Json(PaginatedResponse {
        items: vec![],
        total: 0,
        limit: pagination.limit,
        offset: pagination.offset,
    }))
}

// =============================================================================
// EVIDENCE BY CLAIM
// =============================================================================

/// Evidence response matching the UI's Evidence interface
#[derive(Debug, Serialize)]
pub struct EvidenceResponse {
    pub id: String,
    pub claim_id: String,
    pub content: String,
    pub content_hash: String,
    pub source_url: Option<String>,
    pub evidence_type: String,
    pub created_at: String,
}

/// List evidence for a specific claim
///
/// GET /api/v1/claims/:id/evidence
#[cfg(feature = "db")]
pub async fn list_claim_evidence(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<Vec<EvidenceResponse>>, ApiError> {
    let evidence_list =
        EvidenceRepository::get_by_claim(&state.db_pool, ClaimId::from_uuid(claim_id)).await?;

    let responses: Vec<EvidenceResponse> = evidence_list
        .into_iter()
        .map(|e| {
            let (evidence_type, source_url) = match &e.evidence_type {
                EvidenceType::Document { source_url, .. } => {
                    ("empirical".to_string(), source_url.clone())
                }
                EvidenceType::Observation { .. } => ("empirical".to_string(), None),
                EvidenceType::Testimony { source, .. } => {
                    ("testimonial".to_string(), Some(source.clone()))
                }
                EvidenceType::Literature { doi, .. } => {
                    ("analytical".to_string(), Some(doi.clone()))
                }
                EvidenceType::Consensus { .. } => ("statistical".to_string(), None),
                EvidenceType::Figure { doi, .. } => ("figure".to_string(), Some(doi.clone())),
            };

            EvidenceResponse {
                id: Uuid::from(e.id).to_string(),
                claim_id: Uuid::from(e.claim_id).to_string(),
                content: e.raw_content.unwrap_or_default(),
                content_hash: hex::encode(e.content_hash),
                source_url,
                evidence_type,
                created_at: e.created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(responses))
}

#[cfg(not(feature = "db"))]
pub async fn list_claim_evidence(
    State(_state): State<AppState>,
    Path(_claim_id): Path<Uuid>,
) -> Result<Json<Vec<EvidenceResponse>>, ApiError> {
    Ok(Json(vec![]))
}

#[derive(Debug, Deserialize)]
pub struct NeedingEmbeddingsQuery {
    /// Max claims to return (default 100, max 500)
    pub limit: Option<i64>,
}

/// GET /api/v1/claims/needing-embeddings
///
/// Returns claims with NULL embeddings for the caller to process
/// through an embedding service and write back.
#[cfg(feature = "db")]
pub async fn find_claims_needing_embeddings(
    State(state): State<AppState>,
    Query(params): Query<NeedingEmbeddingsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = params.limit.unwrap_or(100).min(500);
    let claims = ClaimRepository::find_claims_needing_embeddings(&state.db_pool, limit)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: e.to_string(),
        })?;

    Ok(Json(serde_json::json!({
        "claims": claims.iter().map(|(id, content)| {
            serde_json::json!({"id": id, "content": content})
        }).collect::<Vec<_>>(),
        "count": claims.len(),
    })))
}

#[cfg(not(feature = "db"))]
pub async fn find_claims_needing_embeddings(
    State(_state): State<AppState>,
    Query(_params): Query<NeedingEmbeddingsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "claims": [],
        "count": 0,
        "status": "stub"
    })))
}

// =============================================================================
// UPDATE CLAIM
// =============================================================================

/// Request to update an existing claim
#[derive(Deserialize)]
pub struct UpdateClaimRequest {
    /// New truth value in [0.0, 1.0]
    pub truth_value: Option<f64>,
    /// New trace_id to associate with this claim
    pub trace_id: Option<Uuid>,
    /// Optional embedding vector (reserved for future use)
    pub embedding: Option<Vec<f32>>,
    /// Optional JSONB properties (reserved for future use)
    pub properties: Option<serde_json::Value>,
}

/// Request body for PATCH /api/v1/claims/:id
///
/// All fields are optional. Only provided fields are updated.
/// `properties` is merged (JSONB `||`) — existing keys not in the patch are preserved.
/// `add_labels` / `remove_labels` follow the same semantics as PATCH /labels.
#[derive(Deserialize, Debug)]
pub struct PatchClaimRequest {
    /// New trace_id to link to this claim.
    pub trace_id: Option<Uuid>,
    /// Properties to merge into the claim's JSONB properties column.
    /// Keys in this object overwrite matching keys; unmentioned keys are preserved.
    pub properties: Option<serde_json::Value>,
    /// Labels to add (idempotent).
    #[serde(default)]
    pub add_labels: Option<Vec<String>>,
    /// Labels to remove (idempotent).
    #[serde(default)]
    pub remove_labels: Option<Vec<String>>,
}

impl PatchClaimRequest {
    /// Returns true if there is nothing to patch.
    pub fn is_empty(&self) -> bool {
        self.trace_id.is_none()
            && self.properties.is_none()
            && self.add_labels.as_deref().is_none_or(|v| v.is_empty())
            && self.remove_labels.as_deref().is_none_or(|v| v.is_empty())
    }
}

/// Update an existing claim
///
/// PUT /api/v1/claims/:id
///
/// Updates mutable fields on a claim. Content is immutable (create a new
/// superseding claim instead). Truth value and trace_id can be updated.
#[cfg(feature = "db")]
pub async fn update_claim(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateClaimRequest>,
) -> Result<Json<ClaimResponse>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    let claim_id = ClaimId::from_uuid(id);

    // Verify claim exists (404 if not found)
    let mut current = ClaimRepository::get_by_id(&state.db_pool, claim_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: id.to_string(),
        })?;

    // Update truth value if provided
    if let Some(tv) = request.truth_value {
        let truth = TruthValue::new(tv).map_err(|_| ApiError::ValidationError {
            field: "truth_value".to_string(),
            reason: "Truth value must be between 0.0 and 1.0".to_string(),
        })?;
        current = ClaimRepository::update_truth_value(&state.db_pool, claim_id, truth).await?;
    }

    // Update trace_id if provided
    if let Some(trace_uuid) = request.trace_id {
        let trace_id = TraceId::from_uuid(trace_uuid);
        current = ClaimRepository::update_trace_id(&state.db_pool, claim_id, trace_id).await?;
    }

    // Update embedding if provided (used by backfill_embeddings.py)
    if let Some(ref embedding) = request.embedding {
        // Convert Vec<f32> to pgvector literal format: "[0.1,0.2,...]"
        let pgvector = format!(
            "[{}]",
            embedding
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        ClaimRepository::store_embedding(&state.db_pool, id, &pgvector)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to store embedding: {e}"),
            })?;
    }

    // Update properties if provided
    if let Some(ref properties) = request.properties {
        sqlx::query("UPDATE claims SET properties = $1 WHERE id = $2")
            .bind(properties)
            .bind(id)
            .execute(&state.db_pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to update properties: {e}"),
            })?;
    }

    // Record provenance when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let content_hash = blake3::hash(id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "claim",
            id,
            "update",
            content_hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(claim_id = %id, error = %e, "Failed to record claim update provenance");
        }
    }

    Ok(Json(current.into()))
}

/// Update an existing claim (placeholder - no database)
#[cfg(not(feature = "db"))]
pub async fn update_claim(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<UpdateClaimRequest>,
) -> Result<Json<ClaimResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Claim updates require database".to_string(),
    })
}

// ── Partial Update (PATCH) ──

/// Partial update of a claim with full transactional provenance.
///
/// PATCH /api/v1/claims/:id
///
/// All fields are optional. Only provided fields are mutated. `properties` uses
/// JSONB merge (`||`) — existing keys not in the patch are preserved.
///
/// Auth is required: returns 401 if no bearer token is present.
/// All mutations and the provenance record are committed atomically.
#[cfg(feature = "db")]
pub async fn patch_claim(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<PatchClaimRequest>,
) -> Result<Json<ClaimResponse>, ApiError> {
    use epigraph_db::repos::provenance::AUTO_POLICY_AUTHORIZER_ID;
    use epigraph_db::ProvenanceRepository;

    // ── 1. Require authentication ────────────────────────────────────────────
    let auth = match auth_ctx {
        Some(axum::Extension(ref a)) => a.clone(),
        None => {
            return Err(ApiError::Unauthorized {
                reason: "PATCH /api/v1/claims/:id requires authentication".to_string(),
            });
        }
    };

    // ── 2. Scope check ───────────────────────────────────────────────────────
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;

    // ── 3. Validate request — nothing to patch → 400 ────────────────────────
    if request.is_empty() {
        return Err(ApiError::BadRequest {
            message: "At least one field must be specified to patch".to_string(),
        });
    }

    let claim_id = ClaimId::from_uuid(id);

    // ── 5. Open transaction — all mutations + provenance are atomic ──────────
    let mut tx = state
        .db_pool
        .begin()
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to begin transaction: {e}"),
        })?;

    // ── 6. Fetch before-state INSIDE the transaction with FOR UPDATE ──────────
    // Single query covers all fields needed for the diff; FOR UPDATE locks the
    // row for the duration of the transaction, preventing cross-field skew and
    // concurrent mutation races.
    use sqlx::Row as _;
    let before_row = sqlx::query(
        "SELECT trace_id, \
                COALESCE(labels, ARRAY[]::text[]) AS labels, \
                COALESCE(properties, '{}'::jsonb) AS properties \
         FROM claims WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?
    .ok_or_else(|| ApiError::NotFound {
        entity: "Claim".to_string(),
        id: id.to_string(),
    })?;

    let before_labels: Vec<String> = before_row.get("labels");
    let before_props: serde_json::Value = before_row.get("properties");
    let before_trace: Option<Uuid> = before_row.get("trace_id");

    // ── 7. Apply mutations ───────────────────────────────────────────────────
    let mut after_trace = before_trace;
    if let Some(trace_uuid) = request.trace_id {
        let trace_id = TraceId::from_uuid(trace_uuid);
        ClaimRepository::update_trace_id_conn(&mut tx, claim_id, trace_id)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;
        after_trace = Some(trace_uuid);
    }

    let mut after_props = before_props.clone();
    if let Some(ref patch_props) = request.properties {
        sqlx::query(
            "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) || $1 WHERE id = $2",
        )
        .bind(patch_props)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to merge properties: {e}"),
        })?;
        // Compute merged value in memory for diff
        if let (Some(merged), Some(patch_obj)) =
            (after_props.as_object_mut(), patch_props.as_object())
        {
            for (k, v) in patch_obj {
                merged.insert(k.clone(), v.clone());
            }
        }
    }

    let add_labels = request.add_labels.as_deref().unwrap_or(&[]);
    let remove_labels = request.remove_labels.as_deref().unwrap_or(&[]);
    let mut after_labels = before_labels.clone();
    if !add_labels.is_empty() || !remove_labels.is_empty() {
        after_labels = ClaimRepository::update_labels_conn(&mut tx, id, add_labels, remove_labels)
            .await
            .map_err(|e| match e {
                epigraph_db::DbError::NotFound { .. } => ApiError::NotFound {
                    entity: "Claim".to_string(),
                    id: id.to_string(),
                },
                other => ApiError::DatabaseError {
                    message: other.to_string(),
                },
            })?;
    }

    // ── 8. Re-fetch updated claim (for response) ─────────────────────────────
    let updated_claim = ClaimRepository::get_by_id_conn(&mut tx, claim_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: e.to_string(),
        })?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: id.to_string(),
        })?;

    // ── 9. Compute field-level diff ──────────────────────────────────────────
    let mut diff: Vec<serde_json::Value> = Vec::new();

    if request.trace_id.is_some() && after_trace != before_trace {
        diff.push(serde_json::json!({
            "field": "trace_id",
            "before": before_trace,
            "after": after_trace,
        }));
    }

    if request.properties.is_some() && after_props != before_props {
        diff.push(serde_json::json!({
            "field": "properties",
            "before": before_props,
            "after": after_props,
        }));
    }

    let labels_changed = request.add_labels.is_some() || request.remove_labels.is_some();
    if labels_changed {
        let mut before_sorted = before_labels.clone();
        let mut after_sorted = after_labels.clone();
        before_sorted.sort();
        after_sorted.sort();
        if before_sorted != after_sorted {
            diff.push(serde_json::json!({
                "field": "labels",
                "before": before_sorted,
                "after": after_sorted,
            }));
        }
    }

    let diff_value = serde_json::Value::Array(diff);

    // ── 10. Compute content_hash = BLAKE3(serialized diff) ──────────────────
    let diff_bytes = serde_json::to_vec(&diff_value).unwrap_or_default();
    let content_hash = blake3::hash(&diff_bytes);

    // ── 11. Append provenance — fail hard, inside transaction ────────────────
    let principal_id = auth.owner_id.unwrap_or(auth.client_id);
    ProvenanceRepository::append_conn(
        &mut tx,
        "claim",
        id,
        "patch",
        auth.client_id,
        principal_id,
        &[AUTO_POLICY_AUTHORIZER_ID],
        "auto_policy",
        content_hash.as_bytes(),
        &[],
        auth.jti,
        &auth.scopes,
        Some(&diff_value),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to record provenance: {e}"),
    })?;

    // ── 12. Commit ───────────────────────────────────────────────────────────
    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("Failed to commit transaction: {e}"),
    })?;

    Ok(Json(updated_claim.into()))
}

/// Stub for non-db builds
#[cfg(not(feature = "db"))]
pub async fn patch_claim(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<PatchClaimRequest>,
) -> Result<Json<ClaimResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Claim patches require database".to_string(),
    })
}

// ── Label Mutation ──

/// Request body for PATCH /api/v1/claims/:id/labels
#[derive(Deserialize)]
pub struct UpdateLabelsRequest {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Response body for label update
#[derive(Serialize)]
pub struct UpdateLabelsResponse {
    pub id: Uuid,
    pub labels: Vec<String>,
}

/// PATCH /api/v1/claims/:id/labels
///
/// Add and/or remove labels on an existing claim atomically.
/// Idempotent: adding a duplicate is a no-op, removing a nonexistent label is a no-op.
#[cfg(feature = "db")]
pub async fn update_labels(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateLabelsRequest>,
) -> Result<Json<UpdateLabelsResponse>, ApiError> {
    if body.add.is_empty() && body.remove.is_empty() {
        return Err(ApiError::BadRequest {
            message: "At least one of 'add' or 'remove' must be non-empty".to_string(),
        });
    }

    let labels = ClaimRepository::update_labels(&state.db_pool, id, &body.add, &body.remove)
        .await
        .map_err(|e| match e {
            epigraph_db::DbError::NotFound { .. } => ApiError::NotFound {
                entity: "Claim".to_string(),
                id: id.to_string(),
            },
            other => ApiError::DatabaseError {
                message: other.to_string(),
            },
        })?;

    Ok(Json(UpdateLabelsResponse { id, labels }))
}

/// Stub for non-db builds
#[cfg(not(feature = "db"))]
pub async fn update_labels(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(_body): Json<UpdateLabelsRequest>,
) -> Result<Json<UpdateLabelsResponse>, ApiError> {
    Ok(Json(UpdateLabelsResponse { id, labels: vec![] }))
}

/// Phase 1: Propose deletion of a claim. Requires `claims:delete` scope.
///
/// Creates a `proposed_deletion` challenge in pending state. The claim is NOT
/// deleted yet — a human must approve the challenge, then call
/// `POST /api/v1/claims/:id/confirm-delete` with the challenge ID.
///
/// Returns 202 Accepted with `{ "challenge_id": "..." }`.
#[cfg(feature = "db")]
pub async fn delete_claim(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // Require authentication with claims:delete scope
    match &auth_ctx {
        Some(axum::Extension(ref auth)) => {
            crate::middleware::scopes::check_scopes(auth, &["claims:delete"])?;
        }
        None => {
            return Err(ApiError::Unauthorized {
                reason: "DELETE /claims/:id requires authentication with claims:delete scope"
                    .to_string(),
            });
        }
    }

    // Verify claim exists
    let claim = ClaimRepository::get_by_id(&state.db_pool, ClaimId::from(id))
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: id.to_string(),
        })?;

    // Create a pending deletion challenge
    let challenge_id = Uuid::new_v4();
    let explanation = format!(
        "Proposed deletion of claim: {}",
        claim.content.chars().take(200).collect::<String>()
    );
    sqlx::query(
        "INSERT INTO challenges (id, claim_id, challenge_type, explanation, state) VALUES ($1, $2, 'proposed_deletion', $3, 'pending')"
    )
    .bind(challenge_id)
    .bind(id)
    .bind(&explanation)
    .execute(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create deletion challenge: {e}"),
    })?;

    tracing::info!(claim_id = %id, challenge_id = %challenge_id, "Deletion proposed — awaiting human approval");

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "challenge_id": challenge_id,
            "claim_id": id,
            "state": "pending",
            "message": "Deletion proposed. Approve the challenge, then call POST /api/v1/claims/:id/confirm-delete with {\"challenge_id\": \"...\"}"
        })),
    ))
}

#[derive(serde::Deserialize)]
pub struct ConfirmDeleteRequest {
    pub challenge_id: Uuid,
}

/// Phase 2: Execute a previously approved deletion. Requires `claims:delete` scope.
///
/// The challenge must exist, be of type `proposed_deletion`, and have state `approved`.
/// Only then is the claim actually deleted.
#[cfg(feature = "db")]
pub async fn confirm_delete_claim(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ConfirmDeleteRequest>,
) -> Result<StatusCode, ApiError> {
    // Require authentication with claims:delete scope
    match &auth_ctx {
        Some(axum::Extension(ref auth)) => {
            crate::middleware::scopes::check_scopes(auth, &["claims:delete"])?;
        }
        None => {
            return Err(ApiError::Unauthorized {
                reason: "confirm-delete requires authentication with claims:delete scope"
                    .to_string(),
            });
        }
    }

    // Verify the challenge exists, matches this claim, and is approved
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT challenge_type, state FROM challenges WHERE id = $1 AND claim_id = $2",
    )
    .bind(body.challenge_id)
    .bind(id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to query challenge: {e}"),
    })?;

    match row {
        None => {
            return Err(ApiError::NotFound {
                entity: "Challenge".to_string(),
                id: body.challenge_id.to_string(),
            });
        }
        Some((challenge_type, state_str)) => {
            if challenge_type != "proposed_deletion" {
                return Err(ApiError::BadRequest {
                    message: format!(
                        "Challenge {} is type '{}', not 'proposed_deletion'",
                        body.challenge_id, challenge_type
                    ),
                });
            }
            if state_str != "approved" {
                return Err(ApiError::Forbidden {
                    reason: format!(
                        "Challenge {} is '{}' — must be 'approved' before deletion can proceed",
                        body.challenge_id, state_str
                    ),
                });
            }
        }
    }

    // Approved — execute the deletion
    // Clean up edges referencing this claim (no FK cascade)
    sqlx::query(
        "DELETE FROM edges WHERE (source_id = $1 AND source_type = 'claim') OR (target_id = $1 AND target_type = 'claim')",
    )
    .bind(id)
    .execute(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to clean up edges: {e}"),
    })?;

    // Delete the challenge itself (FK to claims would block otherwise)
    sqlx::query("DELETE FROM challenges WHERE claim_id = $1")
        .bind(id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to clean up challenges: {e}"),
        })?;

    let deleted = ClaimRepository::delete(&state.db_pool, ClaimId::from(id)).await?;

    if !deleted {
        return Err(ApiError::NotFound {
            entity: "Claim".to_string(),
            id: id.to_string(),
        });
    }

    // Record provenance
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let content_hash = blake3::hash(id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "claim",
            id,
            "delete",
            content_hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(claim_id = %id, error = %e, "Failed to record claim delete provenance");
        }
    }

    tracing::info!(claim_id = %id, challenge_id = %body.challenge_id, "Claim deleted after human approval");
    Ok(StatusCode::NO_CONTENT)
}

/// Propose claim deletion (placeholder — no database)
#[cfg(not(feature = "db"))]
pub async fn delete_claim(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Claim deletion requires database".to_string(),
    })
}

/// Confirm claim deletion (placeholder — no database)
#[cfg(not(feature = "db"))]
pub async fn confirm_delete_claim(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_body): Json<ConfirmDeleteRequest>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Claim deletion requires database".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_response_from_claim() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let claim = Claim::new(
            "Test claim".to_string(),
            agent_id,
            public_key,
            TruthValue::new(0.75).unwrap(),
        );

        // Consume claim directly - no need to clone since we compare with local vars
        let response: ClaimResponse = claim.into();

        assert_eq!(response.content, "Test claim");
        assert_eq!(response.truth_value, 0.75);
        assert_eq!(response.agent_id, Uuid::from(agent_id));
        assert_eq!(response.trace_id, None);
    }

    #[test]
    fn test_pagination_params_defaults() {
        let json = "{}";
        let params: PaginationParams = serde_json::from_str(json).unwrap();

        assert_eq!(params.limit, DEFAULT_PAGE_LIMIT);
        assert_eq!(params.offset, 0);
    }

    #[test]
    fn test_pagination_params_custom() {
        let json = r#"{"limit": 50, "offset": 10}"#;
        let params: PaginationParams = serde_json::from_str(json).unwrap();

        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 10);
    }

    // ── update_labels HTTP-level tests ──

    #[test]
    fn test_update_labels_request_deserialize_add_only() {
        let json = r#"{"add": ["foo", "bar"]}"#;
        let req: UpdateLabelsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.add, vec!["foo", "bar"]);
        assert!(req.remove.is_empty());
    }

    #[test]
    fn test_update_labels_request_deserialize_remove_only() {
        let json = r#"{"remove": ["baz"]}"#;
        let req: UpdateLabelsRequest = serde_json::from_str(json).unwrap();
        assert!(req.add.is_empty());
        assert_eq!(req.remove, vec!["baz"]);
    }

    #[test]
    fn test_update_labels_request_deserialize_both() {
        let json = r#"{"add": ["new"], "remove": ["old"]}"#;
        let req: UpdateLabelsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.add, vec!["new"]);
        assert_eq!(req.remove, vec!["old"]);
    }

    #[test]
    fn test_update_labels_response_serialization() {
        let resp = UpdateLabelsResponse {
            id: Uuid::nil(),
            labels: vec!["a".into(), "b".into()],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["labels"], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn test_update_labels_request_empty_defaults() {
        let json = "{}";
        let req: UpdateLabelsRequest = serde_json::from_str(json).unwrap();
        assert!(req.add.is_empty());
        assert!(req.remove.is_empty());
    }

    #[test]
    fn test_claim_response_labels_omitted_when_empty() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let claim = Claim::new(
            "Labels test".to_string(),
            agent_id,
            public_key,
            TruthValue::new(0.5).unwrap(),
        );
        let response: ClaimResponse = claim.into();
        let json = serde_json::to_value(&response).unwrap();
        // labels field should be omitted when empty (skip_serializing_if)
        assert!(
            json.get("labels").is_none(),
            "labels should be omitted when empty"
        );
    }

    // ── PatchClaimRequest unit tests ──

    #[test]
    fn test_patch_request_truth_value_ignored() {
        // truth_value is read-only post-creation; the field is not in PatchClaimRequest.
        // Sending it in JSON is silently ignored (unknown fields are dropped by serde).
        let json = r#"{"truth_value": 0.8, "properties": {"x": 1}}"#;
        let req: PatchClaimRequest = serde_json::from_str(json).unwrap();
        assert!(req.properties.is_some(), "properties still parsed");
        assert!(req.trace_id.is_none());
        assert!(req.add_labels.is_none());
        assert!(req.remove_labels.is_none());
    }

    #[test]
    fn test_patch_request_deserialize_labels() {
        let json = r#"{"add_labels": ["foo"], "remove_labels": ["bar"]}"#;
        let req: PatchClaimRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.add_labels, Some(vec!["foo".to_string()]));
        assert_eq!(req.remove_labels, Some(vec!["bar".to_string()]));
    }

    #[test]
    fn test_patch_request_deserialize_properties() {
        let json = r#"{"properties": {"status": "done"}}"#;
        let req: PatchClaimRequest = serde_json::from_str(json).unwrap();
        let props = req.properties.unwrap();
        assert_eq!(props["status"], serde_json::json!("done"));
    }

    #[test]
    fn test_patch_request_is_empty_all_none() {
        let req = PatchClaimRequest {
            trace_id: None,
            properties: None,
            add_labels: None,
            remove_labels: None,
        };
        assert!(req.is_empty());
    }

    #[test]
    fn test_patch_request_not_empty_with_properties() {
        let req = PatchClaimRequest {
            trace_id: None,
            properties: Some(serde_json::json!({"k": "v"})),
            add_labels: None,
            remove_labels: None,
        };
        assert!(!req.is_empty());
    }

    #[test]
    fn test_patch_request_not_empty_with_add_labels() {
        let req = PatchClaimRequest {
            trace_id: None,
            properties: None,
            add_labels: Some(vec!["tag".to_string()]),
            remove_labels: None,
        };
        assert!(!req.is_empty());
    }

    #[test]
    fn test_patch_request_empty_with_only_empty_label_lists() {
        // Empty vecs in both lists with no other fields → nothing to patch
        let req = PatchClaimRequest {
            trace_id: None,
            properties: None,
            add_labels: Some(vec![]),
            remove_labels: Some(vec![]),
        };
        assert!(req.is_empty());
    }
}

#[cfg(all(test, feature = "db"))]
mod db_tests {
    use super::*;
    use crate::middleware::bearer::{AuthContext, ClientType};
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::patch;
    use axum::Extension;
    use axum::Router;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;
    use uuid::Uuid;

    async fn try_test_pool() -> Option<epigraph_db::PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .ok()?;
        // Run migrations so all tables exist before tests touch the DB.
        sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    macro_rules! test_pool_or_skip {
        () => {{
            match try_test_pool().await {
                Some(p) => p,
                None => {
                    eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                    return;
                }
            }
        }};
    }

    /// Insert a minimal agent + claim directly for test setup.
    async fn insert_test_claim(
        pool: &epigraph_db::PgPool,
        claim_id: Uuid,
        truth: f64,
        properties: serde_json::Value,
        labels: &[&str],
    ) {
        // Upsert agent (reuse claim_id as agent_id for simplicity; unique public_key via hash)
        sqlx::query(
            r#"INSERT INTO agents (id, public_key, created_at, updated_at)
               VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(claim_id)
        .execute(pool)
        .await
        .expect("upsert agent");

        // Insert claim
        let labels_arr: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
        sqlx::query(
            r#"INSERT INTO claims
               (id, content, agent_id, content_hash, truth_value, properties, labels, created_at, updated_at)
               VALUES ($1, $2, $3,
                       '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
                       $4, $5, $6, NOW(), NOW())
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(claim_id)
        .bind(format!("test claim {claim_id}"))
        .bind(claim_id)
        .bind(truth)
        .bind(&properties)
        .bind(&labels_arr)
        .execute(pool)
        .await
        .expect("insert claim");
    }

    /// Insert a real oauth_client row so provenance FK succeeds.
    async fn insert_oauth_client(pool: &epigraph_db::PgPool, client_id: Uuid) {
        sqlx::query(
            r#"INSERT INTO oauth_clients
               (id, client_id, client_name, client_type, allowed_scopes, granted_scopes, status, created_at, updated_at)
               VALUES ($1, $2, 'test-client', 'human',
                       ARRAY['claims:write'], ARRAY['claims:write'], 'active', NOW(), NOW())
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(client_id)
        .bind(client_id.to_string())
        .execute(pool)
        .await
        .expect("upsert oauth_client");
    }

    /// Build a test router with patch_claim + an injected AuthContext.
    fn test_router(state: AppState, auth: AuthContext) -> Router {
        Router::new()
            .route("/api/v1/claims/:id", patch(patch_claim))
            .layer(Extension(auth))
            .with_state(state)
    }

    /// Build a valid AuthContext for a given client_id.
    fn auth_ctx(client_id: Uuid) -> AuthContext {
        AuthContext {
            client_id,
            agent_id: Some(client_id),
            owner_id: Some(client_id),
            client_type: ClientType::Service,
            scopes: vec!["claims:write".to_string()],
            jti: Uuid::new_v4(),
        }
    }

    fn patch_request(claim_id: Uuid, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/claims/{claim_id}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap()
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 1: Properties are merged, not replaced
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_properties_merges() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;
        let claim_id = Uuid::new_v4();
        insert_test_claim(&pool, claim_id, 0.7, serde_json::json!({"a": 1}), &[]).await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(client_id));

        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({"properties": {"b": 2}}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify DB: both keys present
        let props: serde_json::Value =
            sqlx::query_scalar("SELECT properties FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(props["a"], serde_json::json!(1), "existing key preserved");
        assert_eq!(props["b"], serde_json::json!(2), "new key added");
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 2: Patch key overwrites, other keys preserved
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_properties_overwrites_key() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;
        let claim_id = Uuid::new_v4();
        insert_test_claim(
            &pool,
            claim_id,
            0.7,
            serde_json::json!({"status": "pending", "x": 99}),
            &[],
        )
        .await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(client_id));

        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({"properties": {"status": "done"}}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let props: serde_json::Value =
            sqlx::query_scalar("SELECT properties FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            props["status"],
            serde_json::json!("done"),
            "key overwritten"
        );
        assert_eq!(props["x"], serde_json::json!(99), "unrelated key preserved");
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 3: truth_value in body is ignored (field removed from PatchClaimRequest)
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_truth_value_ignored() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;
        let claim_id = Uuid::new_v4();
        insert_test_claim(&pool, claim_id, 0.5, serde_json::json!({}), &[]).await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(client_id));

        // Sending truth_value alongside a real patchable field: truth_value is silently dropped,
        // properties patch succeeds, truth_value in DB remains 0.5.
        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({
                    "truth_value": 0.9,
                    "properties": {"patched": true}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // truth_value must be unchanged
        let tv: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(
            (tv - 0.5).abs() < f64::EPSILON,
            "truth_value must not be patched directly"
        );

        // Provenance diff must only mention properties, not truth_value
        let payload: serde_json::Value = sqlx::query_scalar(
            "SELECT patch_payload FROM provenance_log WHERE record_id = $1 AND action = 'patch' ORDER BY created_at DESC LIMIT 1"
        )
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let arr = payload.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["field"], serde_json::json!("properties"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 4: Labels add/remove semantics
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_labels_add_remove() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;
        let claim_id = Uuid::new_v4();
        insert_test_claim(&pool, claim_id, 0.7, serde_json::json!({}), &["existing"]).await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(client_id));

        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({
                    "add_labels": ["new"],
                    "remove_labels": ["existing"]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(labels.contains(&"new".to_string()), "new label added");
        assert!(
            !labels.contains(&"existing".to_string()),
            "old label removed"
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 5: Multiple fields → diff has exactly N entries
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_multi_field_diff_entries() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;
        let claim_id = Uuid::new_v4();
        insert_test_claim(&pool, claim_id, 0.5, serde_json::json!({}), &[]).await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(client_id));

        // Patch two fields at once
        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({
                    "properties": {"tag": "x"},
                    "add_labels": ["multi-test"]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let payload: serde_json::Value = sqlx::query_scalar(
            "SELECT patch_payload FROM provenance_log WHERE record_id = $1 AND action = 'patch' ORDER BY created_at DESC LIMIT 1"
        )
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        // Two fields changed → two diff entries
        assert_eq!(payload.as_array().unwrap().len(), 2);
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 6: No-op patch still records provenance with empty diff
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_noop_still_records_provenance() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;
        let claim_id = Uuid::new_v4();
        insert_test_claim(&pool, claim_id, 0.7, serde_json::json!({"k": 1}), &[]).await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(client_id));

        // Patch properties with a value that is already set → no actual change
        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({
                    "properties": {"k": 1}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let payload: serde_json::Value = sqlx::query_scalar(
            "SELECT patch_payload FROM provenance_log WHERE record_id = $1 AND action = 'patch' ORDER BY created_at DESC LIMIT 1"
        )
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        // Value unchanged → diff is empty array, but row was written
        assert_eq!(payload.as_array().unwrap().len(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 7: Empty request → 400
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_empty_request_400() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;
        let claim_id = Uuid::new_v4();
        insert_test_claim(&pool, claim_id, 0.7, serde_json::json!({}), &[]).await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(client_id));

        let resp = router
            .oneshot(patch_request(claim_id, serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 8: No auth → 401
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_requires_auth_401() {
        let pool = test_pool_or_skip!();
        let claim_id = Uuid::new_v4();

        // Router WITHOUT injected AuthContext extension
        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = Router::new()
            .route("/api/v1/claims/:id", patch(patch_claim))
            .with_state(state);

        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({"properties": {"k": "v"}}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 9: Auth present but wrong scope → 403
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_missing_scope_403() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;
        let claim_id = Uuid::new_v4();
        insert_test_claim(&pool, claim_id, 0.7, serde_json::json!({}), &[]).await;

        // Auth is present but lacks claims:write
        let auth = AuthContext {
            client_id,
            agent_id: Some(client_id),
            owner_id: Some(client_id),
            client_type: ClientType::Service,
            scopes: vec!["claims:read".to_string()],
            jti: Uuid::new_v4(),
        };

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth);

        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({"properties": {"k": "v"}}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 10: truth_value in body is silently ignored; request with only truth_value → 400
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_truth_value_only_is_400() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;
        let claim_id = Uuid::new_v4();
        insert_test_claim(&pool, claim_id, 0.7, serde_json::json!({}), &[]).await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(client_id));

        // truth_value is an unknown field; after deserialization nothing to patch → 400
        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({"truth_value": 0.9}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 11: Unknown claim → 404
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_unknown_claim_404() {
        let pool = test_pool_or_skip!();
        let client_id = Uuid::new_v4();
        insert_oauth_client(&pool, client_id).await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(client_id));

        let resp = router
            .oneshot(patch_request(
                Uuid::new_v4(),
                serde_json::json!({"properties": {"x": 1}}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ────────────────────────────────────────────────────────────────────────
    // TEST 12: Provenance failure rolls back — claim unchanged, no prov row
    // ────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_patch_provenance_failure_rolls_back() {
        let pool = test_pool_or_skip!();
        // Use a client_id that does NOT exist in oauth_clients → provenance FK fails
        let bad_client_id = Uuid::new_v4(); // NOT inserted into oauth_clients
        let claim_id = Uuid::new_v4();
        insert_test_claim(
            &pool,
            claim_id,
            0.5,
            serde_json::json!({"original": true}),
            &[],
        )
        .await;

        let state = AppState::with_db(
            pool.clone(),
            ApiConfig {
                require_signatures: false,
                ..Default::default()
            },
        );
        let router = test_router(state, auth_ctx(bad_client_id));

        let resp = router
            .oneshot(patch_request(
                claim_id,
                serde_json::json!({"properties": {"mutated": true}}),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "provenance failure → 500"
        );

        // Claim must be unchanged (transaction rolled back)
        let props: serde_json::Value =
            sqlx::query_scalar("SELECT properties FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            props["original"],
            serde_json::json!(true),
            "properties rolled back"
        );
        assert!(
            props.get("mutated").is_none(),
            "mutation must not have committed"
        );

        // No provenance row must have been written
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM provenance_log WHERE record_id = $1 AND action = 'patch'",
        )
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0, "no provenance row committed");
    }
}
