//! Claim signature revocation endpoint.
//!
//! POST /api/v1/claims/:id/revoke-signature
//!
//! Sets a claim's `signature` and `signer_id` to NULL, preserving the prior
//! values in the `claim_signature_revocations` audit table (migration 098).
//!
//! # When to use this instead of supersede
//!
//! - **Supersede** (POST /api/v1/claims/:id/supersede) when the claim's
//!   semantic content is still what you want to assert today: creates a new,
//!   currently-signed claim and forwards graph connectivity to it.
//! - **Revoke signature** (this endpoint) when the claim's content is of
//!   unclear provenance, or when revoke-then-supersede is the chosen
//!   disposition and the caller wants the old claim to clearly verify as
//!   "unsigned" rather than "tampered."
//!
//! Re-signing drifted content would forge the original author's consent and
//! is NOT supported. The route is intentionally a hole that forces the
//! caller to either supersede or revoke — never re-sign.
//!
//! # Authorization
//!
//! Requires OAuth2 Bearer token with the `claims:revoke-signature` scope.
//! Legacy Ed25519 signature authentication is NOT accepted on this route —
//! the revoker's identity must be unambiguously extractable from an
//! AuthContext so the audit row's `revoked_by` column is meaningful.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;

/// Maximum length of the revocation reason in bytes.
/// Mirrors versioning::MAX_REASON_LENGTH to keep audit text bounded.
const MAX_REASON_LENGTH: usize = 32_768;

/// Request body for revoking a claim's signature.
#[derive(Debug, Deserialize)]
pub struct RevokeSignatureRequest {
    /// Free-text reason recorded in the audit row. Required.
    /// Examples:
    ///   - "content_hash_drift_from_uncaptured_content_rewrite"
    ///   - "superseded_by_<uuid>_content_of_unclear_provenance"
    ///   - "migration_attestation_<date>_attested_drifted_content"
    pub reason: String,

    /// If the revocation is part of a supersession workflow, the UUID of the
    /// superseding claim. The audit row carries this forward link; `None` for
    /// standalone revocations.
    #[serde(default)]
    pub superseded_by: Option<Uuid>,

    /// Optional fat-finger guard: the caller asserts the first N hex chars of
    /// the current signature it expects to revoke. If set and mismatched, the
    /// handler returns 409 Conflict without touching the row. Case-insensitive
    /// hex; length determines how many prefix bytes to compare.
    #[serde(default)]
    pub expected_signature_prefix: Option<String>,
}

/// Response returned after a successful revocation.
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeSignatureResponse {
    /// The claim whose signature was revoked.
    pub claim_id: Uuid,
    /// UUID of the newly-inserted row in claim_signature_revocations.
    pub revocation_id: Uuid,
    /// The signer_id that was cleared (None if the prior signer had been
    /// deleted and the FK was already NULL).
    pub previous_signer_id: Option<Uuid>,
    /// When the revocation was recorded (DB NOW()).
    pub revoked_at: DateTime<Utc>,
}

/// Error body returned when a claim is already revoked (409 Conflict).
/// Names the most recent revocation so the caller can correlate.
#[derive(Debug, Serialize)]
struct AlreadyRevokedDetail {
    revocation_id: Uuid,
    revoked_by: Uuid,
    revoked_at: DateTime<Utc>,
}

/// Parse the optional `expected_signature_prefix` field into raw bytes.
///
/// Accepts None, empty, or a hex string optionally prefixed with `0x`.
/// Rejects odd-length hex, prefixes longer than the 64-byte signature
/// they would guard, and invalid hex characters.
///
/// Pulled out of the handler so it can be unit-tested without a DB.
fn parse_expected_signature_prefix(input: Option<&str>) -> Result<Option<Vec<u8>>, ApiError> {
    let Some(s) = input else { return Ok(None) };
    if s.is_empty() {
        return Ok(None);
    }
    let cleaned = s.trim().trim_start_matches("0x").to_ascii_lowercase();
    if cleaned.len() % 2 != 0 {
        return Err(ApiError::ValidationError {
            field: "expected_signature_prefix".to_string(),
            reason: "hex prefix must have an even number of characters".to_string(),
        });
    }
    if cleaned.len() > 128 {
        return Err(ApiError::ValidationError {
            field: "expected_signature_prefix".to_string(),
            reason: "hex prefix is longer than the 64-byte signature it would guard".to_string(),
        });
    }
    Ok(Some(hex::decode(&cleaned).map_err(|e| {
        ApiError::ValidationError {
            field: "expected_signature_prefix".to_string(),
            reason: format!("invalid hex: {e}"),
        }
    })?))
}

/// Revoke the signature on a claim.
///
/// POST /api/v1/claims/:id/revoke-signature
///
/// # Behavior
///
/// 1. Verifies Bearer-token AuthContext has the `claims:revoke-signature` scope.
/// 2. Validates request: non-empty reason (≤32 KiB), optional prefix guard,
///    optional superseded_by UUID (must reference an existing claim).
/// 3. In a single DB transaction:
///    a. SELECT the claim's current (signature, signer_id, content_hash).
///       Returns 404 if the claim doesn't exist.
///       Returns 409 with prior-revocation reference if signature is already NULL.
///    b. If `expected_signature_prefix` is set, checks it against the stored
///       signature's hex. Returns 409 on mismatch.
///    c. If `superseded_by` is set, verifies the target claim exists.
///       Returns 400 if it doesn't.
///    d. INSERTs a row into claim_signature_revocations with the preserved
///       signature, signer_id, content_hash, reason, and the caller's agent_id
///       as revoked_by.
///    e. UPDATEs the claim to set signature = NULL AND signer_id = NULL
///       (satisfies the migration 073 CHECK constraint).
///
/// # Errors
///
/// - 401 Unauthorized: no Bearer AuthContext (legacy Ed25519 is rejected here).
/// - 403 Forbidden: AuthContext present but missing `claims:revoke-signature` scope.
/// - 400 Bad Request: validation failure, or superseded_by references a missing claim.
/// - 404 Not Found: claim_id doesn't exist.
/// - 409 Conflict: claim is already revoked, or expected_signature_prefix mismatch.
#[cfg(feature = "db")]
pub async fn revoke_claim_signature(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(claim_id): Path<Uuid>,
    Json(request): Json<RevokeSignatureRequest>,
) -> Result<(StatusCode, Json<RevokeSignatureResponse>), ApiError> {
    // ---- Auth: bearer-only; legacy Ed25519 is not accepted here. ----
    let axum::Extension(ref auth) = auth_ctx.ok_or(ApiError::Unauthorized {
        reason: "claims:revoke-signature requires a Bearer token (AuthContext \
                 with agent_id); legacy Ed25519 auth is not accepted on this route"
            .to_string(),
    })?;
    crate::middleware::scopes::check_scopes(auth, &["claims:revoke-signature"])?;

    let revoker_agent_id = auth.agent_id.ok_or(ApiError::Forbidden {
        reason: "revoke-signature requires an AuthContext with a bound agent_id; \
                 service-only tokens without agent binding cannot be recorded as \
                 the revoker"
            .to_string(),
    })?;

    // ---- Request validation. ----
    let reason = request.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::ValidationError {
            field: "reason".to_string(),
            reason: "reason cannot be empty".to_string(),
        });
    }
    if request.reason.len() > MAX_REASON_LENGTH {
        return Err(ApiError::ValidationError {
            field: "reason".to_string(),
            reason: format!(
                "reason too long: {} bytes, maximum is {}",
                request.reason.len(),
                MAX_REASON_LENGTH
            ),
        });
    }

    // Parse expected_signature_prefix early so we don't start a transaction
    // just to reject malformed hex.
    let expected_prefix_bytes: Option<Vec<u8>> =
        parse_expected_signature_prefix(request.expected_signature_prefix.as_deref())?;

    // ---- DB transaction. ----
    let mut tx = state
        .db_pool
        .begin()
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("transaction begin failed: {e}"),
        })?;

    // Fetch current signature state.
    let row: Option<(Option<Vec<u8>>, Option<Uuid>, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT signature, signer_id, content_hash FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("claim lookup failed: {e}"),
            })?;

    let (current_signature, current_signer_id, current_content_hash) =
        row.ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        })?;

    // Already revoked? Surface the prior revocation for correlation.
    let Some(current_signature) = current_signature else {
        let prior: Option<(Uuid, Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, revoked_by, revoked_at FROM claim_signature_revocations \
             WHERE claim_id = $1 ORDER BY revoked_at DESC LIMIT 1",
        )
        .bind(claim_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("prior revocation lookup failed: {e}"),
        })?;

        let detail = match prior {
            Some((id, by, at)) => serde_json::to_value(AlreadyRevokedDetail {
                revocation_id: id,
                revoked_by: by,
                revoked_at: at,
            })
            .ok()
            .map(|v| format!(" (prior: {v})"))
            .unwrap_or_default(),
            None => String::new(),
        };
        return Err(ApiError::BadRequest {
            message: format!(
                "claim {claim_id} has no active signature to revoke (signature IS NULL){detail}"
            ),
        });
    };

    // Signature is NOT NULL, so migration 073's CHECK guarantees signer_id is
    // NOT NULL and the byte length is 64. Content_hash is also stored. Assert
    // defensively to surface any future schema drift loudly.
    let current_signer_id = current_signer_id.ok_or_else(|| ApiError::IntegrityError {
        field: "signer_id".to_string(),
        expected: "NOT NULL when signature is NOT NULL (migration 073 CHECK)".to_string(),
        actual: "NULL".to_string(),
    })?;
    let current_content_hash = current_content_hash.ok_or_else(|| ApiError::IntegrityError {
        field: "content_hash".to_string(),
        expected: "NOT NULL on any signed claim".to_string(),
        actual: "NULL".to_string(),
    })?;

    // Prefix guard (optional): reject fat-finger UUID mistakes.
    if let Some(expected) = &expected_prefix_bytes {
        if !current_signature.starts_with(expected) {
            return Err(ApiError::BadRequest {
                message: format!(
                    "expected_signature_prefix mismatch: supplied prefix does not \
                     match the current signature of claim {claim_id}"
                ),
            });
        }
    }

    // If superseded_by is set, verify the target claim exists.
    if let Some(sup_by) = request.superseded_by {
        let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM claims WHERE id = $1")
            .bind(sup_by)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("superseded_by lookup failed: {e}"),
            })?;
        if exists.is_none() {
            return Err(ApiError::BadRequest {
                message: format!("superseded_by claim {sup_by} does not exist"),
            });
        }
    }

    // Insert the audit row.
    let revocation_id: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_signature_revocations \
            (claim_id, previous_signature, previous_signer_id, previous_content_hash, \
             revoked_by, reason, superseded_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id",
    )
    .bind(claim_id)
    .bind(&current_signature)
    .bind(current_signer_id)
    .bind(&current_content_hash)
    .bind(revoker_agent_id)
    .bind(reason)
    .bind(request.superseded_by)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: format!("revocation audit insert failed: {e}"),
    })?;

    // Null the signature + signer_id. The migration 073 CHECK requires both
    // change together; doing both in one UPDATE keeps the constraint satisfied.
    let affected = sqlx::query(
        "UPDATE claims SET signature = NULL, signer_id = NULL, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(claim_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: format!("claim signature clear failed: {e}"),
    })?
    .rows_affected();

    if affected != 1 {
        return Err(ApiError::DatabaseError {
            message: format!(
                "expected to null exactly 1 claim signature, affected {affected} rows"
            ),
        });
    }

    // Fetch revoked_at from the just-inserted row so the response is authoritative.
    let revoked_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT revoked_at FROM claim_signature_revocations WHERE id = $1")
            .bind(revocation_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("revoked_at fetch failed: {e}"),
            })?;

    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("transaction commit failed: {e}"),
    })?;

    tracing::info!(
        claim_id = %claim_id,
        revocation_id = %revocation_id,
        revoked_by = %revoker_agent_id,
        previous_signer_id = %current_signer_id,
        superseded_by = ?request.superseded_by,
        reason = %reason,
        "claim signature revoked",
    );

    Ok((
        StatusCode::OK,
        Json(RevokeSignatureResponse {
            claim_id,
            revocation_id,
            previous_signer_id: Some(current_signer_id),
            revoked_at,
        }),
    ))
}

/// Stub for builds without the `db` feature. Always returns 503.
#[cfg(not(feature = "db"))]
pub async fn revoke_claim_signature(
    State(_state): State<AppState>,
    Path(_claim_id): Path<Uuid>,
    Json(_request): Json<RevokeSignatureRequest>,
) -> Result<(StatusCode, Json<RevokeSignatureResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Signature revocation requires database".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_expected_signature_prefix ----

    #[test]
    fn prefix_none_returns_none() {
        let out = parse_expected_signature_prefix(None).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn prefix_empty_string_returns_none() {
        let out = parse_expected_signature_prefix(Some("")).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn prefix_accepts_lowercase_hex() {
        let out = parse_expected_signature_prefix(Some("deadbeef"))
            .unwrap()
            .unwrap();
        assert_eq!(out, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn prefix_accepts_uppercase_hex() {
        let out = parse_expected_signature_prefix(Some("DEADBEEF"))
            .unwrap()
            .unwrap();
        assert_eq!(out, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn prefix_strips_0x_prefix() {
        let out = parse_expected_signature_prefix(Some("0xdeadbeef"))
            .unwrap()
            .unwrap();
        assert_eq!(out, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn prefix_trims_whitespace() {
        let out = parse_expected_signature_prefix(Some("  deadbeef  "))
            .unwrap()
            .unwrap();
        assert_eq!(out, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn prefix_rejects_odd_length() {
        let err = parse_expected_signature_prefix(Some("abc")).unwrap_err();
        match err {
            ApiError::ValidationError { field, reason } => {
                assert_eq!(field, "expected_signature_prefix");
                assert!(reason.contains("even number"), "got: {reason}");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn prefix_rejects_too_long() {
        // 130 hex chars = longer than a 64-byte (128-hex-char) signature.
        // Must be even so we hit the length check rather than the odd-length
        // check that would otherwise short-circuit.
        let long = "a".repeat(130);
        let err = parse_expected_signature_prefix(Some(&long)).unwrap_err();
        match err {
            ApiError::ValidationError { field, reason } => {
                assert_eq!(field, "expected_signature_prefix");
                assert!(
                    reason.contains("longer than the 64-byte signature"),
                    "got: {reason}"
                );
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn prefix_accepts_full_64_byte_signature() {
        // 128 hex chars = exactly one 64-byte signature, should pass.
        let full = "a".repeat(128);
        let out = parse_expected_signature_prefix(Some(&full))
            .unwrap()
            .unwrap();
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn prefix_rejects_invalid_hex_chars() {
        let err = parse_expected_signature_prefix(Some("gggg")).unwrap_err();
        match err {
            ApiError::ValidationError { field, reason } => {
                assert_eq!(field, "expected_signature_prefix");
                assert!(reason.contains("invalid hex"), "got: {reason}");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    // ---- DTO serde roundtrip ----

    #[test]
    fn request_deserializes_minimal() {
        let req: RevokeSignatureRequest = serde_json::from_value(serde_json::json!({
            "reason": "hash drift",
        }))
        .unwrap();
        assert_eq!(req.reason, "hash drift");
        assert!(req.superseded_by.is_none());
        assert!(req.expected_signature_prefix.is_none());
    }

    #[test]
    fn request_deserializes_full() {
        let sup_by = Uuid::new_v4();
        let req: RevokeSignatureRequest = serde_json::from_value(serde_json::json!({
            "reason": "superseded",
            "superseded_by": sup_by.to_string(),
            "expected_signature_prefix": "0xdead",
        }))
        .unwrap();
        assert_eq!(req.reason, "superseded");
        assert_eq!(req.superseded_by, Some(sup_by));
        assert_eq!(req.expected_signature_prefix.as_deref(), Some("0xdead"));
    }

    #[test]
    fn response_serializes_roundtrip() {
        let resp = RevokeSignatureResponse {
            claim_id: Uuid::new_v4(),
            revocation_id: Uuid::new_v4(),
            previous_signer_id: Some(Uuid::new_v4()),
            revoked_at: Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("claim_id").is_some());
        assert!(json.get("revocation_id").is_some());
        assert!(json.get("previous_signer_id").is_some());
        assert!(json.get("revoked_at").is_some());
        let back: RevokeSignatureResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.claim_id, resp.claim_id);
        assert_eq!(back.revocation_id, resp.revocation_id);
        assert_eq!(back.previous_signer_id, resp.previous_signer_id);
    }

    // ---- Non-db stub returns 503 ----

    #[cfg(not(feature = "db"))]
    mod stub {
        use super::*;
        use crate::state::{ApiConfig, AppState};

        #[tokio::test]
        async fn stub_returns_service_unavailable() {
            let state = AppState::new(ApiConfig::default());
            let claim_id = Uuid::new_v4();
            let req = RevokeSignatureRequest {
                reason: "test".to_string(),
                superseded_by: None,
                expected_signature_prefix: None,
            };
            let err = revoke_claim_signature(
                axum::extract::State(state),
                axum::extract::Path(claim_id),
                axum::Json(req),
            )
            .await
            .unwrap_err();
            assert!(matches!(err, ApiError::ServiceUnavailable { .. }));
        }
    }
}
