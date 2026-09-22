//! POST /oauth/revoke — Token revocation (RFC 7009).

// UNSCOPED-POOL-EXEMPT: Pre-authentication. RFC 7009 revocation authenticates the token being revoked
// rather than a session principal, and is reachable on the anonymous OAuth router.

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;

use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    /// "access_token" or "refresh_token"
    pub token_type_hint: Option<String>,
}

pub async fn revoke_endpoint(
    State(state): State<AppState>,
    Json(req): Json<RevokeRequest>,
) -> Result<StatusCode, ApiError> {
    let hint = req.token_type_hint.as_deref().unwrap_or("refresh_token");

    match hint {
        "refresh_token" => {
            let raw = hex::decode(&req.token).map_err(|_| ApiError::BadRequest {
                message: "Invalid token format".to_string(),
            })?;
            let hash = blake3::hash(&raw);

            #[cfg(feature = "db")]
            {
                use epigraph_db::repos::refresh_token::RefreshTokenRepository;
                // Revoke if it exists; if not, that's fine (idempotent per RFC 7009)
                if let Some(stored) =
                    RefreshTokenRepository::get_valid(&state.db_pool, hash.as_bytes())
                        .await
                        .map_err(|e| ApiError::InternalError {
                            message: e.to_string(),
                        })?
                {
                    RefreshTokenRepository::revoke(&state.db_pool, stored.id)
                        .await
                        .map_err(|e| ApiError::InternalError {
                            message: e.to_string(),
                        })?;
                }
            }
        }
        "access_token" => {
            // Access tokens are JWTs. Only one whose SIGNATURE VERIFIES is
            // recorded: this endpoint is anonymous, and recording unverified
            // input would let anyone grow the list without bound (the shared
            // one is a table). A token that fails validation, expired
            // included, is already rejected everywhere, so there is nothing
            // to revoke. That is a 200 no-op under RFC 7009 §2.2.
            //
            // The record lands in the shared `revoked_access_tokens` list when
            // this process has it, so MCP and every other API replica reject
            // the token too. If that write fails the answer is 503 (RFC 7009
            // §2.2.1), not a 200 claiming a revocation other processes never saw.
            if let Ok(claims) = state.jwt_config.validate_token(&req.token) {
                state.revoke_access_token(&claims).await?;
            }
        }
        _ => {
            return Err(ApiError::BadRequest {
                message: "token_type_hint must be 'access_token' or 'refresh_token'".to_string(),
            });
        }
    }

    // RFC 7009: always return 200 OK regardless of whether the token existed
    Ok(StatusCode::OK)
}
