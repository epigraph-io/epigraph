//! POST /oauth/revoke — Token revocation (RFC 7009).

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
            // Access tokens are JWTs — add to in-memory revocation set
            state.revoke_access_token(&req.token);
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
