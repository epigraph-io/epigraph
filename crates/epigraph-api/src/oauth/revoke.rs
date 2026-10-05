//! POST /oauth/revoke — Token revocation (RFC 7009).

// UNSCOPED-POOL-EXEMPT: Pre-authentication. RFC 7009 revocation authenticates the token being revoked
// rather than a session principal, and is reachable on the anonymous OAuth router. Two sites: the
// refresh-token definer (118) and the access-token denylist definer (141).

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
                // Revoke if it exists; if not, that's fine (idempotent per RFC
                // 7009). One definer call (migration 118): the application role
                // cannot read `token_hash`, so the lookup by hash is inside it.
                RefreshTokenRepository::revoke_by_hash(&state.db_pool, hash.as_bytes())
                    .await
                    .map_err(|e| ApiError::InternalError {
                        message: e.to_string(),
                    })?;
            }
        }
        "access_token" => {
            // Access tokens are JWTs. This router is anonymous, so the token's
            // signature (and issuer and audience) is verified BEFORE anything
            // is written: a token this server did not sign is answered 200 and
            // recorded nowhere (RFC 7009 section 2.2), so no caller can fill
            // the denylist with chosen jtis.
            //
            // Expiry is NOT checked on this host's clock. A host running ahead
            // of another would otherwise answer a revoke that arrives just
            // after `exp` (by its clock) 200 and record nothing, while the
            // lagging host keeps admitting the token. The definer decides,
            // with migration 141's 24-hour margin on the database clock: it
            // records a token less than a day past `exp` and declines older.
            if let Ok(claims) = state.jwt_config.verify_for_revocation(&req.token) {
                #[cfg(feature = "db")]
                {
                    use epigraph_db::RevokedAccessTokenRepository;
                    let expires_at =
                        chrono::DateTime::from_timestamp(claims.exp, 0).ok_or_else(|| {
                            ApiError::BadRequest {
                                message: "Invalid token expiry".to_string(),
                            }
                        })?;
                    // Durable and shared (migration 141): every API process and
                    // the MCP transport read the same denylist. One definer call;
                    // the application role holds no write on the table.
                    RevokedAccessTokenRepository::revoke(
                        &state.db_pool,
                        claims.jti,
                        claims.sub,
                        expires_at,
                    )
                    .await
                    .map_err(|e| ApiError::InternalError {
                        message: e.to_string(),
                    })?;
                }
                // The non-db build has no revocation store: nothing is recorded,
                // and the token stays live until its `exp`. A known limitation,
                // documented on the non-db `middleware::bearer::access_token_is_revoked`.
                #[cfg(not(feature = "db"))]
                let _ = claims;
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
