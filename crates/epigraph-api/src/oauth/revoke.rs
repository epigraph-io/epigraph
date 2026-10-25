//! POST /oauth/revoke — Token revocation (RFC 7009).

// UNSCOPED-POOL-EXEMPT: Pre-authentication. RFC 7009 revocation authenticates the token being revoked
// rather than a session principal, and is reachable on the anonymous OAuth router. Two sites: the
// refresh-token definer (118) and the access-token denylist definer (141).

use axum::{
    body::Bytes,
    extract::State,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
};
use serde::Deserialize;

use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    /// "access_token" or "refresh_token". Advisory only (RFC 7009 section
    /// 2.1): the endpoint tries every token type whatever this says.
    pub token_type_hint: Option<String>,
}

/// RFC 7009 section 2.1 sends the request as
/// `application/x-www-form-urlencoded`; JSON is also accepted because deployed
/// clients send it. The same split as `token.rs::parse_token_request`, kept
/// separate because that one is `db`-only and this endpoint is not.
fn parse_revoke_request(headers: &HeaderMap, body: &[u8]) -> Result<RevokeRequest, ApiError> {
    let ct = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ct.starts_with("application/json") {
        serde_json::from_slice(body).map_err(|e| ApiError::BadRequest {
            message: format!("invalid JSON revocation request: {e}"),
        })
    } else {
        serde_urlencoded::from_bytes(body).map_err(|e| ApiError::BadRequest {
            message: format!("invalid form-encoded revocation request: {e}"),
        })
    }
}

pub async fn revoke_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let req = parse_revoke_request(&headers, &body)?;

    // `token_type_hint` is not consulted. RFC 7009 section 2.1: the server
    // "MAY ignore this parameter", and when the token is not found under the
    // hint it "MUST extend its search across all of its supported token
    // types". The two types cannot be confused: an access token is a JWT
    // (it contains '.'), a refresh token is hex. So the endpoint tries the
    // JWT verification first and the refresh-token lookup second, and an
    // unknown hint value is answered like any other (section 2.2: 200).

    // Access tokens are JWTs. This router is anonymous, so the token's
    // signature (and issuer and audience) is verified BEFORE anything is
    // written: a token this server did not sign is answered 200 and recorded
    // nowhere (RFC 7009 section 2.2), so no caller can fill the denylist with
    // chosen jtis.
    //
    // Expiry is NOT checked on this host's clock. A host running ahead of
    // another would otherwise answer a revoke that arrives just after `exp`
    // (by its clock) 200 and record nothing, while the lagging host keeps
    // admitting the token. The definer decides, with migration 141's 24-hour
    // margin on the database clock: it records a token less than a day past
    // `exp` and declines older.
    if let Ok(claims) = state.jwt_config.verify_for_revocation(&req.token) {
        #[cfg(feature = "db")]
        {
            use epigraph_db::RevokedAccessTokenRepository;
            let expires_at = chrono::DateTime::from_timestamp(claims.exp, 0).ok_or_else(|| {
                ApiError::BadRequest {
                    message: "Invalid token expiry".to_string(),
                }
            })?;
            // Durable and shared (migration 141): every API process and the
            // MCP transport read the same denylist. One definer call; the
            // application role holds no write on the table.
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
        // The non-db build has no revocation store: nothing is recorded, and
        // the token stays live until its `exp`. A known limitation, documented
        // on the non-db `middleware::bearer::access_token_is_revoked`.
        #[cfg(not(feature = "db"))]
        let _ = claims;
        return Ok(StatusCode::OK);
    }

    // Refresh tokens are hex. A token that is neither (or a JWT this server
    // did not sign, which is not hex either) is an invalid token: 200, and
    // nothing is looked up or written.
    if let Ok(raw) = hex::decode(&req.token) {
        #[cfg(feature = "db")]
        {
            use epigraph_db::repos::refresh_token::RefreshTokenRepository;
            let hash = blake3::hash(&raw);
            // Revoke if it exists; if not, that's fine (idempotent per RFC
            // 7009). One definer call (migration 118): the application role
            // cannot read `token_hash`, so the lookup by hash is inside it.
            RefreshTokenRepository::revoke_by_hash(&state.db_pool, hash.as_bytes())
                .await
                .map_err(|e| ApiError::InternalError {
                    message: e.to_string(),
                })?;
        }
        #[cfg(not(feature = "db"))]
        let _ = raw;
    }

    // RFC 7009: always return 200 OK regardless of whether the token existed
    Ok(StatusCode::OK)
}
