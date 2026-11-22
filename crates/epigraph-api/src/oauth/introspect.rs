//! POST /oauth/introspect — Token introspection (RFC 7662).

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// The token's `fam` claim (its refresh family), when it carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fam: Option<String>,
}

/// The RFC 7662 answer for a token that is not active (invalid, expired or
/// revoked). Says nothing else about it.
fn inactive() -> IntrospectResponse {
    IntrospectResponse {
        active: false,
        sub: None,
        client_id: None,
        scope: None,
        exp: None,
        iat: None,
        token_type: None,
        fam: None,
    }
}

pub async fn introspect_endpoint(
    State(state): State<AppState>,
    Json(req): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, ApiError> {
    // Validate as a JWT first, so only a verified jti reaches the revocation
    // lookup.
    let Ok(claims) = state.jwt_config.validate_token(&req.token) else {
        return Ok(Json(inactive()));
    };

    // Revoked through /oauth/revoke (migration 141's durable denylist):
    // inactive. A lookup that cannot answer is a 503, never `active: true`.
    let revoked = crate::middleware::bearer::access_token_is_revoked(&state, claims.jti)
        .await
        .map_err(|e| {
            tracing::error!(
                reason = "revocation_unavailable",
                error = %e,
                "introspection refused: the revocation lookup failed"
            );
            ApiError::ServiceUnavailable {
                service: "token revocation".to_string(),
            }
        })?;
    if revoked {
        return Ok(Json(inactive()));
    }

    // A DELEGATED run token (`dlg`) is active only while its delegation is
    // live (backlog 8d6c886f): the scope ceiling, a named principal, and the
    // live-delegation read (operator link acting, delegator's allowance,
    // client and writer membership live, `EPIGRAPH_RUN_TOKENS=on`). The SAME
    // check the bearer middleware runs on every request that carries one, so
    // introspection never answers `active: true` for a token the API refuses.
    // A check that cannot answer is a 503, never `active: true`.
    if claims.dlg.is_some() {
        let auth: epigraph_auth::AuthContext = claims.clone().into();
        let mut scratch = axum::http::Extensions::new();
        match crate::middleware::bearer::admit_delegated(
            &state,
            &auth,
            &mut scratch,
            "/oauth/introspect",
        )
        .await
        {
            Ok(()) => {}
            Err(e @ ApiError::ServiceUnavailable { .. }) => return Err(e),
            Err(_) => return Ok(Json(inactive())),
        }
    }

    Ok(Json(IntrospectResponse {
        active: true,
        sub: Some(claims.sub.to_string()),
        client_id: Some(claims.sub.to_string()),
        scope: Some(claims.scopes.join(" ")),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        token_type: Some("Bearer".to_string()),
        fam: claims.fam.map(|f| f.to_string()),
    }))
}
