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
}

pub async fn introspect_endpoint(
    State(state): State<AppState>,
    Json(req): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, ApiError> {
    // Validate first: the revocation list is keyed on the verified jti. A
    // revoked token is inactive; a failed revocation lookup is a 503, because
    // answering `active: true` for a token that may be revoked is the one
    // wrong answer an introspection endpoint can give.
    match state.jwt_config.validate_token(&req.token) {
        Ok(claims) if state.is_access_token_revoked(&claims).await? => {
            Ok(Json(IntrospectResponse {
                active: false,
                sub: None,
                client_id: None,
                scope: None,
                exp: None,
                iat: None,
                token_type: None,
            }))
        }
        Ok(claims) => Ok(Json(IntrospectResponse {
            active: true,
            sub: Some(claims.sub.to_string()),
            client_id: Some(claims.sub.to_string()),
            scope: Some(claims.scopes.join(" ")),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            token_type: Some("Bearer".to_string()),
        })),
        Err(_) => Ok(Json(IntrospectResponse {
            active: false,
            sub: None,
            client_id: None,
            scope: None,
            exp: None,
            iat: None,
            token_type: None,
        })),
    }
}
