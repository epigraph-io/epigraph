//! Bearer-token extraction for the MCP HTTP transport.
//!
//! Mirrors `epigraph-api`'s `bearer_auth_middleware`. The two share JWT
//! validation via `epigraph-auth` so a single token works against both
//! servers.
//!
//! ## Deferred: revocation
//!
//! The HTTP API consults `AppState::is_token_revoked` here. MCP has no
//! equivalent state and v1 relies on short JWT TTLs. When MCP grows shared
//! state, plumb the revocation set through and call it before
//! `validate_token`. Tracked separately — do not silently skip when adding
//! state.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::StatusCode;

use epigraph_auth::{AuthContext, JwtConfig};

#[derive(Clone)]
pub struct McpAuthState {
    pub jwt_config: Arc<JwtConfig>,
}

pub async fn bearer_auth_middleware(
    State(state): State<McpAuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match header.as_deref() {
        Some(h) if h.starts_with("Bearer ") => {
            let token = &h[7..];
            match state.jwt_config.validate_token(token) {
                Ok(claims) => {
                    let auth: AuthContext = claims.into();
                    req.extensions_mut().insert(auth);
                    next.run(req).await
                }
                Err(e) => (StatusCode::UNAUTHORIZED, format!("Invalid token: {e}")).into_response(),
            }
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            "Missing Authorization header".to_string(),
        )
            .into_response(),
    }
}
