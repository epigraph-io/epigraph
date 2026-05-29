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

/// Build an [`AuthContext`] that holds every scope the tool registry knows
/// about (derived from [`crate::scope_map::SCOPE_MAP`] so new scopes are
/// covered automatically).
///
/// Used ONLY on the `--allow-unauthenticated-http` path. There, the operator
/// has explicitly opted out of Bearer auth, so no real token is validated and
/// no `AuthContext` would otherwise be attached — which makes the per-tool
/// scope gate (`server::enforce_tool_scope`, applied to every HTTP call) reject
/// *everything* with "no auth context", rendering the flag misleading (backlog
/// bug `be2a3391`). Injecting this permissive context lets calls through, which
/// is exactly what the operator asked for.
pub fn unauthenticated_context() -> AuthContext {
    let mut scopes: Vec<String> = crate::scope_map::SCOPE_MAP
        .iter()
        .map(|(_, scope)| (*scope).to_string())
        .collect();
    scopes.sort();
    scopes.dedup();
    AuthContext {
        client_id: uuid::Uuid::nil(),
        agent_id: None,
        owner_id: None,
        client_type: epigraph_auth::ClientType::Service,
        scopes,
        jti: uuid::Uuid::nil(),
    }
}

/// Axum middleware for the `--allow-unauthenticated-http` listener: inject the
/// permissive [`unauthenticated_context`] into every request so the downstream
/// scope gate passes. Mirrors how [`bearer_auth_middleware`] inserts a
/// *validated* `AuthContext`, minus the validation. Attach this ONLY when the
/// operator passed `--allow-unauthenticated-http` (enforced in `main.rs`).
pub async fn inject_unauthenticated_context(mut req: Request, next: Next) -> Response {
    req.extensions_mut().insert(unauthenticated_context());
    next.run(req).await
}
