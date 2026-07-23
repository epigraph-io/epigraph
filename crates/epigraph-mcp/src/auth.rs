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
use http::{header::WWW_AUTHENTICATE, HeaderValue, StatusCode};

use epigraph_auth::{AuthContext, JwtConfig};

/// RFC 6750 `error` code for a present-but-rejected (or absent) Bearer token.
/// Single source so both 401 arms emit the same value.
const INVALID_TOKEN: &str = "invalid_token";

/// The raw (still-encoded) Bearer token string, captured by
/// [`bearer_auth_middleware`] after successful validation and stashed in the
/// request extensions alongside [`AuthContext`].
///
/// The federation gateway needs the *verbatim* caller token to forward it to a
/// downstream extension MCP: rmcp's `StreamableHttpClientTransportConfig`
/// `auth_header` is set once at transport construction and there is no per-call
/// token slot, so the gateway builds a fresh transport per federated call using
/// this token. `AuthContext` alone is insufficient because it is the *decoded*
/// claims, not the signed string the downstream server will re-validate.
///
/// Present only on the HTTP path (stdio has no Bearer header); federated calls
/// over stdio therefore have no token to forward.
#[derive(Clone)]
pub struct RawBearerToken(pub String);

#[derive(Clone)]
pub struct McpAuthState {
    pub jwt_config: Arc<JwtConfig>,
    /// Absolute URL of the protected-resource metadata doc, advertised in 401s.
    pub resource_metadata_url: Option<String>,
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
                    // Stash the raw, still-signed token so the federation gateway
                    // can forward it verbatim to a downstream extension MCP.
                    req.extensions_mut()
                        .insert(RawBearerToken(token.to_string()));
                    next.run(req).await
                }
                Err(_) => unauthorized(state.resource_metadata_url.as_deref(), INVALID_TOKEN),
            }
        }
        _ => unauthorized(state.resource_metadata_url.as_deref(), INVALID_TOKEN),
    }
}

/// Build the RFC 9728 `WWW-Authenticate` challenge `HeaderValue`. Returns `None`
/// when the interpolated `resource_metadata_url` produces a value `HeaderValue`
/// rejects (control chars / non-ASCII). The single source of the challenge
/// format, shared by [`unauthorized`] (per-request) and
/// [`validate_resource_metadata_url`] (boot-time fail-fast) so the two cannot drift.
fn challenge_header(resource_metadata_url: Option<&str>, error: &str) -> Option<HeaderValue> {
    let challenge = match resource_metadata_url {
        Some(url) => format!("Bearer resource_metadata=\"{url}\", error=\"{error}\""),
        None => format!("Bearer error=\"{error}\""),
    };
    challenge.parse().ok()
}

/// Validate an operator-supplied `--resource-metadata-url` at startup by building
/// the challenge it would produce. A malformed URL (control chars / non-ASCII)
/// would otherwise make every 401 fail to attach the header; failing fast at boot
/// surfaces the misconfiguration before the listener accepts traffic.
pub fn validate_resource_metadata_url(resource_metadata_url: &str) -> Result<(), String> {
    challenge_header(Some(resource_metadata_url), INVALID_TOKEN)
        .map(|_| ())
        .ok_or_else(|| {
            "--resource-metadata-url is not a valid HTTP header value \
             (control characters or non-ASCII bytes?)"
                .to_string()
        })
}

/// Build a 401 with an RFC 9728 WWW-Authenticate challenge.
pub fn unauthorized(resource_metadata_url: Option<&str>, error: &str) -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    // The `Some` URL is validated at startup (`validate_resource_metadata_url`)
    // and the `None` branch is a static valid string, so the challenge is
    // expected to be a valid header value. If it somehow is not, drop the header
    // rather than panicking on every request.
    if let Some(value) = challenge_header(resource_metadata_url, error) {
        resp.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    resp
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn unauthorized_response_advertises_resource_metadata() {
        let url = "https://5-78-124-36.nip.io/.well-known/oauth-protected-resource";
        let resp = unauthorized(Some(url), "invalid_token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            www.contains(&format!("resource_metadata=\"{url}\"")),
            "got: {www}"
        );
        assert!(www.contains("error=\"invalid_token\""));
    }

    #[test]
    fn unauthorized_response_without_metadata_url_is_bare_challenge() {
        // The default production path (no --resource-metadata-url): the challenge
        // must be exactly `Bearer error="invalid_token"` with NO resource_metadata
        // parameter. This is what tests/http_auth_test.rs boots with.
        let resp = unauthorized(None, "invalid_token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(www, "Bearer error=\"invalid_token\"");
        assert!(!www.contains("resource_metadata"), "got: {www}");
    }
}
