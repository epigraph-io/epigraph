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

/// Static, non-secret label for why a Bearer token was rejected.
///
/// The wire response deliberately stays a uniform `invalid_token` (RFC 6750 —
/// the client must not be told *why*, or the 401 becomes an oracle). That
/// leaves the operator with nothing: an expired token, a wrong shared secret,
/// and a token minted for the HTTP API's audience all produced byte-identical
/// 401s and no log line. This restores the distinction server-side only.
///
/// Returns a fixed `&'static str` rather than the `Error`'s `Display`, so no
/// token-derived bytes can reach a log sink through this path.
fn rejection_reason(kind: &jsonwebtoken::errors::ErrorKind) -> &'static str {
    use jsonwebtoken::errors::ErrorKind as K;
    match kind {
        K::ExpiredSignature => "expired",
        K::InvalidSignature => "bad_signature",
        K::InvalidIssuer => "bad_issuer",
        K::InvalidAudience => "bad_audience",
        K::ImmatureSignature => "not_yet_valid",
        K::InvalidToken | K::Base64(_) | K::Json(_) | K::Utf8(_) => "malformed",
        _ => "other",
    }
}

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
                Err(e) => {
                    let reason = rejection_reason(e.kind());
                    // A bad signature means the caller is presenting a token
                    // this server did not mint — misconfiguration or probing,
                    // either way worth seeing at default log levels. Expiry is
                    // routine and stays at debug so it cannot drown the journal.
                    if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::InvalidSignature) {
                        tracing::warn!(reason, "MCP bearer token rejected");
                    } else {
                        tracing::debug!(reason, "MCP bearer token rejected");
                    }
                    unauthorized(state.resource_metadata_url.as_deref(), INVALID_TOKEN)
                }
            }
        }
        _ => {
            // Distinguishes "sent nothing" from "sent something invalid" — the
            // two were previously indistinguishable in the journal, and they
            // point at different misconfigurations.
            tracing::debug!(
                reason = "missing_or_non_bearer_header",
                "MCP request rejected"
            );
            unauthorized(state.resource_metadata_url.as_deref(), INVALID_TOKEN)
        }
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
///
/// # Tenancy (PR-09)
///
/// `agent_id` now carries `server_agent_id` — the server's own `agents.id` —
/// instead of `None`. Plan §4.12 assigns this change to PR-09, and it is
/// required for the flag to keep working now that
/// `tools::viewer::request_viewer` refuses an `AuthContext` with no agent
/// principal: with `None` here, every content tool on this listener would
/// return the "token carries no agent principal" error and the flag would be
/// misleading in a *new* way.
///
/// **Call it a widening, because it is one.** Before, `request_viewer` mapped
/// this context's nil `client_id` to `Viewer::resolve(pool, nil)` — an empty
/// group set, public rows only, fail-closed by accident. Now every holder of
/// this listener's credential (in production, one shared bearer token in front
/// of a unix socket) reads with the server agent's group set. On today's corpus
/// the two are identical, because migration 062 defaults `visibility` to
/// `'public'` and backfills nothing; the difference appears the moment PR-12's
/// backfill writes the first `'group'` row. Operators who do not want that
/// should not be running `--allow-unauthenticated-http`.
pub fn unauthenticated_context(server_agent_id: Option<uuid::Uuid>) -> AuthContext {
    let mut scopes: Vec<String> = crate::scope_map::SCOPE_MAP
        .iter()
        .map(|(_, scope)| (*scope).to_string())
        .collect();
    scopes.sort();
    scopes.dedup();
    AuthContext {
        client_id: uuid::Uuid::nil(),
        agent_id: server_agent_id,
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
pub async fn inject_unauthenticated_context(
    axum::extract::State(server_agent_id): axum::extract::State<Option<uuid::Uuid>>,
    mut req: Request,
    next: Next,
) -> Response {
    req.extensions_mut()
        .insert(unauthenticated_context(server_agent_id));
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

    // ── Rejection-reason classification (issue #367) ──

    /// Mint a token that is already expired, via a negative TTL.
    fn expired_token(secret: &[u8]) -> String {
        let cfg = JwtConfig::from_secret(secret);
        cfg.issue_access_token(
            uuid::Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "service",
            None,
            None,
            chrono::Duration::minutes(-5),
        )
        .unwrap()
        .0
    }

    fn valid_token(secret: &[u8]) -> String {
        let cfg = JwtConfig::from_secret(secret);
        cfg.issue_access_token(
            uuid::Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "service",
            None,
            None,
            chrono::Duration::minutes(5),
        )
        .unwrap()
        .0
    }

    const SECRET: &[u8] = b"this-secret-is-at-least-32-bytes-long!!";
    const WRONG_SECRET: &[u8] = b"a-completely-different-32-byte-key!!xx";

    #[test]
    fn expired_token_classifies_as_expired() {
        let cfg = JwtConfig::from_secret(SECRET);
        let err = cfg.validate_token(&expired_token(SECRET)).unwrap_err();
        assert_eq!(rejection_reason(err.kind()), "expired");
    }

    #[test]
    fn wrong_secret_classifies_as_bad_signature() {
        // The case that most needs to be visible: a caller presenting a token
        // this server did not mint. Previously indistinguishable from expiry.
        let cfg = JwtConfig::from_secret(SECRET);
        let err = cfg.validate_token(&valid_token(WRONG_SECRET)).unwrap_err();
        assert_eq!(rejection_reason(err.kind()), "bad_signature");
    }

    #[test]
    fn garbage_classifies_as_malformed() {
        let cfg = JwtConfig::from_secret(SECRET);
        let err = cfg.validate_token("not-a-jwt").unwrap_err();
        assert_eq!(rejection_reason(err.kind()), "malformed");
    }

    #[test]
    fn expiry_and_bad_signature_are_distinguishable() {
        // The whole point of #367: these two produce identical wire responses,
        // so if the classifier collapses them the operator is blind again.
        let cfg = JwtConfig::from_secret(SECRET);
        let expired = rejection_reason(
            cfg.validate_token(&expired_token(SECRET))
                .unwrap_err()
                .kind(),
        );
        let bad_sig = rejection_reason(
            cfg.validate_token(&valid_token(WRONG_SECRET))
                .unwrap_err()
                .kind(),
        );
        assert_ne!(expired, bad_sig);
    }

    #[test]
    fn reasons_never_contain_token_material() {
        // `rejection_reason` returns fixed &'static str, never the Error's
        // Display. Guards against someone "helpfully" switching to `{e}`, which
        // can echo decoded token fragments into logs.
        let cfg = JwtConfig::from_secret(SECRET);
        let token = valid_token(WRONG_SECRET);
        let reason = rejection_reason(cfg.validate_token(&token).unwrap_err().kind());
        assert!(!reason.contains(&token[..16]));
        assert!(reason.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}
