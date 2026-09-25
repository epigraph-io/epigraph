//! Spec-correct status codes for rmcp's streamable-HTTP session errors.
//!
//! ## Why this exists
//!
//! The workspace pins `rmcp = "0.15"` (Cargo.lock resolves 0.15.0). Its
//! `StreamableHttpService` answers the session-lifecycle error cases with
//! status codes that break client recovery:
//!
//! | rmcp 0.15.0 response | cause | spec (2025-03-26 streamable HTTP) |
//! |---|---|---|
//! | `401 Unauthorized: Session not found` | `Mcp-Session-Id` unknown to the session manager | 404 |
//! | `500 Encounter an error when get session: Session error: Session service terminated` (also `… create standalone stream …`) | the id is still registered but its worker has ended | 404 |
//! | `422 Unexpected message, expect initialize request` | non-initialize POST with no session id | 400 |
//!
//! Sessions live only in the in-memory `LocalSessionManager`, so EVERY client
//! holding a session id gets the first row after a server restart. An OAuth MCP
//! client (claude.ai, Claude Code) reads a 401 as "this credential is invalid":
//! it discards a perfectly good token and demands an interactive re-auth,
//! instead of doing what the spec requires on a 404 — re-initialize a new
//! session with the token it already holds. Agents therefore could not
//! reconnect after a restart.
//!
//! rmcp 0.17.0 fixed the first row upstream (unknown session → 404); the 500
//! and 422 rows are still present in rmcp 3.4.1. Until the bump, this layer
//! rewrites the three cases.
//!
//! ## What it touches
//!
//! Only responses produced by rmcp's session handling, identified by
//! [`rmcp_session_status_rewrite`] — the single discriminator. Our own
//! authentication 401s (`crate::auth::unauthorized`) are excluded twice over:
//!
//! 1. **Ordering.** [`nest_mcp_service`] applies this layer directly around
//!    the rmcp service, BEFORE `main.rs` adds the bearer-auth layer and the
//!    Host/Origin guard. It is therefore the innermost layer: a bearer 401 or a
//!    host-guard 403 short-circuits outside it and never passes through.
//! 2. **Discriminator.** A 401 is rewritten only if it carries no
//!    `WWW-Authenticate` header (every auth 401 does) and its body is exactly
//!    rmcp's literal.
//!
//! ## Streaming safety
//!
//! Bodies are buffered only when the status is 401/422/500 AND the body
//! reports an exact size no larger than [`MAX_INSPECTED_BODY`]. rmcp's error
//! responses are `Full` bodies with an exact size; an SSE stream is a 200 with
//! no exact size and is never buffered.

use axum::body::{Body, HttpBody};
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::StreamableHttpService;

/// The rmcp streamable-HTTP service type every MCP HTTP listener serves.
pub type McpHttpService = StreamableHttpService<crate::EpiGraphMcpFull, LocalSessionManager>;

/// Largest body this layer will buffer for inspection. rmcp's session error
/// bodies are well under 200 bytes; anything larger is not one of them.
pub const MAX_INSPECTED_BODY: u64 = 4096;

/// rmcp 0.15.0's body for an unknown `Mcp-Session-Id` (`tower.rs`, POST and GET).
pub const RMCP_SESSION_NOT_FOUND_BODY: &str = "Unauthorized: Session not found";

/// Prefix of rmcp 0.15.0's `internal_error_response` bodies.
pub const RMCP_INTERNAL_ERROR_PREFIX: &str = "Encounter an error when";

/// rmcp 0.15.0's body for a non-initialize POST that carries no session id.
pub const RMCP_EXPECT_INITIALIZE_BODY: &str = "Unexpected message, expect initialize request";

/// Would `status` ever be rewritten? Decides whether the body is buffered at
/// all, so it must stay in step with [`rmcp_session_status_rewrite`].
#[must_use]
pub fn is_candidate_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::UNAUTHORIZED
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::INTERNAL_SERVER_ERROR
    )
}

/// THE discriminator: given a response's status, headers and (buffered) body,
/// return the status it should carry instead, or `None` to leave it untouched.
///
/// - 401, no `WWW-Authenticate`, body exactly [`RMCP_SESSION_NOT_FOUND_BODY`] → 404
/// - 500, body starts with [`RMCP_INTERNAL_ERROR_PREFIX`] and contains
///   `Session service terminated` or `Session not found` → 404
/// - 422, body exactly [`RMCP_EXPECT_INITIALIZE_BODY`] → 400
///
/// Anything else — in particular every `crate::auth::unauthorized` 401, which
/// always carries a `WWW-Authenticate` challenge — returns `None`.
#[must_use]
pub fn rmcp_session_status_rewrite(
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> Option<StatusCode> {
    let body = std::str::from_utf8(body).ok()?;
    match status {
        StatusCode::UNAUTHORIZED
            if !headers.contains_key(axum::http::header::WWW_AUTHENTICATE)
                && body == RMCP_SESSION_NOT_FOUND_BODY =>
        {
            Some(StatusCode::NOT_FOUND)
        }
        StatusCode::INTERNAL_SERVER_ERROR
            if body.starts_with(RMCP_INTERNAL_ERROR_PREFIX)
                && (body.contains("Session service terminated")
                    || body.contains("Session not found")) =>
        {
            Some(StatusCode::NOT_FOUND)
        }
        StatusCode::UNPROCESSABLE_ENTITY if body == RMCP_EXPECT_INITIALIZE_BODY => {
            Some(StatusCode::BAD_REQUEST)
        }
        _ => None,
    }
}

/// Axum middleware applying [`rmcp_session_status_rewrite`]. The body text is
/// kept verbatim; only the status changes.
pub async fn rewrite_rmcp_session_status(req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    let status = response.status();
    if !is_candidate_status(status) {
        return response;
    }
    // Never buffer a body of unknown length (a stream) or a large one.
    match response.body().size_hint().exact() {
        Some(len) if len <= MAX_INSPECTED_BODY => {}
        _ => return response,
    }

    let (mut parts, body) = response.into_parts();
    let Ok(bytes) =
        axum::body::to_bytes(body, usize::try_from(MAX_INSPECTED_BODY).unwrap_or(4096)).await
    else {
        // Unreachable for an exact-size body under the limit; keep the status
        // rather than invent one.
        return Response::from_parts(parts, Body::empty());
    };

    if let Some(new_status) = rmcp_session_status_rewrite(status, &parts.headers, &bytes) {
        tracing::debug!(
            from = status.as_u16(),
            to = new_status.as_u16(),
            body = %String::from_utf8_lossy(&bytes),
            "rewrote rmcp session-handling status to the MCP-spec code"
        );
        parts.status = new_status;
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// Mount the rmcp streamable-HTTP `service` at `/mcp` with the session-status
/// rewrite as its INNERMOST layer.
///
/// Both `main.rs` and the tests build the listener through this function, so
/// the tests exercise the production composition. Callers add the bearer-auth
/// (or unauthenticated-context) layer and the Host/Origin guard on the returned
/// router; those wrap OUTSIDE this layer, so their responses never reach
/// [`rewrite_rmcp_session_status`].
///
/// The service is taken already built (not its session manager) so a test can
/// keep its own handle on the `LocalSessionManager` it passed in.
pub fn nest_mcp_service(service: McpHttpService) -> axum::Router {
    axum::Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn(rewrite_rmcp_session_status))
}
