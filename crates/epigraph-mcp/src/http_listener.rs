//! The rmcp streamable-HTTP service behind an MCP HTTP listener, built in one
//! place.
//!
//! `main.rs` serves `--listen` through [`mcp_http_listener`], and the HTTP
//! test suites build their listeners through it too. That keeps three
//! choices that must agree in one function instead of copied into each
//! caller:
//!
//! - which rmcp service config the listener kind gets
//!   ([`crate::host_guard::streamable_http_server_config`]: the TCP allowlist
//!   for a TCP address, no in-service Host check for a unix socket);
//! - the [`HostAllowlist`] that `main.rs` then installs as the outer guard
//!   layer, which is the same value the rmcp config was built from;
//! - the session manager and its [`SessionConfig`](rmcp::transport::streamable_http_server::session::local::SessionConfig).
//!
//! The auth layer (Bearer or the unauthenticated principal) and the outer
//! Host/Origin guard stay in `main.rs`: they depend on the CLI's auth mode and
//! on the database, which the listener's transport configuration does not.

use std::sync::Arc;

use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::StreamableHttpService;

use crate::host_guard::{streamable_http_server_config, HostAllowlist};

/// How long an MCP HTTP session may go without a session event before rmcp
/// ends it.
///
/// rmcp's default (2.x and 3.x) is 5 minutes (rmcp 0.15 had no timer at all). The timer
/// is NOT an idle-client timer: rmcp's session worker re-arms it only on an
/// inbound HTTP event or a message from the handler, and an in-flight tool
/// call produces neither until it returns. Under the default, any single tool
/// call that runs past 5 minutes without progress notifications ends its own
/// session and the client never receives the result. This server has such
/// calls (`backfill_embeddings` over thousands of claims,
/// `sweep_semantic_duplicates`, `recompute_beliefs`, federated calls waiting
/// on a downstream) and no tool-level timeout.
///
/// One hour outlasts those calls while keeping a bound on abandoned sessions
/// (a client whose connection dropped without a `DELETE`). Sessions can only
/// be created through the auth layer, so a longer bound does not let an
/// unauthenticated caller grow the session table; the separate `init_timeout`
/// (rmcp's default, 60 s) still bounds sessions that never initialize.
pub const SESSION_KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// The largest MCP HTTP request body the listener reads: 4 MiB, rmcp 3.x's
/// default, set explicitly in
/// [`crate::host_guard::streamable_http_server_config`].
///
/// rmcp 2.2 read a body of any size; 3.x reads at most
/// `max_request_body_bytes` and answers a larger one with
/// `413 Payload Too Large` before parsing it. That is an explicit refusal the
/// client sees, unlike the stdio framing's silent drop (see
/// [`crate::stdio_transport`]), so the cap is kept. It bounds the memory one
/// request can pin. On a `--jwt-secret` listener (every TCP listener) it sits
/// inside the bearer layer, so only an authenticated caller reaches it. A
/// unix-socket listener started with `--allow-unauthenticated-http` has no
/// bearer layer; there the socket's filesystem permissions stand in front of
/// it, and the cap applies the same way. 4 MiB is far above what a
/// model-generated tool call carries (a claim's content is capped at 64 KiB).
/// A client that needs a larger single call, such as a very large
/// `ingest_document_inline`, can use stdio, which has no cap. Raising it is a one-line change here, pinned by
/// `tests/http_auth_test.rs`
/// (`request_body_over_4_mib_is_refused_with_413_and_at_the_cap_is_served`).
pub const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The session manager every MCP HTTP listener uses: rmcp's defaults, except
/// `keep_alive` = [`SESSION_KEEP_ALIVE`].
#[must_use]
pub fn session_manager() -> LocalSessionManager {
    let mut manager = LocalSessionManager::default();
    manager.session_config.keep_alive = Some(SESSION_KEEP_ALIVE);
    manager
}

/// What [`mcp_http_listener`] builds for one `--listen` address.
pub struct McpHttpListener<S> {
    /// The rmcp service, ready to mount with
    /// [`crate::session_status::nest_mcp_service`].
    pub service: StreamableHttpService<S, LocalSessionManager>,
    /// The session manager inside `service`, so a caller (in practice a test)
    /// can inspect or plant sessions.
    pub sessions: Arc<LocalSessionManager>,
    /// The TCP listener's Host/Origin allowlist, or `None` for a unix socket.
    /// `main.rs` installs it as the outer guard layer; the rmcp config inside
    /// `service` was built from this same value.
    pub tcp_allowlist: Option<HostAllowlist>,
}

/// Build the rmcp streamable-HTTP service for the `--listen` address `listen`,
/// with the operator's `--allowed-host` entries `allowed_hosts`.
///
/// `factory` runs once per MCP session and returns that session's handler. On
/// rmcp 3.x's stateless 2026-07-28 path there is no session, and it runs once
/// per REQUEST, so anything a handler memoizes for speed belongs in state the
/// factory shares (see [`crate::SessionFactory`]).
#[must_use]
pub fn mcp_http_listener<S, F>(
    listen: &str,
    allowed_hosts: &[String],
    factory: F,
) -> McpHttpListener<S>
where
    S: rmcp::ServerHandler + Send + 'static,
    F: Fn() -> Result<S, std::io::Error> + Send + Sync + 'static,
{
    let tcp_allowlist = (!crate::is_unix_listener(listen))
        .then(|| HostAllowlist::for_tcp_listener(listen, allowed_hosts));
    let sessions = Arc::new(session_manager());
    let service = StreamableHttpService::new(
        factory,
        sessions.clone(),
        streamable_http_server_config(tcp_allowlist.as_ref()),
    );
    McpHttpListener {
        service,
        sessions,
        tcp_allowlist,
    }
}
