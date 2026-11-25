#![allow(clippy::doc_markdown)]

pub mod auth;
pub mod background;
pub mod claim_helper;
pub mod elevated_access;
pub mod embed;
pub mod errors;
pub mod federation;
pub mod host_guard;
pub mod http_listener;
pub mod log_filter;
pub mod maintenance;
pub mod operator;
pub mod role_gate;
pub mod scope_map;
pub mod server;
pub mod session_status;
pub mod signing_identity;
pub mod stdio_transport;
pub mod tools;
pub mod types;
pub mod unauthenticated_reader;
pub mod write_identity;

pub use server::{EpiGraphMcpFull, SessionFactory};

use std::time::Duration;

/// Return all registered MCP tools as a JSON value.
///
/// Calls the static tool router (no database access) so callers don't need a
/// live server instance. Used by the REST discovery endpoint in epigraph-api.
#[must_use]
pub fn list_tools() -> serde_json::Value {
    EpiGraphMcpFull::all_tools_json()
}

/// The REST catalog's tools as `auth` may see them (elevation plan EL-11):
/// the static router minus `sudo`/`unsudo`, and minus every admin-only-scoped
/// tool the caller's scope gate would refuse (`AuthContext::has_scope`, with
/// the switch and the database-checked elevation already stamped by the
/// API's bearer and recorder layers).
///
/// `sudo`/`unsudo` are left out for EVERY caller: they act on an MCP
/// connection's own refresh family, the API process cannot see whether an
/// MCP listener serves connector mode, and leaving them out is the
/// fail-closed side of "listed only to role holders". The MCP manifest
/// (`EpiGraphMcpFull::manifest_for`) is where a holder sees them.
#[must_use]
pub fn catalog_for(auth: &epigraph_auth::AuthContext) -> serde_json::Value {
    let caller = tools::elevation::ManifestCaller {
        http: true,
        auth: Some(auth),
        holds_elevating_role: false,
        connector_elevation: false,
    };
    let tools: Vec<_> = EpiGraphMcpFull::static_tools()
        .into_iter()
        .filter(|t| tools::elevation::listed(t.name.as_ref(), &caller))
        .collect();
    serde_json::to_value(tools).unwrap_or(serde_json::Value::Array(vec![]))
}

/// Does this `--listen` spec name a Unix-domain socket rather than a TCP address?
///
/// The single discriminator between the two listener kinds, shared by
/// [`serve_with_listener`] (which binds accordingly), the startup auth gate in
/// `main.rs` (unauthenticated serving is permitted only for the unix case, whose
/// trust gate is filesystem permissions), and the router build (the Host/Origin
/// DNS-rebinding guard is attached only for the TCP case). Keeping one function
/// means those three decisions cannot drift apart.
///
/// Deliberately not `#[cfg(unix)]`-gated: on a non-unix target
/// [`serve_with_listener`] would fall through and attempt a TCP bind of a
/// `unix:`-prefixed string, which fails loudly — far better than a gate that
/// silently classifies the same string differently from the code that binds it.
#[must_use]
pub fn is_unix_listener(listen: &str) -> bool {
    listen.starts_with(UNIX_LISTEN_PREFIX)
}

/// The `--listen` prefix that selects a Unix-domain socket. One literal, so
/// [`is_unix_listener`] and [`serve_with_listener`] cannot disagree about what
/// counts as a unix listener.
pub const UNIX_LISTEN_PREFIX: &str = "unix:";

/// Serve `router` on the given `listen` spec, until the process is killed.
///
/// Accepts either a `host:port` TCP address or a `unix:/abs/path` Unix socket spec.
/// For Unix sockets, the file is removed if stale, then created with `0o660`
/// permissions (rw for owner+group, nothing for others), so only processes
/// with filesystem access can connect.
///
/// The router is passed in (rather than built here) because the production
/// router depends on a DB pool, signer, and embedder; tests can pass a trivial
/// `axum::Router::new()` to exercise only the listener-binding logic. The
/// production listener stops on a signal instead
/// ([`serve_with_listener_until`]).
///
/// # Errors
/// Returns the underlying I/O error from `bind`, `set_permissions`, or `axum::serve`.
pub async fn serve_with_listener(listen: &str, router: axum::Router) -> std::io::Result<()> {
    serve_with_listener_until(
        listen,
        router,
        std::future::pending::<()>(),
        GracefulShutdown::new(background::BackgroundTasks::default(), Duration::ZERO),
    )
    .await
}

/// How long, at most, a stopping HTTP listener waits for its open requests
/// before it ends the MCP sessions under them ([`serve_with_listener_until`]),
/// within the whole drain bound.
pub const HTTP_REQUEST_GRACE: Duration = Duration::from_secs(10);

/// How long, at most, a stopping HTTP listener waits for its connections to
/// close once it has ended the MCP sessions under them.
pub const HTTP_SESSION_END_GRACE: Duration = Duration::from_secs(5);

/// What a stopping HTTP listener does after its shutdown signal (backlog
/// 526f7508): wait for its open requests, end the MCP sessions still open,
/// then wait for the detached work its tools spawned, all within `drain` of
/// the signal.
pub struct GracefulShutdown {
    background: background::BackgroundTasks,
    drain: Duration,
    end_sessions: Option<Box<dyn FnOnce() + Send>>,
}

impl GracefulShutdown {
    /// Wait for `background` (the server template's tracker, which every
    /// session clone shares), and for everything else, at most `drain` from
    /// the signal ([`background::exit_drain_timeout`] in production).
    #[must_use]
    pub fn new(background: background::BackgroundTasks, drain: Duration) -> Self {
        Self {
            background,
            drain,
            end_sessions: None,
        }
    }

    /// Run `end` once open requests have had [`HTTP_REQUEST_GRACE`]: it ends
    /// the MCP sessions (rmcp's cancellation token,
    /// [`http_listener::McpHttpListener::end_sessions`]). Without it, one open
    /// SSE stream keeps the listener's graceful wait open for the whole drain.
    #[must_use]
    pub fn ending_sessions_with(mut self, end: impl FnOnce() + Send + 'static) -> Self {
        self.end_sessions = Some(Box::new(end));
        self
    }
}

/// Resolves when the process receives SIGTERM (systemd's stop) or SIGINT
/// (Ctrl-C), logging which. A signal whose handler cannot be installed is not
/// waited for (logged); the process then stops on the other, or by being
/// killed, as it did before this existed.
pub async fn shutdown_signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "cannot listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => tracing::info!("SIGINT received: stopping the MCP HTTP listener"),
        () = terminate => tracing::info!("SIGTERM received: stopping the MCP HTTP listener"),
    }
}

/// [`serve_with_listener`] until `shutdown` resolves, then stop gracefully
/// (backlog 526f7508): stop accepting connections, let open requests finish
/// for at most [`HTTP_REQUEST_GRACE`], end the MCP sessions still open, and
/// wait for the detached work the tools spawned (a queued ingest walk,
/// post-commit embedding, a recall audit row) until `plan`'s drain bound from
/// the signal, logging what is abandoned. Returning drops the runtime, which
/// cancels whatever is still running on it, so the wait is what lets that
/// work finish.
///
/// # Errors
/// Returns the underlying I/O error from `bind`, `set_permissions`, or `axum::serve`.
#[allow(clippy::missing_panics_doc)]
pub async fn serve_with_listener_until<F>(
    listen: &str,
    router: axum::Router,
    shutdown: F,
    plan: GracefulShutdown,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let (signalled_tx, signalled_rx) = tokio::sync::oneshot::channel::<()>();
    let graceful = async move {
        shutdown.await;
        let _ = signalled_tx.send(());
    };
    #[cfg(unix)]
    if let Some(path) = listen.strip_prefix(UNIX_LISTEN_PREFIX) {
        // Best-effort cleanup of a stale socket from a previous run.
        //
        // NOTE: AF_UNIX has no SO_REUSEADDR equivalent. If two MCP processes
        // start concurrently against the same path, the second's remove_file
        // unlinks the first's just-bound inode and the first listener is
        // silently orphaned. We rely on systemd (single-instance unit) to
        // ensure this race never fires in production.
        let _ = std::fs::remove_file(path);
        let listener = tokio::net::UnixListener::bind(path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        tracing::info!("EpiGraph MCP server listening on unix:{path} (HTTP path: /mcp)");
        let serve = std::future::IntoFuture::into_future(
            axum::serve(listener, router).with_graceful_shutdown(graceful),
        );
        return stop_gracefully(serve, signalled_rx, plan).await;
    }

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("EpiGraph MCP server listening on http://{listen}/mcp");
    let serve = std::future::IntoFuture::into_future(
        axum::serve(listener, router).with_graceful_shutdown(graceful),
    );
    stop_gracefully(serve, signalled_rx, plan).await
}

/// The part of [`serve_with_listener_until`] after the bind: `serve` is the
/// listener in graceful-shutdown mode, `signalled` fires with its signal.
async fn stop_gracefully(
    serve: impl std::future::Future<Output = std::io::Result<()>>,
    signalled: tokio::sync::oneshot::Receiver<()>,
    plan: GracefulShutdown,
) -> std::io::Result<()> {
    tokio::pin!(serve);
    // `biased`, signal first: the graceful future sends on `signalled` before
    // it lets `serve` finish, so once the signal came both are ready, and
    // taking `serve`'s result as "stopped without a signal" would skip the
    // drain below.
    tokio::select! {
        biased;
        _ = signalled => {}
        served = &mut serve => return served,
    }
    let GracefulShutdown {
        background,
        drain,
        end_sessions,
    } = plan;
    let deadline = tokio::time::Instant::now() + drain;
    let requests = std::cmp::min(tokio::time::Instant::now() + HTTP_REQUEST_GRACE, deadline);
    let served = match tokio::time::timeout_at(requests, &mut serve).await {
        Ok(served) => Some(served),
        Err(_) => {
            if let Some(end) = end_sessions {
                tracing::info!("ending the MCP sessions still open");
                end();
            }
            let sessions = std::cmp::min(
                tokio::time::Instant::now() + HTTP_SESSION_END_GRACE,
                deadline,
            );
            tokio::time::timeout_at(sessions, &mut serve).await.ok()
        }
    };
    match &served {
        Some(Ok(())) => tracing::info!("MCP HTTP listener stopped: no connection left open"),
        Some(Err(e)) => tracing::warn!(error = %e, "MCP HTTP listener stopped with an error"),
        None => tracing::warn!(
            "MCP HTTP listener stopping with connections still open; their requests are cut off"
        ),
    }
    let pending = background.active();
    if pending > 0 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        tracing::info!(
            pending,
            timeout_secs = left.as_secs(),
            "waiting for background work to finish before exiting"
        );
        if !background.wait_idle(left).await {
            tracing::warn!(
                unfinished = background.active(),
                timeout_secs = drain.as_secs(),
                "exiting with background work unfinished: a queued ingest may have written \
                 nothing, and committed claims may have no embedding until a backfill"
            );
        }
    }
    served.unwrap_or(Ok(()))
}
