#![allow(clippy::doc_markdown)]

pub mod auth;
pub mod claim_helper;
pub mod embed;
pub mod errors;
pub mod scope_map;
pub mod server;
pub mod tools;
pub mod types;

pub use server::EpiGraphMcpFull;

/// Return all registered MCP tools as a JSON value.
///
/// Calls the static tool router (no database access) so callers don't need a
/// live server instance. Used by the REST discovery endpoint in epigraph-api.
#[must_use]
pub fn list_tools() -> serde_json::Value {
    EpiGraphMcpFull::all_tools_json()
}

/// Serve `router` on the given `listen` spec.
///
/// Accepts either a `host:port` TCP address or a `unix:/abs/path` Unix socket spec.
/// For Unix sockets, the file is removed if stale, then created with `0o660`
/// permissions (rw for owner+group, nothing for others), so only processes
/// with filesystem access can connect.
///
/// The router is passed in (rather than built here) because the production
/// router depends on a DB pool, signer, and embedder; tests can pass a trivial
/// `axum::Router::new()` to exercise only the listener-binding logic.
///
/// # Errors
/// Returns the underlying I/O error from `bind`, `set_permissions`, or `axum::serve`.
#[allow(clippy::missing_panics_doc)]
pub async fn serve_with_listener(listen: &str, router: axum::Router) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(path) = listen.strip_prefix("unix:") {
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
        return axum::serve(listener, router).await;
    }

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("EpiGraph MCP server listening on http://{listen}/mcp");
    axum::serve(listener, router).await
}
