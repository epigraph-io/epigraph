//! Per-request [`Viewer`] acquisition for content-reading MCP tools.
//!
//! # Scope note: this is PR-09 work, arriving early, on purpose
//!
//! Plan §4.12 assigns `mcp_viewer` to PR-09. PR-06 lands a minimal version of it
//! anyway, because it has no choice: PR-06 makes `viewer: &Viewer` a *required*
//! parameter on ~150 repo functions, ~27 of the resulting call sites are inside
//! `crates/epigraph-mcp/src/tools/`, and
//! `crates/epigraph-api/tests/no_bypass_in_handlers.rs` makes the plan's
//! "pass a Bypass at every call site" illegal in exactly that directory. A
//! required parameter with no legal argument does not compile.
//!
//! What PR-09 still owns: moving the eight inline-SQL tools to the repo layer,
//! `no_inline_sql_in_tools.rs`, `theme_cluster`'s within-viewer clustering, and
//! the `auth.rs::unauthenticated_context()` change. This file is the acquisition
//! half only.
//!
//! # The two transports
//!
//! * **HTTP.** Every request carries a validated `AuthContext`. PR-02 guarantees
//!   a non-null `agents.id` for every principal minted through
//!   `oauth/token.rs`, so `auth.agent_id` is the principal and
//!   [`Viewer::resolve`] reads its live group set. When `agent_id` is `None` —
//!   the `--allow-unauthenticated-http` context, or a token predating PR-02 —
//!   we fall back to `owner_id`, then to `client_id`, in that order. All three
//!   are `agents.id`-shaped or resolve to an empty group set, which yields a
//!   correct `Scoped` viewer that reads public rows only. It never yields a
//!   bypass.
//! * **stdio.** There is no per-request identity: the process IS the principal.
//!   The viewer resolves the server's own `agents.id`
//!   (`EpiGraphMcpFull::agent_id`), which is the same identity every claim it
//!   writes is authored by. This is the arm PR-09 revisits when
//!   `unauthenticated_context()` starts carrying `Some(server_agent_id)`.
//!
//! There is deliberately **no** third arm, and no `Option<Viewer>`: a tool that
//! cannot determine a principal must fail, not read.

use epigraph_db::visibility::Viewer;
use rmcp::model::ErrorData as McpError;

use crate::server::EpiGraphMcpFull;

/// Resolve the viewer for one tool call.
///
/// `auth` is the per-request `AuthContext` on the HTTP transport and `None` on
/// stdio.
///
/// # Errors
///
/// Returns an MCP internal error if the membership lookup fails, or if the
/// stdio arm cannot establish the server's own agent row.
pub(crate) async fn request_viewer(
    server: &EpiGraphMcpFull,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<Viewer, McpError> {
    let principal = match auth {
        Some(a) => a.agent_id.or(a.owner_id).unwrap_or(a.client_id),
        // stdio: the process is the principal.
        None => server.agent_id().await?,
    };
    Viewer::resolve(&server.pool, principal)
        .await
        .map_err(|e| McpError::internal_error(format!("viewer resolution failed: {e}"), None))
}
