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
//! * **HTTP.** Every request carries a validated `AuthContext`. PR-02
//!   guarantees a non-null `agents.id` for every principal minted through
//!   `oauth/token.rs`, so `auth.agent_id` is the principal and
//!   [`Viewer::resolve`] reads its live group set. When `agent_id` is `None`,
//!   the call is **refused** — see the fail-closed note below.
//! * **stdio.** There is no per-request identity: the process IS the principal.
//!   The viewer resolves the server's own `agents.id`
//!   (`EpiGraphMcpFull::agent_id`), which is the same identity every claim it
//!   writes is authored by.
//!
//! There is deliberately **no** third arm, and no `Option<Viewer>`: a tool that
//! cannot determine a principal must fail, not read.
//!
//! # Why there is no HTTP-with-no-context arm
//!
//! Plan §4.12's sketch threads an `is_http_call` discriminator into this
//! function and adds an explicit `(true, None) => Err(unauthorized("no auth
//! context"))` arm, "so it cannot become reachable silently". This function
//! takes no such flag, and the reason is that the arm is not merely
//! *unreachable by convention* — it is refused one frame up, by an enforced
//! gate, using that exact discriminator.
//!
//! `server.rs::call_tool` derives
//! `is_http_call = context.extensions.get::<Parts>().is_some()` (HTTP requests
//! carry `http::request::Parts`; stdio has none) and then, **before** dispatch
//! reaches any `#[tool]` body:
//!
//! ```ignore
//! if is_http_call {
//!     if let Err(err) = Self::enforce_tool_scope(auth_owned.as_ref(), &request.name) { ... return Err(err); }
//! }
//! ```
//!
//! `enforce_tool_scope`'s first branch is `let Some(auth) = auth else { return
//! Err(... "Unauthorized: no auth context (Bearer token required)") }`. So an
//! HTTP call with no `AuthContext` never reaches a tool at all, and `auth ==
//! None` here means stdio and nothing else. This matters because `main.rs` DOES
//! have a router arm that layers neither `bearer_auth_middleware` nor
//! `inject_unauthenticated_context` (neither `--jwt-secret` nor
//! `--allow-unauthenticated-http` given); the dispatch gate, not the middleware
//! stack, is what closes it.
//!
//! Duplicating the refusal here would be dead code, and dead security code that
//! looks live is its own hazard. What the property does need is a ratchet, so
//! `tests/http_calls_cannot_reach_a_tool_without_an_auth_context.rs` pins the
//! gate's presence and ordering in `call_tool`.
//!
//! # PR-09: the flatten is gone
//!
//! PR-06 shipped `a.agent_id.or(a.owner_id).unwrap_or(a.client_id)` and defended
//! it as yielding "a correct `Scoped` viewer that reads public rows only". Plan
//! §4.12 indicts exactly that line: `owner_id` and `client_id` are
//! `oauth_clients.id` values, not `agents.id` values, so feeding either to
//! [`Viewer::resolve`] is a type confusion whose membership lookup happens never
//! to match. The result — public-only — is the right answer under D3, arrived at
//! by accident, with no error and no metric. A schema change that made an
//! `oauth_clients.id` collide with an `agents.id` would turn it into a silent
//! authority grant.
//!
//! It is now a hard refusal. `agent_id == None` on the HTTP arm returns an MCP
//! error rather than a viewer. **This is a behaviour change for any HTTP token
//! that carries no agent principal**: such a token previously read public rows
//! and now reads nothing. PR-02 makes every token minted through
//! `oauth/token.rs` carry one, so the reachable population is pre-PR-02 tokens
//! and hand-minted service tokens.
//!
//! The `--allow-unauthenticated-http` listener is NOT in that population: its
//! injected context now carries `agent_id: Some(server_agent_id)`
//! (`auth.rs::unauthenticated_context`), so it resolves the server's own viewer
//! — the same arm stdio takes. That is the change plan §4.12 assigns to PR-09,
//! and it is a **widening**, not a hardening: every holder of that listener's
//! shared bearer token now reads with the server agent's group set instead of a
//! nil principal's empty one. It is inert on today's corpus (migration 062
//! defaults `visibility` to `'public'` and backfills nothing) and becomes
//! load-bearing the moment PR-12's backfill writes the first `'group'` row.
//!
//! **The stdio arm widens by exactly the same amount, and for the same
//! reason.** `server.rs::agent_id` now calls
//! `AgentRepository::ensure_personal_group`, so `server.agent_id()` returns an
//! agent with a populated group set where it previously returned one with an
//! empty set. Both arms therefore move from public-only to the server agent's
//! personal group. It is easy to read this section as being about the HTTP flag
//! alone; it is not.

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
/// stdio arm cannot establish the server's own agent row. Returns an MCP
/// invalid-request error when an HTTP `AuthContext` carries no `agent_id` — a
/// token with no agent principal has no read authority under plan §0.1's D3.
pub(crate) async fn request_viewer(
    server: &EpiGraphMcpFull,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<Viewer, McpError> {
    let principal = match auth {
        Some(a) => a.agent_id.ok_or_else(|| {
            McpError::invalid_request(
                concat!(
                    "token carries no agent principal; no read authority (see plan D3). ",
                    "Re-mint the token through /oauth/token, which has attached an ",
                    "agents.id to every principal since PR-02."
                )
                .to_string(),
                None,
            )
        })?,
        // No AuthContext ⇒ stdio, where the process is the principal. See the
        // module doc's "why there is no HTTP-with-no-context arm".
        None => server.agent_id().await?,
    };
    Viewer::resolve(&server.pool, principal)
        .await
        .map_err(|e| McpError::internal_error(format!("viewer resolution failed: {e}"), None))
}
