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
//! `no_inline_sql_in_tools.rs`, `theme_cluster`'s within-viewer clustering (moot:
//! the tool is retired with the k-means prototype, backlog a0ed0180), and
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
//! injected context carries an agent principal (`auth.rs::unauthenticated_context`).
//! PR-09 made that the server's own agent, which was a **widening**: every
//! holder of that listener's shared credential read with the server agent's
//! group set. Backlog fe514fc3 (operator decision) narrowed it again: on the
//! READ-ONLY listener (the default) the principal is a dedicated agent with no
//! group (`crate::unauthenticated_reader`), so it reads public rows only, and
//! [`request_viewer`] refuses such a context whose viewer carries any group.
//! The `--allow-unauthenticated-writes` opt-in keeps the server agent, whose
//! writes its callers author.
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

/// The HTTP arm's resolution: ELEVATED when the database answers for a live
/// session (elevation plan EL-6), the plain scoped viewer otherwise.
///
/// * A token carrying an elevation claim (`elv`, the elevate grant's) and its
///   family: `Viewer::resolve_elevated` with that claim.
/// * A token carrying a family but NO claim: a connector-mode session on the
///   family (MCP `sudo`), ONLY when the server's connector switch is on
///   (`EpiGraphMcpFull::with_connector_elevation`; OFF by default, operator
///   ruling pending plan EQ-7). Off, no liveness round trip is made.
/// * Anything else, or a server with no `ScopedPool` to stamp the check on:
///   `Viewer::resolve`, exactly as before.
///
/// A claim that is not a live session (forged, ended, expired, the check
/// failing) resolves the scoped viewer: the call is served, unelevated. The
/// stdio arm never comes here, so stdio never elevates.
async fn resolve_http(
    server: &EpiGraphMcpFull,
    auth: Option<&epigraph_auth::AuthContext>,
    principal: uuid::Uuid,
) -> Result<Viewer, epigraph_db::DbError> {
    let claim = auth.and_then(|a| a.family_id.map(|f| (a.elevation_claim, f)));
    match (claim, server.scoped.as_ref()) {
        (Some((Some(elv), family)), Some(scoped)) => {
            Viewer::resolve_elevated(scoped, principal, Some(elv), family).await
        }
        (Some((None, family)), Some(scoped)) if server.connector_elevation => {
            Viewer::resolve_elevated(scoped, principal, None, family).await
        }
        _ => Viewer::resolve(&server.pool, principal).await,
    }
}

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
///
/// # Visibility
///
/// `pub`, not `pub(crate)`, since PR-14, and only so that an INTEGRATION test
/// can drive the stdio arm through the real function. `tests/read_path_absence.rs`
/// previously modelled that arm by resolving a viewer from the literal
/// `server.agent_id()`, which is the value the arm produces — so the test
/// confirmed its own fixture and would have passed if the arm stopped producing
/// it. A test that cannot fail when its subject changes is not coverage.
///
/// This is not an invitation to acquire a viewer somewhere new.
/// `tests/tool_viewer_coverage.rs::viewer_acquisition_lives_in_server_rs_not_in_the_tool_modules`
/// still asserts that `viewer.rs` is the ONLY file under `src/tools/` naming
/// this function, and every production call site remains a `#[tool]` body in
/// `server.rs`.
pub async fn request_viewer(
    server: &EpiGraphMcpFull,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<Viewer, McpError> {
    let principal = match auth {
        // The `--allow-unauthenticated-http` listener whose principal did not
        // resolve: no token was presented, so "re-mint the token" would point
        // at the wrong cause.
        Some(a) if a.agent_id.is_none() && crate::auth::is_principal_less(a) => {
            return Err(unresolved_listener_principal());
        }
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
    if auth.is_none() {
        return Viewer::resolve(&server.pool, principal)
            .await
            .map_err(|e| crate::errors::internal_error_logged("viewer resolution failed", e));
    }
    // HTTP: an OPERATED principal gets no viewer. Operated agents are
    // stdio-only (migration 107); token issuance refuses them, but a token
    // minted BEFORE the link would otherwise carry the operator's group in
    // this viewer until it expired. Keyed on the link RECORD (any state,
    // retired included), not on the acting read, which can say "not acting"
    // while the agent's writer row in the operator's group is live. Checked
    // concurrently with the resolve, so it adds a round trip of work but no
    // latency.
    //
    // A DELEGATED run token (`dlg`) is the one carve-out, and only while its
    // delegation is live NOW ([`live_delegation`]). A token carrying `dlg`
    // whose delegation is not live is refused whatever the principal's link
    // state: an unlinked principal is never delegated to.
    let (viewer, actor, delegation) = tokio::join!(
        resolve_http(server, auth, principal),
        epigraph_db::AgentRepository::operator_of_author_pool(&server.pool, principal),
        live_delegation(server, auth, principal),
    );
    let delegated = match (auth.and_then(|a| a.delegated_by), delegation?) {
        (None, _) => false,
        (Some(_), Some(_)) => true,
        (Some(delegator), None) => {
            tracing::warn!(
                target: "auth.delegation.rejected",
                reason = "delegation_not_live",
                principal = %principal,
                delegator = %delegator,
                "MCP viewer refused: a delegated run token whose delegation is not live"
            );
            return Err(delegation_not_live(principal, delegator));
        }
    };
    match actor {
        Ok(None) => {}
        // A live delegation names this operated principal's own operator. The
        // viewer is the principal's own membership set, exactly as on stdio;
        // what it may WRITE is bounded by the database's operator-scope rule
        // (migration 122, `OPL02`) to groups its operator writes.
        Ok(Some(_)) if delegated => {}
        Ok(Some(link)) => {
            return Err(McpError::invalid_request(
                format!(
                    "agent {principal} is operated by {} and operated agents are stdio-only: \
                     this token predates the link and carries no HTTP authority",
                    link.operator_id
                ),
                None,
            ))
        }
        Err(e) => {
            return Err(crate::errors::internal_error_logged(
                format!("could not check whether agent {principal} is operated"),
                e,
            ))
        }
    }
    let viewer =
        viewer.map_err(|e| crate::errors::internal_error_logged("viewer resolution failed", e))?;
    if auth.is_some_and(is_read_only_principal_less) {
        refuse_a_grouped_principal_less_viewer(&viewer)?;
    }
    Ok(viewer)
}

/// The refusal on the `--allow-unauthenticated-http` listener when its
/// injected principal has not resolved (`unauthenticated_reader::listener_principal`
/// logs why). On the read-only listener the usual cause is a group membership
/// someone granted the reader agent, which `UnauthenticatedReader::resolve`
/// refuses to read with (fail-closed, backlog fe514fc3).
fn unresolved_listener_principal() -> McpError {
    McpError::invalid_request(
        concat!(
            "refused: the unauthenticated listener's principal did not resolve, so it ",
            "has no read authority; the server log says why. On the read-only listener ",
            "the usual cause is a group membership held by the reader agent ",
            "(mcp-unauthenticated-reader), which reads public rows only: revoke that ",
            "agent's group memberships."
        )
        .to_string(),
        None,
    )
}

/// Whether `auth` is the READ-ONLY `--allow-unauthenticated-http` context: no
/// token was presented (`auth::is_principal_less`) and it carries no write
/// scope (`auth::UnauthenticatedWrites::Refused`). The same test
/// `EpiGraphMcpFull::write_identity` applies before it refuses a write.
fn is_read_only_principal_less(auth: &epigraph_auth::AuthContext) -> bool {
    crate::auth::is_principal_less(auth) && !auth.has_scope("claims:write")
}

/// The read-only unauthenticated listener reads PUBLIC rows only (backlog
/// fe514fc3): its viewer must be a scoped one over ZERO groups. Its principal
/// is the dedicated zero-membership agent (`unauthenticated_reader`), whose
/// resolution already refuses a membership; this re-checks on every call, so
/// a membership granted to that agent after boot (or a wiring that injects
/// some other agent) refuses the call instead of reading with that group.
/// Elevated and bypass viewers carry no scoped group bind and are refused too.
fn refuse_a_grouped_principal_less_viewer(viewer: &Viewer) -> Result<(), McpError> {
    if viewer.group_bind().is_some_and(<[uuid::Uuid]>::is_empty) {
        return Ok(());
    }
    let principal = viewer
        .principal()
        .map_or_else(|| "none".to_string(), |p| p.to_string());
    tracing::error!(
        principal = %principal,
        "refusing a read on the --allow-unauthenticated-http listener: its principal resolved \
         to a viewer with group access, and that listener reads public rows only"
    );
    Err(McpError::invalid_request(
        format!(
            "refused: the unauthenticated listener reads public rows only, and its principal \
             {principal} resolved to a viewer with group access. Revoke that agent's group \
             memberships, or use an authenticated (--jwt-secret) listener"
        ),
        None,
    ))
}

/// The refusal of a delegated run token whose delegation is not live: one
/// wording at dispatch and at the viewer.
fn delegation_not_live(principal: uuid::Uuid, delegator: uuid::Uuid) -> McpError {
    McpError::invalid_request(
        format!(
            "this token was delegated to agent {principal} by agent {delegator}, and that \
             delegation is not live: delegated run tokens are refused, or the delegator's \
             allowance, client, or writer membership, or the agent's operator link, has ended"
        ),
        None,
    )
}

/// One delegation the dispatch found live for the tool call in flight
/// ([`admit_delegated_call`]); see [`ADMITTED`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct AdmittedDelegation {
    delegator: uuid::Uuid,
    principal: uuid::Uuid,
    live: epigraph_db::DelegationLive,
}

tokio::task_local! {
    /// The delegation `call_tool` found live for the tool call it is running
    /// (set only by [`with_admitted_delegation`], around that one call), so a
    /// tool's [`request_viewer`] and the ownership gate reuse the dispatch's
    /// one read instead of repeating it. Private to this module: nothing
    /// outside can claim a delegation was checked. A tool that resolves its
    /// viewer outside the call's task sees no value and reads again; the
    /// fallback only ever READS, it never admits unchecked.
    static ADMITTED: AdmittedDelegation;
}

/// Run `call` (one tool call) with `admitted` visible to [`live_delegation`].
pub(crate) async fn with_admitted_delegation<F: std::future::Future>(
    admitted: Option<AdmittedDelegation>,
    call: F,
) -> F::Output {
    match admitted {
        Some(a) => ADMITTED.scope(a, call).await,
        None => call.await,
    }
}

/// THE per-call check of a DELEGATED run token on the MCP HTTP transport, run
/// by `call_tool` FIRST, before any gate, lineage write or tool: a tool that
/// never resolves a viewer is covered exactly like one that does. `Ok(None)`
/// for a context without `dlg` (and on stdio, which has no context), with no
/// read.
///
/// # Errors
/// INVALID_REQUEST (logged, never with the token) when the token carries a
/// scope outside `epigraph_auth::DELEGATED_SCOPE_CEILING` (checked first, no
/// read), when the delegation is not live, or when it names no principal; an internal error with a fixed
/// message when the check cannot answer (fails closed).
pub(crate) async fn admit_delegated_call(
    server: &EpiGraphMcpFull,
    auth: Option<&epigraph_auth::AuthContext>,
    tool: &str,
) -> Result<Option<AdmittedDelegation>, McpError> {
    let Some(auth) = auth else {
        return Ok(None);
    };
    let Some(delegator) = auth.delegated_by else {
        return Ok(None);
    };
    let outside = epigraph_auth::outside_delegated_ceiling(&auth.scopes);
    if !outside.is_empty() {
        tracing::warn!(
            target: "auth.delegation.rejected",
            reason = "scope_outside_ceiling",
            tool = %tool,
            principal = ?auth.agent_id,
            delegator = %delegator,
            jti = %auth.jti,
            scopes = ?outside,
            "MCP call refused: a delegated run token carrying scopes outside the delegated ceiling"
        );
        return Err(McpError::invalid_request(
            format!(
                "a delegated run token may carry only the delegated scope ceiling ({}); this one \
                 also carries {}",
                epigraph_auth::DELEGATED_SCOPE_CEILING.join(" "),
                outside.join(" ")
            ),
            None,
        ));
    }
    let Some(principal) = auth.agent_id else {
        tracing::warn!(
            target: "auth.delegation.rejected",
            reason = "no_principal",
            tool = %tool,
            delegator = %delegator,
            jti = %auth.jti,
            "MCP call refused: a delegated run token that names no principal"
        );
        return Err(McpError::invalid_request(
            format!(
                "this token was delegated by agent {delegator} but names no principal; that \
                 delegation is not live"
            ),
            None,
        ));
    };
    match read_delegation(server, delegator, principal).await? {
        Some(live) => Ok(Some(AdmittedDelegation {
            delegator,
            principal,
            live,
        })),
        None => {
            tracing::warn!(
                target: "auth.delegation.rejected",
                reason = "delegation_not_live",
                tool = %tool,
                principal = %principal,
                delegator = %delegator,
                jti = %auth.jti,
                "MCP call refused: a delegated run token whose delegation is not live"
            );
            Err(delegation_not_live(principal, delegator))
        }
    }
}

/// The live delegation of `auth`'s `dlg` claim to `principal`. `None` when the
/// token carries no `dlg`, and when its delegation is not live.
///
/// Inside a tool call the dispatch already checked ([`ADMITTED`] holds this
/// very delegator and principal) it reuses that answer; anywhere else it asks
/// THE shared per-request check (`AgentRepository::delegated_principal_pool`,
/// with this listener's `EPIGRAPH_RUN_TOKENS` switch: `None` without a read
/// while it is off).
///
/// Read by [`request_viewer`] and by the ownership gate's actor arm
/// (`tools::claims::require_owner_or_admin`), so both sites admit a delegated
/// token on the same answer.
///
/// # Errors
/// An MCP internal error with a fixed message when the check cannot answer;
/// callers refuse.
pub(crate) async fn live_delegation(
    server: &EpiGraphMcpFull,
    auth: Option<&epigraph_auth::AuthContext>,
    principal: uuid::Uuid,
) -> Result<Option<epigraph_db::DelegationLive>, McpError> {
    let Some(delegator) = auth.and_then(|a| a.delegated_by) else {
        return Ok(None);
    };
    if let Ok(a) = ADMITTED.try_with(|a| *a) {
        if a.delegator == delegator && a.principal == principal {
            return Ok(Some(a.live));
        }
    }
    read_delegation(server, delegator, principal).await
}

/// The one read: `AgentRepository::delegated_principal_pool` on this
/// listener's pool and switch. The database error is logged here and never
/// sent to the client.
async fn read_delegation(
    server: &EpiGraphMcpFull,
    delegator: uuid::Uuid,
    principal: uuid::Uuid,
) -> Result<Option<epigraph_db::DelegationLive>, McpError> {
    epigraph_db::AgentRepository::delegated_principal_pool(
        &server.pool,
        server.run_tokens,
        delegator,
        principal,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            reason = "delegation_check_unavailable",
            principal = %principal,
            delegator = %delegator,
            error = %e,
            "the delegated run token check failed"
        );
        McpError::internal_error(
            "could not check whether this token's delegation is live".to_string(),
            None,
        )
    })
}

impl EpiGraphMcpFull {
    /// A connection stamped with `viewer`'s tenancy context, for a tool's
    /// READS: the MCP twin of `epigraph_api::AppState::read_as`.
    ///
    /// A content-reading tool resolves its [`Viewer`] (above) and then reads
    /// on what this returns, `&mut *read` into the repo layer, never on the
    /// server's plain application pool. That pool's connections carry EMPTY
    /// tenancy GUCs, and row security, FORCEd on the application login, then
    /// admits public rows only: the in-query predicate admits a member's
    /// group-private row and the session's policy drops it, so a member read
    /// its own group's rows as absent, with no error. Measured on production
    /// 2026-11-05: every MCP caller saw public rows only. CI did not see it
    /// because it connects as a BYPASSRLS superuser, on which the policy filters
    /// nothing (`tests/mcp_reads_are_stamped_app_role.rs` reads as the
    /// application role instead).
    ///
    /// One per tool call where a tool makes several reads: take it once, keep
    /// it short-lived, and take it AFTER any embedder round trip rather than
    /// holding a pooled connection across one. Elevated viewers are handled by
    /// [`epigraph_db::ScopedPool::read_as`] itself (a `BEGIN READ ONLY` arm
    /// under transaction-mode pooling). Call [`epigraph_db::ScopedRead::commit`]
    /// at the end when convenient; dropping it instead is safe for a read (the
    /// transaction arm rolls back) and costs one wasted round trip.
    ///
    /// This is for reads. Writes take `ScopedPool::begin_as` through
    /// `claim_helper`'s stamped-transaction helpers.
    ///
    /// # It REFUSES rather than falling back to the plain pool
    ///
    /// For the reason `AppState::read_as` documents: a fallback would be the
    /// only branch a fixture without a `ScopedPool` takes and the one branch a
    /// deployed server never takes, so no test could tell a stamped read from
    /// an unstamped one, and on a deployed server it would hide rows from their
    /// own owners without an error. `tool` names the caller in the refusal and
    /// in the log line.
    ///
    /// # Errors
    /// An MCP internal error naming the fix when this server was not built
    /// with [`Self::with_scoped_pool`]; a redacted internal error (the cause
    /// logged) when the connection or the stamp fails, including for a bypass
    /// viewer, which belongs on the maintenance session instead.
    pub(crate) async fn read_as(
        &self,
        viewer: &Viewer,
        tool: &'static str,
    ) -> Result<epigraph_db::ScopedRead<'_>, McpError> {
        let scoped = self.scoped.as_ref().ok_or_else(|| {
            tracing::error!(
                target: "tenancy.scoped_read",
                tool,
                "read refused: this MCP process was not built from a ScopedPool"
            );
            crate::errors::internal_error_text(format!(
                "{tool}: this MCP server was not built from a ScopedPool, so this read cannot \
                 be stamped with the caller's tenancy context. Refusing rather than reading on \
                 the plain application pool, where row security admits public rows only and \
                 the caller's own group-private rows would be silently missing. Nothing was \
                 read. Construct the server with EpiGraphMcpFull::with_scoped_pool."
            ))
        })?;
        scoped.read_as(viewer).await.map_err(|e| {
            crate::errors::internal_error_logged(
                format!("{tool}: could not acquire a viewer-stamped connection"),
                e,
            )
        })
    }
}
