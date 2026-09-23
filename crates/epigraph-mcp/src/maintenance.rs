//! Maintenance-lease acquisition for MCP tools, deliberately outside `tools/`.
//!
//! # Why this module exists
//!
//! `crates/epigraph-api/tests/no_bypass_in_handlers.rs` (landed PR-03) fails the
//! build on the literal strings `Viewer::system(` or `MaintenanceLease` anywhere
//! under `crates/epigraph-mcp/src/tools/`. That lint is correct: a bypass viewer
//! constructed inside a tool body is exactly the fail-open the tenancy work
//! exists to prevent, and it is the kind of thing that reads as innocent in a
//! diff.
//!
//! But three MCP tools genuinely are maintenance jobs, not content reads:
//!
//! * `tools/dedup_sweep.rs` — the semantic-duplicate sweep enumerates the whole
//!   corpus and pairs it against itself. A per-tenant sweep would never see the
//!   duplicate pair that spans two tenants, which is the pair that matters.
//! * `tools/embeddings.rs` — the embedding backfill. A per-tenant view of the
//!   gap leaves every other tenant permanently unembedded, and CLAUDE.md's
//!   embedding invariant is corpus-wide by construction.
//! * `tools/cdst_maintenance.rs` — belief recomputation across the corpus.
//!
//! Each of those has an enumerated [`SystemReason`] variant, so the bypass is
//! already counted by `crates/epigraph-db/tests/viewer_ratchet.rs` and is a
//! visible enum diff if a fourth is ever added.
//!
//! # Why this is not lint-laundering
//!
//! A reviewer will and should ask whether moving `Viewer::system` one directory
//! up is just defeating the lint. The answer has three parts, and it should be
//! checked rather than taken on trust:
//!
//! 1. **The lint's subject is request handlers.** Its scan roots are
//!    `epigraph-api/src/routes/` and `epigraph-mcp/src/tools/` because those are
//!    the two directories where code runs on behalf of a caller. This module
//!    does not, and a `#[tool_router]` tool that calls it is making an explicit,
//!    greppable request for a bypass rather than minting one inline.
//! 2. **The reason set is closed.** [`SystemReason`] is a `#[non_exhaustive]`
//!    enum with a monotone-decreasing ratchet on its cardinality. This module
//!    cannot invent a reason; it can only pass one through.
//! 3. **The concentration is the point.** "Who in `epigraph-mcp` can bypass
//!    tenancy?" is now answered by reading one 60-line file, instead of by
//!    grepping thirteen tool modules and hoping.
//!
//! If a future tool reaches for this to read *content* on a caller's behalf,
//! that is the abuse, and the fix is `tools::viewer::request_viewer`.

use std::ops::{Deref, DerefMut};

use epigraph_db::visibility::SystemReason;
use epigraph_db::MaintenanceSession;
use rmcp::model::ErrorData as McpError;
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::server::EpiGraphMcpFull;

/// How many maintenance tool calls may hold a [`MaintenanceSession`] at once,
/// process-wide.
///
/// Each admitted call pins ONE connection for its whole run (the session), and
/// two of the three tools — `sweep_semantic_duplicates` and `recompute_beliefs`
/// — additionally check out ONE transient connection at a time from the same
/// pool, through [`MaintenanceSession::pool`], for the engine callees that
/// still take `&PgPool` (`mark_duplicate_with_cascade`,
/// `recompute_claim_cached_belief`). Neither callee holds a transaction open
/// while acquiring another connection, so one transient slot per call is the
/// peak, not an estimate.
///
/// Without a bound, N concurrent calls against an N-connection pool pin every
/// connection and then each waits out the acquire timeout for a transient slot
/// that can never free — once per claim or per pair, which across a 2000-item
/// page is hours, not an error. See [`MAINTENANCE_POOL_CONNECTIONS`] for the
/// other half of the arithmetic.
pub const MAINTENANCE_TOOL_CONCURRENCY: usize = 3;

/// The size `epigraph-mcp-full` gives its maintenance pool: one pinned
/// connection per admitted call plus ONE shared slot for the transient
/// checkouts. With every admitted call pinning one and needing at most one
/// more at a time, that last slot is always eventually released, so the
/// transients are served in turn rather than starved.
///
/// A pool at least this large is what makes [`MAINTENANCE_TOOL_CONCURRENCY`]
/// sufficient; a smaller one reintroduces the starvation.
pub const MAINTENANCE_POOL_CONNECTIONS: u32 = MAINTENANCE_TOOL_CONCURRENCY as u32 + 1;

/// Process-wide rather than per server: the HTTP transport builds one
/// `EpiGraphMcpFull` per MCP session, all over clones of one `ScopedPool`, so a
/// per-server gate would bound nothing.
static MAINTENANCE_GATE: Semaphore = Semaphore::const_new(MAINTENANCE_TOOL_CONCURRENCY);

/// A [`MaintenanceSession`] plus the gate permit that admitted it.
///
/// Derefs to the session, so a dispatch body passes `&mut session` straight to
/// a tool function taking `&mut MaintenanceSession<'_>`. Field order is drop
/// order: the session (and its pinned connection) goes back to the pool before
/// the permit admits the next caller.
pub(crate) struct GatedMaintenanceSession<'a> {
    session: MaintenanceSession<'a>,
    _permit: SemaphorePermit<'static>,
}

impl<'a> Deref for GatedMaintenanceSession<'a> {
    type Target = MaintenanceSession<'a>;
    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl DerefMut for GatedMaintenanceSession<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session
    }
}

/// A bypass viewer plus the maintenance connection it is inseparable from.
///
/// # Where the three tools spend it
///
/// `tools::dedup_sweep`, `tools::embeddings::backfill_embeddings` and
/// `tools::cdst_maintenance` take the session itself (`&mut
/// MaintenanceSession<'_>`), not a bare `&Viewer`, and run every statement on
/// it: the reads and the embedding stores on the pinned connection
/// ([`MaintenanceSession::split`]), and the two engine callees that still take
/// `&PgPool` on [`MaintenanceSession::pool`] — the pool that connection came
/// from. None of them names `server.pool`.
///
/// That is what makes attaching a `ScopedPool` safe. Before it, the tools took
/// `&self` and a `&Viewer` and queried `self.pool`, the ordinary application
/// pool, so attaching one would have let them mint a privileged viewer and
/// spend it on an unprivileged connection — the privileged-viewer/ordinary-pool
/// hybrid PR-15 deleted from eleven CLI binaries. Under row security that is a
/// silent no-op, which plan §4.3's R2 is explicit about being the worse
/// failure: *"fail-closed regressions look like data loss, not errors."*
///
/// Returns one [`MaintenanceSession`] (behind the concurrency gate above),
/// which owns the connection and the viewer together and hands the viewer out
/// only by reference — so a call site can no longer drop the connection and
/// keep the bypass (`D-PR17-maintenance-lease-coupling-is-a-convention`). A
/// previous revision of this parenthesis said that covered only the ACCIDENTAL
/// shape, because `Viewer` was `Clone`; it is no longer, so the deliberate one
/// is closed too. The mint is `ScopedPool::maintenance_session`, shared with
/// the CLI and API wrappers.
///
/// ```ignore
/// let mut session = maintenance::maintenance_viewer(self, SystemReason::DedupSweep).await?;
/// tools::dedup_sweep::sweep_semantic_duplicates(self, &mut session, params).await
/// ```
///
/// # Errors
///
/// Returns an MCP internal error when this server was not built from a
/// [`epigraph_db::ScopedPool`] — a process that never built one cannot mint a
/// `MaintenanceLease`, and therefore cannot construct a bypass viewer at all.
/// That is the intended failure mode, not a gap: it means a stdio server or a
/// fixture must be given a real pool before it can run a maintenance job.
pub(crate) async fn maintenance_viewer(
    server: &EpiGraphMcpFull,
    reason: SystemReason,
) -> Result<GatedMaintenanceSession<'_>, McpError> {
    let scoped = server.scoped.as_ref().ok_or_else(|| {
        McpError::internal_error(
            "this MCP server was not built from a ScopedPool, so no maintenance \
             lease can be minted; construct it with EpiGraphMcpFull::with_scoped_pool",
            None,
        )
    })?;
    // Admission BEFORE the checkout, so a call waiting its turn holds nothing.
    // The semaphore is a `static` that is never closed, so `acquire` cannot
    // fail; the arm exists only because the signature is fallible.
    let permit = MAINTENANCE_GATE
        .acquire()
        .await
        .map_err(|e| McpError::internal_error(format!("maintenance gate closed: {e}"), None))?;
    let session = scoped
        .maintenance_session(reason)
        .await
        .map_err(|e| McpError::internal_error(format!("maintenance acquire failed: {e}"), None))?;
    Ok(GatedMaintenanceSession {
        session,
        _permit: permit,
    })
}
