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

use epigraph_db::visibility::{SystemReason, Viewer};
use epigraph_db::MaintenanceConn;
use rmcp::model::ErrorData as McpError;

use crate::server::EpiGraphMcpFull;

/// A bypass viewer plus the maintenance connection it is inseparable from.
///
/// # PR-15 status: DEFERRED, deliberately, and the reason is not "we forgot"
///
/// `EpiGraphMcpFull::with_scoped_pool` has zero callers. The shipped
/// `epigraph-mcp-full` binary builds its pool with `create_pool` and never
/// attaches a `ScopedPool`, so this function returns its "was not built from a
/// `ScopedPool`" error on every call and the three maintenance tools cannot run
/// at all today. That is a live functional gap — and it is **fail-closed**.
///
/// PR-15 did not close it by calling `with_scoped_pool` in `main`, because
/// doing only that would make it *worse*. The three tools take `&self` and run
/// their queries on `self.pool`, the ordinary application pool; attaching a
/// `ScopedPool` would let them mint a privileged viewer and then spend it on an
/// unprivileged connection — the privileged-viewer/ordinary-pool hybrid this PR
/// exists to delete from eleven CLI binaries. Under FORCE that trades a hard
/// error for a silent no-op, which plan §4.3's R2 is explicit about being the
/// worse failure: *"fail-closed regressions look like data loss, not errors."*
///
/// Closing it properly means routing the three tools' queries onto the
/// maintenance connection, which is a change to `tools::dedup_sweep`,
/// `tools::embeddings` and `tools::cdst_maintenance`'s query plumbing rather
/// than to the pool wiring. That is PR-17's to do, alongside the RLS work that
/// makes it matter. Until then the failure mode is a clear error naming the
/// missing constructor, which is the right thing for it to be.
///
/// The `MaintenanceConn` must be held for as long as the viewer is used —
/// dropping it returns the connection to the pool, and from PR-15 on the
/// maintenance connection is the privileged one. Call sites bind it:
///
/// ```ignore
/// let (_conn, viewer) = maintenance::maintenance_viewer(self, SystemReason::DedupSweep).await?;
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
) -> Result<(MaintenanceConn<'_>, Viewer), McpError> {
    let scoped = server.scoped.as_ref().ok_or_else(|| {
        McpError::internal_error(
            "this MCP server was not built from a ScopedPool, so no maintenance \
             lease can be minted; construct it with EpiGraphMcpFull::with_scoped_pool",
            None,
        )
    })?;
    let (conn, lease) = scoped
        .unscoped_for_maintenance(reason)
        .await
        .map_err(|e| McpError::internal_error(format!("maintenance acquire failed: {e}"), None))?;
    Ok((conn, Viewer::system(&lease, reason)))
}
