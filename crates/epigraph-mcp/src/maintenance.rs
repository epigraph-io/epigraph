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

use epigraph_db::visibility::SystemReason;
use epigraph_db::MaintenanceSession;
use rmcp::model::ErrorData as McpError;

use crate::server::EpiGraphMcpFull;

/// Is the three maintenance tools' QUERY PLUMBING converted to run on the
/// maintenance connection? **No**, and this gate is what keeps that fact from
/// turning into a silent no-op.
///
/// # Why this is a named predicate and not `self.scoped.is_some()`
///
/// Attaching a `ScopedPool` to the MCP server is PROCESS-WIDE. The write path
/// needs one (`claim_helper::begin_author_stamped_tx`), and the instant
/// `with_scoped_pool` acquired that caller, `maintenance_viewer` started
/// succeeding too — for three tools whose statements still run on
/// `server.pool`, the ordinary application pool. A bypass `Viewer` emits no SQL
/// predicate, so under FORCE those statements are filtered by the *database* and
/// return **zero rows with no error**: the privileged-viewer / ordinary-pool
/// hybrid PR-15 deleted from eleven CLI binaries, and plan §4.3's R2 is explicit
/// that this is the worse failure — *"fail-closed regressions look like data
/// loss, not errors."*
///
/// `crates/epigraph-db/tests/no_hybrid_bypass_spend.rs` CANNOT SEE those three
/// sites. Its scanner is function-granular and the mint (`server.rs`) and the
/// spend (`tools/`) are in different files; its own known-limit (b) says the
/// `"server.pool"` entry in `FOREIGN_POOLS` "contributes zero detections today".
/// So a one-line `with_scoped_pool` in `main` would have shipped the hybrid with
/// every ratchet green.
///
/// Keying the refusal on `false` rather than on the absence of a `ScopedPool` is
/// the whole point: the condition that licenses these tools is *the conversion*,
/// which is a change to `tools::dedup_sweep`, `tools::embeddings` and
/// `tools::cdst_maintenance`'s query plumbing (PR-17), not the presence of a
/// pool. Flip this to `true` in the same commit that lands that conversion, and
/// not before. `crates/epigraph-mcp/src/maintenance.rs`'s own test module pins
/// that attaching a `ScopedPool` does not enable them.
const fn maintenance_tools_run_on_the_maintenance_connection() -> bool {
    false
}

/// A bypass viewer plus the maintenance connection it is inseparable from.
///
/// # Status: still fail-CLOSED, on a DIFFERENT gate than before
///
/// Until the MCP write path was converted, this function failed closed because
/// `EpiGraphMcpFull::with_scoped_pool` had no production caller at all. It now
/// has one — `main` attaches a `ScopedPool` so `submit_claim` / `memorize` can
/// stamp a connection with the author's tenancy context — so that accident is no
/// longer the control. The control is now
/// [`maintenance_tools_run_on_the_maintenance_connection`], which is `false` and
/// says why.
///
/// The three maintenance tools therefore still cannot run, and the error names
/// the conversion rather than the missing constructor. Closing it properly means
/// routing their queries onto the maintenance connection: a change to
/// `tools::dedup_sweep`, `tools::embeddings` and `tools::cdst_maintenance`
/// rather than to the pool wiring. That is PR-17's to do.
///
/// Returns one [`MaintenanceSession`], which owns the connection and the viewer
/// together and hands the viewer out only by reference — so a call site can no
/// longer drop the connection and keep the bypass
/// (`D-PR17-maintenance-lease-coupling-is-a-convention`). A previous revision
/// of this parenthesis said that covered only the ACCIDENTAL shape, because
/// `Viewer` was `Clone`; it is no longer, so the deliberate one is closed too.
/// The mint is `ScopedPool::maintenance_session`, shared with the CLI and API
/// wrappers.
///
/// ```ignore
/// let session = maintenance::maintenance_viewer(self, SystemReason::DedupSweep).await?;
/// let viewer = session.viewer();
/// ```
///
/// # Errors
///
/// Returns an MCP internal error in two cases, in this order:
///
/// 1. [`maintenance_tools_run_on_the_maintenance_connection`] is `false` — the
///    three tools would spend a bypass viewer on `server.pool`. Checked FIRST
///    and independently of the pool, so attaching a `ScopedPool` for the write
///    path cannot un-gate them as a side effect.
/// 2. This server was not built from a [`epigraph_db::ScopedPool`] — a process
///    that never built one cannot mint a `MaintenanceLease`, and therefore
///    cannot construct a bypass viewer at all.
pub(crate) async fn maintenance_viewer(
    server: &EpiGraphMcpFull,
    reason: SystemReason,
) -> Result<MaintenanceSession<'_>, McpError> {
    if !maintenance_tools_run_on_the_maintenance_connection() {
        // The message names the offending pool as "the server's own application
        // pool" rather than spelling the field access, and that is not
        // squeamishness: `no_hybrid_bypass_spend.rs` matches the FIELD-ACCESS
        // SPELLING over comment-stripped source, and a STRING LITERAL is not
        // stripped. MEASURED — an earlier revision of this sentence spelled it
        // out and turned this function, whose whole purpose is to make the hybrid
        // unreachable, into the lint's only reported offender. That lint's own
        // doc already refuses to "punish a call site for documenting its own
        // hazard"; this is the same false positive one layer down. Recorded in
        // that file's known limits.
        return Err(McpError::internal_error(
            "this MCP tool is a corpus-wide maintenance job whose statements still run on the \
             server's own application pool, not on the maintenance connection. A bypass viewer \
             spent there emits no predicate but is still filtered by RLS, so it would return \
             ZERO rows with no error instead of the whole corpus. Refusing rather than \
             reporting a successful no-op. Closing this means routing tools::dedup_sweep / \
             tools::embeddings / tools::cdst_maintenance onto the maintenance connection \
             (PR-17); attaching a ScopedPool is NOT sufficient and deliberately does not \
             enable it.",
            None,
        ));
    }
    let scoped = server.scoped.as_ref().ok_or_else(|| {
        McpError::internal_error(
            "this MCP server was not built from a ScopedPool, so no maintenance \
             lease can be minted; construct it with EpiGraphMcpFull::with_scoped_pool",
            None,
        )
    })?;
    scoped
        .maintenance_session(reason)
        .await
        .map_err(|e| McpError::internal_error(format!("maintenance acquire failed: {e}"), None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::McpEmbedder;
    use epigraph_crypto::AgentSigner;
    use epigraph_db::{ScopedPool, SessionGucMode};
    use sqlx::PgPool;

    /// The ephemeral `#[sqlx::test]` database's own URL.
    ///
    /// `ScopedPool::connect` takes a DSN, and `#[sqlx::test]` hands out a pool
    /// over a database whose name it generated — so the DSN has to be rebuilt.
    /// This is the same derivation as
    /// `crates/epigraph-db/tests/viewer_fixture.rs::database_url_for`, which
    /// cannot be reused here: that file lives in a `tests/` target and this is a
    /// `#[cfg(test)]` module inside `src/`. Kept to the minimum this one test
    /// needs (no query-string handling) rather than re-forking the whole helper.
    async fn scoped_pool_over(pool: &PgPool) -> ScopedPool {
        // `connect_options().get_database()` rather than the canonical helper's
        // `SELECT current_database()`. Same answer, no round trip — and,
        // load-bearing: `tests/no_inline_sql_in_tools.rs::the_scan_root_choice_is_still_free`
        // fails the build on ANY `sqlx::query*` under `crates/epigraph-mcp/src/`
        // outside `src/tools/`, TEST sites included. MEASURED: the query form put
        // this module in that lint's offender list ("src/maintenance.rs: 0
        // production, 1 test"). Removing the query is the right answer; widening
        // the lint's scan root to accommodate one fixture would be the wrong one.
        let db = pool
            .connect_options()
            .get_database()
            .expect("the #[sqlx::test] pool names its ephemeral database")
            .to_string();
        let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let (authority, query) = match base.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (base.as_str(), None),
        };
        let prefix = authority
            .trim_end_matches('/')
            .rsplit_once('/')
            .expect("DATABASE_URL must carry a database path")
            .0;
        let url = match query {
            Some(q) => format!("{prefix}/{db}?{q}"),
            None => format!("{prefix}/{db}"),
        };
        ScopedPool::connect(&url, SessionGucMode::Session)
            .await
            .expect("ScopedPool::connect over the ephemeral test database")
    }

    /// THE HAZARD THIS PIN EXISTS FOR, stated as a test.
    ///
    /// Attaching a `ScopedPool` is process-wide. The write path needs one; the
    /// three maintenance tools must NOT be enabled by that, because their
    /// statements still run on `server.pool` and a bypass viewer spent there
    /// returns zero rows with **no error** — a silent no-op replacing a loud
    /// failure. `crates/epigraph-db/tests/no_hybrid_bypass_spend.rs` states by
    /// name that its function-granular scanner cannot see those three sites
    /// (known limit (b): the `"server.pool"` entry in `FOREIGN_POOLS`
    /// "contributes zero detections today"), so CI would have stayed green while
    /// a one-line `with_scoped_pool` in `main` shipped the hybrid.
    ///
    /// The assertion is deliberately about the REASON and not just the failure:
    /// a `None` scoped pool also refuses, and a test that accepted either error
    /// would pass on a tree where the gate had been deleted.
    #[sqlx::test(migrations = "../../migrations")]
    async fn attaching_a_scoped_pool_does_not_enable_the_maintenance_tools(pool: PgPool) {
        let scoped = scoped_pool_over(&pool).await;
        let signer = AgentSigner::from_bytes(&[0x5au8; 32]).expect("signer");
        let embedder = McpEmbedder::new(pool.clone(), None);
        let server =
            EpiGraphMcpFull::new(pool.clone(), signer, embedder, false).with_scoped_pool(scoped);

        // Calibration: the ScopedPool really is attached, so the refusal below
        // cannot be the "was not built from a ScopedPool" arm.
        assert!(
            server.scoped.is_some(),
            "the fixture failed to attach a ScopedPool, so this test proves nothing about \
             the gate — it would pass on the `None` arm alone"
        );

        for reason in [
            SystemReason::DedupSweep,
            SystemReason::EmbeddingBackfill,
            SystemReason::BeliefRecomputation,
        ] {
            let err = maintenance_viewer(&server, reason)
                .await
                .err()
                .unwrap_or_else(|| {
                    panic!(
                        "maintenance_viewer({reason:?}) SUCCEEDED on a server whose three \
                         maintenance tools still run their statements on `server.pool`. That \
                         mints a bypass viewer and spends it on an unprivileged connection: \
                         zero rows, no error. Re-gate it, or convert the three tools' query \
                         plumbing in the same change."
                    )
                });
            let msg = err.message.to_string();
            assert!(
                msg.contains("server's own application pool"),
                "maintenance_viewer({reason:?}) was refused for the WRONG reason: {msg}. \
                 Expected the conversion gate, not the missing-ScopedPool arm."
            );
        }
    }
}
