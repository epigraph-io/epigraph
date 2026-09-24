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

/// A bypass viewer plus the maintenance connection it is inseparable from, for
/// one of the three maintenance tools.
///
/// # What licenses the bypass, and why it is checked on every call
///
/// The three tools spend a bypass viewer, which emits no SQL predicate, so what
/// they see and write is decided by the CONNECTION alone. Each one now runs every
/// statement on the connection this session owns: `tools::cdst_maintenance`,
/// `tools::dedup_sweep` and `tools::embeddings` take the [`MaintenanceSession`]
/// itself and name no server pool (`tests/maintenance_tools_spend_only_the_session.rs`
/// is the ratchet). That conversion is what the old gate,
/// `maintenance_tools_run_on_the_maintenance_connection() == false`, was waiting
/// for, and it is why the gate is gone.
///
/// What is left to check is that the connection can actually spend the viewer.
/// `ScopedPool::maintenance_session` draws from the ATTACHED maintenance pool, or,
/// with none attached, silently from the application pool. There a bypass viewer
/// is filtered by RLS into zero rows and zero updates with no error, which is the
/// privileged-viewer / ordinary-pool hybrid. So two refusals come before the
/// session is handed out:
///
/// 1. no maintenance pool is attached. `main` attaches one only when
///    `MAINTENANCE_DATABASE_URL` (or its fallback) resolved AND the boot probe
///    found it privileged, so "unset" and "misconfigured" both land here;
/// 2. the leased connection itself fails `MaintenanceSession::assert_privileged`.
///    This is the per-call half. It does not trust the boot probe or whoever
///    attached the pool, and it asks the connection the statements will run on.
///
/// Attaching a `ScopedPool` for the write path therefore still does NOT enable
/// these tools. `tests::attaching_a_scoped_pool_does_not_enable_the_maintenance_tools`
/// pins that, and `tests::a_privileged_maintenance_pool_enables_them` pins the
/// positive arm.
///
/// Returns one [`MaintenanceSession`], which owns the connection and the viewer
/// together and hands the viewer out only by reference, so a call site cannot
/// drop the connection and keep the bypass
/// (`D-PR17-maintenance-lease-coupling-is-a-convention`). The mint is
/// `ScopedPool::maintenance_session`, shared with the CLI and API wrappers.
///
/// ```ignore
/// let mut session = maintenance::maintenance_viewer(self, SystemReason::DedupSweep).await?;
/// tools::dedup_sweep::sweep_semantic_duplicates(self, &mut session, params).await
/// ```
///
/// # Errors
///
/// An MCP internal error, in this order, naming the fix:
///
/// 1. this server was not built from a [`epigraph_db::ScopedPool`], so no
///    `MaintenanceLease` can be minted;
/// 2. no maintenance pool is attached;
/// 3. the maintenance connection could not be acquired;
/// 4. the leased connection does not satisfy `epigraph_bypass()` while row
///    security is active.
pub(crate) async fn maintenance_viewer(
    server: &EpiGraphMcpFull,
    reason: SystemReason,
) -> Result<MaintenanceSession<'_>, McpError> {
    // The messages name the offending pool as "the server's own application
    // pool" rather than spelling the field access, and that is not
    // squeamishness: `no_hybrid_bypass_spend.rs` matches the FIELD-ACCESS
    // SPELLING over comment-stripped source, and a STRING LITERAL is not
    // stripped. MEASURED: an earlier revision spelled it out and turned this
    // function into that lint's only reported offender (its known limit (b2)).
    let scoped = server.scoped.as_ref().ok_or_else(|| {
        McpError::internal_error(
            "this MCP server was not built from a ScopedPool, so no maintenance \
             lease can be minted; construct it with EpiGraphMcpFull::with_scoped_pool",
            None,
        )
    })?;
    if !scoped.has_maintenance_pool() {
        return Err(McpError::internal_error(
            "this MCP tool is a corpus-wide maintenance job and this server has no privileged \
             maintenance connection attached. Set MAINTENANCE_DATABASE_URL to a role that is a \
             member of epigraph_maintenance and restart; the boot log names why none was \
             attached. Refusing rather than running on the server's own application pool, where \
             a bypass viewer is filtered by RLS into ZERO rows with no error.",
            None,
        ));
    }
    let mut session = scoped
        .maintenance_session(reason)
        .await
        .map_err(|e| McpError::internal_error(format!("maintenance acquire failed: {e}"), None))?;
    session.assert_privileged().await.map_err(|e| {
        tracing::error!(
            target: "tenancy.maintenance",
            reason = reason.as_str(),
            error = %e,
            "maintenance tool refused: the leased maintenance connection cannot bypass RLS"
        );
        McpError::internal_error(
            format!(
                "this MCP tool's maintenance connection cannot bypass row-level security, so \
                 its statements would read and write ZERO rows with no error. Refusing. ({e})"
            ),
            None,
        )
    })?;
    Ok(session)
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
    /// Attaching a `ScopedPool` is process-wide, and the write path needs one.
    /// The three maintenance tools must NOT be enabled by that alone. With no
    /// maintenance pool attached, `ScopedPool::maintenance_session` falls back
    /// to the application pool, where a bypass viewer is filtered by RLS into
    /// zero rows with **no error**: a silent no-op replacing a loud failure.
    ///
    /// The assertion is deliberately about the REASON and not just the failure:
    /// a `None` scoped pool also refuses, and a test that accepted either error
    /// would pass on a tree where the attachment check had been deleted.
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
                        "maintenance_viewer({reason:?}) SUCCEEDED on a server with no maintenance \
                         pool attached. `maintenance_session` would then lease from the \
                         application pool and spend a bypass viewer there: zero rows, no error."
                    )
                });
            let msg = err.message.to_string();
            assert!(
                msg.contains("no privileged maintenance connection attached"),
                "maintenance_viewer({reason:?}) was refused for the WRONG reason: {msg}. \
                 Expected the missing-maintenance-pool arm, not the missing-ScopedPool one."
            );
        }
    }

    /// The positive arm: with a maintenance pool attached on a connection that
    /// satisfies `epigraph_bypass()`, the three tools get a session, and it is a
    /// bypass session on that pool. `#[sqlx::test]` connects as a superuser, for
    /// whom `epigraph_bypass()` is true, so this is the privileged case. The
    /// UNprivileged case cannot be built in this harness (every role it has
    /// bypasses) and is measured by `scripts/e2e/probe-batch-h.sh maintenance`
    /// with `MAINTENANCE_DATABASE_URL` set to the app login.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_privileged_maintenance_pool_enables_them(pool: PgPool) {
        let scoped = scoped_pool_over(&pool)
            .await
            .with_maintenance_pool(pool.clone());
        let signer = AgentSigner::from_bytes(&[0x5bu8; 32]).expect("signer");
        let embedder = McpEmbedder::new(pool.clone(), None);
        let server =
            EpiGraphMcpFull::new(pool.clone(), signer, embedder, false).with_scoped_pool(scoped);
        for reason in [
            SystemReason::DedupSweep,
            SystemReason::EmbeddingBackfill,
            SystemReason::BeliefRecomputation,
        ] {
            let session = maintenance_viewer(&server, reason)
                .await
                .unwrap_or_else(|e| {
                    panic!("maintenance_viewer({reason:?}) refused a privileged pool: {e:?}")
                });
            assert!(
                session.viewer().is_bypass(),
                "maintenance_viewer({reason:?}) must hand out the bypass viewer"
            );
        }
    }
}
