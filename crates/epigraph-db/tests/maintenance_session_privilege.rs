//! `MaintenanceSession::assert_privileged` refuses a session whose connection
//! cannot bypass row-level security, and admits one that can.
//!
//! # Why this is the check that matters
//!
//! A bypass [`Viewer`](epigraph_db::Viewer) emits no SQL predicate, so what a
//! maintenance job sees is decided by the CONNECTION alone.
//! `ScopedPool::maintenance_session` draws from whatever maintenance pool is
//! attached (or, with none, from the application pool). If that pool's role
//! cannot bypass RLS, every corpus-wide statement returns zero rows and updates
//! zero rows, and the job reports success: the privileged-viewer /
//! ordinary-pool hybrid. The MCP maintenance tools call `assert_privileged` on
//! every session they are handed, so a misconfigured pool is refused by the
//! call that would have been the silent no-op.
//!
//! `#[sqlx::test]` connects as a superuser, for whom `epigraph_bypass()` is
//! always true. The unprivileged arm therefore uses
//! `viewer_fixture::downgraded_pool`, which re-authorizes every connection as
//! `epigraph_app` (`rolbypassrls = false`, not a member of
//! `epigraph_maintenance`) on a database migrated to head, where migration 077
//! has enabled row security.

mod viewer_fixture;
use viewer_fixture as fixture;

use epigraph_db::visibility::SystemReason;
use epigraph_db::DbError;
use sqlx::PgPool;

/// The refusal arm, with its calibration: the SAME statement set run by the
/// same code on a privileged pool must pass, or the refusal proves nothing
/// about privilege (it could be a broken probe).
#[sqlx::test(migrations = "../../migrations")]
async fn a_session_on_an_unprivileged_connection_refuses_itself(pool: PgPool) {
    // Unprivileged: the maintenance pool re-authorizes as `epigraph_app`.
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let scoped = fixture::scoped_pool(&pool).await.with_maintenance_pool(app);
    let mut session = scoped
        .maintenance_session(SystemReason::BeliefRecomputation)
        .await
        .expect("a lease can be minted on any attached pool");
    let err = session.assert_privileged().await.expect_err(
        "assert_privileged ADMITTED a session whose connection is `epigraph_app` on a schema \
         with row security enabled. A bypass viewer spent there reads zero rows with no error.",
    );
    assert!(
        matches!(&err, DbError::InvalidData { reason } if reason.contains("epigraph_bypass()")),
        "refused for the wrong reason: {err:?}"
    );

    // Calibration: a privileged maintenance pool (the superuser's own) passes.
    let scoped = fixture::scoped_pool(&pool)
        .await
        .with_maintenance_pool(pool.clone());
    let mut session = scoped
        .maintenance_session(SystemReason::BeliefRecomputation)
        .await
        .expect("lease");
    let privilege = session
        .assert_privileged()
        .await
        .expect("a superuser maintenance connection satisfies epigraph_bypass()");
    assert!(
        privilege.bypass && privilege.rls_active,
        "calibration: expected a bypassing connection on an RLS-enabled schema, got \
         {privilege:?}. If rls_active is false, migration 077 did not run and the refusal arm \
         above was never testing the armed state."
    );
}
