//! `MaintenanceSession::pool` — the pool a session's connection came from.
//!
//! # Why this file exists
//!
//! `MaintenanceSession::pool` hands a `&PgPool` to callees that cannot yet take
//! a connection (the engine's retraction cascade and cached-belief recompute).
//! Its whole value is WHICH pool it returns: the privileged one the session was
//! drawn from, never the application pool beside it. A session whose `pool()`
//! returned `ScopedPool::inner` while a maintenance pool was attached would be
//! the privileged-viewer/ordinary-pool hybrid in a new place, and under row
//! security it reads zero rows and writes none, with no error.
//!
//! So the assertions are on the IDENTITY of the pool (pointer-equal to the
//! attached one, not to the application one) and on the EFFECT: under row
//! security, the bypass viewer finds a group-private row through `pool()` and
//! finds nothing when the same viewer is spent on an unprivileged pool.
//!
//! The two arms do different jobs, and only one of them pins the accessor.
//! MEASURED: making `ScopedPool::maintenance_session` hand the session
//! `&self.inner` instead of `self.maintenance_inner()` fails the identity arm
//! and leaves the effect arm green — a `#[sqlx::test]` `ScopedPool`'s `inner`
//! is the superuser pool, which bypasses too, and `ScopedPoolOptions` has no
//! `after_connect` to downgrade it. The effect arm is there to show why the
//! identity matters: the same viewer on an application-role pool sees nothing.
//!
//! # Why two DOWNGRADED pools and not the `#[sqlx::test]` pool
//!
//! `#[sqlx::test]` connects as the superuser, which bypasses every policy, so an
//! effect assertion on it passes for any pool. `fixture::downgraded_pool` issues
//! `SET SESSION AUTHORIZATION`, which changes `session_user` — the column
//! `epigraph_bypass()` reads — so `epigraph_maintenance` there really does
//! bypass and `epigraph_app` really does not.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::SystemReason;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn the_session_pool_is_the_attached_maintenance_pool(pool: PgPool) {
    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let scoped = fixture::scoped_pool(&pool)
        .await
        .with_maintenance_pool(maint);

    let mut session = scoped
        .maintenance_session(SystemReason::SchemaContractTest)
        .await
        .expect("maintenance session");

    assert!(
        std::ptr::eq(session.pool(), scoped.maintenance_inner()),
        "a session's pool() must be the pool its connection was drawn from"
    );
    assert!(
        !std::ptr::eq(session.pool(), scoped.inner()),
        "with a maintenance pool attached, pool() must NOT be the application pool: \
         that is the hybrid this accessor exists to make unreachable"
    );

    // And the pinned connection and pool() agree on who they are.
    let conn_user: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(session.conn())
        .await
        .expect("session_user on the pinned connection");
    let pool_user: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(session.pool())
        .await
        .expect("session_user on pool()");
    assert_eq!(conn_user, "epigraph_maintenance");
    assert_eq!(pool_user, "epigraph_maintenance");
}

#[sqlx::test(migrations = "../../migrations")]
async fn without_an_attached_pool_the_session_pool_is_the_one_its_connection_came_from(
    pool: PgPool,
) {
    let scoped = fixture::scoped_pool(&pool).await;
    assert!(!scoped.has_maintenance_pool());
    let session = scoped
        .maintenance_session(SystemReason::SchemaContractTest)
        .await
        .expect("maintenance session");

    // Nothing attached: the session's connection came from `inner`, so pool()
    // must be `inner` too. Anything else would split the pair across two pools.
    assert!(std::ptr::eq(session.pool(), scoped.inner()));
}

/// The effect: under row security the session's bypass viewer, spent on
/// `pool()`, reads a group-private row — and spent on an application-role pool
/// it reads nothing. The second half is the counterfactual that proves the
/// first is not vacuous.
#[sqlx::test(migrations = "../../migrations")]
async fn under_row_security_pool_reads_a_private_row_the_app_pool_cannot(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "msp-owner").await;
    let private = fixture::seed_group_claim(&pool, agent, group, "msp private claim").await;

    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let scoped = fixture::scoped_pool(&pool)
        .await
        .with_maintenance_pool(maint);
    let session = scoped
        .maintenance_session(SystemReason::SchemaContractTest)
        .await
        .expect("maintenance session");

    let via_session_pool =
        ClaimRepository::content_hashes_for(session.pool(), session.viewer(), &[private])
            .await
            .expect("read through pool()");
    assert!(
        via_session_pool.contains_key(&private),
        "the bypass viewer spent on the session's own pool must see the group-private row"
    );

    let via_app_pool = ClaimRepository::content_hashes_for(&app, session.viewer(), &[private])
        .await
        .expect("read through the application-role pool");
    assert!(
        via_app_pool.is_empty(),
        "the SAME bypass viewer on an epigraph_app pool must see nothing under row \
         security; if it sees the row, this test cannot tell the two pools apart"
    );
}
