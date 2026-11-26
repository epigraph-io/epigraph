//! A `ScopedPool` with NO maintenance pool attached issues no maintenance
//! connection (backlog e27ad9b6).
//!
//! `ScopedPool::unscoped_for_maintenance` (and `maintenance_session`, which is
//! built on it) used to fall back to the APPLICATION pool when nothing was
//! attached. Under row security a bypass viewer spent on that connection
//! emits no predicate but is still filtered by the policies, so a maintenance
//! read returned ZERO rows and reported success. A request-serving process
//! holds no maintenance DSN and attaches no maintenance pool, so the fallback
//! was exactly the silent-empty shape. Now the pool refuses with a typed error.
//!
//! The refusal is observed on a pool built by the PRODUCTION constructor
//! (`ScopedPool::connect`), on a `#[sqlx::test]` superuser DSN: the fallback
//! would have SUCCEEDED here (the superuser connection is even privileged), so
//! an `Err` can only come from the refusal, never from a failed connect or
//! an unprivileged role.

mod viewer_fixture;
use viewer_fixture as fixture;

use epigraph_db::visibility::SystemReason;
use epigraph_db::{DbError, ScopedPool, SessionGucMode};
use sqlx::PgPool;

async fn production_pool(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
    )
    .await
    .expect("ScopedPool::connect over the test database")
}

/// No maintenance pool attached: both entry points refuse with
/// `MaintenancePoolNotAttached`, naming the reason asked for.
#[sqlx::test(migrations = "../../migrations")]
async fn a_pool_with_no_maintenance_pool_refuses_maintenance(pool: PgPool) {
    let scoped = production_pool(&pool).await;
    assert!(
        !scoped.has_maintenance_pool(),
        "fixture: the production constructor attaches no maintenance pool"
    );

    let Err(err) = scoped
        .unscoped_for_maintenance(SystemReason::BeliefRecomputation)
        .await
    else {
        panic!(
            "unscoped_for_maintenance issued a connection from a pool with NO maintenance pool \
             attached: it fell back to the application pool, where a bypass viewer reads zero \
             rows under row security with no error"
        );
    };
    assert!(
        matches!(
            err,
            DbError::MaintenancePoolNotAttached { reason } if reason == "belief_recomputation"
        ),
        "refused, but not as MaintenancePoolNotAttached naming the reason: {err:?}"
    );

    let Err(err) = scoped
        .maintenance_session(SystemReason::EmbeddingBackfill)
        .await
    else {
        panic!("maintenance_session must refuse the same way");
    };
    assert!(
        matches!(
            err,
            DbError::MaintenancePoolNotAttached { reason } if reason == "embedding_backfill"
        ),
        "maintenance_session refused, but not as MaintenancePoolNotAttached: {err:?}"
    );
}

/// Calibration for the refusal: the SAME production-built pool, once a
/// maintenance pool is attached, issues the connection, and it is the
/// attached pool's (proved by attaching a pool on a different role).
#[sqlx::test(migrations = "../../migrations")]
async fn an_attached_maintenance_pool_is_used(pool: PgPool) {
    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let scoped = production_pool(&pool).await.with_maintenance_pool(maint);
    assert!(scoped.has_maintenance_pool());
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(SystemReason::BeliefRecomputation)
        .await
        .expect("an attached maintenance pool issues the connection");
    let user: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *conn)
        .await
        .expect("session_user");
    assert_eq!(
        user, "epigraph_maintenance",
        "the connection must come from the ATTACHED pool, not the application pool"
    );
}

/// The test-support opt-in restores the application-pool fallback for a
/// single-role test database WITHOUT reporting a maintenance pool, so a
/// request-serving surface that gates on `has_maintenance_pool` still answers
/// "not served" in tests.
#[sqlx::test(migrations = "../../migrations")]
async fn the_test_opt_in_falls_back_without_claiming_a_maintenance_pool(pool: PgPool) {
    let scoped = production_pool(&pool)
        .await
        .with_application_pool_maintenance_for_tests();
    assert!(
        !scoped.has_maintenance_pool(),
        "the test opt-in must not turn a gated maintenance surface on"
    );
    let session = scoped
        .maintenance_session(SystemReason::SchemaContractTest)
        .await
        .expect("the opt-in draws from the application pool");
    assert!(session.viewer().is_bypass());
}
