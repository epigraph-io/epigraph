//! Verifies that the API binary applies pending migrations against an empty DB
//! before serving traffic. Uses sqlx::test with no pre-applied migrations.
//!
//! Uses non-macro `sqlx::query`/`query_scalar` forms to avoid extending the
//! offline (`.sqlx/`) prepare cache for a single test (CI runs with
//! `SQLX_OFFLINE=true`).

use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn server_startup_applies_migrations(pool: PgPool) {
    // Pre-condition: no _sqlx_migrations table.
    let pre: Option<String> = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations')::text")
        .fetch_one(&pool)
        .await
        .expect("regclass lookup should succeed");
    assert!(pre.is_none(), "test fixture must start clean");

    // Invoke the production migration step the same way server.rs will.
    epigraph_api::run_migrations(&pool)
        .await
        .expect("run_migrations should succeed against empty DB");

    let applied: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM _sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await
            .expect("count query should succeed");
    assert!(
        applied >= 26,
        "expected >= 26 migrations applied, got {}",
        applied
    );

    // Spot-check a known table from a recent migration.
    let claims: Option<String> = sqlx::query_scalar("SELECT to_regclass('public.claims')::text")
        .fetch_one(&pool)
        .await
        .expect("regclass lookup should succeed");
    assert!(claims.is_some(), "claims table should exist");
}
