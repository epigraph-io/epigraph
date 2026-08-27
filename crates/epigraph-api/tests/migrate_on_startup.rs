//! Verifies that `run_migrations` — the step `epigraph-migrate` runs before the
//! API serves traffic, and that `bin/server.rs` runs only under
//! `EPIGRAPH_MIGRATE_ON_BOOT` — applies every pending migration against an empty
//! DB. Uses sqlx::test with no pre-applied migrations.
//!
//! The gate itself (`should_migrate_on_boot`) is unit-tested in
//! `crates/epigraph-api/src/lib.rs`; server startup no longer migrates by
//! default, so nothing here may be named for that behaviour.
//!
//! Uses non-macro `sqlx::query`/`query_scalar` forms to avoid extending the
//! offline (`.sqlx/`) prepare cache for a single test (CI runs with
//! `SQLX_OFFLINE=true`).

use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn run_migrations_applies_all_from_empty(pool: PgPool) {
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
    // The floor is the migration-file count at the time of writing (59 files,
    // 001..060 with one gap). The old floor of 26 could not notice 34
    // migrations silently failing to resolve — which is precisely the
    // cross-worktree stale-binary failure mode docs/deploy.md documents.
    assert!(
        applied >= 59,
        "expected >= 59 migrations applied, got {}",
        applied
    );

    // Version-precise: the newest migration in the tree must have applied, not
    // merely "enough of them". A stale embedded migration list passes a count
    // floor and fails this.
    let head_ok: Option<bool> =
        sqlx::query_scalar("SELECT success FROM _sqlx_migrations WHERE version = 60")
            .fetch_optional(&pool)
            .await
            .expect("migration-head lookup should succeed");
    assert_eq!(
        head_ok,
        Some(true),
        "migration 060 must be applied and successful"
    );

    // Spot-check a known table from a recent migration.
    let claims: Option<String> = sqlx::query_scalar("SELECT to_regclass('public.claims')::text")
        .fetch_one(&pool)
        .await
        .expect("regclass lookup should succeed");
    assert!(claims.is_some(), "claims table should exist");

    // ...and one 060 created, so this test fails if 060 resolves but no-ops.
    let ce: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.claim_encryption')::text")
            .fetch_one(&pool)
            .await
            .expect("regclass lookup should succeed");
    assert!(ce.is_some(), "claim_encryption table should exist");
}
