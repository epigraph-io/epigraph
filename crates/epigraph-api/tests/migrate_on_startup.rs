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
    // The floor is the migration-file count at the time of writing (68 files,
    // 001..069 with one gap). The old floor of 26 could not notice 34
    // migrations silently failing to resolve — which is precisely the
    // cross-worktree stale-binary failure mode docs/deploy.md documents.
    // BUMP THIS TOO, or the floor stops meaning "all of them".
    assert!(
        applied >= 68,
        "expected >= 68 migrations applied, got {}",
        applied
    );

    // Version-precise: the newest migration in the tree must have applied, not
    // merely "enough of them". A stale embedded migration list passes a count
    // floor and fails this.
    //
    // BUMP THIS WITH EVERY MIGRATION. PR-02 shipped 061 and left this at 60, so
    // for one PR the comment above claimed a guarantee the assertion no longer
    // gave. PR-04 shipped 062-067; PR-05 ships 068-069, so 069 is the head.
    //
    // 063-066 are `-- no-transaction` migrations, and their bookkeeping is NOT
    // atomic with their DDL (sqlx-postgres 0.8.6 src/migrate.rs:214). Asserting
    // a head above 066 therefore also asserts that all four of them recorded a
    // row rather than dying half-applied.
    //
    // 068/069 are ordinary transactional migrations (no CREATE INDEX
    // CONCURRENTLY), which is what keeps
    // `tenancy_migration_shape.rs::no_transaction_files_contain_exactly_one_statement`
    // passing without extending its INDEX_MIGRATIONS list.
    const MIGRATION_HEAD: i64 = 69;
    let head_ok: Option<bool> =
        sqlx::query_scalar("SELECT success FROM _sqlx_migrations WHERE version = $1")
            .bind(MIGRATION_HEAD)
            .fetch_optional(&pool)
            .await
            .expect("migration-head lookup should succeed");
    assert_eq!(
        head_ok,
        Some(true),
        "migration {MIGRATION_HEAD:03} must be applied and successful"
    );

    // And every migration between 060 and the head, so a gap cannot hide behind
    // the head being present.
    let tenancy_applied: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM _sqlx_migrations WHERE success AND version BETWEEN 60 AND $1",
    )
    .bind(MIGRATION_HEAD)
    .fetch_one(&pool)
    .await
    .expect("tenancy-range count should succeed");
    assert_eq!(
        tenancy_applied,
        MIGRATION_HEAD - 60 + 1,
        "every tenancy migration 060..={MIGRATION_HEAD} must have applied"
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
