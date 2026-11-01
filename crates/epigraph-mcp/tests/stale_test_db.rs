//! A test database that will not migrate to head is reported, not skipped
//! (backlog acffb2c4).
//!
//! The shared integration database once sat at a pre-tenancy version with a
//! `claim_encryption` table provisioned outside the public migration series,
//! so migrating it failed closed at 060 ("already exists in a pre-060
//! shape"). `common::try_test_pool` swallowed that error with `.ok()?`, which
//! turned every test on the pool into a silent skip. This rebuilds that
//! database shape on a private `#[sqlx::test]` database: the public series up
//! to 059, plus a `claim_encryption` without 060's sentinel constraint.

mod common;

use sqlx::migrate::Migrator;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn a_database_that_fails_closed_at_060_is_reported_with_the_procedure(pool: PgPool) {
    let full: Migrator = sqlx::migrate!("../../migrations");
    let mut pre_060 = sqlx::migrate!("../../migrations");
    pre_060.migrations = full
        .iter()
        .filter(|m| m.version < 60)
        .cloned()
        .collect::<Vec<_>>()
        .into();
    pre_060
        .run(&pool)
        .await
        .expect("the public series up to 059");
    sqlx::query("CREATE TABLE public.claim_encryption (claim_id uuid PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("a claim_encryption provisioned outside the series");

    let why = common::migrate_test_db(&pool)
        .await
        .expect_err("a database that fails closed at 060 must not pass as migrated");
    assert!(
        why.contains("already exists in a pre-060 shape") && why.contains("claim_encryption"),
        "the migration error itself is reported: {why}"
    );
    assert!(
        why.contains(common::stale_test_db_help()),
        "with the fresh-database procedure: {why}"
    );
}

/// Control: the same helper on a database migrated from empty succeeds, so
/// the refusal above is about the database's shape, not the helper.
#[sqlx::test(migrations = false)]
async fn a_database_migrated_from_empty_passes(pool: PgPool) {
    common::migrate_test_db(&pool)
        .await
        .expect("001 -> head from empty");
    let tenancy_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'claims' \
            AND column_name IN ('visibility', 'owner_group_id')",
    )
    .fetch_one(&pool)
    .await
    .expect("columns");
    assert_eq!(tenancy_columns, 2);
}
