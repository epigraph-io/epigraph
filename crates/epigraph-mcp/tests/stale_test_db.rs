//! A test database that will not migrate to head is reported, not skipped
//! (backlog acffb2c4).
//!
//! The shared integration database once sat at a pre-tenancy version with a
//! `claim_encryption` table provisioned outside the public migration series,
//! so migrating it failed closed at 060 ("already exists in a pre-060
//! shape"). `common::try_test_pool` swallowed that error with `.ok()?`, which
//! turned every test on the pool into a silent skip. This rebuilds that
//! database shape on a private `#[sqlx::test]` database: the public series up
//! to 059, plus a `claim_encryption` without 060's sentinel constraint. The
//! arms drive `common::try_test_pool_at`, the pool constructor every
//! `test_pool_or_skip!` user goes through, not just the migration helper.

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

    let url = url_of(&pool).await;
    let refused = tokio::spawn(async move { common::try_test_pool_at(&url).await.is_some() })
        .await
        .expect_err("a database that fails closed at 060 must not come back as a pool or a skip");
    let panic = refused.into_panic();
    let msg = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        msg.contains("already exists in a pre-060 shape") && msg.contains("claim_encryption"),
        "the migration error itself is reported: {msg}"
    );
    assert!(
        msg.contains(common::stale_test_db_help()),
        "with the fresh-database procedure: {msg}"
    );
}

/// Control: the same constructor on a database migrated from empty hands back
/// a pool at head, so the refusal above is about the database's shape.
#[sqlx::test(migrations = false)]
async fn a_database_migrated_from_empty_passes(pool: PgPool) {
    let url = url_of(&pool).await;
    let migrated = common::try_test_pool_at(&url)
        .await
        .expect("001 -> head from empty yields a pool");
    migrated.close().await;
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

/// Control: a database that cannot be connected to is still a skip (`None`),
/// not a panic, so the unreachable-`DATABASE_URL` behaviour is unchanged.
#[sqlx::test(migrations = false)]
async fn a_database_that_cannot_be_connected_to_is_still_a_skip(pool: PgPool) {
    let url = url_of(&pool).await;
    let (prefix, _) = url.rsplit_once('/').expect("a database path");
    let missing = format!("{prefix}/no_such_db_{}_test", uuid::Uuid::new_v4().simple());
    assert!(common::try_test_pool_at(&missing).await.is_none());
}

/// The URL of `pool`'s private `#[sqlx::test]` database: the ambient
/// `DATABASE_URL` with its database path replaced.
async fn url_of(pool: &PgPool) -> String {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    format!("{prefix}/{db}")
}
