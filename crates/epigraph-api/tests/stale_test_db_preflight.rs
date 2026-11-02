//! `common::spawn_app*` refuses a test database that is not at this tree's
//! migration head, with the fresh-database procedure (backlog acffb2c4).
//!
//! The shared integration database once sat at a pre-tenancy version (no
//! `claims.visibility` / `owner_group_id`) and could not be migrated forward,
//! and the binaries that read the ambient `DATABASE_URL` do not migrate it:
//! a full run produced hundreds of failures that read like a code regression.
//! This rebuilds that shape on a private `#[sqlx::test]` database: the public
//! series up to 059 only.

mod common;

use sqlx::migrate::Migrator;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn a_pre_tenancy_database_is_refused_with_the_procedure(pool: PgPool) {
    pre_060()
        .run(&pool)
        .await
        .expect("the public series up to 059");

    let why = common::stale_test_db_reason(&pool)
        .await
        .expect("a database at 059 is not at head");
    assert!(
        why.contains("highest applied migration Some(59)")
            && why.contains("claims tenancy columns 0/2"),
        "the reason names the version and the missing tenancy columns: {why}"
    );
    assert!(why.contains(common::STALE_TEST_DB_HELP), "{why}");

    // Control: the same database migrated forward to head passes.
    let full: Migrator = sqlx::migrate!("../../migrations");
    full.run(&pool).await.expect("059 -> head");
    assert_eq!(common::stale_test_db_reason(&pool).await, None);
}

/// The refusal is wired into the shared app fixture itself: building an app on
/// the pre-tenancy database panics with the reason before any route runs.
#[sqlx::test(migrations = false)]
async fn spawn_app_refuses_a_database_below_head(pool: PgPool) {
    pre_060()
        .run(&pool)
        .await
        .expect("the public series up to 059");
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
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
    let url = format!("{prefix}/{db}");

    let refused = tokio::spawn(async move { common::spawn_app(&url).await })
        .await
        .expect_err("spawn_app must refuse a database below head");
    let panic = refused.into_panic();
    let msg = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        msg.contains("is not at this tree's migration head")
            && msg.contains(common::STALE_TEST_DB_HELP),
        "{msg}"
    );
}

/// This tree's public migration series up to 059: the last database shape
/// before the tenancy migrations.
fn pre_060() -> Migrator {
    let mut m: Migrator = sqlx::migrate!("../../migrations");
    m.migrations = m
        .iter()
        .filter(|x| x.version < 60)
        .cloned()
        .collect::<Vec<_>>()
        .into();
    m
}
