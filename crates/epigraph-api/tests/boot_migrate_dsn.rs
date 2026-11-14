#![cfg(feature = "db")]
//! `EPIGRAPH_MIGRATE_ON_BOOT` migrates on the MIGRATION DSN, not on the request
//! pool (backlog e1b96df7). Drives the compiled `server` binary.
//!
//! - With `MIGRATION_DATABASE_URL` pointing at a port nothing listens on, the
//!   server refuses to start and names the variable (without echoing the
//!   password). The application DSN is valid and the database is already
//!   migrated, so a server that still migrated on the request pool boots and
//!   serves; that is what it did before this change.
//! - With `MIGRATION_DATABASE_URL` naming an EMPTY sibling database and
//!   `DATABASE_URL` the (already migrated) test database, the sibling is the
//!   one that ends up migrated. A server that connected the migration pool but
//!   ran the migrations on the request pool leaves the sibling empty.
//!
//! The DSN-selection rule (blank is unset, the fallback) is unit-tested next
//! to `select_migration_dsn` in `src/migrate.rs`.

#[path = "common/served.rs"]
mod served;

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;

const UNREACHABLE: &str = "postgres://migrator:s3kr1t-migration-pw@127.0.0.1:1/unreachable";

#[sqlx::test(migrations = "../../migrations")]
async fn an_unreachable_migration_dsn_refuses_to_start(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let boot = tokio::task::spawn_blocking(move || {
        let mut cmd = served::base_command(&db_url);
        cmd.env("EPIGRAPH_MIGRATE_ON_BOOT", "1")
            .env("MIGRATION_DATABASE_URL", UNREACHABLE);
        served::boot(cmd)
    })
    .await
    .expect("join");
    match boot {
        served::Boot::Serving(server) => panic!(
            "the server served although its migration DSN is unreachable: it migrated on \
             the request pool:\n{}",
            server.boot_log
        ),
        served::Boot::Exited { status, log } => {
            assert_eq!(status.code(), Some(1), "{log}");
            assert!(
                log.contains("MIGRATION_DATABASE_URL") && log.contains("cannot be reached"),
                "the refusal must name the migration DSN's variable:\n{log}"
            );
            assert!(
                !log.contains("s3kr1t"),
                "the refusal echoed the migration password:\n{log}"
            );
        }
    }
}

/// `url` with its database replaced by `name` (any `?query` kept).
fn with_database(url: &str, name: &str) -> String {
    let (authority, query) = match url.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (url, None),
    };
    let prefix = authority
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("a database path")
        .0;
    match query {
        Some(q) => format!("{prefix}/{name}?{q}"),
        None => format!("{prefix}/{name}"),
    }
}

async fn applied(url: &str) -> i64 {
    let pool = PgPool::connect(url).await.expect("connect");
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename = '_sqlx_migrations'",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    let applied = if n == 0 {
        0
    } else {
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await
            .expect("count applied")
    };
    pool.close().await;
    applied
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_migrations_run_on_the_migration_dsn_not_the_request_pool(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    // An empty sibling on the same cluster (same roles, which the migrations'
    // `pg_roles` blocks read). A fresh `*_test` name: sqlx's test database
    // names already sit at NAMEDATALEN.
    let sibling = format!("migrate_dsn_{}_test", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{sibling}\""))
        .execute(&pool)
        .await
        .expect("create the empty sibling");
    let sibling_url = with_database(&db_url, &sibling);
    assert_eq!(applied(&sibling_url).await, 0, "the sibling starts empty");

    let server = tokio::task::spawn_blocking({
        let (db_url, sibling_url) = (db_url.clone(), sibling_url.clone());
        move || {
            let mut cmd = served::base_command(&db_url);
            cmd.env("EPIGRAPH_MIGRATE_ON_BOOT", "1")
                .env("MIGRATION_DATABASE_URL", &sibling_url);
            served::boot(cmd).serving()
        }
    })
    .await
    .expect("join");
    let log = server.boot_log.clone();
    drop(server);

    let migrated = applied(&sibling_url).await;
    sqlx::query(&format!("DROP DATABASE \"{sibling}\" WITH (FORCE)"))
        .execute(&pool)
        .await
        .expect("drop the sibling");

    let embedded =
        i64::try_from(epigraph_api::migrate::embedded_migration_versions().len()).expect("count");
    assert_eq!(
        migrated, embedded,
        "the migration DSN's database must carry every embedded migration; it was left \
         at {migrated}, so the migrations ran on the request pool:\n{log}"
    );
    let line = log
        .lines()
        .find(|l| l.contains("migrating on boot over the migration DSN"))
        .unwrap_or_else(|| panic!("no migration-DSN line in the boot log:\n{log}"));
    assert!(line.contains("MIGRATION_DATABASE_URL"), "{line}");
    assert!(
        !log.contains("falling back to DATABASE_URL"),
        "the migration DSN is set, so there is no fallback:\n{log}"
    );
}
