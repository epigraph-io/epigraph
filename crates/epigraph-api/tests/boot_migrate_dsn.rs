#![cfg(feature = "db")]
//! `EPIGRAPH_MIGRATE_ON_BOOT` migrates on the MIGRATION DSN, not on the request
//! pool (backlog e1b96df7). Drives the compiled `server` binary.
//!
//! - With `MIGRATION_DATABASE_URL` pointing at a port nothing listens on, the
//!   server refuses to start and names the variable (without echoing the
//!   password). The application DSN is valid and the database is already
//!   migrated, so a server that still migrated on the request pool boots and
//!   serves; that is what it did before this change.
//! - With `MIGRATION_DATABASE_URL` valid, it serves and its log names the
//!   variable it migrated over.
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

#[sqlx::test(migrations = "../../migrations")]
async fn a_reachable_migration_dsn_is_the_one_migrated_over(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let server = tokio::task::spawn_blocking(move || {
        let mut cmd = served::base_command(&db_url);
        cmd.env("EPIGRAPH_MIGRATE_ON_BOOT", "1")
            .env("MIGRATION_DATABASE_URL", &db_url);
        served::boot(cmd).serving()
    })
    .await
    .expect("join");
    let log = &server.boot_log;
    let line = log
        .lines()
        .find(|l| l.contains("migrating on boot over the migration DSN"))
        .unwrap_or_else(|| panic!("no migration-DSN line in the boot log:\n{log}"));
    assert!(line.contains("MIGRATION_DATABASE_URL"), "{line}");
    assert!(log.contains("Migrations up to date"), "{log}");
    assert!(
        !log.contains("falling back to DATABASE_URL"),
        "the migration DSN is set, so there is no fallback:\n{log}"
    );
}
