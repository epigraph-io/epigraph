#![cfg(feature = "db")]
//! The pgvector floor (backlog e30316ae), through the production code paths.
//!
//! No test database can be downgraded below the floor (pgvector ships upgrade
//! scripts only), so the migrator's refusal is driven by raising the floor
//! through `run_migrator_with_pgvector_floor`, the same path `run_migrations`
//! takes with the real floor. The server's refusal is driven by the state a
//! real deployment can be in: a database the extension was never created in.
//!
//! The version comparison and every verdict are unit-tested in
//! `epigraph-db/src/pgvector.rs`.
//!
//! Verified to fail on the parent commit: there `run_migrator` applies every
//! migration whatever the pgvector version, and the server boots past the
//! migration block on an empty database and fails later, on the entity-type
//! cache, without naming pgvector.

#[path = "common/served.rs"]
mod served;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::migrate::{
    embedded_migration_versions, run_migrator_with_pgvector_floor, MigrateOptions, MigrationError,
};
use epigraph_db::pgvector::{read_state, Refusal, State, Version, PGVECTOR_FLOOR};
use sqlx::PgPool;

/// A floor no released pgvector meets.
const UNMET: Version = Version {
    major: 99,
    minor: 0,
    patch: 0,
};

fn migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!("../../migrations");
    m.set_ignore_missing(true);
    m
}

#[sqlx::test(migrations = false)]
async fn the_test_server_meets_the_real_floor(pool: PgPool) {
    // CALIBRATION for the arms below: the real floor passes here, so a refusal
    // under UNMET is the floor, not this server.
    match read_state(&pool).await.expect("read pgvector state") {
        State::NotInstalled { default_version } => {
            assert!(
                Version::parse(&default_version).is_some_and(|v| v >= PGVECTOR_FLOOR),
                "this test server's pgvector is {default_version}, below the floor"
            );
        }
        other => panic!("a fresh test database must not have pgvector yet: {other:?}"),
    }
}

#[sqlx::test(migrations = false)]
async fn a_fresh_database_below_the_floor_is_refused_before_anything_is_applied(pool: PgPool) {
    let err =
        run_migrator_with_pgvector_floor(&migrator(), &pool, MigrateOptions::default(), UNMET)
            .await
            .expect_err("an unmet floor must refuse");
    let MigrationError::Pgvector(Refusal::AvailableTooOld { found, floor }) = &err else {
        panic!("expected the available-too-old refusal, got {err}");
    };
    assert_eq!(*floor, UNMET);
    assert!(err.to_string().contains(found.as_str()), "{err}");
    let table: Option<String> = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations')::text")
        .fetch_one(&pool)
        .await
        .expect("regclass");
    assert_eq!(
        table, None,
        "the refusal came after migrations were applied"
    );
    assert!(
        matches!(read_state(&pool).await.unwrap(), State::NotInstalled { .. }),
        "the extension was created: something ran"
    );
}

#[sqlx::test(migrations = false)]
async fn an_installed_extension_below_the_floor_is_refused_and_says_alter_extension(pool: PgPool) {
    // Migrate with the real floor first (the calibration that the path works),
    // then re-run against the unmet one.
    let report = run_migrator_with_pgvector_floor(
        &migrator(),
        &pool,
        MigrateOptions::default(),
        PGVECTOR_FLOOR,
    )
    .await
    .expect("the real floor passes on this server");
    assert_eq!(
        Some(report.binary_head),
        embedded_migration_versions().last().copied()
    );
    let err =
        run_migrator_with_pgvector_floor(&migrator(), &pool, MigrateOptions::default(), UNMET)
            .await
            .expect_err("an unmet floor must refuse");
    assert!(
        matches!(
            err,
            MigrationError::Pgvector(Refusal::InstalledTooOld { .. })
        ),
        "{err}"
    );
    assert!(
        err.to_string().contains("ALTER EXTENSION vector UPDATE"),
        "{err}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_server_refuses_a_database_without_pgvector(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let boot = tokio::task::spawn_blocking(move || served::boot(served::base_command(&db_url)))
        .await
        .expect("join");
    match boot {
        served::Boot::Serving(server) => {
            panic!("served an unmigrated database:\n{}", server.boot_log)
        }
        served::Boot::Exited { status, log } => {
            assert_eq!(status.code(), Some(1), "{log}");
            assert!(
                log.contains("pgvector extension is not installed in this database"),
                "the refusal must name pgvector:\n{log}"
            );
        }
    }
}
