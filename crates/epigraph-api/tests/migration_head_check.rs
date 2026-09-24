//! Issue #492: `epigraph-migrate` must not report `migrations: ok` unless the
//! database is at this binary's embedded head, and must refuse a database that
//! is AHEAD of it unless the operator opts in to the rollback case.
//!
//! Each arm gets a fresh `#[sqlx::test(migrations = false)]` database so the
//! migration state is exactly what the arm constructs. The "stale binary" is
//! reproduced the way the issue measured it: the real embedded set truncated at
//! version 59, run through the same `run_migrator` code path production uses.
//!
//! The last two arms spawn the real `epigraph-migrate` binary, so the exit code
//! and the stdout marker ops scripts grep for are tested, not just the library.
//!
//! Non-macro `sqlx::query*` forms only: CI builds with `SQLX_OFFLINE=true`.

use std::borrow::Cow;
use std::process::Command;

use epigraph_api::migrate::{
    embedded_migration_versions, run_migrator, MigrateOptions, MigrationError, ALLOW_DB_AHEAD_ENV,
    ALLOW_DB_AHEAD_FLAG,
};
use sqlx::PgPool;

/// The head the issue's stale binary stopped at.
const STALE_HEAD: i64 = 59;

const STRICT: MigrateOptions = MigrateOptions {
    allow_db_ahead: false,
};
const ALLOW_AHEAD: MigrateOptions = MigrateOptions {
    allow_db_ahead: true,
};

fn binary_head() -> i64 {
    *embedded_migration_versions()
        .last()
        .expect("embedded migration set is empty")
}

/// The real embedded set, truncated to `<= head` — a binary built before
/// migration `head + 1` existed.
fn stale_migrator(head: i64) -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!("../../migrations");
    m.migrations = Cow::Owned(
        m.migrations
            .iter()
            .filter(|x| x.version <= head)
            .cloned()
            .collect(),
    );
    m.set_ignore_missing(true);
    m
}

async fn successful_versions(pool: &PgPool) -> Vec<i64> {
    sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
        .fetch_all(pool)
        .await
        .expect("read _sqlx_migrations")
}

/// Record a migration a NEWER build applied: a successful row above this
/// binary's head, with every NOT NULL column populated.
async fn record_future_migration(pool: &PgPool, version: i64) {
    sqlx::query(
        "INSERT INTO _sqlx_migrations \
             (version, description, success, checksum, execution_time) \
         VALUES ($1, 'applied by a newer build (#492 test)', true, '\\x00'::bytea, 1)",
    )
    .bind(version)
    .execute(pool)
    .await
    .expect("insert future migration row");
}

#[sqlx::test(migrations = false)]
async fn database_at_head_is_ok_and_applies_nothing(pool: PgPool) {
    let first = epigraph_api::run_migrations(&pool, STRICT)
        .await
        .expect("fresh database migrates");
    assert_eq!(first.db_head_before, None);
    assert_eq!(first.db_head, binary_head());
    assert_eq!(first.applied_this_run, embedded_migration_versions().len());

    let again = epigraph_api::run_migrations(&pool, STRICT)
        .await
        .expect("database at head is ok");
    assert_eq!(again.db_head_before, Some(binary_head()));
    assert_eq!(again.db_head, binary_head());
    assert_eq!(again.binary_head, binary_head());
    assert_eq!(again.applied_this_run, 0);
    assert!(!again.db_ahead);
}

#[sqlx::test(migrations = false)]
async fn database_behind_is_migrated_to_the_binary_head(pool: PgPool) {
    // The #492 measurement: a stale binary on an empty database stops at 59.
    let stale = run_migrator(&stale_migrator(STALE_HEAD), &pool, STRICT)
        .await
        .expect("stale binary reaches ITS head");
    assert_eq!((stale.db_head, stale.binary_head), (STALE_HEAD, STALE_HEAD));

    // The current binary then takes it the rest of the way, and says so.
    let r = epigraph_api::run_migrations(&pool, STRICT)
        .await
        .expect("behind database migrates to head");
    assert_eq!(r.db_head_before, Some(STALE_HEAD));
    assert_eq!(r.db_head, binary_head());
    let expected_new = embedded_migration_versions()
        .into_iter()
        .filter(|v| *v > STALE_HEAD)
        .count();
    assert!(expected_new > 0, "tree has nothing above {STALE_HEAD}");
    assert_eq!(r.applied_this_run, expected_new);

    let applied = successful_versions(&pool).await;
    for v in embedded_migration_versions() {
        assert!(applied.contains(&v), "embedded migration {v} not applied");
    }
}

#[sqlx::test(migrations = false)]
async fn database_ahead_of_binary_is_refused_before_applying_anything(pool: PgPool) {
    // A database a newer build migrated: at 59, plus a row above even the
    // CURRENT head, so the current binary is the stale one here.
    run_migrator(&stale_migrator(STALE_HEAD), &pool, STRICT)
        .await
        .expect("seed to 59");
    let future = binary_head() + 1;
    record_future_migration(&pool, future).await;
    let before = successful_versions(&pool).await;

    let err = epigraph_api::run_migrations(&pool, STRICT)
        .await
        .expect_err("a database ahead of the binary must be refused");
    match &err {
        MigrationError::DbAheadOfBinary {
            db_head,
            binary_head: bh,
            ahead,
        } => {
            assert_eq!(*db_head, future);
            assert_eq!(*bh, binary_head());
            assert_eq!(ahead, &vec![future]);
        }
        other => panic!("expected DbAheadOfBinary, got {other:?}"),
    }
    let msg = err.to_string();
    for needle in [
        future.to_string(),
        binary_head().to_string(),
        ALLOW_DB_AHEAD_FLAG.to_string(),
        ALLOW_DB_AHEAD_ENV.to_string(),
    ] {
        assert!(msg.contains(&needle), "refusal lacks {needle:?}: {msg}");
    }

    // Refused BEFORE running: 60..=head were pending and none was applied.
    assert_eq!(successful_versions(&pool).await, before);
}

#[sqlx::test(migrations = false)]
async fn database_ahead_proceeds_when_opted_in(pool: PgPool) {
    run_migrator(&stale_migrator(STALE_HEAD), &pool, STRICT)
        .await
        .expect("seed to 59");
    let future = binary_head() + 1;
    record_future_migration(&pool, future).await;

    let r = epigraph_api::run_migrations(&pool, ALLOW_AHEAD)
        .await
        .expect("opt-in proceeds");
    assert!(r.db_ahead, "report must flag the database as ahead");
    assert_eq!(r.db_head, future);
    assert_eq!(r.binary_head, binary_head());
    // Rollback semantics: pending migrations at or below the binary head are
    // still applied; the newer row is left in place.
    let applied = successful_versions(&pool).await;
    for v in embedded_migration_versions() {
        assert!(applied.contains(&v), "embedded migration {v} not applied");
    }
    assert!(applied.contains(&future));
}

// ---------------------------------------------------------------------------
// The real binary
// ---------------------------------------------------------------------------

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-migrate");

/// Connection URL for `pool`'s database: the ambient `DATABASE_URL` authority
/// with the `#[sqlx::test]` database name spliced in.
async fn database_url_for(pool: &PgPool) -> String {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database()");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let (authority, query) = match base.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (base.as_str(), None),
    };
    let prefix = authority
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0;
    match query {
        Some(q) => format!("{prefix}/{db}?{q}"),
        None => format!("{prefix}/{db}"),
    }
}

/// Run `epigraph-migrate` against `pool`'s database. BOTH DSN variables are
/// set, because the binary prefers `MIGRATION_DATABASE_URL` and `Command::env`
/// only adds to an inherited environment; the opt-in variable is removed unless
/// `allow_env` so an ambient value cannot decide the outcome.
async fn run_bin(pool: &PgPool, args: &[&str], allow_env: bool) -> (i32, String, String) {
    let url = database_url_for(pool).await;
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env("DATABASE_URL", &url)
        .env("MIGRATION_DATABASE_URL", &url)
        .env("RUST_LOG", "warn");
    if allow_env {
        cmd.env(ALLOW_DB_AHEAD_ENV, "1");
    } else {
        cmd.env_remove(ALLOW_DB_AHEAD_ENV);
    }
    let out = cmd.output().expect("spawn epigraph-migrate");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[sqlx::test(migrations = false)]
async fn binary_reports_both_heads_on_success(pool: PgPool) {
    let (code, stdout, stderr) = run_bin(&pool, &[], false).await;
    assert_eq!(code, 0, "stderr: {stderr}");
    let head = binary_head();
    let n = embedded_migration_versions().len();
    assert!(
        stdout.contains(&format!(
            "migrations: ok db_head={head} binary_head={head} applied={n}"
        )),
        "stdout: {stdout}"
    );

    let (code, stdout, stderr) = run_bin(&pool, &[], false).await;
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains(&format!(
            "migrations: ok db_head={head} binary_head={head} applied=0"
        )),
        "stdout: {stdout}"
    );
}

#[sqlx::test(migrations = false)]
async fn binary_refuses_a_database_ahead_and_honours_both_opt_ins(pool: PgPool) {
    let (code, _, stderr) = run_bin(&pool, &[], false).await;
    assert_eq!(code, 0, "initial migrate failed: {stderr}");
    let future = binary_head() + 1;
    record_future_migration(&pool, future).await;

    // Strict: nonzero, and the ops marker must NOT appear.
    let (code, stdout, stderr) = run_bin(&pool, &[], false).await;
    assert_ne!(code, 0, "a stale binary must not exit 0; stdout: {stdout}");
    assert!(
        !stdout.contains("migrations: ok"),
        "refusal printed the success marker: {stdout}"
    );
    for needle in [
        future.to_string(),
        binary_head().to_string(),
        ALLOW_DB_AHEAD_FLAG.to_string(),
        ALLOW_DB_AHEAD_ENV.to_string(),
    ] {
        assert!(
            stderr.contains(&needle),
            "stderr lacks {needle:?}: {stderr}"
        );
    }

    // Opt-in by flag, then by env: exit 0, a WARNING, and the marker flags it.
    for (args, env) in [(&[ALLOW_DB_AHEAD_FLAG][..], false), (&[][..], true)] {
        let (code, stdout, stderr) = run_bin(&pool, args, env).await;
        assert_eq!(
            code, 0,
            "opt-in (args={args:?}, env={env}) failed: {stderr}"
        );
        assert!(stderr.contains("WARNING"), "no warning: {stderr}");
        assert!(
            stdout.contains(&format!("migrations: ok db_head={future}"))
                && stdout.contains("db_ahead_of_binary=allowed"),
            "stdout: {stdout}"
        );
    }
}
