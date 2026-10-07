//! `epigraph-operator arm-admin-scopes` / `disarm-admin-scopes` (elevation plan
//! EL-9, migration 128), driven through the real binary against a
//! `#[sqlx::test]` database migrated 001 -> head, on the dedicated
//! maintenance DSN.
//!
//! What is pinned: a dry run changes and records nothing; `--apply` arms with
//! one `platform.admin_scopes_armed` event carrying the reason and the
//! database login; asking again changes and records nothing; disarming is the
//! same in reverse; a blank or missing reason is refused before anything
//! runs; the verbs run on the maintenance DSN only.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn show(&self) -> String {
        format!(
            "exit={}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

fn run_with_env(args: &[&str], set: &[(&str, &str)], remove: &[&str]) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env("RUST_LOG", "warn");
    for r in remove {
        cmd.env_remove(r);
    }
    for (k, v) in set {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Run with ONLY the dedicated DSN pointing at `pool`'s database.
async fn run_op(pool: &PgPool, args: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    run_with_env(
        args,
        &[(DSN_ENV, url.as_str())],
        &["DATABASE_URL", "MAINTENANCE_DATABASE_URL"],
    )
}

async fn armed(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT public.epigraph_admin_scopes_armed()")
        .fetch_one(pool)
        .await
        .expect("armed()")
}

async fn events(pool: &PgPool, event_type: &str) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = $1 ORDER BY created_at, id",
    )
    .bind(event_type)
    .fetch_all(pool)
    .await
    .expect("events")
}

async fn login(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(pool)
        .await
        .expect("session_user")
}

/// The whole lifecycle through the binary: dry run (nothing), arm (one
/// event), arm again (nothing), disarm dry run (nothing), disarm (one event).
///
/// Catches: the dry run committing (armed after it, or an event); `--apply`
/// not committing; the reason not reaching the audit; the verbs swapped.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_and_disarm_are_audited_and_a_dry_run_changes_nothing(pool: PgPool) {
    let who = login(&pool).await;

    let r = run_op(&pool, &["arm-admin-scopes", "--reason", "soak read zero"]).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(r.stdout.contains("WOULD BE ARMED"), "{}", r.show());
    assert!(r.stdout.contains("BEFORE\tarmed=false"), "{}", r.show());
    assert!(!armed(&pool).await, "a dry run arms nothing");
    assert!(events(&pool, "platform.admin_scopes_armed")
        .await
        .is_empty());

    let r = run_op(
        &pool,
        &["arm-admin-scopes", "--reason", "soak read zero", "--apply"],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(r.stdout.contains("ARMED\t"), "{}", r.show());
    assert!(armed(&pool).await, "applied");
    let ev = events(&pool, "platform.admin_scopes_armed").await;
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0]["reason"], "soak read zero");
    assert_eq!(ev[0]["recorded_by"], who.as_str());

    let r = run_op(&pool, &["arm-admin-scopes", "--reason", "again", "--apply"]).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(r.stdout.contains("UNCHANGED"), "{}", r.show());
    assert_eq!(events(&pool, "platform.admin_scopes_armed").await.len(), 1);

    let r = run_op(
        &pool,
        &["disarm-admin-scopes", "--reason", "a consumer broke"],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(r.stdout.contains("WOULD BE DISARMED"), "{}", r.show());
    assert!(armed(&pool).await, "a dry disarm disarms nothing");

    let r = run_op(
        &pool,
        &[
            "disarm-admin-scopes",
            "--reason",
            "a consumer broke",
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(!armed(&pool).await, "disarmed");
    let ev = events(&pool, "platform.admin_scopes_disarmed").await;
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!(ev[0]["reason"], "a consumer broke");
}

/// A blank reason is refused before anything runs, a missing one by the
/// argument parser, and the verbs run on the dedicated maintenance DSN only
/// (an inherited `DATABASE_URL` is never used).
///
/// Catches: the blank-reason check dropped (the definer would refuse too, but
/// only after connecting; the message here is the CLI's); the DSN fallback.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reason_is_required_and_only_the_maintenance_dsn_is_used(pool: PgPool) {
    let r = run_op(&pool, &["arm-admin-scopes", "--reason", "   ", "--apply"]).await;
    assert_ne!(r.code, 0, "{}", r.show());
    assert!(r.stderr.contains("--reason must say why"), "{}", r.show());
    assert!(
        !r.stderr.contains("connected as"),
        "refused before connecting: {}",
        r.show()
    );

    let r = run_op(&pool, &["arm-admin-scopes", "--apply"]).await;
    assert_eq!(r.code, 2, "clap refuses a missing --reason: {}", r.show());

    let url = fixture::database_url_for(&pool).await;
    let r = run_with_env(
        &["arm-admin-scopes", "--reason", "x", "--apply"],
        &[("DATABASE_URL", url.as_str())],
        &[DSN_ENV, "MAINTENANCE_DATABASE_URL"],
    );
    assert_ne!(r.code, 0, "{}", r.show());
    assert!(r.stderr.contains(DSN_ENV), "{}", r.show());
    assert!(!armed(&pool).await, "nothing armed");
}
