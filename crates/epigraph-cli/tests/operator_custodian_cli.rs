//! `epigraph-operator` platform-role commands (migration 123), driven through
//! the real binary against a `#[sqlx::test]` database migrated 001 -> head, on
//! the dedicated maintenance DSN variable only:
//!
//! * `grant-role` / `end-role-assignment` / `list-role-assignments`;
//! * `epigraph-instance-admin grant|revoke`, which refuse and name them.
//!
//! Each test names the mutation it was verified against in its doc.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const INSTANCE_ADMIN_BIN: &str = env!("CARGO_BIN_EXE_epigraph-instance-admin");
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

async fn run_bin(pool: &PgPool, bin: &str, args: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(bin)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, url)
        .output()
        .expect("spawn");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn run_op(pool: &PgPool, args: &[&str]) -> Run {
    run_bin(pool, BIN, args).await
}

async fn assignments(pool: &PgPool, holder: Uuid) -> Vec<(Uuid, bool)> {
    sqlx::query_as(
        "SELECT id, revoked_at IS NULL FROM role_assignments WHERE holder_person_id = $1 \
          ORDER BY created_at",
    )
    .bind(holder)
    .fetch_all(pool)
    .await
    .expect("assignments")
}

/// The window is always explicit, and the role is a catalog role: refused
/// (exit 1) before any write when neither or both of `--valid-to` /
/// `--open-ended` are given, or the role is unknown.
///
/// Verified to fail: `Window::from_flags`' `(None, false)` arm admitting an
/// open-ended grant -> the grant with no window lands.
#[sqlx::test(migrations = "../../migrations")]
async fn grant_role_needs_an_explicit_window(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human").await;
    let holder = h.to_string();
    for (extra, what) in [
        (vec![], "no window"),
        (
            vec!["--valid-to", "2099-01-01T00:00:00Z", "--open-ended"],
            "both",
        ),
    ] {
        let mut args = vec![
            "grant-role",
            "--role",
            "role:platform-custodian",
            "--holder",
            &holder,
            "--reason",
            "test",
            "--apply",
        ];
        args.extend(extra);
        let run = run_op(&pool, &args).await;
        assert_eq!(run.code, 1, "{what}: {}", run.show());
    }
    let unknown = run_op(
        &pool,
        &[
            "grant-role",
            "--role",
            "role:superuser",
            "--holder",
            &holder,
            "--open-ended",
            "--reason",
            "test",
            "--apply",
        ],
    )
    .await;
    assert_eq!(unknown.code, 1, "an unknown role: {}", unknown.show());
    assert!(
        assignments(&pool, h).await.is_empty(),
        "nothing was granted"
    );
}

/// The round trip on the maintenance DSN: a dry-run grant writes nothing (not
/// even its audit row); `--apply` writes one assignment that `list` shows; a
/// grant to an agent is refused CUS01 (exit 1); an end is a dry run until
/// `--apply`, and a second end reports ALREADY-ENDED and changes nothing.
/// `list --role` narrows to one role, and an ended assignment is listed only
/// with `--include-ended`.
///
/// Verified to fail: `custodian::grant` committing on a dry run -> the dry run
/// writes an assignment; `custodian::end` committing on a dry run -> the dry
/// run ends it; `RoleAssignmentRepository::list` ignoring its role filter ->
/// the custodian appears under `--role role:auditor`; ignoring
/// `include_ended` -> the ended assignment is listed by default.
#[sqlx::test(migrations = "../../migrations")]
async fn grant_list_and_end_a_custodian_assignment(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    let holder = h.to_string();
    let grant = |apply: bool| {
        let mut args = vec![
            "grant-role",
            "--role",
            "role:platform-custodian",
            "--holder",
            holder.as_str(),
            "--open-ended",
            "--reason",
            "bootstrap custodian",
        ];
        if apply {
            args.push("--apply");
        }
        args
    };
    let dry = run_op(&pool, &grant(false)).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE GRANTED"), "{}", dry.show());
    assert!(
        assignments(&pool, h).await.is_empty(),
        "a dry run writes nothing"
    );
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type LIKE 'platform.%'",
    )
    .fetch_one(&pool)
    .await
    .expect("events");
    assert_eq!(events, 0, "not even its audit row");

    let applied = run_op(&pool, &grant(true)).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    let rows = assignments(&pool, h).await;
    assert_eq!(rows.len(), 1, "one assignment");
    let (id, live) = rows[0];
    assert!(live);
    let listed = run_op(&pool, &["list-role-assignments"]).await;
    assert_eq!(listed.code, 0, "{}", listed.show());
    assert!(
        listed.stdout.contains(&id.to_string()) && listed.stdout.contains(&holder),
        "{}",
        listed.show()
    );

    let agent_s = agent.to_string();
    let refused = run_op(
        &pool,
        &[
            "grant-role",
            "--role",
            "role:auditor",
            "--holder",
            &agent_s,
            "--open-ended",
            "--granted-by",
            &holder,
            "--reason",
            "an agent",
            "--apply",
        ],
    )
    .await;
    assert_eq!(refused.code, 1, "{}", refused.show());
    assert!(refused.stderr.contains("CUS01"), "{}", refused.show());

    // `--role` narrows the listing (review TST-MTC-12).
    let (h2, _) = fixture::seed_human_operator(&pool, "auditor").await;
    let h2_s = h2.to_string();
    let auditor = run_op(
        &pool,
        &[
            "grant-role",
            "--role",
            "role:auditor",
            "--holder",
            &h2_s,
            "--open-ended",
            "--granted-by",
            &holder,
            "--reason",
            "an auditor",
            "--apply",
        ],
    )
    .await;
    assert_eq!(auditor.code, 0, "{}", auditor.show());
    let id_s = id.to_string();
    let auditors = run_op(&pool, &["list-role-assignments", "--role", "role:auditor"]).await;
    assert_eq!(auditors.code, 0, "{}", auditors.show());
    assert!(
        auditors.stdout.contains(&h2_s) && !auditors.stdout.contains(&id_s),
        "--role role:auditor lists the auditor only: {}",
        auditors.show()
    );
    let custodians = run_op(
        &pool,
        &["list-role-assignments", "--role", "role:platform-custodian"],
    )
    .await;
    assert!(
        custodians.stdout.contains(&id_s) && !custodians.stdout.contains(&h2_s),
        "--role role:platform-custodian lists the custodian only: {}",
        custodians.show()
    );

    let end = |apply: bool| {
        let mut args = vec![
            "end-role-assignment",
            "--assignment",
            id_s.as_str(),
            "--reason",
            "test end",
        ];
        if apply {
            args.push("--apply");
        }
        args
    };
    let dry_end = run_op(&pool, &end(false)).await;
    assert_eq!(dry_end.code, 0, "{}", dry_end.show());
    assert!(
        dry_end.stdout.contains("WOULD BE ENDED"),
        "{}",
        dry_end.show()
    );
    assert_eq!(assignments(&pool, h).await, vec![(id, true)], "still live");
    let ended = run_op(&pool, &end(true)).await;
    assert_eq!(ended.code, 0, "{}", ended.show());
    assert_eq!(assignments(&pool, h).await, vec![(id, false)], "ended");
    let again = run_op(&pool, &end(true)).await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(again.stdout.contains("ALREADY-ENDED"), "{}", again.show());

    // An ended assignment is listed only with --include-ended.
    let live_only = run_op(&pool, &["list-role-assignments"]).await;
    assert!(
        !live_only.stdout.contains(&id_s),
        "the default listing omits an ended assignment: {}",
        live_only.show()
    );
    let all = run_op(&pool, &["list-role-assignments", "--include-ended"]).await;
    assert!(
        all.stdout.contains(&id_s),
        "--include-ended lists it: {}",
        all.show()
    );
}

/// `epigraph-instance-admin grant|revoke` refuse (exit 1) and name the
/// replacement verbs; nothing is written.
///
/// Verified to fail: the `grant` refusal removed (the old write path) -> the
/// binary reaches the frozen table.
#[sqlx::test(migrations = "../../migrations")]
async fn instance_admin_grant_and_revoke_name_their_replacements(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human").await;
    let h_s = h.to_string();
    let grant = run_bin(&pool, INSTANCE_ADMIN_BIN, &["grant", "--agent-id", &h_s]).await;
    assert_eq!(grant.code, 1, "{}", grant.show());
    assert!(
        grant.stderr.contains("epigraph-operator grant-role"),
        "{}",
        grant.show()
    );
    let revoke = run_bin(&pool, INSTANCE_ADMIN_BIN, &["revoke", "--agent-id", &h_s]).await;
    assert_eq!(revoke.code, 1, "{}", revoke.show());
    assert!(
        revoke
            .stderr
            .contains("epigraph-operator end-role-assignment"),
        "{}",
        revoke.show()
    );
    let legacy: i64 = sqlx::query_scalar("SELECT count(*) FROM instance_admins")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(legacy, 0);
    assert!(assignments(&pool, h).await.is_empty());
}
