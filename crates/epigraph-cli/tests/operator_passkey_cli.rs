//! `epigraph-operator` passkey commands (migration 124), driven through the
//! real binary against a `#[sqlx::test]` database migrated 001 -> head, on the
//! dedicated maintenance DSN variable only:
//!
//! * `passkey-enroll` opens a maintenance enrollment ticket and prints the
//!   ceremony PATH (never a host: the public base URL is deployment config);
//! * `list-passkeys` / `revoke-passkey`, the break-glass revoke.
//!
//! Every write is a dry run unless `--apply`. Each test names the mutation it
//! was verified against in its doc.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
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

async fn run_op(pool: &PgPool, args: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
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

async fn enrollments(pool: &PgPool, person: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM passkey_enrollments WHERE person_agent_id = $1 ORDER BY created_at",
    )
    .bind(person)
    .fetch_all(pool)
    .await
    .expect("enrollments")
}

async fn platform_events(pool: &PgPool, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type = $1")
        .bind(event_type)
        .fetch_one(pool)
        .await
        .expect("events")
}

/// A live passkey for `person`, registered through 124's definers on the
/// harness connection (standing in for the ceremony, which is the API's).
async fn registered_passkey(pool: &PgPool, person: Uuid, n: u8) -> Uuid {
    let e: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_create_passkey_enrollment($1, 'cli test', 'cli key')",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("enroll");
    sqlx::query(
        "SELECT public.epigraph_set_passkey_enrollment_challenge($1, '{\"rs\": {}}'::jsonb)",
    )
    .bind(e)
    .execute(pool)
    .await
    .expect("challenge");
    let mut cred = vec![0x5A_u8; 16];
    cred[0] = n;
    sqlx::query_scalar(
        "SELECT public.epigraph_complete_passkey_enrollment($1, $2, '{\"cred\": {}}'::jsonb, \
                '00000000-0000-0000-0000-000000000000'::uuid, 'none', true, false)",
    )
    .bind(e)
    .bind(cred)
    .fetch_one(pool)
    .await
    .expect("complete")
}

/// A dry run writes nothing, not even the audit row, and prints the would-be
/// ticket; `--apply` writes one live ticket for the person and prints its
/// ceremony PATH, `/elevate/enroll/<id>` of the row it wrote, and no host.
/// `--label` is recorded on the ticket.
///
/// Verified to fail: `operator::passkey::enroll` committing on a dry run ->
/// the dry run writes a ticket; the printed path built from the person id
/// instead of the ticket id -> the path names no ticket.
#[sqlx::test(migrations = "../../migrations")]
async fn passkey_enroll_is_a_dry_run_until_apply(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human").await;
    let person = h.to_string();
    let enroll = |apply: bool| {
        let mut args = vec![
            "passkey-enroll",
            "--person",
            person.as_str(),
            "--reason",
            "first passkey",
            "--label",
            "desk key",
        ];
        if apply {
            args.push("--apply");
        }
        args
    };

    let dry = run_op(&pool, &enroll(false)).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE ENROLLED"), "{}", dry.show());
    assert!(dry.stdout.contains("DRY RUN"), "{}", dry.show());
    assert!(
        enrollments(&pool, h).await.is_empty(),
        "a dry run writes nothing"
    );
    assert_eq!(
        platform_events(&pool, "platform.passkey_enrollment_created").await,
        0,
        "not even its audit row"
    );

    let applied = run_op(&pool, &enroll(true)).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    let rows = enrollments(&pool, h).await;
    assert_eq!(rows.len(), 1, "one ticket");
    let id = rows[0];
    assert!(
        applied
            .stdout
            .contains(&format!("ceremony=/elevate/enroll/{id}")),
        "the path of the ticket written: {}",
        applied.show()
    );
    assert!(
        !applied.stdout.contains("http"),
        "a path, never a host: {}",
        applied.show()
    );
    let (label, live): (Option<String>, bool) = sqlx::query_as(
        "SELECT label, consumed_at IS NULL AND now() < expires_at \
           FROM passkey_enrollments WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .expect("the ticket");
    assert_eq!(label.as_deref(), Some("desk key"));
    assert!(live, "the ticket is live");
    assert_eq!(
        platform_events(&pool, "platform.passkey_enrollment_created").await,
        1,
        "audited once"
    );
}

/// An enrollment for an agent is refused by the table's ELV01 (exit 1, the
/// code on stderr), and nothing is written.
///
/// Verified to fail: the binary mapping a refused enrollment to exit 0 (the
/// error printed, the code dropped) -> exit 0.
#[sqlx::test(migrations = "../../migrations")]
async fn passkey_enroll_refuses_an_agent(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    let agent_s = agent.to_string();
    let refused = run_op(
        &pool,
        &[
            "passkey-enroll",
            "--person",
            &agent_s,
            "--reason",
            "an agent",
            "--apply",
        ],
    )
    .await;
    assert_eq!(refused.code, 1, "{}", refused.show());
    assert!(refused.stderr.contains("ELV01"), "{}", refused.show());
    assert!(
        enrollments(&pool, agent).await.is_empty(),
        "nothing written"
    );
}

/// `list-passkeys` lists live passkeys (of one person with `--person`); a
/// revoke is a dry run until `--apply`, which revokes it and writes
/// `platform.passkey_revoked`; a revoked passkey is listed only with
/// `--include-revoked`; a second revoke reports ALREADY-REVOKED and changes
/// nothing; an unknown id is refused (exit 1).
///
/// Verified to fail: `operator::passkey::revoke` committing on a dry run ->
/// the dry run revokes it; `PasskeyRepository::list` ignoring its person
/// filter -> the other person's passkey is listed; ignoring
/// `include_revoked` -> the revoked passkey is listed by default.
#[sqlx::test(migrations = "../../migrations")]
async fn list_and_revoke_a_passkey(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "human").await;
    let (other, _) = fixture::seed_human_operator(&pool, "other").await;
    let key = registered_passkey(&pool, h, 1).await;
    let other_key = registered_passkey(&pool, other, 2).await;
    let (key_s, other_s, person) = (key.to_string(), other_key.to_string(), h.to_string());

    let listed = run_op(&pool, &["list-passkeys", "--person", &person]).await;
    assert_eq!(listed.code, 0, "{}", listed.show());
    assert!(
        listed.stdout.contains(&key_s) && !listed.stdout.contains(&other_s),
        "--person lists that person's passkeys only: {}",
        listed.show()
    );
    let all = run_op(&pool, &["list-passkeys"]).await;
    assert!(
        all.stdout.contains(&key_s) && all.stdout.contains(&other_s),
        "{}",
        all.show()
    );

    let revoke = |apply: bool| {
        let mut args = vec![
            "revoke-passkey",
            "--id",
            key_s.as_str(),
            "--reason",
            "lost the device",
        ];
        if apply {
            args.push("--apply");
        }
        args
    };
    let live = |pool: PgPool| async move {
        sqlx::query_scalar::<_, bool>(
            "SELECT revoked_at IS NULL FROM person_authenticators WHERE id = $1",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .expect("the passkey")
    };
    let dry = run_op(&pool, &revoke(false)).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE REVOKED"), "{}", dry.show());
    assert!(live(pool.clone()).await, "a dry run revokes nothing");
    assert_eq!(
        platform_events(&pool, "platform.passkey_revoked").await,
        0,
        "not even its audit row"
    );

    let applied = run_op(&pool, &revoke(true)).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(applied.stdout.contains("REVOKED"), "{}", applied.show());
    assert!(!live(pool.clone()).await, "revoked");
    assert_eq!(
        platform_events(&pool, "platform.passkey_revoked").await,
        1,
        "audited"
    );

    let hidden = run_op(&pool, &["list-passkeys", "--person", &person]).await;
    assert!(
        !hidden.stdout.contains(&key_s),
        "a revoked passkey is not listed by default: {}",
        hidden.show()
    );
    let shown = run_op(
        &pool,
        &["list-passkeys", "--person", &person, "--include-revoked"],
    )
    .await;
    assert!(shown.stdout.contains(&key_s), "{}", shown.show());

    let again = run_op(&pool, &revoke(true)).await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(again.stdout.contains("ALREADY-REVOKED"), "{}", again.show());
    assert_eq!(
        platform_events(&pool, "platform.passkey_revoked").await,
        1,
        "a second revoke writes nothing"
    );

    let unknown = Uuid::new_v4().to_string();
    let missing = run_op(
        &pool,
        &[
            "revoke-passkey",
            "--id",
            &unknown,
            "--reason",
            "x",
            "--apply",
        ],
    )
    .await;
    assert_eq!(missing.code, 1, "{}", missing.show());
}
