//! `epigraph-operator retire-link` (backlog 4dec90c2, migration 191), driven
//! through the real binary against a `#[sqlx::test]` database migrated 001 ->
//! head, as a real NOSUPERUSER maintenance login.
//!
//! What is pinned: the dry run changes nothing and records nothing; `--apply`
//! on an agent that still holds its writer row in the operator's group is
//! REFUSED (exit 1, the definer's OLR03 and its hint printed, nothing
//! written); `--apply --revoke-membership` retires the live link, revokes the
//! row and writes one `operator.link_retired` audit row naming the login and
//! the reason; a repeat prints ALREADY-RETIRED, exits 0 and writes nothing; an
//! agent with no link prints NO-LINK and exits 1 (a mistyped id).

mod viewer_fixture;

use epigraph_db::AgentRepository;
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

fn run_dsn(args: &[&str], dsn: &str) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, dsn)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A fresh NOSUPERUSER login in `epigraph_maintenance`: `(role, dsn)`. The
/// caller drops the role before asserting.
async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("retire_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    (role.clone(), format!("{scheme}://{role}:probe-only@{host}"))
}

/// `(link retired?, live writer/admin rows in the operator group, retire audit rows)`.
async fn state(pool: &PgPool, agent: Uuid, group: Uuid) -> (Option<bool>, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT retired FROM operator_links WHERE agent_id = $1), \
                (SELECT count(*) FROM group_memberships \
                  WHERE group_id = $2 AND agent_id = $1 AND revoked_at IS NULL \
                    AND role IN ('writer', 'admin')), \
                (SELECT count(*) FROM security_events \
                  WHERE agent_id = $1 AND event_type = 'operator.link_retired')",
    )
    .bind(agent)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("state")
}

/// The whole verb, end to end, on one live-linked agent.
///
/// Verified to fail: the dry run committing -> its "nothing changed"
/// assertion fails; `--revoke-membership` not passed through -> the second
/// apply is refused OLR03.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_link_retires_a_live_link_once_and_audits_it(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "retire-cli-human").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "retire-cli-agent").await;
    let (stray, _) = fixture::seed_agent_with_group(&pool, "retire-cli-stray").await;
    let mut conn = pool.acquire().await.expect("acquire");
    let link = AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("live link");
    drop(conn);
    let group = link.operator_group_id;
    assert_eq!(
        state(&pool, agent, group).await,
        (Some(false), 1, 0),
        "PREMISE: a live link with its writer row, unaudited"
    );

    let (role, dsn) = maintenance_login(&pool).await;
    let a = agent.to_string();
    let s = stray.to_string();
    let base = [
        "retire-link",
        "--agent",
        a.as_str(),
        "--reason",
        "key retired",
    ];
    let with = |extra: &[&'static str]| {
        let mut v: Vec<&str> = base.to_vec();
        v.extend_from_slice(extra);
        v
    };

    let dry = run_dsn(&with(&["--revoke-membership"]), &dsn);
    let dry_state = state(&pool, agent, group).await;
    let refused = run_dsn(&with(&["--apply"]), &dsn);
    let refused_state = state(&pool, agent, group).await;
    let applied = run_dsn(&with(&["--apply", "--revoke-membership"]), &dsn);
    let applied_state = state(&pool, agent, group).await;
    let again = run_dsn(&with(&["--apply", "--revoke-membership"]), &dsn);
    let again_state = state(&pool, agent, group).await;
    let none = run_dsn(
        &[
            "retire-link",
            "--agent",
            s.as_str(),
            "--reason",
            "x",
            "--apply",
        ],
        &dsn,
    );
    let recorded_by: Option<String> = sqlx::query_scalar(
        "SELECT details ->> 'recorded_by' FROM security_events \
          WHERE agent_id = $1 AND event_type = 'operator.link_retired'",
    )
    .bind(agent)
    .fetch_optional(&pool)
    .await
    .expect("audit row");
    let rolsuper: bool = sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = $1")
        .bind(&role)
        .fetch_one(&pool)
        .await
        .expect("role row");
    // Drop the cluster-global role BEFORE asserting, so a failure cannot leak it.
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop role");
    assert!(!rolsuper, "fixture: the login is not a superuser");

    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE RETIRED"), "{}", dry.show());
    assert!(
        dry.stdout.contains("memberships_revoked=1"),
        "{}",
        dry.show()
    );
    assert_eq!(dry_state, (Some(false), 1, 0), "a dry run changes nothing");

    assert_eq!(refused.code, 1, "{}", refused.show());
    assert!(refused.stderr.contains("OLR03"), "{}", refused.show());
    assert!(
        refused.stderr.contains("--revoke-membership"),
        "the refusal names the remedy: {}",
        refused.show()
    );
    assert_eq!(
        refused_state,
        (Some(false), 1, 0),
        "a refusal changes nothing"
    );

    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(
        applied.stdout.starts_with("RETIRED\t"),
        "{}",
        applied.show()
    );
    assert_eq!(applied_state, (Some(true), 0, 1));
    assert_eq!(recorded_by.as_deref(), Some(role.as_str()));

    assert_eq!(again.code, 0, "a repeat is idempotent: {}", again.show());
    assert!(
        again.stdout.starts_with("ALREADY-RETIRED\t"),
        "{}",
        again.show()
    );
    assert_eq!(again_state, applied_state, "a repeat writes nothing");

    assert_eq!(none.code, 1, "{}", none.show());
    assert!(none.stdout.starts_with("NO-LINK\t"), "{}", none.show());
}
