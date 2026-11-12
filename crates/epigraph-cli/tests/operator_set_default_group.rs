//! `epigraph-operator set-default-group` (migration 209), driven through the
//! real binary against a `#[sqlx::test]` database migrated 001 -> head, as a
//! real NOSUPERUSER maintenance login.
//!
//! What is pinned: the dry run executes the definer and changes and records
//! nothing; `--apply` sets every listed agent private in one transaction, one
//! audit row each, attributed to `--operator` with the login in
//! `session_user`; a list that includes an agent the operator holds only a
//! RETIRED link to is refused (exit 1, VIS05) and changes NONE of the listed
//! agents; an `--operator` that does not operate the agent is refused the
//! same way; an `--operator` that is not a registered human operator is
//! refused before the definer runs, so `--operator X --agent X` cannot set an
//! arbitrary agent's default as its own (self) act; `--group` replaces a
//! private default with a team; and exactly one of `--group` / `--private` /
//! `--clear` is required.

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

/// A fresh NOSUPERUSER login in `epigraph_maintenance`: `(role, dsn)`.
async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("defgrp_maint_{}", Uuid::new_v4().simple());
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

/// `(default_group_id, default_private)` of each agent.
async fn defaults(pool: &PgPool, agents: &[Uuid]) -> Vec<(Option<Uuid>, bool)> {
    let mut out = Vec::new();
    for a in agents {
        out.push(
            sqlx::query_as("SELECT default_group_id, default_private FROM agents WHERE id = $1")
                .bind(a)
                .fetch_one(pool)
                .await
                .expect("default"),
        );
    }
    out
}

/// `(agent_id, via, session_user)` of the 209 audit rows naming `target`.
async fn audit(pool: &PgPool, target: Uuid) -> Vec<(Option<Uuid>, String, String)> {
    sqlx::query_as(
        "SELECT agent_id, details->>'via', details->>'session_user' FROM security_events \
          WHERE event_type = 'agent.default_group_set' \
            AND details->>'target_agent_id' = $1::text ORDER BY created_at, id",
    )
    .bind(target)
    .fetch_all(pool)
    .await
    .expect("audit")
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_default_group_acts_only_on_the_live_operators_authority(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "defgrp-human").await;
    let (stranger, _) = fixture::seed_human_operator(&pool, "defgrp-stranger").await;
    let (c1, _) = fixture::seed_agent_with_group(&pool, "defgrp-c1").await;
    let (c2, _) = fixture::seed_agent_with_group(&pool, "defgrp-c2").await;
    let (old, _) = fixture::seed_agent_with_group(&pool, "defgrp-retired").await;
    let team = Uuid::new_v4();
    let key: Vec<u8> = team.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, 'ndi', 'did:epigraph:test-team:' || $1::text, $2, 'team')",
    )
    .bind(team)
    .bind(&key)
    .execute(&pool)
    .await
    .expect("team");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(team)
    .bind(human)
    .execute(&pool)
    .await
    .expect("membership");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        for a in [c1, c2] {
            AgentRepository::link_operator(&mut conn, a, human)
                .await
                .expect("live link");
        }
        AgentRepository::link_retired_agent(&mut conn, old, human)
            .await
            .expect("retired link");
    }

    let (role, dsn) = maintenance_login(&pool).await;
    let (h, st, a1, a2, r, t) = (
        human.to_string(),
        stranger.to_string(),
        c1.to_string(),
        c2.to_string(),
        old.to_string(),
        team.to_string(),
    );
    let both: Vec<&str> = vec![
        "set-default-group",
        "--operator",
        &h,
        "--agent",
        &a1,
        "--agent",
        &a2,
    ];
    let with = |base: &[&str], extra: &[&str]| -> Vec<String> {
        base.iter().chain(extra).map(|x| (*x).to_string()).collect()
    };
    let go = |args: Vec<String>| {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        run_dsn(&a, &dsn)
    };

    let dry = go(with(&both, &["--private"]));
    let dry_state = defaults(&pool, &[c1, c2]).await;
    let dry_audit = audit(&pool, c1).await.len();
    let applied = go(with(&both, &["--private", "--apply"]));
    let applied_state = defaults(&pool, &[c1, c2]).await;
    let applied_audit = audit(&pool, c1).await;
    let mixed = go(with(
        &[
            "set-default-group",
            "--operator",
            &h,
            "--agent",
            &a1,
            "--agent",
            &r,
        ],
        &["--clear", "--apply"],
    ));
    let mixed_state = defaults(&pool, &[c1, old]).await;
    let foreign = go(with(
        &["set-default-group", "--operator", &st, "--agent", &a1],
        &["--clear", "--apply"],
    ));
    let foreign_state = defaults(&pool, &[c1]).await;
    let as_itself = go(with(
        &["set-default-group", "--operator", &a2, "--agent", &a2],
        &["--clear", "--apply"],
    ));
    let as_itself_state = defaults(&pool, &[c2]).await;
    let team_run = go(with(
        &["set-default-group", "--operator", &h, "--agent", &a1],
        &["--group", &t, "--apply"],
    ));
    let team_state = defaults(&pool, &[c1]).await;
    let no_mode = go(with(&both, &["--apply"]));
    let two_modes = go(with(&both, &["--private", "--clear"]));

    let rolsuper: bool = sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = $1")
        .bind(&role)
        .fetch_one(&pool)
        .await
        .expect("role row");
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop role");
    assert!(!rolsuper, "fixture: the login is not a superuser");

    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains(&format!(
            "WOULD BE SET\tagent={c1}\tvia=operator\toperator={human}\tprevious=none\tnow=private"
        )),
        "{}",
        dry.show()
    );
    assert!(dry.stdout.contains("DRY RUN"), "{}", dry.show());
    assert_eq!(dry_state, vec![(None, false), (None, false)], "dry run");
    assert_eq!(dry_audit, 0, "a dry run records nothing");

    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(
        applied
            .stdout
            .contains(&format!("SET\tagent={c2}\tvia=operator")),
        "{}",
        applied.show()
    );
    assert_eq!(applied_state, vec![(None, true), (None, true)]);
    assert_eq!(
        applied_audit,
        vec![(Some(human), "operator".to_string(), role.clone())],
        "one row, attributed to the operator, naming the login"
    );

    assert_eq!(mixed.code, 1, "{}", mixed.show());
    assert!(
        mixed.stdout.contains(&format!("REFUSED\tagent={old}")) && mixed.stdout.contains("VIS05"),
        "{}",
        mixed.show()
    );
    assert_eq!(
        mixed_state,
        vec![(None, true), (None, false)],
        "all or nothing: c1 was cleared in the same transaction and rolled back"
    );

    assert_eq!(foreign.code, 1, "{}", foreign.show());
    assert!(foreign.stdout.contains("VIS05"), "{}", foreign.show());
    assert_eq!(foreign_state, vec![(None, true)]);

    assert_eq!(as_itself.code, 1, "{}", as_itself.show());
    assert!(
        as_itself.stdout.contains(&format!(
            "REFUSED\toperator={c2}\tnot a registered live human operator"
        )),
        "{}",
        as_itself.show()
    );
    assert_eq!(
        as_itself_state,
        vec![(None, true)],
        "a non-human --operator naming itself changes nothing"
    );

    assert_eq!(team_run.code, 0, "{}", team_run.show());
    assert!(
        team_run
            .stdout
            .contains(&format!("previous=private\tnow=team:{team}")),
        "{}",
        team_run.show()
    );
    assert_eq!(team_state, vec![(Some(team), false)]);

    assert_eq!(no_mode.code, 2, "clap refuses no mode: {}", no_mode.show());
    assert_eq!(two_modes.code, 2, "clap refuses two: {}", two_modes.show());
}
