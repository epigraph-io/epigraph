//! `epigraph-operator define-group-role`, `bind-group-role`,
//! `end-group-role-binding` and `group-roster` (migration 165's role-derived
//! group membership), and `grant-role` reading the role catalog instead of a
//! fixed list, driven through the real binary against a `#[sqlx::test]`
//! database migrated 001 -> head, as a REAL `NOSUPERUSER` maintenance login.
//!
//! What is pinned: a member role outside reader|writer is refused before any
//! connection; a dry run writes nothing (catalog, binding and audit
//! included); `--apply` defines the role, binds it, and lets `grant-role`
//! grant it (a role the old fixed list did not know); the roster names the
//! holder; an end is applied once and reported as already ended after; and a
//! binding of an elevating or audit-reading role is refused with a non-zero
//! exit and nothing written.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const ROLE: &str = "role:team-member";

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

fn run_with(args: &[&str], dsn: Option<&str>) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env_remove(DSN_ENV);
    if let Some(dsn) = dsn {
        cmd.env(DSN_ENV, dsn);
    }
    let out = cmd.output().expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Create a NOSUPERUSER login in `epigraph_maintenance` and return
/// `(role, dsn)`. The caller drops the role.
async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("gr_maint_{}", Uuid::new_v4().simple());
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

async fn drop_login(pool: &PgPool, role: &str) {
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(pool)
        .await
        .expect("drop role");
}

async fn team_group(pool: &PgPool, name: &str, admin: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, 'cli test')")
        .bind(name)
        .bind(admin)
        .fetch_one(pool)
        .await
        .expect("team group")
}

async fn catalog_has(pool: &PgPool, key: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM platform_roles WHERE key = $1)")
        .bind(key)
        .fetch_one(pool)
        .await
        .expect("catalog")
}

/// `(id, live)` of every binding of `group`.
async fn bindings(pool: &PgPool, group: Uuid) -> Vec<(Uuid, bool)> {
    sqlx::query_as(
        "SELECT id, revoked_at IS NULL FROM group_role_bindings WHERE group_id = $1 \
          ORDER BY created_at",
    )
    .bind(group)
    .fetch_all(pool)
    .await
    .expect("bindings")
}

async fn binding_audit(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type::text FROM security_events \
          WHERE event_type LIKE 'platform.group_role_%' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("audit")
}

/// `details.actor.command` of the one `event_type` row whose `details->>key`
/// is `value`: which operator command the audit row says acted.
async fn audit_command(pool: &PgPool, event_type: &str, key: &str, value: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT details->'actor'->>'command' FROM security_events \
          WHERE event_type = $1 AND details->>$2 = $3",
    )
    .bind(event_type)
    .bind(key)
    .bind(value)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("one {event_type} row with {key} = {value}: {e}"))
}

/// `binding=<uuid>` from a verb's output.
fn binding_of(run: &Run) -> Uuid {
    run.stdout
        .split_whitespace()
        .find_map(|w| w.strip_prefix("binding="))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no binding= in the output: {}", run.show()))
}

/// The whole cycle on a NOSUPERUSER maintenance login: a dry-run define
/// writes nothing; `--apply` defines and binds (one audit row); `grant-role`
/// grants the newly defined role; the roster names its holder; the end is
/// applied once and then reported as already ended; the roster is then empty.
#[sqlx::test(migrations = "../../migrations")]
async fn define_grant_roster_and_end_on_a_maintenance_login(pool: PgPool) {
    let (owner, _) = fixture::seed_human_operator(&pool, "cli-owner").await;
    let (h, _) = fixture::seed_human_operator(&pool, "cli-holder").await;
    let group = team_group(&pool, "Synthetic CLI Team", owner).await;
    let (login, dsn) = maintenance_login(&pool).await;
    let g = group.to_string();
    let define = |apply: bool| {
        let mut args = vec![
            "define-group-role",
            "--key",
            ROLE,
            "--description",
            "synthetic team role",
            "--group",
            &g,
            "--member-role",
            "writer",
            "--include-agents",
            "--reason",
            "cli test",
        ];
        if apply {
            args.push("--apply");
        }
        run_with(&args, Some(&dsn))
    };

    let dry = define(false);
    assert_eq!(dry.code, 0, "dry run: {}", dry.show());
    assert!(dry.stdout.contains("WOULD BE BOUND"), "{}", dry.show());
    assert!(!catalog_has(&pool, ROLE).await, "a dry run defines nothing");
    assert!(
        bindings(&pool, group).await.is_empty(),
        "a dry run binds nothing"
    );
    assert!(binding_audit(&pool).await.is_empty(), "nor audits");
    let defined_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'platform.role_defined'",
    )
    .fetch_one(&pool)
    .await
    .expect("role_defined rows");
    assert_eq!(defined_rows, 0, "a dry run records no definition either");

    let applied = define(true);
    assert_eq!(applied.code, 0, "apply: {}", applied.show());
    let binding = binding_of(&applied);
    assert!(catalog_has(&pool, ROLE).await, "defined");
    assert_eq!(bindings(&pool, group).await, [(binding, true)]);
    assert_eq!(binding_audit(&pool).await, ["platform.group_role_bound"]);
    assert_eq!(
        audit_command(
            &pool,
            "platform.group_role_bound",
            "binding_id",
            &binding.to_string()
        )
        .await
        .as_deref(),
        Some("define-group-role"),
        "the bound row names the acting command, not only the shared login"
    );
    assert_eq!(
        audit_command(&pool, "platform.role_defined", "role", ROLE)
            .await
            .as_deref(),
        Some("define-group-role"),
        "defining the role is recorded, with its acting command"
    );

    let holder = h.to_string();
    let grant = run_with(
        &[
            "grant-role",
            "--role",
            ROLE,
            "--holder",
            &holder,
            "--open-ended",
            "--reason",
            "cli test",
            "--apply",
        ],
        Some(&dsn),
    );
    assert_eq!(grant.code, 0, "grant of a defined role: {}", grant.show());

    let roster = run_with(&["group-roster", "--group", &g], Some(&dsn));
    assert_eq!(roster.code, 0, "{}", roster.show());
    assert!(
        roster.stdout.contains(&format!("agent={h}")) && roster.stdout.contains("role=writer"),
        "the holder is on the roster: {}",
        roster.show()
    );

    let b = binding.to_string();
    let end = |apply: bool| {
        let mut args = vec![
            "end-group-role-binding",
            "--binding",
            &b,
            "--reason",
            "cli test end",
        ];
        if apply {
            args.push("--apply");
        }
        run_with(&args, Some(&dsn))
    };
    let dry_end = end(false);
    assert_eq!(dry_end.code, 0, "{}", dry_end.show());
    assert!(
        dry_end.stdout.contains("WOULD BE ENDED"),
        "{}",
        dry_end.show()
    );
    assert_eq!(
        bindings(&pool, group).await,
        [(binding, true)],
        "a dry end ends nothing"
    );
    let ended = end(true);
    assert_eq!(ended.code, 0, "{}", ended.show());
    assert!(ended.stdout.contains("ENDED"), "{}", ended.show());
    assert_eq!(
        audit_command(&pool, "platform.group_role_unbound", "binding_id", &b)
            .await
            .as_deref(),
        Some("end-group-role-binding"),
        "the unbound row names the acting command"
    );
    assert_eq!(bindings(&pool, group).await, [(binding, false)]);
    let again = end(true);
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(again.stdout.contains("ALREADY-ENDED"), "{}", again.show());
    assert_eq!(
        binding_audit(&pool).await,
        ["platform.group_role_bound", "platform.group_role_unbound"]
    );
    let empty = run_with(&["group-roster", "--group", &g], Some(&dsn));
    assert_eq!(empty.code, 0, "{}", empty.show());
    assert!(
        !empty.stdout.contains(&format!("agent={h}")),
        "nobody after the end: {}",
        empty.show()
    );

    drop_login(&pool, &login).await;
}

/// A member role outside reader|writer is refused before any connection (no
/// DSN is even configured); binding an audit-reading or elevating role is
/// refused by the database (GRB01) with a non-zero exit and nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn refusals_write_nothing(pool: PgPool) {
    let (owner, _) = fixture::seed_human_operator(&pool, "cli-ref-owner").await;
    let group = team_group(&pool, "Synthetic CLI Refusal Team", owner).await;
    let g = group.to_string();
    let admin = run_with(
        &[
            "define-group-role",
            "--key",
            ROLE,
            "--description",
            "d",
            "--group",
            &g,
            "--member-role",
            "admin",
            "--reason",
            "r",
            "--apply",
        ],
        None,
    );
    assert_ne!(admin.code, 0, "{}", admin.show());
    assert!(admin.stderr.contains("--member-role"), "{}", admin.show());

    let (login, dsn) = maintenance_login(&pool).await;
    for role in ["role:auditor", "role:platform-custodian"] {
        let run = run_with(
            &[
                "bind-group-role",
                "--role",
                role,
                "--group",
                &g,
                "--member-role",
                "reader",
                "--reason",
                "r",
                "--apply",
            ],
            Some(&dsn),
        );
        assert_ne!(run.code, 0, "{role}: {}", run.show());
        assert!(run.stderr.contains("GRB01"), "{role}: {}", run.show());
    }
    assert!(bindings(&pool, group).await.is_empty());
    assert!(binding_audit(&pool).await.is_empty());
    drop_login(&pool, &login).await;
}

/// Migration 179's mode through the CLI: `--agent-mode attached_agents` is
/// recorded as the attached mode (and printed); `--agent-mode registered_agents`
/// is 165's `include_agents`; an unknown mode is refused before any connection
/// (no DSN is configured), and so is `--agent-mode` together with
/// `--include-agents` (one choice), each with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn the_agent_mode_flag_binds_each_mode_and_refuses_the_rest(pool: PgPool) {
    let (owner, _) = fixture::seed_human_operator(&pool, "cli-mode-owner").await;
    let attached_group = team_group(&pool, "Synthetic CLI Attached Team", owner).await;
    let registered_group = team_group(&pool, "Synthetic CLI Registered Team", owner).await;
    let (ag, rg) = (attached_group.to_string(), registered_group.to_string());

    let refused = |extra: &'static [&'static str]| {
        let mut args = vec![
            "bind-group-role",
            "--role",
            "role:auditor",
            "--group",
            &ag,
            "--member-role",
            "reader",
            "--reason",
            "r",
            "--apply",
        ];
        args.extend_from_slice(extra);
        run_with(&args, None)
    };
    let unknown = refused(&["--agent-mode", "everyone"]);
    assert_ne!(unknown.code, 0, "{}", unknown.show());
    assert!(
        unknown.stderr.contains("--agent-mode"),
        "{}",
        unknown.show()
    );
    let both = refused(&["--agent-mode", "attached_agents", "--include-agents"]);
    assert_ne!(both.code, 0, "{}", both.show());

    let (login, dsn) = maintenance_login(&pool).await;
    let define = run_with(
        &[
            "define-group-role",
            "--key",
            ROLE,
            "--description",
            "synthetic team role",
            "--group",
            &ag,
            "--member-role",
            "writer",
            "--agent-mode",
            "attached_agents",
            "--reason",
            "cli mode test",
            "--apply",
        ],
        Some(&dsn),
    );
    assert_eq!(define.code, 0, "{}", define.show());
    assert!(
        define.stdout.contains("agent_mode=attached_agents"),
        "{}",
        define.show()
    );
    let bind = run_with(
        &[
            "bind-group-role",
            "--role",
            ROLE,
            "--group",
            &rg,
            "--member-role",
            "reader",
            "--agent-mode",
            "registered_agents",
            "--reason",
            "cli mode test",
            "--apply",
        ],
        Some(&dsn),
    );
    assert_eq!(bind.code, 0, "{}", bind.show());
    let flags = |binding: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (bool, bool)>(
                "SELECT include_agents, attached_agents FROM group_role_bindings WHERE id = $1",
            )
            .bind(binding)
            .fetch_one(&pool)
            .await
            .expect("binding flags")
        }
    };
    assert_eq!(flags(binding_of(&define)).await, (false, true), "attached");
    assert_eq!(flags(binding_of(&bind)).await, (true, false), "registered");
    assert_eq!(
        binding_audit(&pool).await,
        ["platform.group_role_bound", "platform.group_role_bound"],
        "the two refusals wrote nothing"
    );
    drop_login(&pool, &login).await;
}
