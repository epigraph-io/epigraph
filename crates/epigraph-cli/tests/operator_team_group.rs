//! `epigraph-operator create-group` and `epigraph-operator group-member
//! add|remove|set-role` (migration 164's keyless team-group verbs), driven
//! through the real binary against a `#[sqlx::test]` database migrated
//! 001 -> head.
//!
//! What is pinned: a `--kind` other than `team` and a role outside
//! reader|writer|admin are refused before any connection; a dry run writes
//! nothing, audit included; `--apply` creates exactly one keyless group and a
//! re-run with the same name is refused; and the member verbs carry a whole
//! add / set-role / remove cycle (a remove keeps the row, revoked) as a REAL
//! `NOSUPERUSER` maintenance login, with one audit row per act, while the last
//! admin's removal is refused with a non-zero exit and nothing written.

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
    let role = format!("tg_maint_{}", Uuid::new_v4().simple());
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

async fn team_groups_named(pool: &PgPool, name: &str) -> Vec<(Uuid, i32)> {
    sqlx::query_as(
        "SELECT id, octet_length(public_key) FROM groups \
          WHERE kind = 'team' AND display_name = $1 ORDER BY created_at",
    )
    .bind(name)
    .fetch_all(pool)
    .await
    .expect("team groups")
}

async fn group_audit(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type::text FROM security_events WHERE event_type LIKE 'group.%' \
          ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

/// `(role, revoked)` of every membership row of `(group, agent)`, by epoch.
async fn member_rows(pool: &PgPool, group: Uuid, agent: Uuid) -> Vec<(String, bool)> {
    sqlx::query_as(
        "SELECT role::text, revoked_at IS NOT NULL FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 ORDER BY epoch",
    )
    .bind(group)
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("member rows")
}

/// The `details->'actor'` of every `group.*` audit row, oldest first.
async fn audit_actors(pool: &PgPool) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT COALESCE(details->'actor', 'null'::jsonb) FROM security_events \
          WHERE event_type LIKE 'group.%' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("audit actors")
}

/// The `group=<uuid>` field of the first stdout line that has one.
fn group_of(run: &Run) -> Uuid {
    run.stdout
        .split(['\t', '\n'])
        .find_map(|f| f.strip_prefix("group="))
        .and_then(|v| Uuid::parse_str(v.trim()).ok())
        .unwrap_or_else(|| panic!("no group= field:\n{}", run.show()))
}

#[test]
fn a_kind_other_than_team_and_an_unknown_role_are_refused_before_connecting() {
    let admin = Uuid::new_v4().to_string();
    let r = run_with(
        &[
            "create-group",
            "--kind",
            "personal",
            "--name",
            "Synthetic Team",
            "--admin",
            &admin,
            "--reason",
            "test",
        ],
        None,
    );
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(
        r.stderr.contains("--kind") && r.stderr.contains("team"),
        "the refusal names the flag and the one valid kind: {}",
        r.show()
    );
    assert!(
        !r.stderr.contains(DSN_ENV),
        "refused before any connection was attempted: {}",
        r.show()
    );

    let group = Uuid::new_v4().to_string();
    let r = run_with(
        &[
            "group-member",
            "add",
            "--group",
            &group,
            "--agent",
            &admin,
            "--role",
            "owner",
            "--reason",
            "test",
        ],
        None,
    );
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(
        r.stderr.contains("owner") && r.stderr.contains("reader"),
        "the refusal names the bad role and the valid ones: {}",
        r.show()
    );
    assert!(!r.stderr.contains(DSN_ENV), "{}", r.show());

    // POSITIVE CONTROL: `--kind team` passes validation and only then needs
    // the DSN.
    let r = run_with(
        &[
            "create-group",
            "--kind",
            "team",
            "--name",
            "Synthetic Team",
            "--admin",
            &admin,
            "--reason",
            "test",
        ],
        None,
    );
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains(DSN_ENV), "{}", r.show());
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_group_dry_run_writes_nothing_and_apply_creates_exactly_once(pool: PgPool) {
    let (admin, _) = fixture::seed_human_operator(&pool, "cli-create-admin").await;
    let url = fixture::database_url_for(&pool).await;
    let admin_s = admin.to_string();
    let name = "Synthetic Field Team";
    let args = [
        "create-group",
        "--kind",
        "team",
        "--name",
        name,
        "--admin",
        admin_s.as_str(),
        "--reason",
        "cli test",
    ];

    let dry = run_with(&args, Some(&url));
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE CREATED"), "{}", dry.show());
    assert!(dry.stdout.contains("DRY RUN"), "{}", dry.show());
    assert!(
        team_groups_named(&pool, name).await.is_empty(),
        "a dry run created a group"
    );
    assert!(
        group_audit(&pool).await.is_empty(),
        "a dry run wrote an audit row"
    );

    let mut apply_args = args.to_vec();
    apply_args.push("--apply");
    let applied = run_with(&apply_args, Some(&url));
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(
        applied.stdout.starts_with("CREATED\t"),
        "{}",
        applied.show()
    );
    let group = group_of(&applied);
    assert_eq!(
        team_groups_named(&pool, name).await,
        [(group, 0)],
        "exactly one keyless team group"
    );
    assert_eq!(group_audit(&pool).await, ["group.team_created"]);

    // A re-run cannot mint a second group with the same name.
    let again = run_with(&apply_args, Some(&url));
    assert_eq!(again.code, 1, "{}", again.show());
    assert!(again.stderr.contains("already"), "{}", again.show());
    assert_eq!(team_groups_named(&pool, name).await.len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn member_verbs_carry_a_whole_cycle_as_a_non_superuser_maintenance_login(pool: PgPool) {
    let (admin, _) = fixture::seed_human_operator(&pool, "cli-member-admin").await;
    let (member, _) = fixture::seed_human_operator(&pool, "cli-member").await;
    let (role, dsn) = maintenance_login(&pool).await;
    let admin_s = admin.to_string();
    let member_s = member.to_string();

    let create_args = |apply: bool| {
        let mut v = vec![
            "create-group",
            "--kind",
            "team",
            "--name",
            "Synthetic Member Team",
            "--admin",
            admin_s.as_str(),
            "--reason",
            "cli test",
        ];
        if apply {
            v.push("--apply");
        }
        v
    };
    // A dry run as the NOSUPERUSER maintenance login, too.
    let dry_create = run_with(&create_args(false), Some(&dsn));
    let dry_create_left = team_groups_named(&pool, "Synthetic Member Team").await;
    let created = run_with(&create_args(true), Some(&dsn));
    let group = if created.code == 0 {
        group_of(&created)
    } else {
        drop_login(&pool, &role).await;
        panic!("create-group as a maintenance login: {}", created.show());
    };
    let group_s = group.to_string();

    let member_args = |verb: &'static str, role_arg: Option<&'static str>, apply: bool| {
        let mut v: Vec<String> = vec![
            "group-member".into(),
            verb.into(),
            "--group".into(),
            group_s.clone(),
            "--agent".into(),
            member_s.clone(),
            "--reason".into(),
            "cli test".into(),
        ];
        if let Some(r) = role_arg {
            v.push("--role".into());
            v.push(r.into());
        }
        if apply {
            v.push("--apply".into());
        }
        v
    };
    let run = |v: Vec<String>| {
        let refs: Vec<&str> = v.iter().map(String::as_str).collect();
        run_with(&refs, Some(&dsn))
    };

    let dry_add = run(member_args("add", Some("writer"), false));
    let add = run(member_args("add", Some("writer"), true));
    let dry_set = run(member_args("set-role", Some("reader"), false));
    let after_dry_set = member_rows(&pool, group, member).await;
    let set = run(member_args("set-role", Some("reader"), true));
    let dry_remove = run(member_args("remove", None, false));
    let after_dry_remove = member_rows(&pool, group, member).await;
    let audit_after_dry_remove = group_audit(&pool).await;
    let remove = run(member_args("remove", None, true));
    // The last admin cannot be removed.
    let last = run_with(
        &[
            "group-member",
            "remove",
            "--group",
            &group_s,
            "--agent",
            &admin_s,
            "--reason",
            "cli test",
            "--apply",
        ],
        Some(&dsn),
    );
    // Drop the cluster-global role BEFORE asserting, so a failure cannot leak it.
    drop_login(&pool, &role).await;

    assert_eq!(dry_create.code, 0, "{}", dry_create.show());
    assert!(
        dry_create.stdout.contains("DRY RUN"),
        "{}",
        dry_create.show()
    );
    assert!(
        dry_create_left.is_empty(),
        "a dry create as the maintenance login created a group"
    );
    assert_eq!(dry_set.code, 0, "{}", dry_set.show());
    assert!(dry_set.stdout.contains("DRY RUN"), "{}", dry_set.show());
    assert_eq!(
        after_dry_set,
        [("writer".to_string(), false)],
        "a dry set-role changed nothing"
    );
    assert_eq!(dry_remove.code, 0, "{}", dry_remove.show());
    assert!(
        dry_remove.stdout.contains("DRY RUN"),
        "{}",
        dry_remove.show()
    );
    assert_eq!(
        after_dry_remove,
        [("reader".to_string(), false)],
        "a dry remove revoked nothing"
    );
    assert_eq!(
        audit_after_dry_remove,
        [
            "group.team_created",
            "group.member_added",
            "group.member_role_set"
        ],
        "neither dry run wrote an audit row"
    );
    assert_eq!(dry_add.code, 0, "{}", dry_add.show());
    assert!(
        dry_add.stdout.contains("WOULD BE ADDED"),
        "{}",
        dry_add.show()
    );
    assert_eq!(add.code, 0, "{}", add.show());
    assert!(add.stdout.starts_with("ADDED\t"), "{}", add.show());
    assert_eq!(set.code, 0, "{}", set.show());
    assert!(set.stdout.starts_with("ROLE-SET\t"), "{}", set.show());
    assert!(set.stdout.contains("prior_role=writer"), "{}", set.show());
    assert_eq!(remove.code, 0, "{}", remove.show());
    assert!(remove.stdout.starts_with("REMOVED\t"), "{}", remove.show());
    assert_eq!(last.code, 1, "{}", last.show());
    assert!(last.stderr.contains("last live admin"), "{}", last.show());

    let rows = member_rows(&pool, group, member).await;
    assert_eq!(
        rows,
        [("reader".to_string(), true)],
        "the dry run wrote nothing and the remove kept the row, revoked"
    );
    let admin_live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_memberships WHERE group_id = $1 AND agent_id = $2 \
                          AND role = 'admin' AND revoked_at IS NULL)",
    )
    .bind(group)
    .bind(admin)
    .fetch_one(&pool)
    .await
    .expect("admin row");
    assert!(admin_live, "the refused removal left the last admin live");
    assert_eq!(
        group_audit(&pool).await,
        [
            "group.team_created",
            "group.member_added",
            "group.member_role_set",
            "group.member_removed"
        ],
        "one audit row per applied act; none for the dry run or the refusal"
    );
    // Each audit row names the PROCESS that acted, not only the shared
    // maintenance login: the tool, its version and the process's real uid
    // (from the kernel, which no environment variable changes).
    let own_uid = epigraph_cli::operator::client_scope::Operator::process_uid();
    for actor in audit_actors(&pool).await {
        assert_eq!(actor["tool"], "epigraph-operator", "{actor}");
        assert_eq!(actor["cli_version"], env!("CARGO_PKG_VERSION"), "{actor}");
        assert_eq!(
            actor["process_uid"].as_u64(),
            own_uid.map(u64::from),
            "{actor}"
        );
        assert!(actor["command"].is_string(), "{actor}");
    }
}
