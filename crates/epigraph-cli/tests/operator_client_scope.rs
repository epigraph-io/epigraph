//! `epigraph-operator grant-client-scope` / `revoke-client-scope` (batch OA1),
//! driven through the real binary against a `#[sqlx::test]` database migrated
//! 001 → head.
//!
//! What is pinned: human clients only (service and agent clients refused, with
//! nothing written); admin-only scopes only (refused before any connection);
//! both scope arrays kept consistent for the one scope, every other element
//! kept in order (the fixture's two arrays differ, as a real client's may);
//! idempotence; one `security_events` row per `--apply` with who, the client,
//! the scope and both arrays before and after; a dry run that writes nothing;
//! a grant refused to a client that is not `active` (a revoke is not); the
//! advisory environment user recorded beside the kernel's uid; the
//! maintenance-DSN-only connection; and the happy path as a real NOSUPERUSER
//! maintenance login, the shape the runbook uses.

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

fn v(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_string()).collect()
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_client(
    pool: &PgPool,
    client_type: &str,
    allowed: &[&str],
    granted: &[&str],
    agent: Option<Uuid>,
    owner: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(format!("oa1-{}", id.simple()))
    .bind(format!("oa1 {client_type} client"))
    .bind(client_type)
    .bind(v(allowed))
    .bind(v(granted))
    .bind(agent)
    .bind(owner)
    .bind((client_type == "service").then_some("OA1 Test Ltd"))
    .bind((client_type == "service").then_some("ops@example.invalid"))
    .execute(pool)
    .await
    .expect("seed client");
    id
}

async fn scopes(pool: &PgPool, client: Uuid) -> (Vec<String>, Vec<String>) {
    sqlx::query_as("SELECT allowed_scopes, granted_scopes FROM oauth_clients WHERE id = $1")
        .bind(client)
        .fetch_one(pool)
        .await
        .expect("client")
}

/// Every audit row this command wrote for `client`, oldest first:
/// `(event_type, agent_id, details)`.
async fn audit(pool: &PgPool, client: Uuid) -> Vec<(String, Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type::text, agent_id, details FROM security_events \
          WHERE event_type LIKE 'oauth.client_scope_%' \
            AND details->'client'->>'id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(client)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

async fn all_scope_audit_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type LIKE 'oauth.client_scope_%'",
    )
    .fetch_one(pool)
    .await
    .expect("count")
}

const ALLOWED: &[&str] = &["claims:read", "claims:write", "evidence:write"];
const GRANTED: &[&str] = &["claims:read", "claims:write"];

/// The dry run reports the change and writes nothing (no scope, no audit row);
/// the apply appends the scope to BOTH arrays, keeps every other element in
/// order, and writes one audit row naming who, the client, the scope and both
/// arrays before and after.
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_client_is_granted_an_admin_only_scope_with_one_audit_row(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let c = seed_client(&pool, "human", ALLOWED, GRANTED, Some(agent), None).await;
    let id = c.to_string();

    let dry = run_op(
        &pool,
        &["grant-client-scope", &id, "claims:admin", "--dry-run"],
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("DRY RUN"), "{}", dry.show());
    assert!(dry.stdout.contains("granted"), "{}", dry.show());
    assert!(dry.stdout.contains("status active"), "{}", dry.show());
    assert_eq!(scopes(&pool, c).await, (v(ALLOWED), v(GRANTED)));
    assert_eq!(
        all_scope_audit_rows(&pool).await,
        0,
        "a dry run writes nothing"
    );

    let r = run_op(
        &pool,
        &[
            "grant-client-scope",
            &id,
            "claims:admin",
            "--apply",
            "--reason",
            "oa1 test grant",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(r.stdout.contains("APPLIED"), "{}", r.show());
    let (allowed, granted) = scopes(&pool, c).await;
    assert_eq!(
        allowed,
        v(&[
            "claims:read",
            "claims:write",
            "evidence:write",
            "claims:admin"
        ])
    );
    assert_eq!(granted, v(&["claims:read", "claims:write", "claims:admin"]));

    let rows = audit(&pool, c).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (et, who, d) = &rows[0];
    assert_eq!(et, "oauth.client_scope_granted");
    assert_eq!(*who, Some(agent), "attributed to the client's principal");
    assert_eq!(d["scope"], "claims:admin");
    assert_eq!(d["changed"], true);
    assert_eq!(d["reason"], "oa1 test grant");
    assert_eq!(d["client"]["client_type"], "human");
    assert_eq!(d["before"]["allowed_scopes"], serde_json::json!(ALLOWED));
    assert_eq!(d["before"]["granted_scopes"], serde_json::json!(GRANTED));
    assert_eq!(d["after"]["allowed_scopes"], serde_json::json!(allowed));
    assert_eq!(d["after"]["granted_scopes"], serde_json::json!(granted));
    let session_user: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&pool)
        .await
        .expect("session_user");
    assert_eq!(d["operator"]["session_user"], session_user, "{d}");
    assert!(d["operator"].get("os_user").is_some(), "{d}");
    assert_eq!(d["client"]["status"], "active", "{d}");
    assert_eq!(
        d["operator"]["process_uid"],
        serde_json::json!(this_uid()),
        "the kernel's uid of the process that ran it: {d}"
    );
    assert_eq!(
        d["operator"]["login_uid"],
        serde_json::json!(this_login_uid()),
        "the kernel's audit login uid, inherited by the spawned binary: {d}"
    );
    assert!(d["operator"].get("client_addr").is_some(), "{d}");
    assert!(d["operator"].get("application_name").is_some(), "{d}");
}

/// The REAL uid of this test process, which spawns the binary under the same
/// real uid: the first field of the `Uid:` line of `/proc/self/status`.
fn this_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let line = status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .expect("a Uid: line");
    line.split_whitespace()
        .nth(1)
        .expect("the real uid field")
        .parse()
        .expect("a numeric uid")
}

/// This test process's audit login uid, which a spawned child inherits, or
/// `None` where the kernel has none (unset reads as `4294967295`).
fn this_login_uid() -> Option<u32> {
    std::fs::read_to_string("/proc/self/loginuid")
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
        .filter(|&u| u != u32::MAX)
}


/// A grant to a human client whose status is not `active` is refused, exit 1,
/// with nothing written and no audit row: it would carry the scope the moment
/// it was reactivated or approved, and anyone can register a `pending` human
/// client. A REVOKE on such a client is allowed (taking authority away is
/// always safe) and audited.
#[sqlx::test(migrations = "../../migrations")]
async fn a_grant_to_a_client_that_is_not_active_is_refused_and_a_revoke_is_not(pool: PgPool) {
    for status in ["revoked", "suspended", "pending"] {
        let c = seed_client(&pool, "human", GRANTED, GRANTED, None, None).await;
        sqlx::query("UPDATE oauth_clients SET status = $2 WHERE id = $1")
            .bind(c)
            .bind(status)
            .execute(&pool)
            .await
            .expect("set status");
        for mode in ["--dry-run", "--apply"] {
            let r = run_op(
                &pool,
                &["grant-client-scope", &c.to_string(), "claims:admin", mode],
            )
            .await;
            assert_eq!(r.code, 1, "{status} {mode}: {}", r.show());
            assert!(
                r.stderr.contains(&format!("its status is \"{status}\"")),
                "{status} {mode}: {}",
                r.show()
            );
        }
        assert_eq!(scopes(&pool, c).await, (v(GRANTED), v(GRANTED)), "{status}");
        assert!(
            audit(&pool, c).await.is_empty(),
            "{status}: nothing audited"
        );
    }

    let held = &["claims:read", "claims:admin"];
    let c = seed_client(&pool, "human", held, held, None, None).await;
    sqlx::query("UPDATE oauth_clients SET status = 'revoked' WHERE id = $1")
        .bind(c)
        .execute(&pool)
        .await
        .expect("set status");
    let r = run_op(
        &pool,
        &[
            "revoke-client-scope",
            &c.to_string(),
            "claims:admin",
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(r.stdout.contains("status revoked"), "{}", r.show());
    assert_eq!(
        scopes(&pool, c).await,
        (v(&["claims:read"]), v(&["claims:read"]))
    );
    let rows = audit(&pool, c).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].2["client"]["status"], "revoked");
}

/// The environment's user name is recorded as `os_user` and labelled advisory,
/// because anyone can set `SUDO_USER`; beside it, the audit row carries the
/// process's real uid from the kernel, which the environment cannot change,
/// and that uid's passwd name.
#[sqlx::test(migrations = "../../migrations")]
async fn the_environment_user_is_advisory_and_the_kernel_uid_is_recorded(pool: PgPool) {
    let c = seed_client(&pool, "human", GRANTED, GRANTED, None, None).await;
    let url = fixture::database_url_for(&pool).await;
    let r = run_with_env(
        &[
            "grant-client-scope",
            &c.to_string(),
            "claims:admin",
            "--apply",
        ],
        &[(DSN_ENV, url.as_str()), ("SUDO_USER", "someone-else")],
        &["DATABASE_URL", "MAINTENANCE_DATABASE_URL"],
    );
    assert_eq!(r.code, 0, "{}", r.show());
    let rows = audit(&pool, c).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let op = &rows[0].2["operator"];
    assert_eq!(op["os_user"], "someone-else", "{op}");
    assert!(
        op["os_user_source"]
            .as_str()
            .is_some_and(|s| s.contains("advisory")),
        "{op}"
    );
    let uid = this_uid();
    assert_eq!(op["process_uid"], serde_json::json!(uid), "{op}");
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let name = passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 2 && f[2] == uid.to_string()).then(|| f[0].to_string())
    });
    assert_eq!(op["process_user"], serde_json::json!(name), "{op}");
    assert_ne!(
        op["process_user"], "someone-else",
        "the kernel's user is not the spoofed one"
    );
}

/// The happy path as a REAL maintenance login: `NOSUPERUSER`, a member of
/// `epigraph_maintenance`, the shape the runbook prescribes. (Every other test
/// here connects as the cluster superuser, for which the membership check is
/// trivially true.) The grant applies to both arrays and the one audit row
/// names that login.
#[sqlx::test(migrations = "../../migrations")]
async fn the_grant_applies_as_a_non_superuser_maintenance_login(pool: PgPool) {
    let c = seed_client(&pool, "human", ALLOWED, GRANTED, None, None).await;
    let url = fixture::database_url_for(&pool).await;
    let role = format!("oa1_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(&pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    let dsn = format!("{scheme}://{role}:probe-only@{host}");
    let r = run_with_env(
        &[
            "grant-client-scope",
            &c.to_string(),
            "claims:admin",
            "--apply",
            "--reason",
            "as a maintenance login",
        ],
        &[(DSN_ENV, &dsn)],
        &["DATABASE_URL", "MAINTENANCE_DATABASE_URL"],
    );
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
    assert_eq!(r.code, 0, "{}", r.show());
    let (allowed, granted) = scopes(&pool, c).await;
    assert!(allowed.contains(&"claims:admin".to_string()), "{allowed:?}");
    assert!(granted.contains(&"claims:admin".to_string()), "{granted:?}");
    let rows = audit(&pool, c).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].2["operator"]["session_user"], role.as_str());
}

/// Granting a held scope changes nothing, and the `--apply` is still recorded
/// (`changed: false`, before == after): that is how a grant made some other
/// way is ratified. Revoking twice is the same.
#[sqlx::test(migrations = "../../migrations")]
async fn the_commands_are_idempotent_and_every_apply_is_audited(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let c = seed_client(&pool, "human", ALLOWED, GRANTED, Some(agent), None).await;
    let id = c.to_string();

    for _ in 0..2 {
        let r = run_op(
            &pool,
            &["grant-client-scope", &id, "claims:admin", "--apply"],
        )
        .await;
        assert_eq!(r.code, 0, "{}", r.show());
    }
    let after_grant = scopes(&pool, c).await;
    assert_eq!(
        after_grant
            .0
            .iter()
            .filter(|s| *s == "claims:admin")
            .count(),
        1
    );
    assert_eq!(
        after_grant
            .1
            .iter()
            .filter(|s| *s == "claims:admin")
            .count(),
        1
    );

    let again = run_op(
        &pool,
        &["grant-client-scope", &id, "claims:admin", "--dry-run"],
    )
    .await;
    assert!(again.stdout.contains("unchanged"), "{}", again.show());

    for _ in 0..2 {
        let r = run_op(
            &pool,
            &["revoke-client-scope", &id, "claims:admin", "--apply"],
        )
        .await;
        assert_eq!(r.code, 0, "{}", r.show());
    }
    assert_eq!(
        scopes(&pool, c).await,
        (v(ALLOWED), v(GRANTED)),
        "revoke restored exactly the original arrays"
    );

    let rows = audit(&pool, c).await;
    let shape: Vec<(&str, bool)> = rows
        .iter()
        .map(|(et, _, d)| (et.as_str(), d["changed"].as_bool().expect("changed")))
        .collect();
    assert_eq!(
        shape,
        vec![
            ("oauth.client_scope_granted", true),
            ("oauth.client_scope_granted", false),
            ("oauth.client_scope_revoked", true),
            ("oauth.client_scope_revoked", false),
        ]
    );
    let (_, _, noop) = &rows[1];
    assert_eq!(noop["before"], noop["after"], "{noop}");
}

/// A scope held in one array but not the other is made consistent: a grant
/// puts it in both, and a revoke takes it out of both.
#[sqlx::test(migrations = "../../migrations")]
async fn a_half_held_scope_is_made_consistent(pool: PgPool) {
    let c = seed_client(
        &pool,
        "human",
        &["claims:read", "claims:admin"],
        &["claims:read"],
        None,
        None,
    )
    .await;
    let id = c.to_string();

    let r = run_op(
        &pool,
        &["grant-client-scope", &id, "claims:admin", "--apply"],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(
        scopes(&pool, c).await,
        (
            v(&["claims:read", "claims:admin"]),
            v(&["claims:read", "claims:admin"])
        )
    );
    let rows = audit(&pool, c).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2["changed"], true);
    assert_eq!(
        rows[0].1, None,
        "a client with no agent yet: unattributed row"
    );

    let c2 = seed_client(
        &pool,
        "human",
        &["claims:read"],
        &["claims:admin"],
        None,
        None,
    )
    .await;
    let r = run_op(
        &pool,
        &[
            "revoke-client-scope",
            &c2.to_string(),
            "claims:admin",
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(scopes(&pool, c2).await, (v(&["claims:read"]), v(&[])));
}

/// Service and agent clients are refused on both commands, with nothing
/// written: not the arrays, not an audit row. The same scope on a human client
/// in the same database is accepted, so the refusal is the client's type.
#[sqlx::test(migrations = "../../migrations")]
async fn service_and_agent_clients_are_refused(pool: PgPool) {
    let human = seed_client(&pool, "human", GRANTED, GRANTED, None, None).await;
    let service = seed_client(&pool, "service", GRANTED, GRANTED, None, None).await;
    let agent = seed_client(&pool, "agent", GRANTED, GRANTED, None, Some(human)).await;
    let held = seed_client(
        &pool,
        "service",
        &["claims:admin"],
        &["claims:admin"],
        None,
        None,
    )
    .await;

    for (client, kind, cmd) in [
        (service, "service", "grant-client-scope"),
        (agent, "agent", "grant-client-scope"),
        (held, "service", "revoke-client-scope"),
    ] {
        let before = scopes(&pool, client).await;
        let r = run_op(
            &pool,
            &[cmd, &client.to_string(), "claims:admin", "--apply"],
        )
        .await;
        assert_eq!(r.code, 1, "{}", r.show());
        assert!(
            r.stderr.contains("refusing client") && r.stderr.contains(&format!("a {kind} client")),
            "{}",
            r.show()
        );
        assert_eq!(scopes(&pool, client).await, before, "nothing was written");
    }
    assert_eq!(all_scope_audit_rows(&pool).await, 0);

    let ok = run_op(
        &pool,
        &[
            "grant-client-scope",
            &human.to_string(),
            "claims:admin",
            "--apply",
        ],
    )
    .await;
    assert_eq!(ok.code, 0, "{}", ok.show());
}

/// A scope that is not admin-only is refused before any connection is made
/// (the DSN is not even set, and the error is the scope's, not the DSN's); with
/// the DSN set it is refused with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn only_admin_only_scopes_are_accepted(pool: PgPool) {
    let c = seed_client(&pool, "human", GRANTED, GRANTED, None, None).await;
    let id = c.to_string();

    let r = run_with_env(
        &["grant-client-scope", &id, "claims:write", "--apply"],
        &[],
        &[DSN_ENV, "DATABASE_URL", "MAINTENANCE_DATABASE_URL"],
    );
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("refusing scope"), "{}", r.show());
    assert!(
        !r.stderr.contains(DSN_ENV),
        "checked before connecting: {}",
        r.show()
    );

    for scope in ["claims:write", "evidence:read", "CLAIMS:ADMIN"] {
        let r = run_op(&pool, &["revoke-client-scope", &id, scope, "--apply"]).await;
        assert_eq!(r.code, 1, "{scope}: {}", r.show());
        assert!(r.stderr.contains("refusing scope"), "{}", r.show());
    }
    assert_eq!(scopes(&pool, c).await, (v(GRANTED), v(GRANTED)));
    assert_eq!(all_scope_audit_rows(&pool).await, 0);
}

/// An id that names no client is refused; a bare invocation (no mode) and one
/// with both modes are refused by the argument parser. Nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_client_and_a_missing_mode_are_refused(pool: PgPool) {
    let c = seed_client(&pool, "human", GRANTED, GRANTED, None, None).await;
    let id = c.to_string();

    let r = run_op(
        &pool,
        &[
            "grant-client-scope",
            &Uuid::new_v4().to_string(),
            "claims:admin",
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("no OAuth client has id"), "{}", r.show());

    let bare = run_op(&pool, &["grant-client-scope", &id, "claims:admin"]).await;
    assert_eq!(bare.code, 2, "{}", bare.show());
    let both = run_op(
        &pool,
        &[
            "grant-client-scope",
            &id,
            "claims:admin",
            "--dry-run",
            "--apply",
        ],
    )
    .await;
    assert_eq!(both.code, 2, "{}", both.show());

    assert_eq!(scopes(&pool, c).await, (v(GRANTED), v(GRANTED)));
    assert_eq!(all_scope_audit_rows(&pool).await, 0);
}

/// The command never falls back to `DATABASE_URL` or
/// `MAINTENANCE_DATABASE_URL`, and a login outside `epigraph_maintenance` is
/// refused. Nothing is written either way.
#[sqlx::test(migrations = "../../migrations")]
async fn it_runs_on_the_maintenance_dsn_only(pool: PgPool) {
    let c = seed_client(&pool, "human", GRANTED, GRANTED, None, None).await;
    let id = c.to_string();
    let url = fixture::database_url_for(&pool).await;

    let r = run_with_env(
        &["grant-client-scope", &id, "claims:admin", "--apply"],
        &[("DATABASE_URL", &url), ("MAINTENANCE_DATABASE_URL", &url)],
        &[DSN_ENV],
    );
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(
        r.stderr
            .contains("EPIGRAPH_OPERATOR_MAINTENANCE_DSN is not set"),
        "{}",
        r.show()
    );

    let role = format!("oa1_probe_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE ROLE {role} LOGIN PASSWORD 'probe-only'"))
        .execute(&pool)
        .await
        .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    let probe = format!("{scheme}://{role}:probe-only@{host}");
    let r = run_with_env(
        &["grant-client-scope", &id, "claims:admin", "--apply"],
        &[(DSN_ENV, &probe)],
        &["DATABASE_URL", "MAINTENANCE_DATABASE_URL"],
    );
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(
        r.stderr.contains("is not a member of epigraph_maintenance"),
        "{}",
        r.show()
    );
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop role");

    assert_eq!(scopes(&pool, c).await, (v(GRANTED), v(GRANTED)));
    assert_eq!(all_scope_audit_rows(&pool).await, 0);
}
