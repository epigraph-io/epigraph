//! `epigraph-operator approve-client` (backlog f33bb29f item 3), driven through
//! the real binary against a `#[sqlx::test]` database migrated 001 -> head, on
//! a REAL `NOSUPERUSER` maintenance login (migration 188 left EXECUTE on the
//! approval definer to its owner, `epigraph_maintenance`).
//!
//! What is pinned: a pending client named by its `client_id` STRING is mapped
//! to its row; a dry run approves nothing and audits nothing; `--apply` makes
//! it `active` with exactly the given scopes and writes the definer's and the
//! verb's audit rows; an active or revoked client is refused with nothing
//! changed (the definer itself would rewrite or resurrect it); an admin-only
//! scope is refused while migration 128 is armed; `platform:admin` is refused
//! before any connection.

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

async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("approve_maint_{}", Uuid::new_v4().simple());
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

/// A service client at `status`: `(oauth_clients.id, client_id)`.
async fn client(pool: &PgPool, status: &str) -> (Uuid, String) {
    let (agent, _) = fixture::seed_agent_with_group(pool, "approve-subject").await;
    let client_id = format!("epigraph_{}", Uuid::new_v4().simple());
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, legal_entity_name, \
                                    legal_contact_email) \
         VALUES ($1, 'approve test', 'service', ARRAY['claims:read','claims:write'], \
                 ARRAY[]::text[], $2, $3, 'Fixture Org', 'fixture@example.invalid') \
         RETURNING id",
    )
    .bind(&client_id)
    .bind(status)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the client");
    (id, client_id)
}

/// `(status, granted_scopes)`.
async fn state(pool: &PgPool, id: Uuid) -> (String, Vec<String>) {
    sqlx::query_as("SELECT status::text, granted_scopes FROM oauth_clients WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("state")
}

/// The approval audit rows naming client `id`, by event type.
async fn audit(pool: &PgPool, id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_type FROM security_events \
          WHERE (event_type = 'oauth.client_approved' AND details->>'oauth_client_id' = $1::text) \
             OR (event_type = 'oauth.client_approved_cli' AND details->'client'->>'id' = $1::text) \
          ORDER BY event_type",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .expect("audit")
}

fn approve(which: &[&str], scopes: &[&str], apply: bool, dsn: &str) -> Run {
    let mut args = vec!["approve-client"];
    args.extend_from_slice(which);
    for s in scopes {
        args.extend(["--scope", s]);
    }
    args.extend(["--reason", "cli test"]);
    if apply {
        args.push("--apply");
    }
    run_with(&args, Some(dsn))
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_pending_client_named_by_its_client_id_is_approved_once(pool: PgPool) {
    let (id, client_id) = client(&pool, "pending").await;
    let (login, dsn) = maintenance_login(&pool).await;
    let scopes = ["claims:read", "claims:write"];

    let dry = approve(&["--client-id", &client_id], &scopes, false, &dsn);
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE APPROVED"), "{}", dry.show());
    assert!(
        dry.stdout.contains(&format!("client={id}")),
        "the client_id string is mapped to its row: {}",
        dry.show()
    );
    assert_eq!(state(&pool, id).await, ("pending".into(), vec![]));
    assert!(
        audit(&pool, id).await.is_empty(),
        "a dry run audits nothing"
    );

    let applied = approve(&["--client-id", &client_id], &scopes, true, &dsn);
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert_eq!(
        state(&pool, id).await,
        (
            "active".into(),
            scopes.iter().map(|s| (*s).to_string()).collect()
        )
    );
    assert_eq!(
        audit(&pool, id).await,
        ["oauth.client_approved", "oauth.client_approved_cli"],
        "the definer's row and the verb's row"
    );

    // Now active: a second approval would rewrite its scopes. Refused.
    let again = approve(&["--client", &id.to_string()], &["claims:read"], true, &dsn);
    assert_eq!(again.code, 1, "{}", again.show());
    assert!(again.stderr.contains("not pending"), "{}", again.show());
    assert_eq!(state(&pool, id).await.1, scopes.map(String::from).to_vec());
    assert_eq!(audit(&pool, id).await.len(), 2);

    drop_login(&pool, &login).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_client_is_never_resurrected(pool: PgPool) {
    let (id, _) = client(&pool, "revoked").await;
    let (login, dsn) = maintenance_login(&pool).await;
    let r = approve(&["--client", &id.to_string()], &["claims:read"], true, &dsn);
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("is revoked, not pending"), "{}", r.show());
    assert_eq!(state(&pool, id).await, ("revoked".into(), vec![]));
    assert!(audit(&pool, id).await.is_empty());

    let unknown = approve(
        &["--client-id", "epigraph_no_such"],
        &["claims:read"],
        true,
        &dsn,
    );
    assert_eq!(unknown.code, 1, "{}", unknown.show());
    assert!(
        unknown.stderr.contains("no OAuth client"),
        "{}",
        unknown.show()
    );
    drop_login(&pool, &login).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn admin_scopes_are_refused_while_armed_and_platform_admin_always(pool: PgPool) {
    let (id, _) = client(&pool, "pending").await;
    let (login, dsn) = maintenance_login(&pool).await;
    let pa = approve(
        &["--client", &id.to_string()],
        &["claims:read", "platform:admin"],
        true,
        "postgres://unused@127.0.0.1:1/none",
    );
    assert_eq!(pa.code, 1, "{}", pa.show());
    assert!(pa.stderr.contains("elevate grant"), "{}", pa.show());

    let arm = run_with(
        &["arm-admin-scopes", "--reason", "cli test", "--apply"],
        Some(&dsn),
    );
    assert_eq!(arm.code, 0, "{}", arm.show());
    let armed = approve(
        &["--client", &id.to_string()],
        &["claims:read", "claims:admin"],
        true,
        &dsn,
    );
    assert_eq!(armed.code, 1, "{}", armed.show());
    assert!(armed.stderr.contains("armed"), "{}", armed.show());
    assert_eq!(state(&pool, id).await, ("pending".into(), vec![]));
    assert!(audit(&pool, id).await.is_empty());
    drop_login(&pool, &login).await;
}
