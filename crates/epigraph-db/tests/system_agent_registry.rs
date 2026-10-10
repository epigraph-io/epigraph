//! Migration 148: the system-agent registry (`system_agents`), its definer
//! `epigraph_register_system_agent`, and the two guards it adds to tables it
//! does not own (`agents_refuse_registered_system_key`,
//! `human_operators_refuse_system_agent`).
//!
//! Application-role behaviour runs on `fixture::downgraded_pool(.., "epigraph_app")`;
//! maintenance behaviour on `fixture::as_role(.., "epigraph_maintenance")`
//! (`SET SESSION AUTHORIZATION`, so `session_user` and `epigraph_bypass()` are
//! the real ones). The harness superuser seeds, rotates keys and reads. No test
//! here calls `fixture::grant_app_privileges`: its `ON ALL TABLES` grant would
//! override the migration's REVOKE and hide a missing one.
//!
//! Several layers answer SQLSTATE 42501, so every refusal asserts WHICH layer
//! answered: PostgreSQL's own `permission denied for function|table ...` (the
//! grant set), the definer body's `epigraph_register_system_agent:` prefix, or
//! the table guard's `system_agents:` prefix, and the absence of the others.
//! Otherwise defence in depth would mask the very mutation a test claims to kill.
//!
//! The `rolsuper` arm of the definer and of the guard (a database without
//! `epigraph_maintenance` registers as a superuser) is not demonstrable on this
//! harness: the role always exists here, and a superuser is also a member of it.
//!
//! Verified to fail (each mutation of `migrations/148_system_agent_registry.sql`
//! run against this file): the app-role `REVOKE ALL` removed ->
//! `the_app_role_cannot_write_the_registry` (the guard answered 42501 and only
//! the message assert caught it); the guard's session check removed ->
//! `the_guard_refuses_a_non_maintenance_direct_insert_even_if_granted` (the
//! INSERT landed); the definer's session check removed ->
//! `the_definer_refuses_a_non_maintenance_session_even_if_granted` (the guard's
//! prefix answered); `system_agents_no_truncate` removed ->
//! `a_registration_is_immutable` (superuser TRUNCATE returned Ok); the reserved
//! event policy removed -> `the_registration_event_type_is_reserved` (the app
//! forge landed); the `agents` guard's `agent_id <> NEW.id` exclusion removed ->
//! `a_registered_key_cannot_be_taken_by_another_agent` step (0). Not run: the
//! remaining per-branch guard mutations named in each test's doc.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::SystemAgentRole;
use sqlx::PgPool;
use uuid::Uuid;

const EVENT: &str = "operator.system_agent_registered";

fn role() -> &'static str {
    SystemAgentRole::WorkflowIngest.as_str()
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

/// Assert `r` failed with `code`, its message containing `fragment` and none of
/// `absent`.
fn assert_refused<T: std::fmt::Debug>(
    r: &Result<T, sqlx::Error>,
    code: &str,
    fragment: &str,
    absent: &[&str],
    what: &str,
) {
    let e = r
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("{what}: expected SQLSTATE {code}, got {r:?}"));
    assert_eq!(sqlstate(e).as_deref(), Some(code), "{what}: {e}");
    let msg = e.to_string();
    assert!(
        msg.contains(fragment),
        "{what}: the message must contain {fragment:?}: {msg}"
    );
    for a in absent {
        assert!(
            !msg.contains(a),
            "{what}: the message must NOT contain {a:?} (another layer answered): {msg}"
        );
    }
}

async fn seed_agent(pool: &PgPool, label: &str) -> Uuid {
    fixture::seed_agent_with_group(pool, label).await.0
}

async fn key_of(pool: &PgPool, agent: Uuid) -> Vec<u8> {
    sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("agent key")
}

async fn registry_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM system_agents")
        .fetch_one(pool)
        .await
        .expect("registry count")
}

async fn registered_agent(pool: &PgPool) -> Option<Uuid> {
    sqlx::query_scalar("SELECT agent_id FROM system_agents WHERE role = $1")
        .bind(role())
        .fetch_optional(pool)
        .await
        .expect("registry row")
}

async fn audit_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type = $1")
        .bind(EVENT)
        .fetch_one(pool)
        .await
        .expect("audit count")
}

/// Call the definer on a maintenance session; autocommit.
async fn maint_register(
    pool: &PgPool,
    role: Option<&str>,
    agent: Uuid,
    reason: &str,
) -> Result<(bool, Uuid, String), sqlx::Error> {
    let role = role.map(str::to_string);
    let reason = reason.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query_as::<_, (bool, Uuid, String)>(
            "SELECT registered_now, registered_agent, registered_by \
               FROM public.epigraph_register_system_agent($1, $2, $3)",
        )
        .bind(role.as_deref())
        .bind(agent)
        .bind(&reason)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// The definer on a maintenance session inside a transaction that is ROLLED
/// BACK, so several subjects can each be tried against an empty registry.
async fn maint_register_rolled_back(pool: &PgPool, agent: Uuid) -> Result<bool, sqlx::Error> {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("BEGIN")
            .execute(&mut *conn)
            .await
            .expect("begin");
        let r = sqlx::query_scalar::<_, bool>(
            "SELECT registered_now FROM public.epigraph_register_system_agent($1, $2, 'x')",
        )
        .bind(role())
        .bind(agent)
        .fetch_one(&mut *conn)
        .await;
        sqlx::query("ROLLBACK")
            .execute(&mut *conn)
            .await
            .expect("rollback");
        (conn, r)
    })
    .await
}

/// One statement on a maintenance session, `$1` bound to `id`.
async fn maint_exec(pool: &PgPool, sql: &str, id: Uuid) -> Result<u64, sqlx::Error> {
    let sql = sql.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(&sql)
            .bind(id)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
        (conn, r)
    })
    .await
}

/// An `oauth_clients` row; returns its `id`.
async fn seed_client(
    pool: &PgPool,
    client_id: &str,
    client_type: &str,
    status: &str,
    agent: Option<Uuid>,
    owner: Option<Uuid>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, owner_id) \
         VALUES ($1, 'system agent registry test', $2, ARRAY['claims:write'], $3, $4, $5) \
         RETURNING id",
    )
    .bind(client_id)
    .bind(client_type)
    .bind(status)
    .bind(agent)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed oauth client")
}

/// Kills: dropping `REVOKE ALL ON public.system_agents FROM epigraph_app` (077's
/// default privileges would hand the app role INSERT/UPDATE/DELETE on the new
/// table). The INSERT asserts PostgreSQL's own text and the ABSENCE of the guard
/// trigger's prefix, because the trigger also answers 42501 and would otherwise
/// mask the missing REVOKE. Holds only where the migrating role is `epigraph`
/// (077's grants are `ALTER DEFAULT PRIVILEGES FOR ROLE epigraph`), which is
/// CI's and this harness's `POSTGRES_USER`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_write_the_registry(pool: PgPool) {
    let a = seed_agent(&pool, "a").await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;

    let insert =
        sqlx::query("INSERT INTO system_agents (role, agent_id, reason) VALUES ($1, $2, 'x')")
            .bind(role())
            .bind(a)
            .execute(&app)
            .await;
    assert_refused(
        &insert,
        "42501",
        "permission denied for table system_agents",
        &["system_agents: only"],
        "app INSERT",
    );
    assert_eq!(registry_rows(&pool).await, 0);

    assert!(fixture::register_system_agent(&pool, a).await);
    let b = seed_agent(&pool, "b").await;
    for (sql, what) in [
        ("UPDATE system_agents SET reason = 'y'", "app UPDATE"),
        ("DELETE FROM system_agents", "app DELETE"),
        ("TRUNCATE system_agents", "app TRUNCATE"),
    ] {
        let r = sqlx::query(sql).execute(&app).await;
        assert_refused(
            &r,
            "42501",
            "permission denied for table system_agents",
            &["system_agents: "],
            what,
        );
    }
    let r = sqlx::query("UPDATE system_agents SET agent_id = $1")
        .bind(b)
        .execute(&app)
        .await;
    assert_refused(
        &r,
        "42501",
        "permission denied for table system_agents",
        &[],
        "app re-point",
    );

    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM system_agents")
        .fetch_one(&app)
        .await
        .expect("the app role reads the registry");
    assert_eq!(visible, 1, "the registry is app-readable");
    assert_eq!(registered_agent(&pool).await, Some(a), "row unchanged");
    let reason: String = sqlx::query_scalar("SELECT reason FROM system_agents")
        .fetch_one(&pool)
        .await
        .expect("reason");
    assert_eq!(reason, "test fixture");
}

/// Kills: dropping the `REVOKE EXECUTE ... FROM epigraph_app` / `FROM PUBLIC` on
/// the definer. The message assert keeps the body's own 42501 from masking it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_execute_the_register_definer(pool: PgPool) {
    let a = seed_agent(&pool, "a").await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let r = sqlx::query("SELECT * FROM public.epigraph_register_system_agent($1, $2, 'x')")
        .bind(role())
        .bind(a)
        .execute(&app)
        .await;
    assert_refused(
        &r,
        "42501",
        "permission denied for function epigraph_register_system_agent",
        &[
            "epigraph_register_system_agent: only",
            "system_agents: only",
        ],
        "app EXECUTE",
    );
    assert_eq!(registry_rows(&pool).await, 0);
    assert_eq!(audit_rows(&pool).await, 0);
}

/// Kills: removing the definer body's privileged-session check. With it gone,
/// the INSERT reaches the guard trigger, which answers `system_agents: only`;
/// the prefix assert tells the two apart.
#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_refuses_a_non_maintenance_session_even_if_granted(pool: PgPool) {
    let a = seed_agent(&pool, "a").await;
    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.epigraph_register_system_agent(text, uuid, text) \
         TO epigraph_app",
    )
    .execute(&pool)
    .await
    .expect("test-local stray grant");
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let r = sqlx::query("SELECT * FROM public.epigraph_register_system_agent($1, $2, 'x')")
        .bind(role())
        .bind(a)
        .execute(&app)
        .await;
    assert_refused(
        &r,
        "42501",
        "epigraph_register_system_agent: only a maintenance session",
        &["system_agents: only", "permission denied"],
        "granted app EXECUTE",
    );
    assert_eq!(registry_rows(&pool).await, 0);
}

/// Kills: removing the guard trigger's session check. A stray column-level
/// `GRANT INSERT` would then let the application role choose the system agent
/// on an empty registry.
#[sqlx::test(migrations = "../../migrations")]
async fn the_guard_refuses_a_non_maintenance_direct_insert_even_if_granted(pool: PgPool) {
    let a = seed_agent(&pool, "a").await;
    sqlx::query("GRANT INSERT (role, agent_id, reason) ON public.system_agents TO epigraph_app")
        .execute(&pool)
        .await
        .expect("test-local stray column grant");
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let r = sqlx::query("INSERT INTO system_agents (role, agent_id, reason) VALUES ($1, $2, 'x')")
        .bind(role())
        .bind(a)
        .execute(&app)
        .await;
    assert_refused(
        &r,
        "42501",
        "system_agents: only a maintenance session",
        &["permission denied", "epigraph_register_system_agent:"],
        "granted app direct INSERT",
    );
    assert_eq!(registry_rows(&pool).await, 0);
    assert_eq!(audit_rows(&pool).await, 0);
}

/// Kills: the audit trigger dropped (0 events); `v_rows` inverted; a double
/// insert (2 events); the key snapshot not taken (a NULL `registered_public_key`
/// violates NOT NULL, 23502).
#[sqlx::test(migrations = "../../migrations")]
async fn maintenance_registers_once_and_audits_once(pool: PgPool) {
    let a = seed_agent(&pool, "a").await;
    let first = maint_register(&pool, Some(role()), a, "the ingest identity")
        .await
        .expect("first registration");
    assert_eq!(first, (true, a, "epigraph_maintenance".to_string()));
    let second = maint_register(&pool, Some(role()), a, "again")
        .await
        .expect("idempotent re-registration");
    assert_eq!(second, (false, a, "epigraph_maintenance".to_string()));

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT details->>'role', details->>'reason' FROM security_events \
          WHERE event_type = $1 AND agent_id = $2",
    )
    .bind(EVENT)
    .bind(a)
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    assert_eq!(
        rows,
        vec![(role().to_string(), "the ingest identity".to_string())],
        "exactly one audit row, naming the role and the reason"
    );
    let snapshot: Vec<u8> =
        sqlx::query_scalar("SELECT registered_public_key FROM system_agents WHERE role = $1")
            .bind(role())
            .fetch_one(&pool)
            .await
            .expect("snapshot");
    assert_eq!(snapshot, key_of(&pool, a).await, "the key at registration");
}

/// Kills: the definer's `v_existing <> p_agent` check removed (the INSERT would
/// then hit the primary key: 23505, not 55000); the row trigger dropped (a
/// superuser UPDATE lands); `system_agents_no_truncate` dropped (a superuser
/// TRUNCATE empties the table); the `TG_LEVEL` branch missing (the statement
/// path reads `OLD` and raises something other than `cannot be truncated`); a
/// GRANT UPDATE to maintenance.
#[sqlx::test(migrations = "../../migrations")]
async fn a_registration_is_immutable(pool: PgPool) {
    let a = seed_agent(&pool, "a").await;
    let b = seed_agent(&pool, "b").await;
    assert!(fixture::register_system_agent(&pool, a).await);

    let repoint = maint_register(&pool, Some(role()), b, "re-point").await;
    assert_refused(
        &repoint,
        "55000",
        "a registration is immutable",
        &[],
        "re-register another agent",
    );

    for (sql, what) in [
        (
            "UPDATE system_agents SET agent_id = $1",
            "maintenance UPDATE",
        ),
        (
            "DELETE FROM system_agents WHERE agent_id <> $1",
            "maintenance DELETE",
        ),
    ] {
        let r = maint_exec(&pool, sql, b).await;
        assert_refused(
            &r,
            "42501",
            "permission denied for table system_agents",
            &[],
            what,
        );
    }
    let truncate = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query("TRUNCATE system_agents")
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await;
    assert_refused(
        &truncate,
        "42501",
        "permission denied for table system_agents",
        &[],
        "maintenance TRUNCATE",
    );

    let su_update = sqlx::query("UPDATE system_agents SET agent_id = $1")
        .bind(b)
        .execute(&pool)
        .await;
    assert_refused(&su_update, "55000", "is immutable", &[], "superuser UPDATE");
    let su_delete = sqlx::query("DELETE FROM system_agents")
        .execute(&pool)
        .await;
    assert_refused(&su_delete, "55000", "is immutable", &[], "superuser DELETE");
    let su_truncate = sqlx::query("TRUNCATE system_agents").execute(&pool).await;
    assert_refused(
        &su_truncate,
        "55000",
        "cannot be truncated",
        &[],
        "superuser TRUNCATE",
    );

    assert_eq!(registered_agent(&pool).await, Some(a), "still A");
    assert_eq!(audit_rows(&pool).await, 1, "still one audit row");
}

/// Six kinds of agent are never a system agent. Each subject isolates its own
/// guard branch (the earlier branches do not fire for it), so removing any one
/// branch turns its case green-to-red. `pending` kills a mutation of the client
/// arms to `status = 'active'`; the UPPER-case `client_id` kills a
/// case-sensitive key compare.
#[sqlx::test(migrations = "../../migrations")]
async fn the_registry_refuses_identities_that_are_never_system_agents(pool: PgPool) {
    // H: a registered human operator.
    let (h, _) = fixture::seed_human_operator(&pool, "h").await;
    // R: the graph node of a platform role (123's catalog seed).
    let r: Uuid = sqlx::query_scalar(
        "SELECT role_node_id FROM platform_roles WHERE key = 'role:platform-custodian'",
    )
    .fetch_one(&pool)
    .await
    .expect("custodian role node");
    // C: the principal of a non-revoked OAuth client (two statuses).
    let c_pending = seed_agent(&pool, "c-pending").await;
    let c_pending_client = seed_client(
        &pool,
        &format!("c-p-{c_pending}"),
        "human",
        "pending",
        Some(c_pending),
        None,
    )
    .await;
    let c_suspended = seed_agent(&pool, "c-suspended").await;
    seed_client(
        &pool,
        &format!("c-s-{c_suspended}"),
        "human",
        "suspended",
        Some(c_suspended),
        None,
    )
    .await;
    // C2: an agent whose KEY is the client_id of a pending agent-type client
    // that has not adopted it yet (agent_id NULL).
    let c2 = seed_agent(&pool, "c2").await;
    let owner = seed_client(&pool, &format!("owner-{c2}"), "human", "active", None, None).await;
    let c2_key_upper = hex::encode(key_of(&pool, c2).await).to_uppercase();
    let c2_client = seed_client(&pool, &c2_key_upper, "agent", "pending", None, Some(owner)).await;
    // O: a FORMER human that operates an agent (while O is a live human the
    // human arm would answer first).
    let (o, _) = fixture::seed_human_operator(&pool, "o").await;
    let operated = seed_agent(&pool, "operated").await;
    let t_human = fixture::seed_human_operator(&pool, "t-human").await.0;
    let t = seed_agent(&pool, "t").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, operated, o)
            .await
            .expect("live link to O");
        // T: an agent holding a RETIRED link (permanent, never promoted).
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, t, t_human)
            .await
            .expect("retired link of T");
    }
    sqlx::query("SELECT * FROM epigraph_revoke_human_operator($1, 'no longer a human')")
        .bind(o)
        .execute(&pool)
        .await
        .expect("revoke O");
    sqlx::query("UPDATE oauth_clients SET status = 'revoked' WHERE agent_id = $1")
        .bind(o)
        .execute(&pool)
        .await
        .expect("revoke O's client");

    for (subject, fragment, what) in [
        (h, "registered human operator", "H"),
        (r, "graph node of a platform role", "R"),
        (
            c_pending,
            "principal of an OAuth client that is not revoked",
            "C pending",
        ),
        (
            c_suspended,
            "principal of an OAuth client that is not revoked",
            "C suspended",
        ),
        (c2, "key of an agent OAuth client", "C2"),
        (o, "operates other agents", "O"),
        (t, "retired operator link", "T"),
    ] {
        let res = maint_register(&pool, Some(role()), subject, "x").await;
        assert_refused(&res, "55000", fragment, &[], what);
    }
    assert_eq!(registry_rows(&pool).await, 0);
    assert_eq!(audit_rows(&pool).await, 0);

    // Controls: each client subject registers once its client is revoked.
    for (client, subject, what) in [(c_pending_client, c_pending, "C"), (c2_client, c2, "C2")] {
        sqlx::query("UPDATE oauth_clients SET status = 'revoked' WHERE id = $1")
            .bind(client)
            .execute(&pool)
            .await
            .expect("revoke the client");
        let ok = maint_register_rolled_back(&pool, subject).await;
        assert!(
            matches!(ok, Ok(true)),
            "control {what}: registers once its client is revoked: {ok:?}"
        );
    }
}

/// Kills: guards moved into the definer only (a direct INSERT bypasses them);
/// the audit only in the definer; the `created_at` half of the recorded-columns
/// check removed; a caller-supplied key snapshot accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn direct_inserts_meet_the_same_rules_and_audit(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "h").await;
    let a = seed_agent(&pool, "a").await;

    let ins = |sql: &'static str, agent: Uuid| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
                let r = sqlx::query(sql)
                    .bind(role())
                    .bind(agent)
                    .execute(&mut *conn)
                    .await;
                (conn, r)
            })
            .await
        }
    };
    let plain = "INSERT INTO system_agents (role, agent_id, reason) VALUES ($1, $2, 'x')";
    assert_refused(
        &ins(plain, h).await,
        "55000",
        "system_agents: ",
        &[],
        "direct INSERT of a human",
    );
    assert_refused(
        &ins(
            "INSERT INTO system_agents (role, agent_id, reason) VALUES ($1, $2, ' ')",
            a,
        )
        .await,
        "22004",
        "a reason is required",
        &[],
        "blank reason",
    );
    assert_refused(
        &ins(
            "INSERT INTO system_agents (role, agent_id, reason, created_by) \
             VALUES ($1, $2, 'x', 'someone')",
            a,
        )
        .await,
        "55000",
        "recorded, not supplied",
        &[],
        "spoofed created_by",
    );
    assert_refused(
        &ins(
            "INSERT INTO system_agents (role, agent_id, reason, created_at) \
             VALUES ($1, $2, 'x', now() - interval '1 day')",
            a,
        )
        .await,
        "55000",
        "recorded, not supplied",
        &[],
        "back-dated created_at",
    );
    assert_refused(
        &ins(
            "INSERT INTO system_agents (role, agent_id, reason, registered_public_key) \
             VALUES ($1, $2, 'x', decode(md5(random()::text) || md5(random()::text), 'hex'))",
            a,
        )
        .await,
        "55000",
        "registered_public_key is recorded, not supplied",
        &[],
        "supplied key snapshot",
    );
    assert_eq!(registry_rows(&pool).await, 0);
    assert_eq!(audit_rows(&pool).await, 0);

    ins(plain, a)
        .await
        .expect("a valid direct maintenance INSERT");
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT details->>'recorded_by' FROM security_events WHERE event_type = $1 AND agent_id = $2",
    )
    .bind(EVENT)
    .bind(a)
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(audit, vec!["epigraph_maintenance".to_string()]);
    let snapshot: Vec<u8> = sqlx::query_scalar("SELECT registered_public_key FROM system_agents")
        .fetch_one(&pool)
        .await
        .expect("snapshot");
    assert_eq!(snapshot, key_of(&pool, a).await);
}

/// Kills: the role CHECK dropped (23514 expected); the definer's existence check
/// removed (the FK would answer 23503 instead of 22023).
#[sqlx::test(migrations = "../../migrations")]
async fn only_known_roles_and_real_agents_register(pool: PgPool) {
    let a = seed_agent(&pool, "a").await;
    let typo = maint_register(&pool, Some("workflow_ingest"), a, "x").await;
    assert_refused(
        &typo,
        "23514",
        "system_agents_role_known",
        &[],
        "unknown role",
    );
    let missing = maint_register(&pool, Some(role()), Uuid::new_v4(), "x").await;
    assert_refused(&missing, "22023", "does not exist", &[], "missing agent");
    let blank = maint_register(&pool, Some(role()), a, "").await;
    assert_refused(
        &blank,
        "22004",
        "a reason are required",
        &[],
        "blank reason",
    );
    let no_role = maint_register(&pool, None, a, "x").await;
    assert_refused(&no_role, "22004", "a reason are required", &[], "NULL role");
    assert_eq!(registry_rows(&pool).await, 0);
}

/// After registration and a rotation, NOTHING can hold the registered key under
/// another id: not the pre-148 resolver's exact create call on the application
/// role, not `POST /agents`' `AgentRepository::create`, not a superuser key
/// UPDATE. The registered agent itself may rotate again.
///
/// Kills: the `agents` trigger dropped (1-3 land: the split); the trigger not
/// covering `UPDATE OF public_key` (3 lands); the `agent_id <> NEW.id`
/// exclusion dropped (0 and 5 fail: the registered agent could no longer
/// write its own registered key); the snapshot taken from the post-rotation
/// key (1 lands).
#[sqlx::test(migrations = "../../migrations")]
async fn a_registered_key_cannot_be_taken_by_another_agent(pool: PgPool) {
    let legacy = SystemAgentRole::WorkflowIngest.legacy_public_key();
    let seed_name = SystemAgentRole::WorkflowIngest.legacy_seed_name();
    let s = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::create_conn(
            &mut conn,
            &epigraph_core::Agent::new(legacy, Some(seed_name.to_string())),
        )
        .await
        .expect("the pre-148 resolver's create")
        .id
    };
    let s: Uuid = s.into();
    assert!(fixture::register_system_agent(&pool, s).await);
    // (0) The registered agent itself keeps its key through an UPDATE that
    // names the column (the trigger fires on `UPDATE OF public_key` even when
    // the value is unchanged).
    sqlx::query("UPDATE agents SET public_key = public_key WHERE id = $1")
        .bind(s)
        .execute(&pool)
        .await
        .expect("(0) the registered agent may re-write its own registered key");
    sqlx::query(
        "UPDATE agents SET public_key = decode(md5(random()::text) || md5(random()::text), 'hex') \
          WHERE id = $1",
    )
    .bind(s)
    .execute(&pool)
    .await
    .expect("rotate S");

    let holders = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM agents WHERE public_key = $1")
            .bind(legacy.as_slice())
            .fetch_one(&pool)
            .await
            .expect("K holders")
    };
    let refused_55000 = |r: Result<epigraph_core::Agent, epigraph_db::DbError>, what: &str| {
        let e = r.expect_err(what);
        let source = match &e {
            epigraph_db::DbError::QueryFailed { source } => source,
            other => panic!("{what}: expected a QueryFailed(55000), got {other:?}"),
        };
        assert_eq!(sqlstate(source).as_deref(), Some("55000"), "{what}: {e}");
        assert!(
            source
                .to_string()
                .contains("registered for the workflow-ingest system agent"),
            "{what}: {source}"
        );
    };

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    {
        let mut conn = app.acquire().await.expect("app conn");
        let r = epigraph_db::AgentRepository::create_conn(
            &mut conn,
            &epigraph_core::Agent::new(legacy, Some(seed_name.to_string())),
        )
        .await;
        refused_55000(r, "(1) the pre-148 resolver's create on the app role");
    }
    assert_eq!(holders().await, 0);
    let r = epigraph_db::AgentRepository::create(
        &app,
        &epigraph_core::Agent::new(legacy, Some("someone".to_string())),
    )
    .await;
    refused_55000(r, "(2) a create of an arbitrary agent holding K");
    assert_eq!(holders().await, 0);

    let x = seed_agent(&pool, "x").await;
    let r = sqlx::query("UPDATE agents SET public_key = $1 WHERE id = $2")
        .bind(legacy.as_slice())
        .bind(x)
        .execute(&pool)
        .await;
    assert_refused(
        &r,
        "55000",
        "registered for the workflow-ingest system agent",
        &[],
        "(3) superuser re-key of another agent to K",
    );
    assert_eq!(holders().await, 0);

    sqlx::query(
        "UPDATE agents SET public_key = decode(md5(random()::text) || md5(random()::text), 'hex') \
          WHERE id = $1",
    )
    .bind(s)
    .execute(&pool)
    .await
    .expect("(4) the registered agent may rotate again");
    sqlx::query("UPDATE agents SET public_key = $1 WHERE id = $2")
        .bind(legacy.as_slice())
        .bind(s)
        .execute(&pool)
        .await
        .expect("(5) the registered agent may even rotate back to its registered key");
    assert_eq!(holders().await, 1);
}

/// Kills: `human_operators_refuse_system_agent` dropped.
#[sqlx::test(migrations = "../../migrations")]
async fn a_registered_system_agent_never_becomes_a_human_operator(pool: PgPool) {
    let s = seed_agent(&pool, "s").await;
    assert!(fixture::register_system_agent(&pool, s).await);
    let client = seed_client(
        &pool,
        &format!("late-{s}"),
        "human",
        "active",
        Some(s),
        None,
    )
    .await;
    let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query("SELECT * FROM epigraph_register_human_operator($1, 'x', $2)")
            .bind(s)
            .bind(client)
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await;
    assert_refused(
        &r,
        "55000",
        "is a registered system agent",
        &[],
        "human registration of S",
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM human_operators WHERE agent_id = $1")
        .bind(s)
        .fetch_one(&pool)
        .await
        .expect("human rows");
    assert_eq!(rows, 0);
    let human: bool = sqlx::query_scalar("SELECT epigraph_is_human_operator($1)")
        .bind(s)
        .fetch_one(&pool)
        .await
        .expect("is human");
    assert!(!human);
}

/// Kills: the RESTRICTIVE policy not created; its prefix length or its
/// `lower(btrim(..))` normalisation wrong. The control proves the refusal is
/// the new policy, not a general refusal of `operator.` rows.
#[sqlx::test(migrations = "../../migrations")]
async fn the_registration_event_type_is_reserved(pool: PgPool) {
    let p = seed_agent(&pool, "p").await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let forge = |event: &'static str| {
        let app = app.clone();
        async move {
            sqlx::query(
                "INSERT INTO security_events (event_type, agent_id, success, details) \
                 VALUES ($1, $2, true, '{}')",
            )
            .bind(event)
            .bind(p)
            .execute(&app)
            .await
        }
    };
    for event in [EVENT, " OPERATOR.SYSTEM_AGENT_x"] {
        let r = forge(event).await;
        assert_refused(&r, "42501", "row-level security", &[], event);
    }
    forge("operator.something_else")
        .await
        .expect("control: another operator.* type is still app-writable");
    assert_eq!(audit_rows(&pool).await, 0);
}

// ── A registered system agent is never retire-linked, by any door ──────────

/// `(operator_id, retired)` of `agent`'s one link, if any.
async fn link_of(pool: &PgPool, agent: Uuid) -> Option<(Uuid, bool)> {
    sqlx::query_as("SELECT operator_id, retired FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_optional(pool)
        .await
        .expect("link read")
}

/// The guard refuses to REGISTER an agent holding a retired operator link (a
/// retired link is permanent, so the agent could never be bound). The same
/// invariant must hold in the other order: once registered, no definer may
/// RETIRE-link it, or an armed database refuses every workflow-ingest write
/// for good behind an immutable registration. Each of the three retired-link
/// definers (the bulk legacy-author tie, the single retire, the attested
/// shared-signer retire) is refused by `operator_links`' own trigger (its
/// `operator_links:` prefix), the bulk tie with S excluded still runs, and S
/// is afterwards live-linkable and BOUND (the row, not the definer's Ok: a
/// live link over a retired one returns Ok and changes nothing).
///
/// Kills: `operator_links_refuse_retired_system_agent` missing (each door lands
/// a retired link, and the final live link is a silent no-op).
#[sqlx::test(migrations = "../../migrations")]
async fn a_registered_system_agent_is_never_retire_linked(pool: PgPool) {
    let s = seed_agent(&pool, "s").await;
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    let other = seed_agent(&pool, "other-principal").await;
    assert!(fixture::register_system_agent(&pool, s).await);
    // Every real system agent has authored something, so the bulk tie sees it.
    fixture::seed_public_claim(&pool, s, "a claim the system agent authored").await;
    // The bulk tie that excludes S runs and reports it excluded (the control:
    // the refusal below is about S, not about the tie).
    let outcomes: Vec<(Uuid, String)> =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query_as(
                "SELECT agent_id, outcome FROM public.epigraph_link_legacy_authors($1, $2, NULL)",
            )
            .bind(human)
            .bind(vec![s])
            .fetch_all(&mut *conn)
            .await
            .expect("the tie with S excluded runs");
            (conn, r)
        })
        .await;
    assert!(
        outcomes.contains(&(s, "skipped:excluded".to_string())),
        "{outcomes:?}"
    );
    assert_eq!(link_of(&pool, s).await, None);

    let doors = [
        (
            "the legacy-author tie",
            "SELECT * FROM public.epigraph_link_legacy_authors($2, ARRAY[]::uuid[], NULL)",
        ),
        (
            "the single retire",
            "SELECT * FROM public.epigraph_link_retired_agent($1, $2)",
        ),
        (
            "the attested shared-signer retire",
            "SELECT * FROM public.epigraph_link_retired_shared_signer($1, $2, ARRAY[$3]::uuid[])",
        ),
    ];
    for (door, sql) in doors {
        if door.contains("shared-signer") {
            // The shared-signer fingerprint (OPERATED_BY lineage to two
            // principals), seeded only now: the tie and the single retire
            // would skip or refuse such an agent for that reason instead.
            for target in [human, other] {
                sqlx::query(
                    "INSERT INTO edges (source_id, source_type, target_id, target_type, \
                                        relationship) \
                     VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY')",
                )
                .bind(s)
                .bind(target)
                .execute(&pool)
                .await
                .expect("lineage edge");
            }
        }
        let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query(sql)
                .bind(s)
                .bind(human)
                .bind(other)
                .execute(&mut *conn)
                .await;
            (conn, r)
        })
        .await;
        assert_refused(
            &r,
            "55000",
            "operator_links: ",
            &[],
            &format!("{door} of a registered system agent"),
        );
        assert!(
            r.as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("registered system agent")),
            "{door}: {r:?}"
        );
        assert_eq!(link_of(&pool, s).await, None, "{door}: no link written");
    }

    // S is still bindable: a live link lands and binds it. (The shared-signer
    // lineage seeded for the third door is removed first: 107's live link
    // refuses that fingerprint for its own reason.)
    sqlx::query(
        "DELETE FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'OPERATED_BY'",
    )
    .bind(s)
    .bind(other)
    .execute(&pool)
    .await
    .expect("drop the second lineage principal");
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, s, human)
        .await
        .expect("live link");
    drop(conn);
    assert_eq!(link_of(&pool, s).await, Some((human, false)), "a LIVE link");
    let bound: Option<Uuid> = sqlx::query_scalar("SELECT public.epigraph_human_of($1, true)")
        .bind(s)
        .fetch_one(&pool)
        .await
        .expect("human_of");
    assert_eq!(bound, Some(human), "S is bound to its human");
}

// ── The cross-registry guards serialize ────────────────────────────────────

/// Run `second` on its own connection while a maintenance transaction holds an
/// UNCOMMITTED registration of `s`; return whether `second` blocked on the
/// shared advisory lock before that transaction committed, and its result.
///
/// The guards on either side read the other's table; without a common lock an
/// uncommitted registration is invisible to the other guard and both commit.
/// The wait is bounded: when `second` does not block, it finishes and the poll
/// stops, so a missing lock reports red rather than hanging.
async fn race_against_an_uncommitted_registration<F, Fut>(
    pool: &PgPool,
    s: Uuid,
    second: F,
) -> (bool, Result<(), sqlx::Error>)
where
    F: FnOnce(PgPool) -> Fut,
    Fut: std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'static,
{
    use sqlx::Executor;
    let mut t1 = pool.acquire().await.expect("connection T1");
    t1.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("T1 as maintenance");
    t1.execute("BEGIN").await.expect("begin T1");
    sqlx::query("SELECT * FROM public.epigraph_register_system_agent($1, $2, 'race')")
        .bind(role())
        .bind(s)
        .execute(&mut *t1)
        .await
        .expect("T1's uncommitted registration");

    let t2 = tokio::spawn(second(pool.clone()));
    let mut blocked = false;
    for _ in 0..200 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
              WHERE datname = current_database() AND wait_event_type = 'Lock' \
                AND wait_event = 'advisory'",
        )
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity");
        if waiting > 0 {
            blocked = true;
            break;
        }
        if t2.is_finished() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    t1.execute("COMMIT").await.expect("commit T1");
    t1.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset T1");
    (blocked, t2.await.expect("join T2"))
}

/// A retired link of S written concurrently with S's registration waits for
/// it and is then refused. Kills: the registry guard not taking
/// `epigraph.operator_links` (the link definer never blocks, reads no
/// registration, and lands its retired link beside it).
#[sqlx::test(migrations = "../../migrations")]
async fn a_registration_and_a_concurrent_retired_link_serialize(pool: PgPool) {
    let s = seed_agent(&pool, "s-retire").await;
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    let (blocked, r) = race_against_an_uncommitted_registration(&pool, s, move |p| async move {
        let mut c = p.acquire().await?;
        sqlx::query("SET SESSION AUTHORIZATION epigraph_maintenance")
            .execute(&mut *c)
            .await?;
        let r = sqlx::query("SELECT * FROM public.epigraph_link_retired_agent($1, $2)")
            .bind(s)
            .bind(human)
            .execute(&mut *c)
            .await
            .map(|_| ());
        sqlx::query("RESET SESSION AUTHORIZATION")
            .execute(&mut *c)
            .await?;
        r
    })
    .await;
    assert!(
        blocked,
        "the retire must wait for the uncommitted registration: {r:?}"
    );
    assert_refused(&r, "55000", "operator_links: ", &[], "a concurrent retire");
    assert_eq!(link_of(&pool, s).await, None);
}

/// A human registration of S written concurrently with S's registration waits
/// for it and is then refused. Kills: `human_operators_refuse_system_agent`
/// not taking `epigraph.operator_links` (the human row lands beside the
/// registration).
#[sqlx::test(migrations = "../../migrations")]
async fn a_registration_and_a_concurrent_human_registration_serialize(pool: PgPool) {
    let s2 = seed_agent(&pool, "s-human").await;
    let (blocked, r) = race_against_an_uncommitted_registration(&pool, s2, move |p| async move {
        // The client lands at once (no guard reads oauth_clients for a system
        // agent after registration; that window is accepted and documented);
        // the registry row is what must wait.
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                        status, agent_id) \
             VALUES ($1, 'race', 'human', ARRAY['claims:write'], 'active', $2)",
        )
        .bind(format!("race-human-{s2}"))
        .bind(s2)
        .execute(&p)
        .await?;
        sqlx::query("INSERT INTO human_operators (agent_id, reason) VALUES ($1, 'race')")
            .bind(s2)
            .execute(&p)
            .await
            .map(|_| ())
    })
    .await;
    assert!(blocked, "the human registration must wait: {r:?}");
    assert_refused(
        &r,
        "55000",
        "is a registered system agent",
        &[],
        "a concurrent human registration",
    );
    let human_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM human_operators WHERE agent_id = $1")
            .bind(s2)
            .fetch_one(&pool)
            .await
            .expect("human rows");
    assert_eq!(human_rows, 0);
}

/// A registration is not written under REPEATABLE READ: its snapshot predates
/// the wait for a concurrent link or human registration of the agent, so the
/// guard's reads would not see it. Kills: the isolation refusal removed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_registration_under_repeatable_read_is_refused(pool: PgPool) {
    let s = seed_agent(&pool, "s").await;
    let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *conn)
            .await
            .expect("begin RR");
        let r = sqlx::query("SELECT * FROM public.epigraph_register_system_agent($1, $2, 'x')")
            .bind(role())
            .bind(s)
            .execute(&mut *conn)
            .await;
        sqlx::query("ROLLBACK")
            .execute(&mut *conn)
            .await
            .expect("rollback");
        (conn, r)
    })
    .await;
    assert_refused(
        &r,
        "55000",
        "system_agents: ",
        &[],
        "a REPEATABLE READ registration",
    );
    assert!(
        r.as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("REPEATABLE READ")),
        "{r:?}"
    );
    assert_eq!(registry_rows(&pool).await, 0);
}
