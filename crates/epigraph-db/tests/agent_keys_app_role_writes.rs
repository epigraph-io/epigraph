//! Migration 239 (backlog 54018ca1): the application role can no longer add an
//! agent key, nor move or rotate a key of an agent it is not, in SQL.
//!
//! Before 239, 118 kept INSERT on `agent_keys` for `epigraph_app` and granted
//! it `epigraph_agent_key_set_status` with no caller check; 161 then closed
//! the two ATTESTED key types (`signing`, `identity-legacy`) only. So a holder
//! of the application DSN could still plant a key of any other type for any
//! agent, and rotate or revoke any agent's non-attested key, which is what
//! `POST /agents/:id/keys/rotate` and `/revoke` refuse over HTTP unless the
//! caller is the agent or an admin.
//!
//! Every write under test runs as `epigraph_app` (`SET SESSION AUTHORIZATION`,
//! so `session_user` is the application role), stamped with
//! `epigraph.principal_id` the way `ScopedPool` stamps it. Fixtures are seeded
//! and read back on the harness (superuser) connection.
//!
//! # Verified to fail
//!
//! * On the migrations without 239 (the first three tests, before 239 was
//!   written): the `encryption` INSERT succeeds, another agent's principal
//!   moves the key to `rotated`, and the rotation definer does not exist
//!   (42883).
//! * 239 with its `REVOKE INSERT` removed: fails
//!   `the_application_role_cannot_insert_an_agent_key_of_any_type` only.
//! * 239 with the caller gate of `epigraph_agent_key_set_status` forced true:
//!   fails `a_status_change_needs_the_keys_agent_or_an_admin` and
//!   `the_routes_repository_calls_admit_only_the_stamped_owner`.
//! * 239 with the rotation definer's caller gate forced true: fails
//!   `the_rotation_definer_rotates_only_for_the_keys_agent` and
//!   `the_routes_repository_calls_admit_only_the_stamped_owner`.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;

const INSUFFICIENT_PRIVILEGE: &str = "42501";
const INVALID_PARAMETER: &str = "22023";

fn random32() -> Vec<u8> {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    [a.as_bytes().as_slice(), b.as_bytes().as_slice()].concat()
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

/// An agent seeded on the harness connection, with no key rows.
async fn plain_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'software_agent')",
    )
    .bind(id)
    .bind(random32())
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

/// One active key of `key_type` for `agent`, on the harness connection.
async fn seed_key(pool: &PgPool, agent: Uuid, key_type: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'active', now() - interval '1 day') RETURNING id",
    )
    .bind(agent)
    .bind(random32())
    .bind(key_type)
    .fetch_one(pool)
    .await
    .expect("seed key")
}

/// `(status, valid_until IS NULL)` of one key, read on the harness connection.
async fn key_state(pool: &PgPool, key: Uuid) -> (String, bool) {
    sqlx::query_as("SELECT status::text, valid_until IS NULL FROM agent_keys WHERE id = $1")
        .bind(key)
        .fetch_one(pool)
        .await
        .expect("key state")
}

async fn key_count(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agent_keys WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("key count")
}

/// Run `sql` (binds: `binds` in order, as text cast by the statement) on a
/// `role` session stamped as `principal` (`None`: unstamped).
async fn run_as(
    pool: &PgPool,
    role: &'static str,
    principal: Option<Uuid>,
    sql: &'static str,
    binds: Vec<String>,
) -> Result<(), sqlx::Error> {
    fixture::as_role(pool, role, |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.map(|p| p.to_string()).unwrap_or_default())
            .execute(&mut *conn)
            .await
            .expect("stamp");
        let mut q = sqlx::query(sql);
        for b in binds {
            q = q.bind(b);
        }
        let r = q.execute(&mut *conn).await.map(|_| ());
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("unstamp");
        (conn, r)
    })
    .await
}

async fn set_status_as(
    pool: &PgPool,
    role: &'static str,
    principal: Option<Uuid>,
    key: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    run_as(
        pool,
        role,
        principal,
        "SELECT * FROM public.epigraph_agent_key_set_status($1::uuid, $2, 'test', NULL)",
        vec![key.to_string(), status.to_string()],
    )
    .await
}

async fn rotate_as(
    pool: &PgPool,
    role: &'static str,
    principal: Option<Uuid>,
    key: Uuid,
    new_key: &[u8],
) -> Result<(), sqlx::Error> {
    run_as(
        pool,
        role,
        principal,
        "SELECT * FROM public.epigraph_agent_key_rotate($1::uuid, decode($2, 'hex'))",
        vec![key.to_string(), hex::encode(new_key)],
    )
    .await
}

fn assert_refused(r: Result<(), sqlx::Error>, code: &str, what: &str) -> String {
    let e = r.expect_err(what);
    assert_eq!(sqlstate(&e).as_deref(), Some(code), "{what}: {e}");
    e.to_string()
}

/// No application session adds a key row, of any type and for any agent, its
/// own included: an `agent_keys` row is written by the identity registration,
/// the rotation definer or a maintenance session only. CALIBRATION: the
/// harness connection inserts the same row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_role_cannot_insert_an_agent_key_of_any_type(pool: PgPool) {
    let agent = plain_agent(&pool).await;
    for key_type in ["encryption", "dual_purpose", "signing\t", "anything"] {
        let r = run_as(
            &pool,
            "epigraph_app",
            Some(agent),
            "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from) \
             VALUES ($1::uuid, decode($2, 'hex'), $3, 'active', now())",
            vec![
                agent.to_string(),
                hex::encode(random32()),
                key_type.to_string(),
            ],
        )
        .await;
        assert_refused(
            r,
            INSUFFICIENT_PRIVILEGE,
            &format!("the application role inserted a {key_type:?} key for its own agent"),
        );
    }
    assert_eq!(key_count(&pool, agent).await, 0, "no row was written");
    seed_key(&pool, agent, "encryption").await;
    assert_eq!(
        key_count(&pool, agent).await,
        1,
        "CALIBRATION: the harness connection records the row"
    );
}

/// `epigraph_agent_key_set_status` moves a key only for the key's own agent
/// (the stamped principal) or an admin, for EVERY key type. A principal that
/// is another agent, and an unstamped application session, are refused 42501
/// and the key is unchanged. Positive controls: the agent itself, an
/// instance admin while the admin-scope switch is unarmed, and a maintenance
/// session. Armed, the standing instance admin no longer counts.
#[sqlx::test(migrations = "../../migrations")]
async fn a_status_change_needs_the_keys_agent_or_an_admin(pool: PgPool) {
    let owner = plain_agent(&pool).await;
    let other = plain_agent(&pool).await;
    let admin = plain_agent(&pool).await;
    // An instance admin is the live holder of `role:platform-custodian`
    // (123); the fixture grants it the way the operator CLI does.
    fixture::make_custodian(&pool, admin).await;

    let key = seed_key(&pool, owner, "encryption").await;
    for status in ["rotated", "revoked"] {
        let msg = assert_refused(
            set_status_as(&pool, "epigraph_app", Some(other), key, status).await,
            INSUFFICIENT_PRIVILEGE,
            &format!("another agent moved the key to {status}"),
        );
        assert!(msg.contains("AK03"), "{msg}");
        assert_refused(
            set_status_as(&pool, "epigraph_app", None, key, status).await,
            INSUFFICIENT_PRIVILEGE,
            &format!("an unstamped application session moved the key to {status}"),
        );
    }
    assert_eq!(
        key_state(&pool, key).await,
        ("active".to_string(), true),
        "a refused change wrote nothing"
    );

    set_status_as(&pool, "epigraph_app", Some(owner), key, "rotated")
        .await
        .expect("CALIBRATION: the key's own agent rotates it");
    assert_eq!(key_state(&pool, key).await, ("rotated".to_string(), false));

    let k2 = seed_key(&pool, owner, "encryption").await;
    set_status_as(&pool, "epigraph_app", Some(admin), k2, "revoked")
        .await
        .expect("CALIBRATION: an instance admin (switch unarmed) revokes another agent's key");
    assert_eq!(key_state(&pool, k2).await.0, "revoked");

    sqlx::query(
        "SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'agent_keys_app_role_writes')",
    )
    .execute(&pool)
    .await
    .expect("arm the admin-scope switch");
    let k3 = seed_key(&pool, owner, "encryption").await;
    assert_refused(
        set_status_as(&pool, "epigraph_app", Some(admin), k3, "revoked").await,
        INSUFFICIENT_PRIVILEGE,
        "armed: a standing instance admin without an elevation moved another agent's key",
    );
    set_status_as(&pool, "epigraph_app", Some(owner), k3, "revoked")
        .await
        .expect("armed: the key's own agent still revokes it");
    let k4 = seed_key(&pool, owner, "encryption").await;
    set_status_as(&pool, "epigraph_maintenance", None, k4, "revoked")
        .await
        .expect("CALIBRATION: a maintenance session revokes any key");
}

/// `epigraph_agent_key_rotate(old key, new public key)` retires the old key
/// and records the new one in ONE statement, for the old key's own agent (or
/// an admin) only. The new row's agent and type are the old row's, never the
/// caller's choice; its window opens where the old one closed. Refusals:
/// another agent (AK03), an attested type on an application session (AK02),
/// an old key that is no longer active (AK01), a new key that is not 32
/// bytes. Each refusal leaves the agent's rows as they were.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rotation_definer_rotates_only_for_the_keys_agent(pool: PgPool) {
    let owner = plain_agent(&pool).await;
    let other = plain_agent(&pool).await;
    let key = seed_key(&pool, owner, "encryption").await;
    let new_key = random32();

    let msg = assert_refused(
        rotate_as(&pool, "epigraph_app", Some(other), key, &new_key).await,
        INSUFFICIENT_PRIVILEGE,
        "another agent rotated the key",
    );
    assert!(msg.contains("AK03"), "{msg}");
    assert_refused(
        rotate_as(&pool, "epigraph_app", None, key, &new_key).await,
        INSUFFICIENT_PRIVILEGE,
        "an unstamped application session rotated the key",
    );
    assert_refused(
        rotate_as(&pool, "epigraph_app", Some(owner), key, &[7u8; 31]).await,
        INVALID_PARAMETER,
        "a 31-byte new key was recorded",
    );
    assert_eq!(key_count(&pool, owner).await, 1, "a refusal wrote no row");
    assert_eq!(key_state(&pool, key).await, ("active".to_string(), true));

    rotate_as(&pool, "epigraph_app", Some(owner), key, &new_key)
        .await
        .expect("the key's own agent rotates it");
    let (agent, key_type, status, opened, old_closed): (
        Uuid,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT n.agent_id, n.key_type::text, n.status::text, n.valid_from, o.valid_until \
           FROM agent_keys n, agent_keys o \
          WHERE n.public_key = $1 AND o.id = $2",
    )
    .bind(&new_key)
    .bind(key)
    .fetch_one(&pool)
    .await
    .expect("the new row");
    assert_eq!(
        (agent, key_type.as_str(), status.as_str()),
        (owner, "encryption", "active")
    );
    assert_eq!(key_state(&pool, key).await.0, "rotated");
    assert_eq!(
        Some(opened),
        old_closed,
        "the new window opens where the old one closed"
    );

    let msg = assert_refused(
        rotate_as(&pool, "epigraph_app", Some(owner), key, &random32()).await,
        INVALID_PARAMETER,
        "a key that is no longer active was rotated again",
    );
    assert!(msg.contains("AK01"), "{msg}");

    let signing = seed_key(&pool, owner, "signing").await;
    let msg = assert_refused(
        rotate_as(&pool, "epigraph_app", Some(owner), signing, &random32()).await,
        INSUFFICIENT_PRIVILEGE,
        "an application session rotated an attested signing key",
    );
    assert!(msg.contains("AK02"), "{msg}");
    assert_eq!(key_count(&pool, owner).await, 3, "refusals wrote no row");
    assert_eq!(key_state(&pool, signing).await.0, "active");

    rotate_as(&pool, "epigraph_maintenance", None, signing, &random32())
        .await
        .expect("CALIBRATION: a maintenance session rotates an attested key");
    assert_eq!(key_state(&pool, signing).await.0, "rotated");
}

/// `docs/runbooks/239-undo.sql` returns the pre-239 state and is safe to run
/// twice: the application role holds INSERT on `agent_keys` again, the
/// rotation definer is gone, and the status definer moves another agent's
/// non-attested key again (163's body, no caller gate) while still refusing
/// an attested one (AK02).
#[sqlx::test(migrations = "../../migrations")]
async fn the_undo_restores_the_pre_239_grants_and_body(pool: PgPool) {
    let undo = include_str!("../../../docs/runbooks/239-undo.sql");
    for _ in 0..2 {
        sqlx::raw_sql(undo)
            .execute(&pool)
            .await
            .expect("239-undo.sql");
    }
    let (insert, rotate): (bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('epigraph_app', 'public.agent_keys', 'INSERT'), \
                to_regprocedure('public.epigraph_agent_key_rotate(uuid, bytea)') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert_eq!((insert, rotate), (true, false));

    let owner = plain_agent(&pool).await;
    let other = plain_agent(&pool).await;
    let key = seed_key(&pool, owner, "encryption").await;
    set_status_as(&pool, "epigraph_app", Some(other), key, "rotated")
        .await
        .expect("163's body has no caller gate");
    let signing = seed_key(&pool, owner, "signing").await;
    let msg = assert_refused(
        set_status_as(&pool, "epigraph_app", Some(owner), signing, "revoked").await,
        INSUFFICIENT_PRIVILEGE,
        "163's body still gates an attested key",
    );
    assert!(msg.contains("AK02"), "{msg}");
}

fn db_code(e: &epigraph_db::DbError) -> Option<String> {
    match e {
        epigraph_db::DbError::QueryFailed { source } => sqlstate(source),
        _ => None,
    }
}

/// The HTTP rotate and revoke routes' exact repository calls
/// (`AgentKeyRepository::get_active_key`, `rotate`, `get_by_id`,
/// `update_status`), each on a transaction an APPLICATION-ROLE `ScopedPool`
/// stamps with a resolved `Viewer`, the way `AppState::write_as` stamps it.
/// The API's own tests connect as a superuser, for which every gate passes,
/// so this is where the route's stamping meets the gate: another agent's
/// viewer is refused AK03 and writes nothing; the owner's viewer rotates
/// (one new row, same agent and type) and revokes.
#[sqlx::test(migrations = "../../migrations")]
async fn the_routes_repository_calls_admit_only_the_stamped_owner(pool: PgPool) {
    use epigraph_core::AgentId;
    use epigraph_db::{AgentKeyRepository, ScopedPool, SessionGucMode, Viewer};

    let owner = plain_agent(&pool).await;
    let other = plain_agent(&pool).await;
    let key = seed_key(&pool, owner, "encryption").await;
    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("application-role ScopedPool");
    let other_viewer = Viewer::resolve(&pool, other).await.expect("viewer");
    let owner_viewer = Viewer::resolve(&pool, owner).await.expect("viewer");

    let mut tx = scoped.begin_as(&other_viewer).await.expect("begin_as");
    let e = AgentKeyRepository::rotate(&mut *tx, key, &[9u8; 32])
        .await
        .expect_err("another agent's stamped transaction rotated the key");
    assert_eq!(db_code(&e).as_deref(), Some(INSUFFICIENT_PRIVILEGE), "{e}");
    assert!(e.to_string().contains("AK03"), "{e}");
    drop(tx);
    let mut tx = scoped.begin_as(&other_viewer).await.expect("begin_as");
    let e = AgentKeyRepository::update_status(&mut *tx, key, "revoked", Some("x"), None)
        .await
        .expect_err("another agent's stamped transaction revoked the key");
    assert_eq!(db_code(&e).as_deref(), Some(INSUFFICIENT_PRIVILEGE), "{e}");
    drop(tx);
    assert_eq!(key_count(&pool, owner).await, 1);
    assert_eq!(key_state(&pool, key).await, ("active".to_string(), true));

    let mut tx = scoped.begin_as(&owner_viewer).await.expect("begin_as");
    let active =
        AgentKeyRepository::get_active_key(&mut *tx, AgentId::from_uuid(owner), "encryption")
            .await
            .expect("lookup")
            .expect("the active key");
    assert_eq!(active.id, key);
    let new = AgentKeyRepository::rotate(&mut *tx, active.id, &[9u8; 32])
        .await
        .expect("the owner rotates")
        .expect("the new row");
    assert!(
        AgentKeyRepository::rotate(&mut *tx, Uuid::new_v4(), &[8u8; 32])
            .await
            .expect("an unknown key is not an error")
            .is_none(),
        "an unknown old key yields no row"
    );
    tx.commit().await.expect("commit");
    assert_eq!(
        (new.agent_id, new.key_type.as_str(), new.status.as_str()),
        (owner, "encryption", "active")
    );
    assert_eq!(new.public_key, vec![9u8; 32]);
    assert_eq!(key_state(&pool, key).await.0, "rotated");

    let mut tx = scoped.begin_as(&owner_viewer).await.expect("begin_as");
    let row = AgentKeyRepository::get_by_id(&mut *tx, new.id)
        .await
        .expect("lookup")
        .expect("the new key");
    let revoked =
        AgentKeyRepository::update_status(&mut *tx, row.id, "revoked", Some("lost"), Some(owner))
            .await
            .expect("the owner revokes");
    tx.commit().await.expect("commit");
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.revoked_by, Some(owner));
}
