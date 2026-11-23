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
//! * On the migrations without 239 (the insert, status and rotation tests,
//!   before 239 was written): the `encryption` INSERT succeeds, another
//!   agent's principal moves the key to `rotated`, and the rotation definer
//!   does not exist (42883).
//! * 239 with its `REVOKE INSERT` removed: fails
//!   `the_application_role_cannot_insert_an_agent_key_of_any_type` only.
//! * 239 with EXECUTE on the rotation definer granted to `epigraph_app` (the
//!   first draft of 239): fails
//!   `the_application_role_does_not_execute_the_rotation_definer` and
//!   `the_routes_repository_calls_admit_only_the_stamped_owner`.
//! * 239 with the caller gate of `epigraph_agent_key_set_status` forced true:
//!   fails `a_status_change_needs_the_keys_agent_or_an_admin` and
//!   `the_routes_repository_calls_admit_only_the_stamped_owner`.
//! * 239 with the rotation definer's caller gate forced true: fails
//!   `the_rotation_definer_rotates_only_for_the_keys_agent`.
//! * 239 with the admin arm deleted from the status definer's gate: fails
//!   `a_status_change_needs_the_keys_agent_or_an_admin` (the unarmed
//!   instance admin); from the rotation definer's gate: fails
//!   `the_rotation_definer_rotates_only_for_the_keys_agent` (likewise).
//! * 239 with the armed arm (`epigraph_is_elevated()`) forced false in both
//!   definers: fails both of those tests at the elevated custodian.

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

/// How a test session is stamped: the principal (`None`: unstamped) and,
/// for an elevated admin, its live elevation session and token family (with
/// the access-recorder declaration a recording build stamps).
#[derive(Clone, Copy)]
struct Stamp {
    principal: Option<Uuid>,
    elevation: Option<(Uuid, Uuid)>,
}

impl Stamp {
    fn as_(principal: Option<Uuid>) -> Self {
        Self {
            principal,
            elevation: None,
        }
    }

    fn elevated(h: &elevation::Holder, session: Uuid) -> Self {
        Self {
            principal: Some(h.person),
            elevation: Some((session, h.family)),
        }
    }
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
    run_stamped(pool, role, Stamp::as_(principal), sql, binds)
        .await
        .1
}

/// [`run_as`] under a full [`Stamp`]. Returns what `epigraph_is_elevated()`
/// answered on that connection (the calibration of an elevated stamp) and the
/// statement's result. Every GUC it sets is cleared again: they are
/// session-level and the pooled connection is reused.
async fn run_stamped(
    pool: &PgPool,
    role: &'static str,
    stamp: Stamp,
    sql: &'static str,
    binds: Vec<String>,
) -> (bool, Result<(), sqlx::Error>) {
    fixture::as_role(pool, role, |mut conn| async move {
        let (elv, fam, rec) = match stamp.elevation {
            Some((session, family)) => (session.to_string(), family.to_string(), "on"),
            None => (String::new(), String::new(), ""),
        };
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.elevation_id', $2, false), \
                    set_config('epigraph.family_id', $3, false), \
                    set_config('epigraph.access_recorder', $4, false)",
        )
        .bind(stamp.principal.map(|p| p.to_string()).unwrap_or_default())
        .bind(elv)
        .bind(fam)
        .bind(rec)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let is: bool = sqlx::query_scalar("SELECT public.epigraph_is_elevated()")
            .fetch_one(&mut *conn)
            .await
            .expect("is_elevated");
        let mut q = sqlx::query(sql);
        for b in binds {
            q = q.bind(b);
        }
        let r = q.execute(&mut *conn).await.map(|_| ());
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.elevation_id', '', false), \
                    set_config('epigraph.family_id', '', false), \
                    set_config('epigraph.access_recorder', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, (is, r))
    })
    .await
}

/// Arm the admin-scope switch (migration 128) on the harness connection.
async fn arm_admin_scopes(pool: &PgPool) {
    sqlx::query(
        "SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'agent_keys_app_role_writes')",
    )
    .execute(pool)
    .await
    .expect("arm the admin-scope switch");
}

/// Since 239 the application role does not execute the rotation definer. The
/// definer's own gates are still pinned, for any future grantee, by granting
/// it EXECUTE here, the way `agent_identity_lineage.rs` re-grants INSERT to
/// keep testing 161's guard.
async fn grant_rotate_to_app_for_this_test(pool: &PgPool) {
    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.epigraph_agent_key_rotate(uuid, bytea) TO epigraph_app",
    )
    .execute(pool)
    .await
    .expect("test-local grant");
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
    rotate_stamped(pool, role, Stamp::as_(principal), key, new_key)
        .await
        .1
}

async fn rotate_stamped(
    pool: &PgPool,
    role: &'static str,
    stamp: Stamp,
    key: Uuid,
    new_key: &[u8],
) -> (bool, Result<(), sqlx::Error>) {
    run_stamped(
        pool,
        role,
        stamp,
        "SELECT * FROM public.epigraph_agent_key_rotate($1::uuid, decode($2, 'hex'))",
        vec![key.to_string(), hex::encode(new_key)],
    )
    .await
}

async fn set_status_stamped(
    pool: &PgPool,
    role: &'static str,
    stamp: Stamp,
    key: Uuid,
    status: &str,
) -> (bool, Result<(), sqlx::Error>) {
    run_stamped(
        pool,
        role,
        stamp,
        "SELECT * FROM public.epigraph_agent_key_set_status($1::uuid, $2, 'test', NULL)",
        vec![key.to_string(), status.to_string()],
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
/// session. Armed, the standing instance admin no longer counts and the same
/// custodian counts only while ELEVATED (the armed admin arm).
#[sqlx::test(migrations = "../../migrations")]
async fn a_status_change_needs_the_keys_agent_or_an_admin(pool: PgPool) {
    let owner = plain_agent(&pool).await;
    let other = plain_agent(&pool).await;
    // An instance admin is the live holder of `role:platform-custodian`
    // (123); the fixture grants it the way the operator CLI does, and gives
    // it a passkey so it can hold a confirmed elevation session.
    let holder = elevation::holder(&pool, "ak status admin", 3).await;
    let admin = holder.person;
    let live = elevation::session(&pool, &holder).await;

    let key = seed_key(&pool, owner, "encryption").await;
    for status in ["rotated", "revoked"] {
        let msg = assert_refused(
            set_status_as(&pool, "epigraph_app", Some(other), key, status).await,
            INSUFFICIENT_PRIVILEGE,
            &format!("another agent moved the key to {status}"),
        );
        assert!(msg.contains("AK03"), "{msg}");
        let msg = assert_refused(
            set_status_as(&pool, "epigraph_app", None, key, status).await,
            INSUFFICIENT_PRIVILEGE,
            &format!("an unstamped application session moved the key to {status}"),
        );
        assert!(msg.contains("AK03"), "{msg}");
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

    arm_admin_scopes(&pool).await;
    let k3 = seed_key(&pool, owner, "encryption").await;
    let msg = assert_refused(
        set_status_as(&pool, "epigraph_app", Some(admin), k3, "revoked").await,
        INSUFFICIENT_PRIVILEGE,
        "armed: a standing instance admin without an elevation moved another agent's key",
    );
    assert!(msg.contains("AK03"), "{msg}");
    let (is, r) = set_status_stamped(
        &pool,
        "epigraph_app",
        Stamp::elevated(&holder, live),
        k3,
        "rotated",
    )
    .await;
    assert!(is, "CALIBRATION: the elevated connection is elevated");
    r.expect("armed: an ELEVATED custodian moves another agent's key");
    assert_eq!(key_state(&pool, k3).await.0, "rotated");
    set_status_as(&pool, "epigraph_app", Some(owner), k3, "revoked")
        .await
        .expect("armed: the key's own agent still revokes it");
    let k4 = seed_key(&pool, owner, "encryption").await;
    set_status_as(&pool, "epigraph_maintenance", None, k4, "revoked")
        .await
        .expect("CALIBRATION: a maintenance session revokes any key");
}

/// The application role does not execute `epigraph_agent_key_rotate`: a
/// grant would hand a holder of the application DSN, which stamps
/// `epigraph.principal_id` itself, a way to record a chosen key for any agent
/// holding an active non-attested key, re-opening in a definer the INSERT 239
/// revokes. Even the key's own agent, stamped, is refused 42501 before the
/// body runs, and nothing is written. CALIBRATION: a maintenance session
/// rotates the same key.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_role_does_not_execute_the_rotation_definer(pool: PgPool) {
    let can: bool = sqlx::query_scalar(
        "SELECT has_function_privilege('epigraph_app', \
                'public.epigraph_agent_key_rotate(uuid, bytea)', 'EXECUTE')",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert!(!can, "the application role executes the rotation definer");

    let owner = plain_agent(&pool).await;
    let key = seed_key(&pool, owner, "encryption").await;
    let msg = assert_refused(
        rotate_as(&pool, "epigraph_app", Some(owner), key, &random32()).await,
        INSUFFICIENT_PRIVILEGE,
        "the key's own agent rotated on the application role",
    );
    assert!(
        !msg.contains("AK0"),
        "refused for the role's missing EXECUTE, before the body: {msg}"
    );
    assert_eq!(key_count(&pool, owner).await, 1, "no row was written");
    assert_eq!(key_state(&pool, key).await, ("active".to_string(), true));

    rotate_as(&pool, "epigraph_maintenance", None, key, &random32())
        .await
        .expect("CALIBRATION: a maintenance session rotates the key");
    assert_eq!(key_count(&pool, owner).await, 2);
}

/// `epigraph_agent_key_rotate(old key, new public key)` retires the old key
/// and records the new one in ONE statement, for the old key's own agent (or
/// an admin) only. Its gates are pinned for any future grantee under a
/// test-local application grant ([`grant_rotate_to_app_for_this_test`]). The
/// new row's agent and type are the old row's, never the caller's choice; its
/// window opens where the old one closed. Refusals: another agent (AK03), an
/// attested type on an application session (AK02), an old key that is no
/// longer active (AK01), a new key that is not 32 bytes. Each refusal leaves
/// the agent's rows as they were. Admin arms: unarmed, a live instance admin
/// rotates another agent's key; armed, the same custodian rotates only while
/// ELEVATED.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rotation_definer_rotates_only_for_the_keys_agent(pool: PgPool) {
    grant_rotate_to_app_for_this_test(&pool).await;
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
    let msg = assert_refused(
        rotate_as(&pool, "epigraph_app", None, key, &new_key).await,
        INSUFFICIENT_PRIVILEGE,
        "an unstamped application session rotated the key",
    );
    assert!(msg.contains("AK03"), "{msg}");
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

    // The admin arms (129's predicate), on another agent's key.
    let holder = elevation::holder(&pool, "ak rotate admin", 5).await;
    let live = elevation::session(&pool, &holder).await;
    let k2 = seed_key(&pool, other, "encryption").await;
    rotate_as(&pool, "epigraph_app", Some(holder.person), k2, &random32())
        .await
        .expect("unarmed: a live instance admin rotates another agent's key");
    assert_eq!(key_state(&pool, k2).await.0, "rotated");

    arm_admin_scopes(&pool).await;
    // A third agent: `other` now holds k2's successor, its one active
    // `encryption` key (`idx_agent_keys_active`).
    let third = plain_agent(&pool).await;
    let k3 = seed_key(&pool, third, "encryption").await;
    let msg = assert_refused(
        rotate_as(&pool, "epigraph_app", Some(holder.person), k3, &random32()).await,
        INSUFFICIENT_PRIVILEGE,
        "armed: a standing instance admin without an elevation rotated another agent's key",
    );
    assert!(msg.contains("AK03"), "{msg}");
    assert_eq!(key_state(&pool, k3).await, ("active".to_string(), true));
    let (is, r) = rotate_stamped(
        &pool,
        "epigraph_app",
        Stamp::elevated(&holder, live),
        k3,
        &random32(),
    )
    .await;
    assert!(is, "CALIBRATION: the elevated connection is elevated");
    r.expect("armed: an ELEVATED custodian rotates another agent's key");
    assert_eq!(key_state(&pool, k3).await.0, "rotated");
    assert_eq!(
        (key_count(&pool, other).await, key_count(&pool, third).await),
        (2, 2),
        "each admitted rotation wrote one new row, refusals none"
    );
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
/// so this is where the route's stamping meets the gates: another agent's
/// viewer is refused AK03 on revoke and writes nothing; the rotation is
/// refused 42501 to every application caller, the owner included (no
/// EXECUTE since 239), and writes nothing; the owner's viewer revokes.
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
    let e = AgentKeyRepository::update_status(&mut *tx, key, "revoked", Some("x"), None)
        .await
        .expect_err("another agent's stamped transaction revoked the key");
    assert_eq!(db_code(&e).as_deref(), Some(INSUFFICIENT_PRIVILEGE), "{e}");
    assert!(e.to_string().contains("AK03"), "{e}");
    drop(tx);

    let mut tx = scoped.begin_as(&owner_viewer).await.expect("begin_as");
    let active =
        AgentKeyRepository::get_active_key(&mut *tx, AgentId::from_uuid(owner), "encryption")
            .await
            .expect("lookup")
            .expect("the active key");
    assert_eq!(active.id, key);
    let e = AgentKeyRepository::rotate(&mut *tx, active.id, &[9u8; 32])
        .await
        .expect_err("the owner's stamped application transaction rotated the key");
    assert_eq!(db_code(&e).as_deref(), Some(INSUFFICIENT_PRIVILEGE), "{e}");
    assert!(
        !e.to_string().contains("AK0"),
        "refused for the role's missing EXECUTE: {e}"
    );
    drop(tx);
    assert_eq!(key_count(&pool, owner).await, 1, "no row was written");
    assert_eq!(key_state(&pool, key).await, ("active".to_string(), true));

    let mut tx = scoped.begin_as(&owner_viewer).await.expect("begin_as");
    let row = AgentKeyRepository::get_by_id(&mut *tx, key)
        .await
        .expect("lookup")
        .expect("the key");
    let revoked =
        AgentKeyRepository::update_status(&mut *tx, row.id, "revoked", Some("lost"), Some(owner))
            .await
            .expect("the owner revokes");
    tx.commit().await.expect("commit");
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.revoked_by, Some(owner));
    assert_eq!(key_state(&pool, key).await, ("revoked".to_string(), false));
}

/// A custodian with a confirmed elevation session, built through migration
/// 125's definers (copied from `agent_identity_lineage.rs`, the minimal
/// subset of `elevated_arms.rs`'s fixtures).
mod elevation {
    use super::fixture;
    use sqlx::PgPool;
    use uuid::Uuid;

    pub struct Holder {
        pub person: Uuid,
        pub client: Uuid,
        pub cred: Vec<u8>,
        pub family: Uuid,
    }

    async fn as_app<F, Fut, T>(pool: &PgPool, principal: Option<Uuid>, f: F) -> T
    where
        F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
        Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
    {
        let principal = principal.map(|p| p.to_string()).unwrap_or_default();
        fixture::as_role(pool, "epigraph_app", |mut conn| async move {
            sqlx::query(
                "SELECT set_config('epigraph.principal_id', $1, false), \
                        set_config('epigraph.elevation_id', '', false), \
                        set_config('epigraph.family_id', '', false)",
            )
            .bind(&principal)
            .execute(&mut *conn)
            .await
            .expect("stamp");
            let (mut conn, out) = f(conn).await;
            sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
                .execute(&mut *conn)
                .await
                .expect("unstamp");
            (conn, out)
        })
        .await
    }

    pub async fn holder(pool: &PgPool, label: &str, n: u8) -> Holder {
        let (person, _group) = fixture::seed_human_operator(pool, label).await;
        let client: Uuid = sqlx::query_scalar(
            "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
        )
        .bind(person)
        .fetch_one(pool)
        .await
        .expect("the human's client");
        fixture::make_custodian(pool, person).await;
        let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
            let e = sqlx::query_scalar(
                "SELECT public.epigraph_create_passkey_enrollment($1, 'agent keys test', 'key')",
            )
            .bind(person)
            .fetch_one(&mut *conn)
            .await
            .expect("enroll");
            (conn, e)
        })
        .await;
        let mut cred = vec![0xA5_u8; 16];
        cred[0] = n;
        let c = cred.clone();
        as_app(pool, None, |mut conn| async move {
            sqlx::query(
                "SELECT public.epigraph_set_passkey_enrollment_challenge($1, '{\"rs\": 1}'::jsonb)",
            )
            .bind(e)
            .execute(&mut *conn)
            .await
            .expect("enrollment challenge");
            sqlx::query(
                "SELECT public.epigraph_complete_passkey_enrollment($1, $2, \
                        '{\"cred\": 1}'::jsonb, '00000000-0000-0000-0000-000000000000'::uuid, \
                        'none', true, false)",
            )
            .bind(e)
            .bind(c)
            .execute(&mut *conn)
            .await
            .expect("complete the enrollment");
            (conn, ())
        })
        .await;
        let hash: Vec<u8> = [
            Uuid::new_v4().as_bytes().to_vec(),
            Uuid::new_v4().as_bytes().to_vec(),
        ]
        .concat();
        let family: Uuid = sqlx::query_scalar(
            "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
             VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
        )
        .bind(&hash)
        .bind(client)
        .fetch_one(pool)
        .await
        .expect("a refresh token");
        Holder {
            person,
            client,
            cred,
            family,
        }
    }

    /// A confirmed grant-mode session for `h`; its id.
    pub async fn session(pool: &PgPool, h: &Holder) -> Uuid {
        let (client, fam) = (h.client, h.family);
        let ticket: Uuid = as_app(pool, Some(h.person), |mut conn| async move {
            let t = sqlx::query_scalar(
                "SELECT public.epigraph_create_elevation_ticket($1, $2, 'grant', \
                        'agent keys test', sha256('an agent keys test secret'::bytea))",
            )
            .bind(client)
            .bind(fam)
            .fetch_one(&mut *conn)
            .await
            .expect("a ticket");
            (conn, t)
        })
        .await;
        let cred = h.cred.clone();
        as_app(pool, None, |mut conn| async move {
            sqlx::query(
                "SELECT public.epigraph_set_elevation_ticket_challenge($1, '{\"st\": 1}'::jsonb)",
            )
            .bind(ticket)
            .execute(&mut *conn)
            .await
            .expect("the ceremony's challenge");
            let (outcome, session): (String, Option<Uuid>) = sqlx::query_as(
                "SELECT outcome, session_id \
                   FROM public.epigraph_confirm_elevation($1, $2, 0, false, '{\"ev\": 1}'::jsonb)",
            )
            .bind(ticket)
            .bind(cred)
            .fetch_one(&mut *conn)
            .await
            .expect("confirm");
            assert_eq!(outcome, "confirmed", "CALIBRATION: the ceremony confirms");
            (conn, session.expect("a session"))
        })
        .await
    }
}
