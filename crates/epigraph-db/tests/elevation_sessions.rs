//! Migration 125: elevation tickets, elevation sessions and
//! `epigraph_is_elevated()`.
//!
//! An elevation is a short (at most 15 minutes), read-only widening of ONE
//! human's reads, bound to one refresh-token family of that human and to the
//! live assignment of an `elevates` role that justified it (operator ruling
//! D2: never `instance_admins`), opened by a passkey ceremony over a ticket.
//! Migration 125 is INERT: nothing stamps `epigraph.elevation_id` /
//! `epigraph.family_id` yet, and no row policy reads `epigraph_is_elevated()`.
//!
//! Every SQL-authority probe runs as `epigraph_app` under `SET SESSION
//! AUTHORIZATION`, stamped with all FIVE session GUCs and unstamped afterwards
//! ([`as_app`]): a GUC left behind on a pooled connection would make an "is
//! not elevated" assertion pass or fail for the wrong reason. Sessions are
//! seeded through the definers (the ticket, the ceremony's challenge, the
//! confirmation) with synthetic evidence: the database cannot verify a
//! signature, so what it is asked to hold here is the binding, not the
//! cryptography. A superuser with triggers off (`session_replication_role =
//! replica`) is used ONLY to age a row or to make a change without its end
//! trigger, so that the COMPUTED check in `epigraph_is_elevated()` is what is
//! under test. Every refusal is asserted by its SQLSTATE.
//!
//! Each test names the mutation of `migrations/125_elevation.sql` it was run
//! against ("Verified to fail").

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;

const CUSTODIAN: &str = "role:platform-custodian";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

fn assert_code<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>, code: &str, what: &str) {
    assert_eq!(
        code_of(r).as_deref(),
        Some(code),
        "{what}: expected SQLSTATE {code}, got {r:?}"
    );
}

/// Run `f` as `epigraph_app` with all five session GUCs stamped: the
/// principal (empty when `None`), empty group sets, and the two elevation
/// GUCs as given (an empty string is "unset"). All five are cleared
/// afterwards, so nothing leaks to the next checkout of the connection.
async fn as_app<F, Fut, T>(pool: &PgPool, principal: Option<Uuid>, elv: &str, fam: &str, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let principal = principal.map(|p| p.to_string()).unwrap_or_default();
    let (elv, fam) = (elv.to_string(), fam.to_string());
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false), \
                    set_config('epigraph.elevation_id', $2, false), \
                    set_config('epigraph.family_id', $3, false)",
        )
        .bind(&principal)
        .bind(&elv)
        .bind(&fam)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.elevation_id', '', false), \
                    set_config('epigraph.family_id', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

/// One statement on an `epigraph_app` session stamped as `principal`
/// (no elevation GUCs); rows affected.
async fn app_exec(pool: &PgPool, principal: Option<Uuid>, sql: &str) -> Result<u64, sqlx::Error> {
    let sql = sql.to_string();
    as_app(pool, principal, "", "", |mut conn| async move {
        let r = sqlx::query(&sql)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
        (conn, r)
    })
    .await
}

/// One statement binding `id` on a maintenance session; rows affected.
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

/// One statement binding `id` as the harness superuser with every trigger
/// off: used only to age a row, or to make a change WITHOUT its end trigger
/// so that the computed check is what holds.
async fn without_triggers(pool: &PgPool, sql: &str, id: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .expect("triggers off");
    let r = sqlx::query(sql).bind(id).execute(&mut *conn).await;
    sqlx::query("SET session_replication_role = DEFAULT")
        .execute(&mut *conn)
        .await
        .expect("triggers on");
    r.unwrap_or_else(|e| panic!("{sql}: {e}"));
}

/// A credential id of WebAuthn's minimum length, distinct per `n`.
fn credential(n: u8) -> Vec<u8> {
    let mut id = vec![0xA5_u8; 16];
    id[0] = n;
    id
}

/// A registered human (an active `human` client and a live registry row):
/// `(agent, human client id)`.
async fn human(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let (person, _) = fixture::seed_human_operator(pool, label).await;
    let client: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client");
    (person, client)
}

/// A live passkey for `person`, through 124's ceremony definers: enrolled on
/// the maintenance role, challenged and completed by the unstamped app.
async fn passkey(pool: &PgPool, person: Uuid, n: u8) -> Uuid {
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'elevation test', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("enroll");
        (conn, e)
    })
    .await;
    as_app(pool, None, "", "", |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_set_passkey_enrollment_challenge($1, '{\"rs\": 1}'::jsonb)",
        )
        .bind(e)
        .execute(&mut *conn)
        .await
        .expect("enrollment challenge");
        let key: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_complete_passkey_enrollment($1, $2, \
                    '{\"cred\": 1}'::jsonb, '00000000-0000-0000-0000-000000000000'::uuid, \
                    'none', true, false)",
        )
        .bind(e)
        .bind(credential(n))
        .fetch_one(&mut *conn)
        .await
        .expect("complete the enrollment");
        (conn, key)
    })
    .await
}

/// A live refresh token of `client`, which is its own family: `(family id,
/// token hash)`.
async fn family(pool: &PgPool, client: Uuid) -> (Uuid, Vec<u8>) {
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh token");
    (id, hash)
}

/// A registered human holding `role:platform-custodian`, with one live
/// passkey and one live refresh family of its own human client.
#[derive(Clone, Debug)]
struct Holder {
    person: Uuid,
    client: Uuid,
    assignment: Uuid,
    passkey: Uuid,
    cred: Vec<u8>,
    family: Uuid,
    token_hash: Vec<u8>,
}

async fn holder(pool: &PgPool, label: &str, n: u8) -> Holder {
    let (person, client) = human(pool, label).await;
    let assignment = fixture::make_custodian(pool, person).await;
    let passkey = passkey(pool, person, n).await;
    let (family, token_hash) = family(pool, client).await;
    Holder {
        person,
        client,
        assignment,
        passkey,
        cred: credential(n),
        family,
        token_hash,
    }
}

/// `epigraph_create_elevation_ticket` on an app session stamped as
/// `principal`; `secret` is hashed (SHA-256) into the grant-mode redeem hash.
async fn create_ticket(
    pool: &PgPool,
    principal: Option<Uuid>,
    client: Uuid,
    fam: Uuid,
    mode: &str,
    secret: Option<&[u8]>,
) -> Result<Uuid, sqlx::Error> {
    let (mode, secret) = (mode.to_string(), secret.map(<[u8]>::to_vec));
    as_app(pool, principal, "", "", |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, $3, 'elevation test', \
                    CASE WHEN $4::bytea IS NULL THEN NULL ELSE sha256($4::bytea) END)",
        )
        .bind(client)
        .bind(fam)
        .bind(&mode)
        .bind(secret)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// The ceremony's first step, as the unauthenticated API runs it.
async fn start(pool: &PgPool, ticket: Uuid) -> Result<(), sqlx::Error> {
    as_app(pool, None, "", "", |mut conn| async move {
        let r = sqlx::query(
            "SELECT public.epigraph_set_elevation_ticket_challenge($1, '{\"st\": 1}'::jsonb)",
        )
        .bind(ticket)
        .execute(&mut *conn)
        .await
        .map(|_| ());
        (conn, r)
    })
    .await
}

/// A started ticket for `h` on its own client and family.
async fn ticket(pool: &PgPool, h: &Holder, mode: &str, secret: Option<&[u8]>) -> Uuid {
    let t = create_ticket(pool, Some(h.person), h.client, h.family, mode, secret)
        .await
        .expect("a ticket");
    start(pool, t).await.expect("the ceremony's challenge");
    t
}

/// `epigraph_confirm_elevation`'s answer: (outcome, session, refusal, code).
type Confirmed = (String, Option<Uuid>, Option<String>, Option<String>);

/// The ceremony's last step, as the unauthenticated API runs it once the
/// library verified an assertion by `cred` with this counter and
/// backup-eligible flag.
async fn confirm(
    pool: &PgPool,
    ticket: Uuid,
    cred: &[u8],
    counter: i64,
    backup_eligible: bool,
) -> Result<Confirmed, sqlx::Error> {
    let cred = cred.to_vec();
    as_app(pool, None, "", "", |mut conn| async move {
        let r = sqlx::query_as::<_, Confirmed>(
            "SELECT outcome, session_id, refusal, code \
               FROM public.epigraph_confirm_elevation($1, $2, $3, $4, '{\"ev\": 1}'::jsonb)",
        )
        .bind(ticket)
        .bind(cred)
        .bind(counter)
        .bind(backup_eligible)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// A confirmed connector-mode session for `h`; its id.
async fn elevated(pool: &PgPool, h: &Holder) -> Uuid {
    let t = ticket(pool, h, "connector", None).await;
    let r = confirm(pool, t, &h.cred, 0, false).await.expect("confirm");
    assert_eq!(
        r.0, "confirmed",
        "CALIBRATION: the ceremony confirms: {r:?}"
    );
    r.1.expect("a session")
}

/// `epigraph_is_elevated()` on an app session with these GUCs.
async fn is_elevated(pool: &PgPool, principal: Option<Uuid>, elv: &str, fam: &str) -> bool {
    as_app(pool, principal, elv, fam, |mut conn| async move {
        let v: bool = sqlx::query_scalar("SELECT public.epigraph_is_elevated()")
            .fetch_one(&mut *conn)
            .await
            .expect("epigraph_is_elevated()");
        (conn, v)
    })
    .await
}

async fn elevated_as(pool: &PgPool, h: &Holder, session: Uuid) -> bool {
    is_elevated(
        pool,
        Some(h.person),
        &session.to_string(),
        &h.family.to_string(),
    )
    .await
}

async fn events(pool: &PgPool, event_type: &str, key: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = $1 AND details->>$2 = $3",
    )
    .bind(event_type)
    .bind(key)
    .bind(id.to_string())
    .fetch_one(pool)
    .await
    .expect("events")
}

async fn ended_reason(pool: &PgPool, session: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT ended_reason FROM elevation_sessions WHERE id = $1")
        .bind(session)
        .fetch_one(pool)
        .await
        .expect("the session")
}

/// Move a session an hour into the past (started and expiry together, so the
/// 15-minute CHECK still holds): expired, still un-ended.
async fn age_session(pool: &PgPool, session: Uuid) {
    without_triggers(
        pool,
        "UPDATE elevation_sessions SET started_at = started_at - interval '1 hour', \
                                       expires_at = expires_at - interval '1 hour' \
          WHERE id = $1",
        session,
    )
    .await;
}

/// `epigraph_elevation_live(elv, family)` on an app session stamped as
/// `h.person`: the session ids it returns.
async fn live_rows(pool: &PgPool, h: &Holder, elv: Option<Uuid>) -> Vec<Uuid> {
    let fam = h.family;
    as_app(pool, Some(h.person), "", "", |mut conn| async move {
        let r: Vec<Uuid> =
            sqlx::query_scalar("SELECT session_id FROM public.epigraph_elevation_live($1, $2)")
                .bind(elv)
                .bind(fam)
                .fetch_all(&mut *conn)
                .await
                .expect("elevation_live");
        (conn, r)
    })
    .await
}

/// The same holder on a SECOND active human client of its own (not the one
/// its registration records), with a live family there.
async fn on_a_second_client(pool: &PgPool, h: &Holder) -> Holder {
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, 'second human client', 'human', ARRAY['claims:read'], 'active', $2) \
         RETURNING id",
    )
    .bind(format!("second-human-{}", h.person))
    .bind(h.person)
    .fetch_one(pool)
    .await
    .expect("a second human client");
    let (family, token_hash) = family(pool, client).await;
    Holder {
        client,
        family,
        token_hash,
        ..h.clone()
    }
}

/// Link `agent` to `operator` as its agent (superuser; every
/// `operator_links` trigger runs).
async fn link_as_agent(pool: &PgPool, agent: Uuid, operator: Uuid) {
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) \
         SELECT $1, $2, m.group_id FROM group_memberships m \
          WHERE m.agent_id = $2 AND m.role = 'admin' AND m.revoked_at IS NULL \
          ORDER BY m.group_id LIMIT 1",
    )
    .bind(agent)
    .bind(operator)
    .execute(pool)
    .await
    .expect("link as an agent");
}

// =====================================================================
// ELV02. Who may open a ticket (D2): a registered human that is no other
// human's agent, holding a LIVE assignment of an `elevates` role, with a
// live passkey, on a live family of its own human client. Never
// `instance_admins`.
// =====================================================================

/// CALIBRATION for the refusals below: a custodian with a passkey, on its own
/// family, gets a ticket, and the request is audited
/// (`platform.elevation_requested`).
#[sqlx::test(migrations = "../../migrations")]
async fn a_holder_gets_a_ticket(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let t = ticket(&pool, &h, "connector", None).await;
    assert_eq!(
        events(&pool, "platform.elevation_requested", "ticket_id", t).await,
        1,
        "the request is audited"
    );
}

/// A registered human with a passkey and a family but NO elevating role
/// assignment is refused `ELV02`.
///
/// Verified to fail: the ticket guard's role check dropped -> the ticket
/// lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_to_a_non_holder(pool: PgPool) {
    let (p, c) = human(&pool, "non-holder").await;
    passkey(&pool, p, 2).await;
    let (fam, _) = family(&pool, c).await;
    assert_code(
        &create_ticket(&pool, Some(p), c, fam, "connector", None).await,
        "ELV02",
        "a registered human holding no elevating role",
    );
}

/// An agent (linked to a custodian, on a family of its own agent client) is
/// refused `ELV02`, and so is the same agent naming its OPERATOR's client and
/// family: the ticket's person is the session principal, never the family's
/// owner.
///
/// Verified to fail: the create definer's principal binding replaced by the
/// person of the family's client -> the agent's ticket on its operator's
/// family lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_to_an_agent(pool: PgPool) {
    let h = holder(&pool, "operator", 1).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    link_as_agent(&pool, agent, h.person).await;
    let agent_client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, owner_id) \
         VALUES ($1, 'agent', 'agent', ARRAY['claims:write'], 'active', $2, $3) RETURNING id",
    )
    .bind(format!("agent-{agent}"))
    .bind(agent)
    .bind(h.client)
    .fetch_one(&pool)
    .await
    .expect("the agent's client");
    let (agent_fam, _) = family(&pool, agent_client).await;
    assert_code(
        &create_ticket(
            &pool,
            Some(agent),
            agent_client,
            agent_fam,
            "connector",
            None,
        )
        .await,
        "ELV02",
        "an agent on its own family",
    );
    assert_code(
        &create_ticket(&pool, Some(agent), h.client, h.family, "connector", None).await,
        "ELV02",
        "an agent naming its operator's client and family",
    );
}

/// A custodian with no passkey is refused `ELV02`, and so is one whose only
/// passkey is revoked.
///
/// Verified to fail: the ticket guard's passkey check dropped -> the
/// passkey-less ticket lands; its `revoked_at IS NULL` filter dropped -> the
/// revoked-only ticket lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_to_a_holder_with_no_live_passkey(pool: PgPool) {
    let (p, c) = human(&pool, "no-passkey").await;
    fixture::make_custodian(&pool, p).await;
    let (fam, _) = family(&pool, c).await;
    assert_code(
        &create_ticket(&pool, Some(p), c, fam, "connector", None).await,
        "ELV02",
        "a custodian with no passkey",
    );
    let key = passkey(&pool, p, 3).await;
    maint_exec(
        &pool,
        "SELECT public.epigraph_revoke_passkey($1, 'elevation test')",
        key,
    )
    .await
    .expect("revoke the passkey");
    assert_code(
        &create_ticket(&pool, Some(p), c, fam, "connector", None).await,
        "ELV02",
        "a custodian whose only passkey is revoked",
    );
}

/// A custodian naming another custodian's client and family, its own client
/// with the other's family, or the other's client with its own family, is
/// refused `ELV02`; so is a family whose token is revoked.
///
/// Verified to fail: the family check's client-owner test (`c.agent_id =
/// p_person`) dropped -> B's client and family land; its client match dropped
/// -> B's client with P's own family lands; its revoked filter dropped -> the
/// revoked family lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_on_a_foreign_or_dead_family(pool: PgPool) {
    let p = holder(&pool, "P", 1).await;
    let b = holder(&pool, "B", 2).await;
    for (client, fam, what) in [
        (b.client, b.family, "B's client and family"),
        (p.client, b.family, "P's client, B's family"),
        (b.client, p.family, "B's client, P's family"),
    ] {
        assert_code(
            &create_ticket(&pool, Some(p.person), client, fam, "connector", None).await,
            "ELV02",
            what,
        );
    }
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now(), revoked_reason = 'revoked' WHERE id = $1",
    )
    .bind(p.family)
    .execute(&pool)
    .await
    .expect("revoke P's family");
    assert_code(
        &create_ticket(&pool, Some(p.person), p.client, p.family, "connector", None).await,
        "ELV02",
        "a revoked family",
    );
}

/// D2: a registered human with a live `instance_admins` row (seeded past
/// 123's freeze) but NO role assignment is refused `ELV02`. A standing flag
/// is not an elevation.
///
/// Verified to fail: the ticket guard keyed on `instance_admins` in place of
/// the role, and keyed on "the role OR `instance_admins`" -> the ticket lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_to_an_instance_admins_only_principal(pool: PgPool) {
    let (p, c) = human(&pool, "legacy-admin").await;
    passkey(&pool, p, 4).await;
    let (fam, _) = family(&pool, c).await;
    without_triggers(
        &pool,
        "INSERT INTO instance_admins (agent_id, note) VALUES ($1, 'legacy')",
        p,
    )
    .await;
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM instance_admins WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(p)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(live, 1, "CALIBRATION: a live instance_admins row");
    assert_code(
        &create_ticket(&pool, Some(p), c, fam, "connector", None).await,
        "ELV02",
        "an instance_admins-only principal",
    );
}

/// An unstamped application session gets no ticket (`ELV02`): the ticket's
/// person is the authenticated principal or nobody.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_unstamped(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    assert_code(
        &create_ticket(&pool, None, h.client, h.family, "connector", None).await,
        "ELV02",
        "an unstamped session",
    );
}

// =====================================================================
// The confirmation: the credential is the TICKET person's, checked at use.
// =====================================================================

/// The confused deputy: P's passkey completing B's ticket is REFUSED (and
/// returned, not raised), the ticket is burned, no session opens, and
/// `platform.elevation_refused` is written. The burned ticket cannot be
/// retried with B's own credential (`ELV06`).
///
/// Verified to fail: the person comparison dropped -> P's credential opens a
/// session on B's ticket; the credential compared to the session principal
/// (unstamped on the ceremony, so to itself) -> likewise; the refusal raised
/// instead of returned -> the audit row rolls back with it; the ticket
/// audit's refused branch dropped -> no `platform.elevation_refused`.
#[sqlx::test(migrations = "../../migrations")]
async fn another_persons_credential_is_refused_with_an_event(pool: PgPool) {
    let b = holder(&pool, "B", 1).await;
    let p = holder(&pool, "P", 2).await;
    let t = ticket(&pool, &b, "connector", None).await;
    let r = confirm(&pool, t, &p.cred, 0, false)
        .await
        .expect("a refusal is an answer, not an error");
    assert_eq!(
        (r.0.as_str(), r.1, r.2.as_deref(), r.3.as_deref()),
        ("refused", None, Some("person_mismatch"), Some("ELV02")),
        "P's passkey on B's ticket"
    );
    assert_eq!(
        events(&pool, "platform.elevation_refused", "ticket_id", t).await,
        1,
        "the refusal is audited"
    );
    let sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM elevation_sessions WHERE ticket_id = $1")
            .bind(t)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(sessions, 0, "no session");
    assert_code(
        &confirm(&pool, t, &b.cred, 0, false).await,
        "ELV06",
        "a retry of the burned ticket with the right credential",
    );
}

/// A confirmation by the ticket person's live passkey opens a session bound
/// to the assignment live at that instant, at most 15 minutes, audited
/// `platform.elevated`; `epigraph_is_elevated()` is true with both GUCs.
#[sqlx::test(migrations = "../../migrations")]
async fn a_confirmed_ceremony_elevates(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    assert_eq!(
        events(&pool, "platform.elevated", "session_id", sid).await,
        1,
        "the elevation is audited"
    );
    let (assignment, bounded): (Uuid, bool) = sqlx::query_as(
        "SELECT assignment_id, expires_at <= started_at + interval '15 minutes' \
           FROM elevation_sessions WHERE id = $1",
    )
    .bind(sid)
    .fetch_one(&pool)
    .await
    .expect("the session");
    assert_eq!(assignment, h.assignment, "the live assignment is stored");
    assert!(bounded, "at most 15 minutes");
    assert!(elevated_as(&pool, &h, sid).await, "elevated with both GUCs");
}

/// A signature counter that does not advance (a cloned authenticator) is
/// refused `ELV05`, returned, audited twice (`platform.passkey_counter_regressed`
/// and `platform.elevation_refused`), and the stored counter does not move. A
/// counterless authenticator (0 -> 0) is not a regression.
///
/// Verified to fail: the counter check dropped, and made strict-less (an
/// equal counter accepted) -> the second 5 confirms; made to refuse 0 -> 0 ->
/// every counterless confirmation in this file is refused; the ticket audit's
/// refused branch dropped -> no `platform.elevation_refused`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_counter_regression_is_refused_and_audited(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let t = ticket(&pool, &h, "connector", None).await;
    let r = confirm(&pool, t, &h.cred, 5, false).await.expect("confirm");
    assert_eq!(r.0, "confirmed", "counter 5: {r:?}");
    let ended: bool = as_app(&pool, Some(h.person), "", "", |mut conn| async move {
        let v = sqlx::query_scalar("SELECT public.epigraph_end_elevation($1, 'ended')")
            .bind(r.1.expect("session"))
            .fetch_one(&mut *conn)
            .await
            .expect("end");
        (conn, v)
    })
    .await;
    assert!(ended, "CALIBRATION: the first session ends");
    let t2 = ticket(&pool, &h, "connector", None).await;
    let r2 = confirm(&pool, t2, &h.cred, 5, false)
        .await
        .expect("confirm");
    assert_eq!(
        (r2.0.as_str(), r2.2.as_deref(), r2.3.as_deref()),
        ("refused", Some("counter_regressed"), Some("ELV05")),
        "counter 5 again"
    );
    assert_eq!(
        events(&pool, "platform.passkey_counter_regressed", "ticket_id", t2).await,
        1,
        "the regression is audited"
    );
    assert_eq!(
        events(&pool, "platform.elevation_refused", "ticket_id", t2).await,
        1,
        "the refusal is audited"
    );
    let stored: i64 =
        sqlx::query_scalar("SELECT sign_count FROM person_authenticators WHERE id = $1")
            .bind(h.passkey)
            .fetch_one(&pool)
            .await
            .expect("counter");
    assert_eq!(stored, 5, "the stored counter did not move");
    let b = holder(&pool, "counterless", 2).await;
    let tb = ticket(&pool, &b, "connector", None).await;
    assert_eq!(
        confirm(&pool, tb, &b.cred, 0, false)
            .await
            .expect("confirm")
            .0,
        "confirmed",
        "0 -> 0"
    );
}

/// A passkey registered device-bound (`backup_eligible = false`) that asserts
/// backup-eligible is refused: the library's passkey path would accept the
/// upgrade, undoing an attested hardware key's guarantee.
///
/// Verified to fail: the backup-eligibility check dropped -> the upgrade
/// confirms.
#[sqlx::test(migrations = "../../migrations")]
async fn a_device_bound_passkey_asserting_backup_eligible_is_refused(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let t = ticket(&pool, &h, "connector", None).await;
    let r = confirm(&pool, t, &h.cred, 0, true).await.expect("confirm");
    assert_eq!(
        (r.0.as_str(), r.2.as_deref()),
        ("refused", Some("backup_eligibility_changed")),
        "a backup-eligibility upgrade"
    );
}

/// The holder is re-checked at USE time, not only at the ticket: an
/// assignment ended between ticket and assertion, and a holder de-registered
/// in between (whose passkey is NOT revoked by it), are refused
/// `no_live_assignment`; a revoked passkey `credential_revoked`; an unknown
/// credential `credential_unknown`.
///
/// Verified to fail: the use-time assignment re-check dropped -> the ended
/// and the de-registered holders confirm; the revoked-credential test dropped
/// -> the revoked passkey confirms.
#[sqlx::test(migrations = "../../migrations")]
async fn a_confirmation_rechecks_the_holder_at_use_time(pool: PgPool) {
    let h = holder(&pool, "ended", 1).await;
    let t = ticket(&pool, &h, "connector", None).await;
    maint_exec(
        &pool,
        "SELECT public.epigraph_end_role_assignment($1, 'elevation test')",
        h.assignment,
    )
    .await
    .expect("end the assignment");
    let r = confirm(&pool, t, &h.cred, 0, false).await.expect("confirm");
    assert_eq!(
        (r.0.as_str(), r.2.as_deref()),
        ("refused", Some("no_live_assignment")),
        "an ended assignment"
    );

    let b = holder(&pool, "deregistered", 2).await;
    let tb = ticket(&pool, &b, "connector", None).await;
    maint_exec(
        &pool,
        "SELECT * FROM public.epigraph_revoke_human_operator($1, 'elevation test')",
        b.person,
    )
    .await
    .expect("de-register");
    let live: bool =
        sqlx::query_scalar("SELECT revoked_at IS NULL FROM person_authenticators WHERE id = $1")
            .bind(b.passkey)
            .fetch_one(&pool)
            .await
            .expect("passkey");
    assert!(
        live,
        "CALIBRATION: the de-registered holder's passkey is still live"
    );
    let r = confirm(&pool, tb, &b.cred, 0, false)
        .await
        .expect("confirm");
    assert_eq!(
        (r.0.as_str(), r.2.as_deref()),
        ("refused", Some("no_live_assignment")),
        "a de-registered holder"
    );

    let c = holder(&pool, "revoked-key", 3).await;
    let tc = ticket(&pool, &c, "connector", None).await;
    maint_exec(
        &pool,
        "SELECT public.epigraph_revoke_passkey($1, 'elevation test')",
        c.passkey,
    )
    .await
    .expect("revoke the passkey");
    let r = confirm(&pool, tc, &c.cred, 0, false)
        .await
        .expect("confirm");
    assert_eq!(
        (r.0.as_str(), r.2.as_deref()),
        ("refused", Some("credential_revoked")),
        "a revoked passkey"
    );

    let d = holder(&pool, "unknown-key", 4).await;
    let td = ticket(&pool, &d, "connector", None).await;
    let r = confirm(&pool, td, &[0x99_u8; 16], 0, false)
        .await
        .expect("confirm");
    assert_eq!(
        (r.0.as_str(), r.2.as_deref()),
        ("refused", Some("credential_unknown")),
        "an unknown credential"
    );
}

/// A confirmation needs a live, STARTED ticket: one with no ceremony started,
/// and one past its 5 minutes, are refused `ELV06`; the expired one is no
/// longer served to the page.
#[sqlx::test(migrations = "../../migrations")]
async fn a_confirmation_needs_a_live_started_ticket(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let t = create_ticket(&pool, Some(h.person), h.client, h.family, "connector", None)
        .await
        .expect("ticket");
    assert_code(
        &confirm(&pool, t, &h.cred, 0, false).await,
        "ELV06",
        "no ceremony started",
    );
    without_triggers(
        &pool,
        "UPDATE elevation_tickets SET created_at = created_at - interval '1 hour', \
                                      expires_at = expires_at - interval '1 hour', \
                                      challenge_state = '{}'::jsonb WHERE id = $1",
        t,
    )
    .await;
    assert_code(
        &confirm(&pool, t, &h.cred, 0, false).await,
        "ELV06",
        "an expired ticket",
    );
    let served: i64 = as_app(&pool, None, "", "", |mut conn| async move {
        let n = sqlx::query_scalar("SELECT count(*) FROM public.epigraph_ticket_for_ceremony($1)")
            .bind(t)
            .fetch_one(&mut *conn)
            .await
            .expect("reader");
        (conn, n)
    })
    .await;
    assert_eq!(served, 0, "an expired ticket is not served");
}

/// The ceremony reads the ticket PERSON's live passkeys only (its
/// allowCredentials), never another person's, and the live ticket itself.
///
/// Verified to fail: the passkey reader's person join widened to every
/// passkey -> B's passkey is served on P's ticket.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ceremony_reads_only_the_ticket_persons_passkeys(pool: PgPool) {
    let p = holder(&pool, "P", 1).await;
    let _b = holder(&pool, "B", 2).await;
    let t = ticket(&pool, &p, "connector", None).await;
    let (keys, served): (Vec<Uuid>, i64) = as_app(&pool, None, "", "", |mut conn| async move {
        let keys = sqlx::query_scalar(
            "SELECT authenticator_id FROM public.epigraph_passkeys_for_ticket($1)",
        )
        .bind(t)
        .fetch_all(&mut *conn)
        .await
        .expect("passkeys");
        let n = sqlx::query_scalar("SELECT count(*) FROM public.epigraph_ticket_for_ceremony($1)")
            .bind(t)
            .fetch_one(&mut *conn)
            .await
            .expect("reader");
        (conn, (keys, n))
    })
    .await;
    assert_eq!(keys, vec![p.passkey], "P's passkey only");
    assert_eq!(served, 1, "the live ticket is served");
}

// =====================================================================
// epigraph_is_elevated(): true only for the principal's own live session,
// named by both GUCs, still backed by the assignment it stored.
// =====================================================================

/// False on an empty or malformed `epigraph.elevation_id` (never an error),
/// and on an empty `epigraph.family_id`.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_on_an_empty_or_malformed_guc(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    let fam = h.family.to_string();
    assert!(
        !is_elevated(&pool, Some(h.person), "", &fam).await,
        "empty elevation_id"
    );
    assert!(
        !is_elevated(&pool, Some(h.person), "not-a-uuid", &fam).await,
        "malformed elevation_id"
    );
    assert!(
        !is_elevated(&pool, Some(h.person), &sid.to_string(), "").await,
        "empty family_id"
    );
}

/// False on a forged session id.
///
/// Verified to fail: the session-id predicate replaced by `true` -> the
/// principal's live session elevates any forged id.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_on_a_forged_id(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    elevated(&pool, &h).await;
    assert!(
        !is_elevated(
            &pool,
            Some(h.person),
            &Uuid::new_v4().to_string(),
            &h.family.to_string()
        )
        .await,
        "a forged id"
    );
}

/// False on the right session id with the wrong family: another family of
/// the same person, or a forged one.
///
/// Verified to fail: the family predicate dropped -> both elevate.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_on_the_wrong_family(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    let (other, _) = family(&pool, h.client).await;
    for fam in [other, Uuid::new_v4()] {
        assert!(
            !is_elevated(&pool, Some(h.person), &sid.to_string(), &fam.to_string()).await,
            "family {fam}"
        );
    }
}

/// False for the right pair under a different principal, or unstamped.
///
/// Verified to fail: the principal predicate dropped -> B's session reads
/// elevated on P's GUC pair.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_for_a_different_principal(pool: PgPool) {
    let h = holder(&pool, "P", 1).await;
    let b = holder(&pool, "B", 2).await;
    let sid = elevated(&pool, &h).await;
    let (elv, fam) = (sid.to_string(), h.family.to_string());
    assert!(
        !is_elevated(&pool, Some(b.person), &elv, &fam).await,
        "another holder"
    );
    assert!(!is_elevated(&pool, None, &elv, &fam).await, "unstamped");
}

/// False once the session is past its expiry, though no one has ended it.
///
/// Verified to fail: the expiry predicate dropped -> the expired session
/// elevates.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_once_expired(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    age_session(&pool, sid).await;
    assert_eq!(
        ended_reason(&pool, sid).await,
        None,
        "CALIBRATION: expired but un-ended"
    );
    assert!(!elevated_as(&pool, &h, sid).await, "expired");
}

/// THE STATEMENT'S CLOCK, NOT THE TRANSACTION'S. An elevated read in
/// transaction mode runs inside ONE application `BEGIN READ ONLY`
/// (`ScopedPool::begin_read_as`), and `now()` is that transaction's START.
/// Here the session expires between two statements of one such transaction
/// (moved to expire 1.5 s later on another connection, triggers off, after
/// the first statement), and the second statement answers false: the
/// 15-minute bound is wall-clock, not "15 minutes from the start of the last
/// transaction opened inside it". After the transaction a fresh statement is
/// false too (calibration).
///
/// Verified to fail: the liveness helper's expiry comparison on `now()`
/// (the transaction's start) -> the second statement is still elevated.
/// The assignment window's comparison is not separately red: a confirmation
/// caps `expires_at` at the assignment's `valid_to`, so the window cannot
/// close before the expiry does (an equivalent mutant for this test).
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_judges_expiry_by_the_statements_clock(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    let (elv, fam) = (sid.to_string(), h.family.to_string());
    let p2 = pool.clone();
    let (first, second, current_user) =
        as_app(&pool, Some(h.person), &elv, &fam, |mut conn| async move {
            sqlx::query("BEGIN READ ONLY")
                .execute(&mut *conn)
                .await
                .expect("begin read only");
            let who: String = sqlx::query_scalar("SELECT current_user::text")
                .fetch_one(&mut *conn)
                .await
                .expect("current_user");
            let first: bool = sqlx::query_scalar("SELECT public.epigraph_is_elevated()")
                .fetch_one(&mut *conn)
                .await
                .expect("first statement");
            without_triggers(
                &p2,
                "UPDATE elevation_sessions \
                    SET expires_at = clock_timestamp() + interval '1500 milliseconds' \
                  WHERE id = $1",
                sid,
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(3000)).await;
            let second: bool = sqlx::query_scalar("SELECT public.epigraph_is_elevated()")
                .fetch_one(&mut *conn)
                .await
                .expect("second statement");
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .expect("commit");
            (conn, (first, second, who))
        })
        .await;
    assert_eq!(current_user, "epigraph_app", "CALIBRATION: the app role");
    assert!(first, "CALIBRATION: elevated at the transaction's first statement");
    assert!(
        !second,
        "an elevated READ ONLY transaction kept its elevation past the session's expiry"
    );
    assert!(
        !elevated_as(&pool, &h, sid).await,
        "CALIBRATION: expired in a fresh transaction"
    );
}

/// False once the holder ends the session (`unsudo`), which is audited
/// `platform.elevation_ended`.
///
/// Verified to fail: the ended predicate dropped -> the ended session
/// elevates; the session audit's end branch dropped -> no
/// `platform.elevation_ended` (also caught by every end-trigger test below).
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_once_ended(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    let ended: bool = as_app(&pool, Some(h.person), "", "", |mut conn| async move {
        let v = sqlx::query_scalar("SELECT public.epigraph_end_elevation($1, 'unsudo')")
            .bind(sid)
            .fetch_one(&mut *conn)
            .await
            .expect("end");
        (conn, v)
    })
    .await;
    assert!(ended, "the holder ends its own session");
    assert_eq!(
        events(&pool, "platform.elevation_ended", "session_id", sid).await,
        1,
        "the end is audited"
    );
    assert!(!elevated_as(&pool, &h, sid).await, "ended");
}

/// THE COMPUTED CHECK, assignment half: the assignment is revoked with its
/// end trigger off, so the row is still un-ended and only the body's
/// re-check of the live assignment can answer false.
///
/// Verified to fail: the assignment re-check dropped -> the revoked holder is
/// still elevated; the re-check replaced by "the stored assignment row is
/// unrevoked" is caught by the de-registration and agent-link tests below,
/// not here.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_once_the_assignment_is_revoked(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    without_triggers(
        &pool,
        "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                                     revoked_reason = 'elevation test' WHERE id = $1",
        h.assignment,
    )
    .await;
    assert_eq!(
        ended_reason(&pool, sid).await,
        None,
        "CALIBRATION: the row is un-ended"
    );
    assert!(!elevated_as(&pool, &h, sid).await, "a revoked assignment");
}

/// THE COMPUTED CHECK, registration half: the holder's registration is
/// revoked with its end trigger off.
///
/// Verified to fail: the assignment re-check dropped, or replaced by "the
/// stored assignment row is unrevoked" -> the de-registered holder is still
/// elevated.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_once_the_holder_is_deregistered(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    without_triggers(
        &pool,
        "UPDATE human_operators SET revoked_at = now(), revoked_by = session_user, \
                                    revoked_reason = 'elevation test' WHERE agent_id = $1",
        h.person,
    )
    .await;
    assert_eq!(
        ended_reason(&pool, sid).await,
        None,
        "CALIBRATION: the row is un-ended"
    );
    assert!(!elevated_as(&pool, &h, sid).await, "a de-registered holder");
}

/// THE COMPUTED CHECK, agent half: the holder is later linked as another
/// human's agent (no trigger ends a session on a link).
///
/// Verified to fail: the assignment re-check replaced by "the stored
/// assignment row is unrevoked" -> the linked holder is still elevated.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_once_the_holder_is_linked_as_an_agent(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let o = holder(&pool, "operator", 2).await;
    let sid = elevated(&pool, &h).await;
    // 123's role-holder guard refuses linking a role holder, so the link is
    // written past it (triggers off): the state "a holder that is also
    // linked" is what the computed check must answer for, however it arises.
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .expect("triggers off");
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) \
         SELECT $1, $2, m.group_id FROM group_memberships m \
          WHERE m.agent_id = $2 AND m.role = 'admin' AND m.revoked_at IS NULL \
          ORDER BY m.group_id LIMIT 1",
    )
    .bind(h.person)
    .bind(o.person)
    .execute(&mut *conn)
    .await
    .expect("link the holder as O's agent");
    sqlx::query("SET session_replication_role = DEFAULT")
        .execute(&mut *conn)
        .await
        .expect("triggers on");
    drop(conn);
    assert!(
        !elevated_as(&pool, &h, sid).await,
        "a holder linked as an agent"
    );
}

/// The re-check compares assignment IDS: a session whose stored assignment
/// ended is not kept alive by a second, later assignment of the same role.
///
/// Verified to fail: the re-check made "the person holds SOME live elevating
/// assignment" -> the session survives on the second assignment.
#[sqlx::test(migrations = "../../migrations")]
async fn the_live_assignment_must_be_the_stored_one(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    let q = holder(&pool, "grantor", 2).await;
    sqlx::query("SELECT public.epigraph_grant_role($1, $2, NULL, NULL, $3, 'a second assignment')")
        .bind(CUSTODIAN)
        .bind(h.person)
        .bind(q.person)
        .execute(&pool)
        .await
        .expect("a second assignment");
    without_triggers(
        &pool,
        "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                                     revoked_reason = 'elevation test' WHERE id = $1",
        h.assignment,
    )
    .await;
    let still: bool = sqlx::query_scalar(
        "SELECT public.epigraph_live_role_assignment($1, $2, now()) IS NOT NULL",
    )
    .bind(h.person)
    .bind(CUSTODIAN)
    .fetch_one(&pool)
    .await
    .expect("live");
    assert!(still, "CALIBRATION: the holder still holds the role");
    assert!(
        !elevated_as(&pool, &h, sid).await,
        "the stored assignment ended"
    );
}

// =====================================================================
// The bounds: 15 minutes, one live session per family, lazy expiry.
// =====================================================================

/// A session longer than 15 minutes is refused by the table's CHECK
/// (`elevation_sessions_ttl`), not by a guard; exactly 15 is admitted.
///
/// Verified to fail: the CHECK widened to 20 minutes -> the 16-minute session
/// lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_session_never_outlives_fifteen_minutes(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let t = ticket(&pool, &h, "connector", None).await;
    let insert = |mins: i32| {
        let (pool, h) = (pool.clone(), h.clone());
        async move {
            sqlx::query(
                "INSERT INTO elevation_sessions (person_agent_id, assignment_id, client_id, \
                     family_id, mode, reason, ticket_id, authenticator_id, expires_at) \
                 VALUES ($1, $2, $3, $4, 'connector', 'elevation test', $5, $6, \
                         now() + make_interval(mins => $7))",
            )
            .bind(h.person)
            .bind(h.assignment)
            .bind(h.client)
            .bind(h.family)
            .bind(t)
            .bind(h.passkey)
            .bind(mins)
            .execute(&pool)
            .await
        }
    };
    let long = insert(16).await;
    assert_code(&long, "23514", "a 16-minute session");
    let constraint = long
        .as_ref()
        .err()
        .and_then(|e| e.as_database_error())
        .and_then(|d| d.constraint().map(str::to_string));
    assert_eq!(
        constraint.as_deref(),
        Some("elevation_sessions_ttl"),
        "the CHECK, not a guard"
    );
    insert(15).await.expect("a 15-minute session");
}

/// One live session per family: a ticket on an elevated family is refused
/// `ELV06`; a ticket that predates the elevation, confirmed after it, is
/// refused `ELV06`; and a direct superuser INSERT past both meets the partial
/// unique index (`23505`).
///
/// Verified to fail: the one-per-family index dropped -> the direct INSERT
/// lands.
#[sqlx::test(migrations = "../../migrations")]
async fn one_live_session_per_family(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    elevated(&pool, &h).await;
    assert_code(
        &create_ticket(&pool, Some(h.person), h.client, h.family, "connector", None).await,
        "ELV06",
        "a ticket on an elevated family",
    );

    let h2 = holder(&pool, "holder-2", 2).await;
    let t1 = ticket(&pool, &h2, "connector", None).await;
    let t2 = ticket(&pool, &h2, "connector", None).await;
    assert_eq!(
        confirm(&pool, t1, &h2.cred, 0, false)
            .await
            .expect("first")
            .0,
        "confirmed"
    );
    assert_code(
        &confirm(&pool, t2, &h2.cred, 0, false).await,
        "ELV06",
        "a second confirmation on the family",
    );
    let direct = sqlx::query(
        "INSERT INTO elevation_sessions (person_agent_id, assignment_id, client_id, family_id, \
             mode, reason, ticket_id, authenticator_id, expires_at) \
         VALUES ($1, $2, $3, $4, 'connector', 'elevation test', $5, $6, \
                 now() + interval '5 minutes')",
    )
    .bind(h2.person)
    .bind(h2.assignment)
    .bind(h2.client)
    .bind(h2.family)
    .bind(t2)
    .bind(h2.passkey)
    .execute(&pool)
    .await;
    assert_code(&direct, "23505", "the partial unique index");
}

/// An expired, un-ended session does not block its family: the person's next
/// ticket ends it `expired` first (audited), and the family elevates again.
///
/// Verified to fail: the create definer's lazy expiry dropped -> the next
/// ticket is refused ELV06.
#[sqlx::test(migrations = "../../migrations")]
async fn a_lazily_expired_session_does_not_block_the_family(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    age_session(&pool, sid).await;
    let t = ticket(&pool, &h, "connector", None).await;
    assert_eq!(
        ended_reason(&pool, sid).await.as_deref(),
        Some("expired"),
        "ended `expired` by the next ticket"
    );
    assert_eq!(
        events(&pool, "platform.elevation_ended", "session_id", sid).await,
        1,
        "the expiry is audited"
    );
    assert_eq!(
        confirm(&pool, t, &h.cred, 0, false)
            .await
            .expect("confirm")
            .0,
        "confirmed",
        "the family elevates again"
    );
}

/// A ticket that predates the family's session, confirmed after that session
/// expired un-ended: the confirmation ends it `expired` first and elevates.
///
/// Verified to fail: the confirm definer's lazy expiry dropped -> the second
/// confirmation is refused ELV06.
#[sqlx::test(migrations = "../../migrations")]
async fn a_confirmation_ends_the_familys_expired_session_first(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let t1 = ticket(&pool, &h, "connector", None).await;
    let t2 = ticket(&pool, &h, "connector", None).await;
    let s1 = confirm(&pool, t1, &h.cred, 0, false)
        .await
        .expect("first")
        .1
        .expect("session");
    age_session(&pool, s1).await;
    let r = confirm(&pool, t2, &h.cred, 0, false).await.expect("second");
    assert_eq!(r.0, "confirmed", "the second confirmation: {r:?}");
    assert_eq!(
        ended_reason(&pool, s1).await.as_deref(),
        Some("expired"),
        "the expired session ended first"
    );
}

// =====================================================================
// Ends by trigger, through the real call paths.
// =====================================================================

/// 118's reuse detector, on an `epigraph_app` session (the refresh grant's
/// own path), ends the family's session `family_reuse`, audited; a ROTATION
/// of the family (the same detector's normal path) does not.
///
/// The rotated token is presented again after the 30-second grace window
/// (its `revoked_at` aged past it): inside the window 118 answers `grace` and
/// revokes nothing. The calibration asserts the detector answered `reuse`, so
/// a never-fired trigger cannot pass as a live session.
///
/// Verified to fail: the reuse trigger made to end nothing -> the session
/// stays live after the reuse.
#[sqlx::test(migrations = "../../migrations")]
async fn a_family_reuse_ends_the_session_and_a_rotation_does_not(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    let successor: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let old = h.token_hash.clone();
    let rotated: String = as_app(&pool, None, "", "", |mut conn| async move {
        let o = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_refresh_token_rotate($1, $2, \
                                                                      now() + interval '1 day')",
        )
        .bind(&old)
        .bind(&successor)
        .fetch_one(&mut *conn)
        .await
        .expect("rotate");
        (conn, o)
    })
    .await;
    assert_eq!(rotated, "rotated", "CALIBRATION: the family rotated");
    assert_eq!(
        ended_reason(&pool, sid).await,
        None,
        "a rotation does not end it"
    );

    without_triggers(
        &pool,
        "UPDATE refresh_tokens SET revoked_at = revoked_at - interval '1 minute' WHERE id = $1",
        h.family,
    )
    .await;
    let old = h.token_hash.clone();
    let outcome: String = as_app(&pool, None, "", "", |mut conn| async move {
        let o = sqlx::query_scalar("SELECT outcome FROM public.epigraph_refresh_token_check($1)")
            .bind(&old)
            .fetch_one(&mut *conn)
            .await
            .expect("check");
        (conn, o)
    })
    .await;
    assert_eq!(outcome, "reuse", "CALIBRATION: the detector saw reuse");
    assert_eq!(
        ended_reason(&pool, sid).await.as_deref(),
        Some("family_reuse"),
        "a reuse revoke ends it"
    );
    assert_eq!(
        events(&pool, "platform.elevation_ended", "session_id", sid).await,
        1,
        "the end is audited"
    );
    assert!(!elevated_as(&pool, &h, sid).await, "not elevated");
}

/// Ending the assignment through 123's maintenance definer ends its session
/// `assignment_revoked`, audited.
///
/// Verified to fail: the assignment trigger made to end nothing -> the
/// session stays un-ended.
#[sqlx::test(migrations = "../../migrations")]
async fn an_assignment_end_ends_its_session(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    maint_exec(
        &pool,
        "SELECT public.epigraph_end_role_assignment($1, 'elevation test')",
        h.assignment,
    )
    .await
    .expect("end the assignment");
    assert_eq!(
        ended_reason(&pool, sid).await.as_deref(),
        Some("assignment_revoked")
    );
    assert_eq!(
        events(&pool, "platform.elevation_ended", "session_id", sid).await,
        1,
        "the end is audited"
    );
}

/// Revoking the holder's registration through 122's maintenance definer ends
/// the person's session `operator_revoked`, audited.
///
/// Verified to fail: the registration trigger made to end nothing -> the
/// session stays un-ended.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deregistration_ends_the_persons_session(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    maint_exec(
        &pool,
        "SELECT * FROM public.epigraph_revoke_human_operator($1, 'elevation test')",
        h.person,
    )
    .await
    .expect("de-register");
    assert_eq!(
        ended_reason(&pool, sid).await.as_deref(),
        Some("operator_revoked")
    );
    assert_eq!(
        events(&pool, "platform.elevation_ended", "session_id", sid).await,
        1,
        "the end is audited"
    );
}

/// THE COMPUTED CHECK, family half: the session's refresh family loses its
/// last live token (revoked with the end trigger off, so the row is still
/// un-ended) and the session is no longer elevated, nor returned by
/// `epigraph_elevation_live`. The elevation is bound to that family (125's
/// header); a family the operator or the user has killed must not keep it.
///
/// Verified to fail: the family re-check dropped from the liveness helper ->
/// still elevated and still returned.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_once_the_family_is_revoked(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    assert!(elevated_as(&pool, &h, sid).await, "CALIBRATION: elevated");
    without_triggers(
        &pool,
        "UPDATE refresh_tokens SET revoked_at = now(), revoked_reason = 'revoked' WHERE id = $1",
        h.family,
    )
    .await;
    assert_eq!(
        ended_reason(&pool, sid).await,
        None,
        "CALIBRATION: the row is un-ended"
    );
    assert!(!elevated_as(&pool, &h, sid).await, "a revoked family");
    assert!(
        live_rows(&pool, &h, Some(sid)).await.is_empty(),
        "elevation_live returns a session whose family is revoked"
    );
}

/// THE COMPUTED CHECK, client half: the session runs on a SECOND human client
/// of the person, not the one the registration records, so 122's
/// human-operator test (which reads the recorded client) still says "human"
/// after that second client is suspended (triggers off). The session's own
/// client is re-checked, so it is no longer elevated.
///
/// Verified to fail: the family re-check dropped from the liveness helper
/// (its client test is the only one that reads the SESSION's client) ->
/// still elevated.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_once_the_sessions_client_is_suspended(pool: PgPool) {
    let first = holder(&pool, "holder", 1).await;
    let h = on_a_second_client(&pool, &first).await;
    let sid = elevated(&pool, &h).await;
    assert!(elevated_as(&pool, &h, sid).await, "CALIBRATION: elevated");
    without_triggers(
        &pool,
        "UPDATE oauth_clients SET status = 'suspended' WHERE id = $1",
        h.client,
    )
    .await;
    let human: bool = sqlx::query_scalar("SELECT public.epigraph_is_human_operator($1)")
        .bind(h.person)
        .fetch_one(&pool)
        .await
        .expect("is_human_operator");
    assert!(
        human,
        "CALIBRATION: the person is still a registered human (the recorded client is live)"
    );
    assert_eq!(
        ended_reason(&pool, sid).await,
        None,
        "CALIBRATION: the row is un-ended"
    );
    assert!(
        !elevated_as(&pool, &h, sid).await,
        "a session on a suspended client"
    );
}

/// THE END, family half, through 118's own definers as the application role:
/// an RFC 7009 revoke (by hash), a denied/revoked revoke (by id) and a
/// client-wide revoke each end the family's session `family_revoked`,
/// audited (a rotation does not: `a_family_reuse_ends_the_session_and_a_rotation_does_not`).
///
/// Verified to fail: the refresh-token end trigger back on `reuse` only ->
/// each session stays un-ended.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_the_family_ends_the_session(pool: PgPool) {
    let a = holder(&pool, "by-hash", 1).await;
    let b = holder(&pool, "by-id", 2).await;
    let c = holder(&pool, "by-client", 3).await;
    let (sa, sb, sc) = (
        elevated(&pool, &a).await,
        elevated(&pool, &b).await,
        elevated(&pool, &c).await,
    );
    let hash = a.token_hash.clone();
    let (fam_b, client_c) = (b.family, c.client);
    as_app(&pool, None, "", "", |mut conn| async move {
        let by_hash: bool =
            sqlx::query_scalar("SELECT public.epigraph_refresh_token_revoke_by_hash($1)")
                .bind(&hash)
                .fetch_one(&mut *conn)
                .await
                .expect("revoke by hash");
        let by_id: bool =
            sqlx::query_scalar("SELECT public.epigraph_refresh_token_revoke($1, 'denied')")
                .bind(fam_b)
                .fetch_one(&mut *conn)
                .await
                .expect("revoke by id");
        let by_client: i64 =
            sqlx::query_scalar("SELECT public.epigraph_refresh_token_revoke_client($1)")
                .bind(client_c)
                .fetch_one(&mut *conn)
                .await
                .expect("revoke the client's tokens");
        assert!(by_hash && by_id && by_client >= 1, "CALIBRATION: each revoked");
        (conn, ())
    })
    .await;
    for (what, h, sid) in [("by hash", &a, sa), ("by id", &b, sb), ("by client", &c, sc)] {
        assert_eq!(
            ended_reason(&pool, sid).await.as_deref(),
            Some("family_revoked"),
            "{what}"
        );
        assert_eq!(
            events(&pool, "platform.elevation_ended", "session_id", sid).await,
            1,
            "{what}: the end is audited"
        );
        assert!(!elevated_as(&pool, h, sid).await, "{what}: not elevated");
    }
}

/// THE END, client half: suspending the session's client ends it
/// `client_revoked`, audited, and the end LATCHES: the client re-activated
/// (by a privileged session, the only one 122 lets do it) inside what was the
/// window does not revive the session.
///
/// Verified to fail: the client end trigger dropped -> the session stays
/// un-ended, and is elevated again once the client is re-activated.
#[sqlx::test(migrations = "../../migrations")]
async fn suspending_the_sessions_client_ends_the_session_for_good(pool: PgPool) {
    let first = holder(&pool, "holder", 1).await;
    let h = on_a_second_client(&pool, &first).await;
    let sid = elevated(&pool, &h).await;
    for status in ["suspended", "active"] {
        sqlx::query("UPDATE oauth_clients SET status = $2 WHERE id = $1")
            .bind(h.client)
            .bind(status)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("client -> {status}: {e}"));
    }
    assert_eq!(
        ended_reason(&pool, sid).await.as_deref(),
        Some("client_revoked")
    );
    assert_eq!(
        events(&pool, "platform.elevation_ended", "session_id", sid).await,
        1,
        "the end is audited"
    );
    assert!(
        !elevated_as(&pool, &h, sid).await,
        "a re-activated client revived the session"
    );
}

/// THE COMPUTED CHECK, passkey half: the passkey that confirmed the session
/// is revoked with its end trigger off (row un-ended), and the session is no
/// longer elevated. A revoked passkey (the operator's break-glass when one is
/// lost or suspected) must take with it what it confirmed.
///
/// Verified to fail: the passkey re-check dropped from the liveness helper ->
/// still elevated.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_false_once_its_passkey_is_revoked(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    assert!(elevated_as(&pool, &h, sid).await, "CALIBRATION: elevated");
    without_triggers(
        &pool,
        "UPDATE person_authenticators SET revoked_at = now(), revoked_by = session_user, \
                                          revoked_reason = 'elevation test' WHERE id = $1",
        h.passkey,
    )
    .await;
    assert_eq!(
        ended_reason(&pool, sid).await,
        None,
        "CALIBRATION: the row is un-ended"
    );
    assert!(
        !elevated_as(&pool, &h, sid).await,
        "a session confirmed by a revoked passkey"
    );
}

/// THE END, passkey half, through 124's maintenance definer (the
/// `epigraph-operator revoke-passkey` path): the session that passkey
/// confirmed ends `passkey_revoked`, audited; a session of the SAME person
/// confirmed by ANOTHER live passkey (on another family) is untouched.
///
/// Verified to fail: the passkey end trigger dropped -> the first session
/// stays un-ended; the trigger widened to every session of the person -> the
/// second session ends too.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_a_passkey_ends_the_sessions_it_confirmed(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let other_key = passkey(&pool, h.person, 2).await;
    let (other_family, other_hash) = family(&pool, h.client).await;
    let h2 = Holder {
        passkey: other_key,
        cred: credential(2),
        family: other_family,
        token_hash: other_hash,
        ..h.clone()
    };
    let sid = elevated(&pool, &h).await;
    let kept = elevated(&pool, &h2).await;
    let revoked: bool = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| {
        let key = h.passkey;
        async move {
            let r = sqlx::query_scalar("SELECT public.epigraph_revoke_passkey($1, 'lost')")
                .bind(key)
                .fetch_one(&mut *conn)
                .await
                .expect("revoke the passkey");
            (conn, r)
        }
    })
    .await;
    assert!(revoked, "CALIBRATION: the passkey was revoked");
    assert_eq!(
        ended_reason(&pool, sid).await.as_deref(),
        Some("passkey_revoked")
    );
    assert_eq!(
        events(&pool, "platform.elevation_ended", "session_id", sid).await,
        1,
        "the end is audited"
    );
    assert!(!elevated_as(&pool, &h, sid).await, "not elevated");
    assert_eq!(
        ended_reason(&pool, kept).await,
        None,
        "a session confirmed by another live passkey is untouched"
    );
    assert!(
        elevated_as(&pool, &h2, kept).await,
        "the other passkey's session is still elevated"
    );
}

// =====================================================================
// Grant mode, and the principal-bound readers.
// =====================================================================

/// Grant mode: `pending` before the assertion; once confirmed, a wrong secret
/// or a different client is `invalid`, the right one is `issued` ONCE (the
/// session, its family), and a second redeem is `invalid`. A connector-mode
/// ticket never redeems.
///
/// Verified to fail: the secret check dropped -> the wrong secret issues; the
/// client check dropped -> the other client issues; the once check dropped ->
/// the second redeem issues. (Admitting connector mode is an EQUIVALENT
/// mutant: a connector ticket carries no hash, so the secret comparison
/// already refuses it.)
#[sqlx::test(migrations = "../../migrations")]
async fn grant_mode_redeems_once(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let other = holder(&pool, "other", 2).await;
    let secret = [b's'; 32];
    let t = ticket(&pool, &h, "grant", Some(&secret)).await;
    let redeem = |ticket: Uuid, secret: Vec<u8>, client: Uuid| {
        let pool = pool.clone();
        async move {
            as_app(&pool, None, "", "", |mut conn| async move {
                let r: (String, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
                    "SELECT status, session_id, family_id \
                       FROM public.epigraph_redeem_elevation_ticket($1, sha256($2::bytea), $3)",
                )
                .bind(ticket)
                .bind(secret)
                .bind(client)
                .fetch_one(&mut *conn)
                .await
                .expect("redeem");
                (conn, r)
            })
            .await
        }
    };
    assert_eq!(redeem(t, secret.to_vec(), h.client).await.0, "pending");
    let r = confirm(&pool, t, &h.cred, 0, false).await.expect("confirm");
    assert_eq!(r.0, "confirmed");
    assert_eq!(
        redeem(t, b"wrong".to_vec(), h.client).await.0,
        "invalid",
        "a wrong secret"
    );
    assert_eq!(
        redeem(t, secret.to_vec(), other.client).await.0,
        "invalid",
        "another client"
    );
    let issued = redeem(t, secret.to_vec(), h.client).await;
    assert_eq!(
        issued,
        ("issued".to_string(), r.1, Some(h.family)),
        "issued once, for the session and its family"
    );
    assert_eq!(
        redeem(t, secret.to_vec(), h.client).await.0,
        "invalid",
        "a second redeem"
    );
    let ct = ticket(&pool, &other, "connector", None).await;
    assert_eq!(
        redeem(ct, secret.to_vec(), other.client).await.0,
        "invalid",
        "connector mode"
    );
}

/// `epigraph_elevation_live` answers only for the session principal: by id
/// (any mode) or, with no id, the family's CONNECTOR-mode session; never
/// another principal's, never unstamped, and a grant-mode session only by its
/// id.
///
/// Verified to fail: its principal binding dropped -> B reads P's session;
/// its connector-mode filter dropped -> the grant session answers by family
/// alone.
#[sqlx::test(migrations = "../../migrations")]
async fn elevation_live_is_principal_bound(pool: PgPool) {
    let p = holder(&pool, "P", 1).await;
    let b = holder(&pool, "B", 2).await;
    let g = holder(&pool, "G", 3).await;
    let sid = elevated(&pool, &p).await;
    let live = |principal: Option<Uuid>, elv: Option<Uuid>, fam: Uuid| {
        let pool = pool.clone();
        async move {
            as_app(&pool, principal, "", "", |mut conn| async move {
                let r: Vec<Uuid> = sqlx::query_scalar(
                    "SELECT session_id FROM public.epigraph_elevation_live($1, $2)",
                )
                .bind(elv)
                .bind(fam)
                .fetch_all(&mut *conn)
                .await
                .expect("elevation_live");
                (conn, r)
            })
            .await
        }
    };
    assert_eq!(
        live(Some(p.person), Some(sid), p.family).await,
        vec![sid],
        "by id"
    );
    assert_eq!(
        live(Some(p.person), None, p.family).await,
        vec![sid],
        "a connector session by its family"
    );
    assert!(
        live(Some(b.person), Some(sid), p.family).await.is_empty(),
        "another principal"
    );
    assert!(
        live(None, Some(sid), p.family).await.is_empty(),
        "unstamped"
    );
    let t = ticket(&pool, &g, "grant", Some(&[b'g'; 32])).await;
    let gs = confirm(&pool, t, &g.cred, 0, false)
        .await
        .expect("confirm")
        .1
        .expect("session");
    assert!(
        live(Some(g.person), None, g.family).await.is_empty(),
        "a grant session is not reached by its family alone"
    );
    assert_eq!(
        live(Some(g.person), Some(gs), g.family).await,
        vec![gs],
        "by its id"
    );
}

/// `epigraph_end_elevation` ends only the principal's own session (false,
/// nothing changed, for another's); a privileged session ends any.
///
/// Verified to fail: its principal binding dropped -> B ends P's session.
#[sqlx::test(migrations = "../../migrations")]
async fn end_elevation_is_principal_bound(pool: PgPool) {
    let p = holder(&pool, "P", 1).await;
    let b = holder(&pool, "B", 2).await;
    let sid = elevated(&pool, &p).await;
    let by_b: bool = as_app(&pool, Some(b.person), "", "", |mut conn| async move {
        let v = sqlx::query_scalar("SELECT public.epigraph_end_elevation($1, 'ended')")
            .bind(sid)
            .fetch_one(&mut *conn)
            .await
            .expect("end");
        (conn, v)
    })
    .await;
    assert!(!by_b, "B cannot end P's session");
    assert_eq!(ended_reason(&pool, sid).await, None, "still live");
    let by_maint: bool = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let v = sqlx::query_scalar("SELECT public.epigraph_end_elevation($1, 'ended')")
            .bind(sid)
            .fetch_one(&mut *conn)
            .await
            .expect("end");
        (conn, v)
    })
    .await;
    assert!(by_maint, "a privileged session ends any");
}

// =====================================================================
// The tables: unreadable and unwritable by the application, append-only,
// and their `platform.` audit unforgeable.
// =====================================================================

/// The application role reads no ticket and no session (stamped as the
/// session's own holder, with its own GUC pair), writes neither table, and
/// cannot call the three unbound helpers (an unbound "who may elevate" or
/// "whose family is this" answer is a roster oracle).
///
/// Verified to fail: the sessions read policy widened to `USING (true)` ->
/// the app reads the session; EXECUTE granted to the app (a GRANT appended
/// after the migration's own REVOKE) on each of
/// `epigraph_live_elevating_assignment`, `epigraph_family_of_person_is_live`
/// and `epigraph_end_expired_elevations` -> that call lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_reads_and_writes_no_row(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    let (sessions, tickets): (i64, i64) = as_app(
        &pool,
        Some(h.person),
        &sid.to_string(),
        &h.family.to_string(),
        |mut conn| async move {
            let s = sqlx::query_scalar("SELECT count(*) FROM elevation_sessions")
                .fetch_one(&mut *conn)
                .await
                .expect("the app holds SELECT; RLS narrows it");
            let t = sqlx::query_scalar("SELECT count(*) FROM elevation_tickets")
                .fetch_one(&mut *conn)
                .await
                .expect("the app holds SELECT; RLS narrows it");
            (conn, (s, t))
        },
    )
    .await;
    assert_eq!((sessions, tickets), (0, 0), "the app reads no row");
    for sql in [
        "UPDATE elevation_sessions SET ended_at = now()",
        "INSERT INTO elevation_tickets (person_agent_id, client_id, family_id, mode, reason, \
                                        expires_at) \
         VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'connector', 'x', now())",
        "DELETE FROM elevation_sessions",
        "DELETE FROM elevation_tickets",
        "SELECT public.epigraph_live_elevating_assignment(gen_random_uuid(), now())",
        "SELECT public.epigraph_family_of_person_is_live(gen_random_uuid(), gen_random_uuid(), \
                                                         gen_random_uuid())",
        "SELECT public.epigraph_end_expired_elevations(NULL, NULL)",
    ] {
        assert_code(&app_exec(&pool, Some(h.person), sql).await, "42501", sql);
    }
    let all: i64 = sqlx::query_scalar("SELECT count(*) FROM elevation_sessions")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(all, 1, "CALIBRATION: the session exists");
}

/// A session is only ever ended, once, now, by the ending login; a ticket is
/// never re-asserted; neither is born in a later state. Each as the harness
/// superuser, which the guards bind exactly as they bind a definer.
///
/// Verified to fail: the session guard's `ended_by = session_user` test
/// dropped -> the end recorded as another login lands.
#[sqlx::test(migrations = "../../migrations")]
async fn sessions_and_tickets_are_append_only(pool: PgPool) {
    let h = holder(&pool, "holder", 1).await;
    let sid = elevated(&pool, &h).await;
    let exec = |sql: &'static str, id: Uuid| {
        let pool = pool.clone();
        async move { sqlx::query(sql).bind(id).execute(&pool).await }
    };
    assert_code(
        &exec(
            "UPDATE elevation_sessions SET expires_at = expires_at + interval '1 minute' \
              WHERE id = $1",
            sid,
        )
        .await,
        "ELV03",
        "an extension",
    );
    assert_code(
        &exec(
            "UPDATE elevation_sessions SET ended_at = now(), ended_by = 'someone-else', \
                                           ended_reason = 'ended' WHERE id = $1",
            sid,
        )
        .await,
        "ELV03",
        "an end recorded as another login",
    );
    exec(
        "UPDATE elevation_sessions SET ended_at = now(), ended_by = session_user, \
                                       ended_reason = 'ended' WHERE id = $1",
        sid,
    )
    .await
    .expect("the one end");
    assert_code(
        &exec(
            "UPDATE elevation_sessions SET ended_reason = 'unsudo' WHERE id = $1",
            sid,
        )
        .await,
        "ELV03",
        "an ended session is final",
    );
    let t: Uuid = sqlx::query_scalar("SELECT ticket_id FROM elevation_sessions WHERE id = $1")
        .bind(sid)
        .fetch_one(&pool)
        .await
        .expect("ticket");
    let reasserted = exec(
        "UPDATE elevation_tickets SET outcome = 'refused', refusal = 'person_mismatch', \
                                      session_id = NULL WHERE id = $1",
        t,
    )
    .await;
    assert!(
        matches!(code_of(&reasserted).as_deref(), Some("ELV06" | "ELV03")),
        "a re-asserted ticket: {reasserted:?}"
    );
    assert_code(
        &exec(
            "INSERT INTO elevation_tickets (person_agent_id, client_id, family_id, mode, reason, \
                 expires_at, outcome, asserted_at, assertion_evidence, refusal) \
             SELECT person_agent_id, client_id, family_id, 'connector', 'r', \
                    now() + interval '1 minute', 'refused', now(), '{}'::jsonb, \
                    'person_mismatch' FROM elevation_tickets WHERE id = $1",
            t,
        )
        .await,
        "ELV03",
        "a ticket born asserted",
    );
}

/// An application session cannot write a `platform.elevated`,
/// `platform.elevation_ended` or `platform.elevation_refused` row of its own,
/// whatever its spelling; a non-`platform.` event is admitted. A PIN of 123's
/// `security_events_platform_privileged` for this batch's event types: it
/// holds before 125 exists, so its red run is that policy's mutation.
///
/// Verified to fail: 123's policy made PERMISSIVE -> every forged row lands.
#[sqlx::test(migrations = "../../migrations")]
async fn forged_platform_events_are_refused(pool: PgPool) {
    let (p, _) = human(&pool, "human").await;
    for event in [
        "platform.elevation_ended",
        "platform.elevated",
        "platform.elevation_refused",
        " Platform.Elevated",
    ] {
        let r = as_app(&pool, Some(p), "", "", |mut conn| async move {
            let r = sqlx::query(
                "INSERT INTO security_events (event_type, agent_id, success, details) \
                 VALUES ($1, $2, true, '{}'::jsonb)",
            )
            .bind(event)
            .bind(p)
            .execute(&mut *conn)
            .await;
            (conn, r)
        })
        .await;
        assert_code(&r, "42501", &format!("a forged {event:?}"));
    }
    let ok = as_app(&pool, Some(p), "", "", |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ('app.elevation_test', $1, true, '{}'::jsonb)",
        )
        .bind(p)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert!(
        ok.is_ok(),
        "CALIBRATION: a non-platform event is admitted: {ok:?}"
    );
}

/// The cost pin: wrapped as a scalar subquery, `epigraph_is_elevated()` runs
/// ONCE per statement (an InitPlan), not once per row; the function is
/// STABLE. A plain relation is used, so no row policy adds InitPlans of its
/// own. Calibration: unwrapped, it is a per-row filter with no InitPlan.
#[sqlx::test(migrations = "../../migrations")]
async fn is_elevated_is_an_initplan(pool: PgPool) {
    let (wrapped, unwrapped): (Vec<String>, Vec<String>) =
        as_app(&pool, None, "", "", |mut conn| async move {
            let w = sqlx::query_scalar(
                "EXPLAIN VERBOSE SELECT g FROM generate_series(1, 1000) g \
                  WHERE (SELECT public.epigraph_is_elevated())",
            )
            .fetch_all(&mut *conn)
            .await
            .expect("explain");
            let u = sqlx::query_scalar(
                "EXPLAIN VERBOSE SELECT g FROM generate_series(1, 1000) g \
                  WHERE public.epigraph_is_elevated() AND g > 0",
            )
            .fetch_all(&mut *conn)
            .await
            .expect("explain");
            (conn, (w, u))
        })
        .await;
    let plan = wrapped.join("\n");
    assert_eq!(
        wrapped.iter().filter(|l| l.contains("InitPlan")).count(),
        1,
        "one InitPlan:\n{plan}"
    );
    assert!(
        plan.contains("epigraph_is_elevated()")
            && !wrapped
                .iter()
                .any(|l| l.contains("Filter") && l.contains("epigraph_is_elevated")),
        "not a per-row filter:\n{plan}"
    );
    let calib = unwrapped.join("\n");
    assert!(
        !calib.contains("InitPlan") && calib.contains("epigraph_is_elevated"),
        "CALIBRATION:\n{calib}"
    );
    let vol: String = sqlx::query_scalar(
        "SELECT provolatile::text FROM pg_proc WHERE proname = 'epigraph_is_elevated'",
    )
    .fetch_one(&pool)
    .await
    .expect("provolatile");
    assert_eq!(vol, "s", "STABLE");
}

// =====================================================================
// The undo takes 125 back out, and only 125.
// =====================================================================

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The embedded migrator, cut at `max` (inclusive).
fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

/// Run `migrator` on one connection and reset it: 001's pg_dump header leaves
/// session-level SETs behind (viewer_fixture::db_at_122_then_head).
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// The catalog facts 125 could leave behind, by name: relations, functions
/// (body and owner), policies, triggers and constraints in `public`.
async fn catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || md5(p.prosrc) || ' ' || p.proowner::regrole::text \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn undo_125() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/125-undo.sql"),
    )
    .expect("125-undo.sql")
}

/// `docs/runbooks/125-undo.sql`, applied to a database that went 124 -> 125
/// and holds a live session, a refused ticket and an open one, returns its
/// catalog (relations, function bodies and owners, policies, triggers,
/// constraints) to the same database's at 124, including the end triggers
/// 125 put on 118's, 122's, 123's, 124's and 001's tables; the `platform.elevat*`
/// history stays. Cut at 125, not head: a later migration (the read arms read
/// `epigraph_is_elevated()`) is undone before this one.
///
/// Verified to fail: the undo's DROP of the reuse end trigger removed -> the
/// trigger still on `refresh_tokens` blocks its function's DROP (2BP01), so
/// the undo does not apply; the DROP of `epigraph_end_expired_elevations`
/// removed -> that function is left behind.
#[sqlx::test(migrations = false)]
async fn the_rollback_returns_the_catalog_to_124(pool: PgPool) {
    migrate(&pool, &up_to(124)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(125)).await;

    let p = holder(&pool, "P", 1).await;
    let b = holder(&pool, "B", 2).await;
    let sid = elevated(&pool, &p).await;
    let refused = ticket(&pool, &b, "connector", None).await;
    confirm(&pool, refused, &p.cred, 0, false)
        .await
        .expect("a refusal");
    ticket(&pool, &b, "grant", Some(&[b'x'; 32])).await;
    assert_ne!(
        catalog(&pool).await,
        before,
        "CALIBRATION: 125 changed the catalog"
    );

    sqlx::raw_sql(&undo_125())
        .execute(&pool)
        .await
        .expect("the undo script applies");

    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&before).collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the catalog is not 124's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
    assert_eq!(
        events(&pool, "platform.elevated", "session_id", sid).await,
        1,
        "the audit history stays"
    );
}

/// The undo refuses while any row policy still reads `epigraph_is_elevated()`
/// (the read arms of a later migration must be undone first), and changes
/// nothing.
///
/// Verified to fail: the undo's policy refusal removed -> the DROP FUNCTION
/// meets the policy's dependency instead (2BP01, not the undo's own refusal).
#[sqlx::test(migrations = false)]
async fn the_undo_refuses_while_a_policy_reads_is_elevated(pool: PgPool) {
    migrate(&pool, &up_to(125)).await;
    sqlx::query(
        "CREATE POLICY elevation_undo_probe ON public.claims FOR SELECT TO PUBLIC \
         USING ((SELECT public.epigraph_is_elevated()))",
    )
    .execute(&pool)
    .await
    .expect("a policy that reads epigraph_is_elevated()");
    let before = catalog(&pool).await;
    // One connection for the script and its ROLLBACK: the script's own BEGIN
    // leaves the connection in an aborted transaction when it raises.
    let mut conn = pool.acquire().await.expect("acquire");
    let undo = undo_125();
    let r = sqlx::raw_sql(&undo).execute(&mut *conn).await;
    let msg = r
        .as_ref()
        .err()
        .and_then(|e| e.as_database_error())
        .map(|d| d.message().to_string())
        .unwrap_or_default();
    assert!(
        msg.contains("125-undo") && msg.contains("epigraph_is_elevated"),
        "the undo's own refusal, not a dependency error: {r:?}"
    );
    sqlx::query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("end the aborted transaction");
    drop(conn);
    assert_eq!(catalog(&pool).await, before, "nothing changed");
}

// =====================================================================
// The registers know every 125 object.
// =====================================================================

/// `(SECURITY DEFINER functions, all functions)` that a migration file
/// creates in `public`, read from its text.
fn functions_of(migration: &str) -> (Vec<String>, Vec<String>) {
    let mut definers = Vec::new();
    let mut all = Vec::new();
    let mut rest = migration;
    while let Some(i) = rest.find("CREATE OR REPLACE FUNCTION public.") {
        let after = &rest[i + "CREATE OR REPLACE FUNCTION public.".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let body_end = after.find("$$;").unwrap_or(after.len());
        let header_end = after.find(" AS $$").unwrap_or(body_end);
        if after[..header_end].contains("SECURITY DEFINER") {
            definers.push(name.clone());
        }
        all.push(name);
        rest = &after[body_end..];
    }
    definers.sort();
    definers.dedup();
    all.sort();
    all.dedup();
    (definers, all)
}

/// Every SECURITY DEFINER migration 125 creates is on
/// `epigraph-tenancy-backfill verify`'s ownership list at 125 (a silently
/// no-opped `OWNER TO` is invisible to every behavioural test, because the
/// harness migrates as a superuser), every function it creates is dropped by
/// `docs/runbooks/125-undo.sql`, and both tables are in the API's FORCE
/// register and the 079 kill switch.
///
/// Verified to fail: the `("epigraph_end_elevations_on_family_revoke", 125)`
/// entry removed from `DEFERRED_DEFINER_FUNCTIONS` -> named here; the undo's
/// DROP of `epigraph_family_of_person_is_live` removed -> named here.
#[test]
fn every_125_object_is_registered() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    };
    let migration = read("migrations/125_elevation.sql");
    let backfill = read("crates/epigraph-cli/src/bin/tenancy_backfill.rs");
    let state = read("crates/epigraph-api/src/state.rs");
    let kill_switch = read("docs/runbooks/079-undo.sql");
    let undo = read("docs/runbooks/125-undo.sql");

    let (definers, all) = functions_of(&migration);
    assert_eq!(
        definers.len(),
        24,
        "CALIBRATION: 125 creates 24 SECURITY DEFINER functions; the scan found {definers:?}"
    );
    assert_eq!(definers, all, "every function 125 creates is a definer");
    let missing: Vec<&String> = definers
        .iter()
        .filter(|n| !backfill.contains(&format!("(\"{n}\", 125)")))
        .collect();
    assert!(
        missing.is_empty(),
        "migration 125 definers missing from tenancy_backfill.rs's ownership list at 125: \
         {missing:?}"
    );
    let undropped: Vec<&String> = all
        .iter()
        .filter(|n| !undo.contains(&format!("DROP FUNCTION IF EXISTS public.{n}(")))
        .collect();
    assert!(
        undropped.is_empty(),
        "125-undo.sql does not drop: {undropped:?}"
    );
    for table in ["elevation_tickets", "elevation_sessions"] {
        assert!(
            state.contains(&format!("\"{table}\"")),
            "state.rs FORCE_PROTECTED_SET lacks {table}"
        );
        assert!(
            kill_switch.contains(&format!("'{table}'")),
            "079-undo.sql lacks {table}"
        );
    }
}
