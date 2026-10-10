//! Migration 130: pending admin acts, the 123 guards bound to confirmed acts,
//! and when a confirmation is required (ELV10).
//!
//! An act is PROPOSED by an elevated session, CONFIRMED by a passkey of its
//! proposer, and CONSUMED from inside the maintenance write it authorizes
//! (the role-assignment guards, the custodial-act recorder, the enrollment
//! guard), whose args the database recomputes from the write itself.
//!
//! Every SQL-authority probe runs as `epigraph_app` or `epigraph_maintenance`
//! under `SET SESSION AUTHORIZATION`, stamped and unstamped as
//! `elevation_sessions.rs` does ([`as_app`]). Sessions and acts are driven
//! through the real definers (ticket, ceremony, confirmation; proposal,
//! challenge, confirmation) with synthetic evidence: the database cannot
//! verify a signature, so what it is asked to hold here is the binding. A
//! superuser with triggers off is used only to age a row. Every refusal is
//! asserted by its SQLSTATE.
//!
//! Each test names the mutation of `migrations/130_pending_admin_acts.sql`
//! it was run against ("Verified to fail").

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;

const CUSTODIAN: &str = "role:platform-custodian";
const AUDITOR: &str = "role:auditor";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn assert_code<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>, code: &str, what: &str) {
    assert_eq!(
        r.as_ref().err().and_then(sqlstate).as_deref(),
        Some(code),
        "{what}: expected SQLSTATE {code}, got {r:?}"
    );
}

/// Run `f` as `epigraph_app` with all five session GUCs stamped (and the
/// recorder declared), cleared afterwards (`elevation_sessions.rs`' helper).
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
                    set_config('epigraph.family_id', $3, false), \
                    set_config('epigraph.access_recorder', 'on', false)",
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
                    set_config('epigraph.family_id', '', false), \
                    set_config('epigraph.access_recorder', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

/// One statement on a MAINTENANCE session, binding the given uuids in order
/// (a `None` binds NULL); rows affected.
async fn maint(pool: &PgPool, sql: &str, ids: &[Option<Uuid>]) -> Result<u64, sqlx::Error> {
    let (sql, ids) = (sql.to_string(), ids.to_vec());
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let mut q = sqlx::query(&sql);
        for id in ids {
            q = q.bind(id);
        }
        let r = q.execute(&mut *conn).await.map(|d| d.rows_affected());
        (conn, r)
    })
    .await
}

/// One statement as the harness superuser with every trigger off (to age a
/// row only).
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

fn credential(n: u8) -> Vec<u8> {
    let mut id = vec![0x5A_u8; 16];
    id[0] = n;
    id
}

/// A registered human: `(agent, human client id)`.
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

/// A live passkey for `person` through 124's ceremony definers (maintenance
/// opens, the unstamped app completes); its id. Since 130 a SECOND passkey of
/// one person is refused here (ELV10); see
/// [`a_later_passkey_rides_a_confirmed_register_act`].
async fn passkey(pool: &PgPool, person: Uuid, n: u8) -> Uuid {
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'act test', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("enroll");
        (conn, e)
    })
    .await;
    complete_enrollment(pool, e, n).await
}

async fn complete_enrollment(pool: &PgPool, enrollment: Uuid, n: u8) -> Uuid {
    as_app(pool, None, "", "", |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_set_passkey_enrollment_challenge($1, '{\"rs\": 1}'::jsonb)",
        )
        .bind(enrollment)
        .execute(&mut *conn)
        .await
        .expect("enrollment challenge");
        let key: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_complete_passkey_enrollment($1, $2, \
                    '{\"cred\": 1}'::jsonb, '00000000-0000-0000-0000-000000000000'::uuid, \
                    'none', true, false)",
        )
        .bind(enrollment)
        .bind(credential(n))
        .fetch_one(&mut *conn)
        .await
        .expect("complete the enrollment");
        (conn, key)
    })
    .await
}

async fn family(pool: &PgPool, client: Uuid) -> Uuid {
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh token")
}

/// A custodian with one live passkey and a live family, and a LIVE elevation
/// session on that family (the recorder gate opened for this database).
#[derive(Clone, Debug)]
struct Elevated {
    person: Uuid,
    assignment: Uuid,
    passkey: Uuid,
    cred: Vec<u8>,
    family: Uuid,
    session: Uuid,
}

async fn elevated_custodian(pool: &PgPool, label: &str, n: u8) -> Elevated {
    let (person, client) = human(pool, label).await;
    let assignment = fixture::make_custodian(pool, person).await;
    let passkey = passkey(pool, person, n).await;
    let family = family(pool, client).await;
    let ticket: Uuid = as_app(pool, Some(person), "", "", |mut conn| async move {
        let t: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, 'connector', 'act test', \
                                                           NULL)",
        )
        .bind(client)
        .bind(family)
        .fetch_one(&mut *conn)
        .await
        .expect("a ticket");
        sqlx::query(
            "SELECT public.epigraph_set_elevation_ticket_challenge($1, '{\"st\": 1}'::jsonb)",
        )
        .bind(t)
        .execute(&mut *conn)
        .await
        .expect("the ticket's challenge");
        (conn, t)
    })
    .await;
    let cred = credential(n);
    let c2 = cred.clone();
    let session: Uuid = as_app(pool, None, "", "", |mut conn| async move {
        let (outcome, session): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT outcome, session_id FROM public.epigraph_confirm_elevation($1, $2, 0, \
                    false, '{\"ev\": 1}'::jsonb)",
        )
        .bind(ticket)
        .bind(c2)
        .fetch_one(&mut *conn)
        .await
        .expect("confirm the elevation");
        assert_eq!(outcome, "confirmed", "CALIBRATION: the elevation confirms");
        (conn, session.expect("a session"))
    })
    .await;
    Elevated {
        person,
        assignment,
        passkey,
        cred,
        family,
        session,
    }
}

/// `epigraph_propose_admin_act` on an app session stamped as `e.person`,
/// elevated on its session when `elevated`, else with no elevation.
async fn propose(
    pool: &PgPool,
    e: &Elevated,
    elevated: bool,
    kind: &str,
    args: &str,
) -> Result<Uuid, sqlx::Error> {
    let (elv, fam) = if elevated {
        (e.session.to_string(), e.family.to_string())
    } else {
        (String::new(), String::new())
    };
    let (kind, args) = (kind.to_string(), args.to_string());
    as_app(pool, Some(e.person), &elv, &fam, |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_propose_admin_act($1, $2::jsonb, 'act test: why', 'jti-1')",
        )
        .bind(&kind)
        .bind(&args)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// The confirmation ceremony's first step, as the unauthenticated API runs it.
async fn start(pool: &PgPool, act: Uuid) -> Result<(), sqlx::Error> {
    as_app(pool, None, "", "", |mut conn| async move {
        let r = sqlx::query(
            "SELECT public.epigraph_set_admin_act_challenge($1, '{\"act\": 1}'::jsonb)",
        )
        .bind(act)
        .execute(&mut *conn)
        .await
        .map(|_| ());
        (conn, r)
    })
    .await
}

type ActOutcome = (String, Option<String>, Option<String>);

/// (kind, args, hex digest, target, proposer, elevation, assignment, jti).
type ActRow = (
    String,
    serde_json::Value,
    String,
    Uuid,
    Uuid,
    Uuid,
    Uuid,
    Option<String>,
);

/// The ceremony's last step: (outcome, refusal, code).
async fn confirm_act(
    pool: &PgPool,
    act: Uuid,
    cred: &[u8],
    counter: i64,
) -> Result<ActOutcome, sqlx::Error> {
    let cred = cred.to_vec();
    as_app(pool, None, "", "", |mut conn| async move {
        let r = sqlx::query_as::<_, ActOutcome>(
            "SELECT outcome, refusal, code \
               FROM public.epigraph_confirm_admin_act($1, $2, $3, false, '{\"ev\": 1}'::jsonb)",
        )
        .bind(act)
        .bind(cred)
        .bind(counter)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// A proposed, started and CONFIRMED act of `e`; its id.
async fn confirmed(pool: &PgPool, e: &Elevated, kind: &str, args: &str) -> Uuid {
    let act = propose(pool, e, true, kind, args).await.expect("propose");
    start(pool, act).await.expect("the act's challenge");
    let r = confirm_act(pool, act, &e.cred, 0).await.expect("confirm");
    assert_eq!(r.0, "confirmed", "CALIBRATION: the act confirms: {r:?}");
    act
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

/// The `confirmation` (and `act_id`) of the newest `event_type` row about
/// assignment `id`.
async fn confirmation_of(pool: &PgPool, event_type: &str, id: Uuid) -> (String, Option<String>) {
    sqlx::query_as(
        "SELECT details->>'confirmation', details->>'act_id' FROM security_events \
          WHERE event_type = $1 AND details->>'assignment_id' = $2 \
          ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(event_type)
    .bind(id.to_string())
    .fetch_one(pool)
    .await
    .expect("the audit row")
}

fn grant_args(role: &str, holder: Uuid, valid_to: Option<&str>, reason: &str) -> String {
    format!(
        "{{\"role\": \"{role}\", \"holder\": \"{holder}\", \"valid_from\": null, \
         \"valid_to\": {}, \"reason\": \"{reason}\"}}",
        valid_to.map_or_else(|| "null".to_string(), |t| format!("\"{t}\""))
    )
}

/// `epigraph_grant_role` (seven-parameter, act-taking form) on a maintenance
/// session; the new assignment id.
async fn grant_on(
    pool: &PgPool,
    role: &str,
    holder: Uuid,
    valid_to: Option<&str>,
    granted_by: Option<Uuid>,
    reason: &str,
    act: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    let (role, valid_to, reason) = (
        role.to_string(),
        valid_to.map(str::to_string),
        reason.to_string(),
    );
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_grant_role($1, $2, NULL, $3::timestamptz, $4, $5, $6)",
        )
        .bind(&role)
        .bind(holder)
        .bind(valid_to)
        .bind(granted_by)
        .bind(&reason)
        .bind(act)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

// =====================================================================
// PROPOSAL: only an elevated session, only through the definer.
// =====================================================================

/// An act is proposed only by an ELEVATED session (ELV07 otherwise), as the
/// session principal, with its args in canonical form and their digest, the
/// target they name, and the elevation and assignment it was proposed under;
/// the proposal is audited.
///
/// Verified to fail: the definer's `epigraph_is_elevated()` check dropped ->
/// the unelevated proposal raises 23502 (no elevation to record), not ELV07.
#[sqlx::test(migrations = "../../migrations")]
async fn an_act_is_proposed_only_while_elevated(pool: PgPool) {
    let p = elevated_custodian(&pool, "proposer", 1).await;
    let (x, _) = human(&pool, "holder").await;
    let args = format!(
        "{{\"role\": \"{AUDITOR}\", \"holder\": \"{}\", \"valid_to\": \
         \"2099-01-01T00:00:00+01:00\", \"reason\": \"audit\"}}",
        x.to_string().to_uppercase()
    );
    assert_code(
        &propose(&pool, &p, false, "role.grant", &args).await,
        "ELV07",
        "an unelevated proposal",
    );
    let act = propose(&pool, &p, true, "role.grant", &args)
        .await
        .expect("an elevated proposal");
    let row: ActRow = sqlx::query_as(
        "SELECT kind, args, encode(args_digest, 'hex'), target_id, proposed_by, \
                    elevation_id, assignment_id, jti \
               FROM pending_admin_acts WHERE id = $1",
    )
    .bind(act)
    .fetch_one(&pool)
    .await
    .expect("the act");
    assert_eq!(row.0, "role.grant");
    assert_eq!(
        row.1,
        serde_json::json!({"role": AUDITOR, "holder": x.to_string(), "valid_from": null,
                           "valid_to": "2098-12-31T23:00:00.000000Z", "reason": "audit"}),
        "canonical args"
    );
    let digest: String = sqlx::query_scalar(
        "SELECT encode(sha256(convert_to(public.epigraph_canonical_json(args), 'UTF8')), 'hex') \
           FROM pending_admin_acts WHERE id = $1",
    )
    .bind(act)
    .fetch_one(&pool)
    .await
    .expect("digest");
    assert_eq!(row.2, digest, "the digest is of the canonical text");
    assert_eq!(
        (row.3, row.4, row.5, row.6, row.7.as_deref()),
        (x, p.person, p.session, p.assignment, Some("jti-1"))
    );
    assert_eq!(
        events(&pool, "platform.admin_act_proposed", "act_id", act).await,
        1
    );
}

/// The TABLE binds an act to a live elevation of its proposer: a
/// maintenance login (on which no session is ever live) inserting a
/// well-formed act naming a live session is refused ELV07, and the
/// application role has no INSERT at all (42501).
///
/// Verified to fail: the insert guard's live-session check dropped -> the
/// maintenance insert lands.
#[sqlx::test(migrations = "../../migrations")]
async fn no_login_inserts_an_act_directly(pool: PgPool) {
    let p = elevated_custodian(&pool, "proposer", 1).await;
    let insert = "INSERT INTO pending_admin_acts (kind, args, args_digest, target_type, \
                    target_id, reason, proposed_by, elevation_id, assignment_id, expires_at) \
                  SELECT 'role.end', a, public.epigraph_admin_act_digest(a), 'role_assignment', \
                         $1, 'direct', $2, $3, $1, now() + interval '30 minutes' \
                    FROM public.epigraph_admin_act_args('role.end', jsonb_build_object( \
                         'assignment', $1, 'reason', 'r')) a";
    assert_code(
        &maint(
            &pool,
            insert,
            &[Some(p.assignment), Some(p.person), Some(p.session)],
        )
        .await,
        "ELV07",
        "a maintenance insert",
    );
    let (a, pr, s) = (p.assignment, p.person, p.session);
    let r = as_app(
        &pool,
        Some(p.person),
        &p.session.to_string(),
        &p.family.to_string(),
        |mut conn| async move {
            let r = sqlx::query(insert)
                .bind(a)
                .bind(pr)
                .bind(s)
                .execute(&mut *conn)
                .await;
            (conn, r)
        },
    )
    .await;
    assert_code(&r, "42501", "an application insert");
}

/// Stored args are canonical and carry their own digest: an insert whose
/// digest is not the digest of its args is refused ELV03 (before any other
/// check), and the canonicalizer refuses a key the kind does not take and a
/// truth value with more than six places (22023).
///
/// Verified to fail: the insert guard's digest comparison dropped -> the
/// mismatched insert is refused ELV07 instead.
#[sqlx::test(migrations = "../../migrations")]
async fn stored_args_are_canonical_and_digested(pool: PgPool) {
    let p = elevated_custodian(&pool, "proposer", 1).await;
    let r = maint(
        &pool,
        "INSERT INTO pending_admin_acts (kind, args, args_digest, target_type, target_id, \
                reason, proposed_by, elevation_id, assignment_id, expires_at) \
         SELECT 'role.end', a, sha256('other'::bytea), 'role_assignment', $1, 'direct', $2, \
                $3, $1, now() + interval '30 minutes' \
           FROM public.epigraph_admin_act_args('role.end', jsonb_build_object( \
                'assignment', $1, 'reason', 'r')) a",
        &[Some(p.assignment), Some(p.person), Some(p.session)],
    )
    .await;
    assert_code(&r, "ELV03", "a digest that is not its args'");
    assert_code(
        &propose(
            &pool,
            &p,
            true,
            "role.end",
            &format!(
                "{{\"assignment\": \"{}\", \"reason\": \"r\", \"extra\": 1}}",
                p.assignment
            ),
        )
        .await,
        "22023",
        "a key role.end does not take",
    );
    assert_code(
        &propose(
            &pool,
            &p,
            true,
            "claim.custodial_supersede",
            &format!(
                "{{\"claim\": \"{}\", \"content_sha256\": \"{}\", \"truth\": 0.1234567, \
                 \"reason\": \"r\", \"allow_owned\": false}}",
                Uuid::new_v4(),
                "a".repeat(64)
            ),
        )
        .await,
        "22023",
        "a truth value with seven places",
    );
}

// =====================================================================
// CONFIRMATION: only the proposer's live passkey; refusals final, audited.
// =====================================================================

/// An act confirmed by ANOTHER person's credential is refused
/// `person_mismatch` (returned, audited), and the refusal is final: the
/// proposer's own passkey cannot confirm it afterwards (ELV08). A direct
/// maintenance UPDATE confirming an act with another person's passkey is
/// refused by the table (ELV02).
///
/// Verified to fail: the definer's person check dropped -> the refusal is no
/// longer recorded and returned (the table guard raises ELV02 at the
/// confirmation instead, so nothing is audited); the table guard's proposer
/// check dropped -> the direct update lands.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_proposers_passkey_confirms(pool: PgPool) {
    let p = elevated_custodian(&pool, "proposer", 1).await;
    let b = elevated_custodian(&pool, "bystander", 2).await;
    let args = format!(
        "{{\"assignment\": \"{}\", \"reason\": \"r\"}}",
        b.assignment
    );
    let act = propose(&pool, &p, true, "role.end", &args)
        .await
        .expect("propose");
    start(&pool, act).await.expect("challenge");
    let r = confirm_act(&pool, act, &b.cred, 1).await.expect("confirm");
    assert_eq!(
        (r.0.as_str(), r.1.as_deref(), r.2.as_deref()),
        ("refused", Some("person_mismatch"), Some("ELV02"))
    );
    assert_eq!(
        events(&pool, "platform.admin_act_refused", "act_id", act).await,
        1
    );
    assert_code(
        &confirm_act(&pool, act, &p.cred, 1).await,
        "ELV08",
        "a refused act is final",
    );

    let act2 = propose(&pool, &p, true, "role.end", &args)
        .await
        .expect("propose again");
    start(&pool, act2).await.expect("challenge");
    let r = maint(
        &pool,
        "UPDATE pending_admin_acts SET asserted_at = now(), outcome = 'confirmed', \
                assertion_evidence = '{}'::jsonb, authenticator_id = $2 WHERE id = $1",
        &[Some(act2), Some(b.passkey)],
    )
    .await;
    assert_code(
        &r,
        "ELV02",
        "a direct confirmation by another person's passkey",
    );
}

/// A regressed signature counter refuses the confirmation `counter_regressed`
/// (ELV05), audited as `platform.passkey_counter_regressed` too.
///
/// Verified to fail: the counter test dropped -> the confirmation raises
/// (124's passkey guard refuses a decreasing counter, ELV03) instead of being
/// refused, recorded and audited.
#[sqlx::test(migrations = "../../migrations")]
async fn a_regressed_counter_refuses_the_confirmation(pool: PgPool) {
    let p = elevated_custodian(&pool, "proposer", 1).await;
    let args = format!(
        "{{\"assignment\": \"{}\", \"reason\": \"r\"}}",
        p.assignment
    );
    let first = confirmed_with(&pool, &p, &args, 7).await;
    assert_eq!(first.0, "confirmed");
    let act = propose(&pool, &p, true, "role.end", &args)
        .await
        .expect("propose");
    start(&pool, act).await.expect("challenge");
    let r = confirm_act(&pool, act, &p.cred, 5).await.expect("confirm");
    assert_eq!(
        (r.0.as_str(), r.1.as_deref(), r.2.as_deref()),
        ("refused", Some("counter_regressed"), Some("ELV05"))
    );
    assert_eq!(
        events(&pool, "platform.passkey_counter_regressed", "act_id", act).await,
        1
    );
}

async fn confirmed_with(pool: &PgPool, e: &Elevated, args: &str, counter: i64) -> ActOutcome {
    let act = propose(pool, e, true, "role.end", args)
        .await
        .expect("propose");
    start(pool, act).await.expect("challenge");
    confirm_act(pool, act, &e.cred, counter)
        .await
        .expect("confirm")
}

// =====================================================================
// ELV10: when a confirmation is required (EQ-2 (a)), and bootstrap.
// =====================================================================

/// The BOOTSTRAP grant (no grantor) is admitted and audited `confirmation =
/// 'none'`; a grant by a grantor with NO passkey is admitted unconfirmed,
/// even to a holder that holds one; once the GRANTOR holds a passkey, its
/// grant without an act is refused ELV10.
///
/// Verified to fail: the ELV10 test keyed on the holder instead of the
/// grantor -> the passkey-holding holder's grant is refused and the
/// passkey-holding grantor's admitted; the ELV10 test dropped -> the last
/// grant lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_grantor_holding_a_passkey_grants_only_on_a_confirmed_act(pool: PgPool) {
    let (g, _) = human(&pool, "grantor").await;
    let boot = grant_on(&pool, CUSTODIAN, g, None, None, "bootstrap", None)
        .await
        .expect("the bootstrap grant");
    assert_eq!(
        confirmation_of(&pool, "platform.role_granted", boot).await,
        ("none".to_string(), None),
        "the bootstrap is recorded unconfirmed"
    );
    let (h, _) = human(&pool, "holder").await;
    passkey(&pool, h, 3).await;
    let a = grant_on(&pool, AUDITOR, h, None, Some(g), "audit", None)
        .await
        .expect("a grantor with no passkey grants unconfirmed");
    assert_eq!(
        confirmation_of(&pool, "platform.role_granted", a).await.0,
        "none"
    );
    passkey(&pool, g, 4).await;
    let (y, _) = human(&pool, "second holder").await;
    assert_code(
        &grant_on(&pool, AUDITOR, y, None, Some(g), "audit", None).await,
        "ELV10",
        "a passkey-holding grantor's unconfirmed grant",
    );
}

/// A confirmed `role.grant` act executes exactly its args, once, by its
/// proposer: a grant whose `valid_to` differs by one field is refused ELV09;
/// one naming another grantor is refused ELV09; the exact grant lands, the
/// act is consumed (by this login, with the assignment as its result), and
/// the grant's audit names the act and its elevation; a second use is
/// refused ELV08.
///
/// Verified to fail: the canonical args built without `valid_to` (a digest
/// over a subset, on both sides) -> the one-field-different grant lands; the
/// actor comparison dropped from the consumer -> the other grantor's grant
/// lands; the consumer's consumption UPDATE dropped -> the act stays
/// unconsumed and the second use lands. EQUIVALENT alone: the consumer's
/// already-consumed test (the table guard refuses any change to a consumed
/// act, ELV08, as a second layer).
#[sqlx::test(migrations = "../../migrations")]
async fn a_confirmed_grant_executes_exactly_its_args_once(pool: PgPool) {
    let p = elevated_custodian(&pool, "proposer", 1).await;
    let q = elevated_custodian(&pool, "other custodian", 2).await;
    let (x, _) = human(&pool, "holder").await;
    let to = "2099-01-01T00:00:00.000000Z";
    let act = confirmed(
        &pool,
        &p,
        "role.grant",
        &grant_args(AUDITOR, x, Some(to), "audit"),
    )
    .await;
    assert_code(
        &grant_on(
            &pool,
            AUDITOR,
            x,
            Some("2099-01-02T00:00:00Z"),
            Some(p.person),
            "audit",
            Some(act),
        )
        .await,
        "ELV09",
        "args differing in valid_to",
    );
    assert_code(
        &grant_on(
            &pool,
            AUDITOR,
            x,
            Some(to),
            Some(q.person),
            "audit",
            Some(act),
        )
        .await,
        "ELV09",
        "another grantor",
    );
    let id = grant_on(
        &pool,
        AUDITOR,
        x,
        Some(to),
        Some(p.person),
        "audit",
        Some(act),
    )
    .await
    .expect("the confirmed grant");
    let (consumed_by, result): (Option<String>, Option<serde_json::Value>) =
        sqlx::query_as("SELECT consumed_by, result FROM pending_admin_acts WHERE id = $1")
            .bind(act)
            .fetch_one(&pool)
            .await
            .expect("the act");
    assert_eq!(consumed_by.as_deref(), Some("epigraph_maintenance"));
    assert_eq!(
        result,
        Some(serde_json::json!({"assignment_id": id.to_string()}))
    );
    assert_eq!(
        confirmation_of(&pool, "platform.role_granted", id).await,
        ("passkey".to_string(), Some(act.to_string()))
    );
    let elevation: Option<String> = sqlx::query_scalar(
        "SELECT details->>'elevation_id' FROM security_events \
          WHERE event_type = 'platform.role_granted' AND details->>'assignment_id' = $1",
    )
    .bind(id.to_string())
    .fetch_one(&pool)
    .await
    .expect("elevation");
    assert_eq!(elevation, Some(p.session.to_string()));
    assert_eq!(
        events(&pool, "platform.admin_act_executed", "act_id", act).await,
        1
    );
    assert_code(
        &grant_on(
            &pool,
            AUDITOR,
            x,
            Some(to),
            Some(p.person),
            "audit",
            Some(act),
        )
        .await,
        "ELV08",
        "a consumed act",
    );
}

/// An act that is not confirmed, an expired confirmed act, an act of another
/// kind, and a FORGED act id are each refused, on a DIRECT maintenance
/// INSERT too (the rule is the table's, not the CLI's).
///
/// Verified to fail: the consumer's not-found test dropped -> the forged id
/// is refused ELV09 (a kind of NULL), not ELV08; the consumer's expiry test
/// dropped TOGETHER with the table guard's -> the expired act executes; the
/// consumer's confirmed test dropped together with the table guard's
/// consumption refusal, its passkey test and the consumed-shape CHECK -> the
/// unconfirmed act still fails, but ELV03 (the guard's challenge-only rule),
/// not ELV08. EQUIVALENT alone (layered on purpose): the consumer's confirmed
/// and expiry tests (the table guard refuses the consumption of an
/// unconfirmed or expired act), and its kind test (every kind has its own key
/// set, so another kind's digest never matches: ELV09 either way).
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_live_confirmed_act_of_the_kind_executes(pool: PgPool) {
    let p = elevated_custodian(&pool, "proposer", 1).await;
    let (x, _) = human(&pool, "holder").await;
    let args = grant_args(AUDITOR, x, None, "audit");
    let unconfirmed = propose(&pool, &p, true, "role.grant", &args)
        .await
        .expect("propose");
    assert_code(
        &grant_on(
            &pool,
            AUDITOR,
            x,
            None,
            Some(p.person),
            "audit",
            Some(unconfirmed),
        )
        .await,
        "ELV08",
        "an unconfirmed act",
    );
    let expired = confirmed(&pool, &p, "role.grant", &args).await;
    without_triggers(
        &pool,
        "UPDATE pending_admin_acts SET proposed_at = proposed_at - interval '1 hour', \
                expires_at = expires_at - interval '1 hour' WHERE id = $1",
        expired,
    )
    .await;
    assert_code(
        &grant_on(
            &pool,
            AUDITOR,
            x,
            None,
            Some(p.person),
            "audit",
            Some(expired),
        )
        .await,
        "ELV08",
        "an expired act",
    );
    let other_kind = confirmed(
        &pool,
        &p,
        "role.end",
        &format!(
            "{{\"assignment\": \"{}\", \"reason\": \"audit\"}}",
            p.assignment
        ),
    )
    .await;
    assert_code(
        &grant_on(
            &pool,
            AUDITOR,
            x,
            None,
            Some(p.person),
            "audit",
            Some(other_kind),
        )
        .await,
        "ELV09",
        "an act of another kind",
    );
    let r = maint(
        &pool,
        "INSERT INTO role_assignments (role, holder_person_id, valid_from, granted_by, reason, \
                                       grant_act_id) \
         VALUES ('role:auditor', $1, now(), $2, 'audit', $3)",
        &[Some(x), Some(p.person), Some(Uuid::new_v4())],
    )
    .await;
    assert_code(&r, "ELV08", "a direct insert naming a forged act");
}

/// An END needs a confirmed `role.end` act while any live custodian holds a
/// passkey (the end names no actor): unconfirmed it is refused ELV10, an act
/// over another reason ELV09, the exact act ends it (audited `passkey`). The
/// BREAK-GLASS: once every custodian's passkey is revoked, a maintenance end
/// is admitted again, recorded `none`; and the revoked passkey voids the
/// act it had confirmed (ELV08).
///
/// Verified to fail: the update guard's ELV10 test dropped -> the
/// unconfirmed end lands; the guard taking the act's own digest instead of
/// recomputing it from the end -> the other-reason end lands; the consumer's
/// passkey-revoked test dropped -> the voided act executes.
#[sqlx::test(migrations = "../../migrations")]
async fn an_end_needs_a_confirmed_act_while_a_custodian_holds_a_passkey(pool: PgPool) {
    let p = elevated_custodian(&pool, "proposer", 1).await;
    let (x, _) = human(&pool, "holder").await;
    let a = grant_on(
        &pool,
        AUDITOR,
        x,
        None,
        Some(p.person),
        "audit",
        Some(
            confirmed(
                &pool,
                &p,
                "role.grant",
                &grant_args(AUDITOR, x, None, "audit"),
            )
            .await,
        ),
    )
    .await
    .expect("an auditor");
    let end = "SELECT public.epigraph_end_role_assignment($1, 'done', $2)";
    assert_code(
        &maint(&pool, end, &[Some(a), None]).await,
        "ELV10",
        "an unconfirmed end",
    );
    let other = confirmed(
        &pool,
        &p,
        "role.end",
        &format!("{{\"assignment\": \"{a}\", \"reason\": \"another reason\"}}"),
    )
    .await;
    assert_code(
        &maint(&pool, end, &[Some(a), Some(other)]).await,
        "ELV09",
        "an act over another reason",
    );
    let act = confirmed(
        &pool,
        &p,
        "role.end",
        &format!("{{\"assignment\": \"{a}\", \"reason\": \"done\"}}"),
    )
    .await;
    maint(&pool, end, &[Some(a), Some(act)])
        .await
        .expect("the confirmed end");
    assert_eq!(
        confirmation_of(&pool, "platform.role_ended", a).await,
        ("passkey".to_string(), Some(act.to_string()))
    );

    // The break-glass.
    let b = grant_on(
        &pool,
        AUDITOR,
        x,
        None,
        Some(p.person),
        "audit again",
        Some(
            confirmed(
                &pool,
                &p,
                "role.grant",
                &grant_args(AUDITOR, x, None, "audit again"),
            )
            .await,
        ),
    )
    .await
    .expect("a second auditor assignment");
    let voided = confirmed(
        &pool,
        &p,
        "role.end",
        &format!("{{\"assignment\": \"{b}\", \"reason\": \"done\"}}"),
    )
    .await;
    maint(
        &pool,
        "SELECT public.epigraph_revoke_passkey($1, 'lost')",
        &[Some(p.passkey)],
    )
    .await
    .expect("revoke the passkey");
    assert_code(
        &maint(&pool, end, &[Some(b), Some(voided)]).await,
        "ELV08",
        "an act whose confirming passkey was revoked",
    );
    maint(&pool, end, &[Some(b), None])
        .await
        .expect("no passkey holds: the maintenance end is admitted");
    assert_eq!(
        confirmation_of(&pool, "platform.role_ended", b).await.0,
        "none"
    );
}

/// A `claim.supersede` custodial act on the authority of a custodian holding
/// a passkey needs its confirmed act (ELV10 without); the privatization acts,
/// which have no act kind yet, record as before, `confirmation = 'none'`. An
/// act id on a privatization act is refused ELV09. (The confirmed supersede
/// itself is driven end to end by the CLI's `custodial_supersede.rs`.)
///
/// Verified to fail: the recorder's ELV10 test dropped -> the unconfirmed
/// supersede record lands; the test widened to every act -> the
/// privatization record is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_custodial_supersede_by_a_passkey_holder_needs_its_act(pool: PgPool) {
    let p = elevated_custodian(&pool, "custodian", 1).await;
    let target = Some(Uuid::new_v4());
    let rec = |act: &'static str| {
        format!(
            "SELECT public.epigraph_record_custodial_act($1, $2, '{act}', 'claim', $3, \
                    '{{}}'::jsonb, $4)"
        )
    };
    assert_code(
        &maint(
            &pool,
            &rec("claim.supersede"),
            &[Some(p.assignment), Some(p.person), target, None],
        )
        .await,
        "ELV10",
        "an unconfirmed supersede record",
    );
    maint(
        &pool,
        &rec("privatization.plan_create"),
        &[Some(p.assignment), Some(p.person), target, None],
    )
    .await
    .expect("a privatization act records unconfirmed");
    let confirmation: String = sqlx::query_scalar(
        "SELECT details->>'confirmation' FROM security_events \
          WHERE event_type = 'platform.custodial_act' AND details->>'actor' = $1",
    )
    .bind(p.person.to_string())
    .fetch_one(&pool)
    .await
    .expect("the record");
    assert_eq!(confirmation, "none");
    assert_code(
        &maint(
            &pool,
            &rec("privatization.plan_create"),
            &[
                Some(p.assignment),
                Some(p.person),
                target,
                Some(Uuid::new_v4()),
            ],
        )
        .await,
        "ELV09",
        "an act id on an act with no kind",
    );
}

/// A person who already holds a passkey gets a LATER one only on a confirmed
/// `passkey.register` act of their own: a maintenance enrollment is refused
/// ELV10; the act's enrollment is opened `confirmed_act` and consumes it; a
/// proposal registering someone else's passkey is refused (22023).
///
/// Verified to fail: the enrollment guard's ELV10 test dropped -> the
/// maintenance enrollment opens; its consumption dropped -> the act stays
/// unconsumed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_later_passkey_rides_a_confirmed_register_act(pool: PgPool) {
    let p = elevated_custodian(&pool, "custodian", 1).await;
    let open3 = "SELECT public.epigraph_create_passkey_enrollment($1, 'a second key', 'key 2', $2)";
    assert_code(
        &maint(&pool, open3, &[Some(p.person), None]).await,
        "ELV10",
        "a maintenance enrollment of a passkey holder",
    );
    let (other, _) = human(&pool, "someone else").await;
    assert_code(
        &propose(
            &pool,
            &p,
            true,
            "passkey.register",
            &format!("{{\"person\": \"{other}\", \"label\": null, \"reason\": \"r\"}}"),
        )
        .await,
        "22023",
        "registering someone else's passkey",
    );
    let act = confirmed(
        &pool,
        &p,
        "passkey.register",
        &format!(
            "{{\"person\": \"{}\", \"label\": \"key 2\", \"reason\": \"a second key\"}}",
            p.person
        ),
    )
    .await;
    maint(&pool, open3, &[Some(p.person), Some(act)])
        .await
        .expect("the confirmed enrollment");
    let (via, consumed): (String, bool) = sqlx::query_as(
        "SELECT e.created_via, a.consumed_at IS NOT NULL FROM passkey_enrollments e \
           JOIN pending_admin_acts a ON a.id = e.act_id WHERE e.act_id = $1",
    )
    .bind(act)
    .fetch_one(&pool)
    .await
    .expect("the enrollment");
    assert_eq!((via.as_str(), consumed), ("confirmed_act", true));
}

// =====================================================================
// THE CANONICAL FORM: the CLI's (Rust) and the database's agree.
// =====================================================================

/// The maintenance CLI recomputes an act's args and digest from its own
/// flags (`epigraph_db::admin_act`) and refuses before writing when they
/// differ from the confirmed act's; the database canonicalizes at proposal
/// and recomputes from the write. The two must agree byte for byte: every
/// builder's output is already canonical by the database's normalizer, and
/// the canonical text and digest are equal, on args carrying quotes, a
/// backslash, a newline, a control character and non-ASCII text, a time
/// with an offset, truth values 0.7 and 1, a null label and a content digest
/// (which equals the database's SHA-256 of the same text). A free-form value
/// whose keys sort differently by byte and by length (`a`, `aa`, `b`) pins
/// the key order.
///
/// Verified to fail: the Rust canonicalizer escaping strings by hand
/// (`format!("\"{s}\"")`) -> the quoted reason differs; the Rust truth form
/// at five places -> the supersede args are not canonical; the Rust time at
/// millisecond precision -> the grant args are not canonical; the Rust key
/// sort by length then bytes (jsonb's order) -> the free-form text differs.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rust_and_database_canonical_forms_agree(pool: PgPool) {
    use epigraph_db::admin_act;
    let t = chrono::DateTime::parse_from_rfc3339("2030-06-01T12:34:56.789012+05:30")
        .expect("time")
        .with_timezone(&chrono::Utc);
    let awkward = "why \"quoted\" \\ back\nslash \u{1} é ✓";
    let content = "revised text ✓\n\"with quotes\"";
    let cases: Vec<(&str, serde_json::Value)> = vec![
        (
            "role.grant",
            admin_act::role_grant_args(AUDITOR, Uuid::new_v4(), None, Some(t), awkward),
        ),
        (
            "role.grant",
            admin_act::role_grant_args(CUSTODIAN, Uuid::new_v4(), Some(t), None, "r"),
        ),
        (
            "role.end",
            admin_act::role_end_args(Uuid::new_v4(), awkward),
        ),
        (
            "claim.custodial_supersede",
            admin_act::custodial_supersede_args(Uuid::new_v4(), content, 0.7, awkward, true)
                .expect("0.7"),
        ),
        (
            "claim.custodial_supersede",
            admin_act::custodial_supersede_args(Uuid::new_v4(), content, 1.0, "r", false)
                .expect("1"),
        ),
        (
            "passkey.register",
            admin_act::passkey_register_args(Uuid::new_v4(), None, "r"),
        ),
        (
            "passkey.register",
            admin_act::passkey_register_args(Uuid::new_v4(), Some(awkward), "r"),
        ),
    ];
    for (kind, args) in cases {
        let (db_args, db_text, db_digest): (serde_json::Value, String, Vec<u8>) = sqlx::query_as(
            "WITH a AS (SELECT public.epigraph_admin_act_args($1, $2) AS v) \
             SELECT a.v, public.epigraph_canonical_json(a.v), \
                    public.epigraph_admin_act_digest(a.v) FROM a",
        )
        .bind(kind)
        .bind(&args)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{kind}: {e}"));
        assert_eq!(db_args, args, "{kind}: the Rust args are already canonical");
        assert_eq!(
            admin_act::canonical_json(&args),
            db_text,
            "{kind}: the canonical text"
        );
        assert_eq!(
            admin_act::args_digest(&args).to_vec(),
            db_digest,
            "{kind}: the digest"
        );
    }
    let db_hash: String =
        sqlx::query_scalar("SELECT encode(sha256(convert_to($1, 'UTF8')), 'hex')")
            .bind(content)
            .fetch_one(&pool)
            .await
            .expect("sha256");
    let rust =
        admin_act::custodial_supersede_args(Uuid::nil(), content, 0.5, "r", false).expect("args");
    assert_eq!(rust["content_sha256"], serde_json::json!(db_hash));

    let free = serde_json::json!({
        "b": 1, "aa": [true, null, {"zz": "\u{1f}\t", "y": "é"}], "a": "q\"\\"
    });
    let db: String = sqlx::query_scalar("SELECT public.epigraph_canonical_json($1)")
        .bind(&free)
        .fetch_one(&pool)
        .await
        .expect("canonical");
    assert_eq!(admin_act::canonical_json(&free), db);
    assert!(
        db.starts_with("{\"a\":"),
        "CALIBRATION: byte order, not jsonb's: {db}"
    );
}

// =====================================================================
// THE UNDO (docs/runbooks/130-undo.sql)
// =====================================================================

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

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

/// The catalog facts 130 could leave behind, by name: relations, functions
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

fn undo_130() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/130-undo.sql"),
    )
    .expect("130-undo.sql")
}

/// `docs/runbooks/130-undo.sql`, applied to a database that went 129 -> 130
/// and holds a consumed act and an open one, returns its catalog (relations,
/// function bodies and owners, policies, triggers, constraints) to the same
/// database's at 129: 123's and 124's guard, audit and recorder bodies
/// byte for byte, every 130 function and overload gone. Every act is archived
/// as one `platform.admin_act_archived` event and the `platform.admin_act_*`
/// history stays; 123's behaviour is back (a writer-supplied `grant_act_id`
/// is CUS02 again, and a grantor holding a passkey grants unconfirmed). A
/// second run changes nothing.
///
/// Verified to fail: the undo's restore of 123's insert guard removed -> the
/// guard keeps 130's body (catalog differs); the archive step removed -> no
/// archived event; the DROP of the act-taking `epigraph_grant_role` removed
/// -> that overload is left behind.
#[sqlx::test(migrations = false)]
async fn the_rollback_returns_the_catalog_to_129_and_archives_the_acts(pool: PgPool) {
    migrate(&pool, &up_to(129)).await;
    // The gate is opened BEFORE the snapshot: it re-bodies a 125 function.
    fixture::open_elevated_access_gate(&pool).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(130)).await;

    let p = elevated_custodian(&pool, "P", 1).await;
    let (x, _) = human(&pool, "holder").await;
    let act = confirmed(
        &pool,
        &p,
        "role.grant",
        &grant_args(AUDITOR, x, None, "audit"),
    )
    .await;
    grant_on(&pool, AUDITOR, x, None, Some(p.person), "audit", Some(act))
        .await
        .expect("a confirmed grant");
    let open = propose(
        &pool,
        &p,
        true,
        "role.end",
        &format!(
            "{{\"assignment\": \"{}\", \"reason\": \"r\"}}",
            p.assignment
        ),
    )
    .await
    .expect("an open act");
    assert_ne!(
        catalog(&pool).await,
        before,
        "CALIBRATION: 130 changed the catalog"
    );

    sqlx::raw_sql(&undo_130())
        .execute(&pool)
        .await
        .expect("the undo script applies");

    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&before).collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the catalog is not 129's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
    for id in [act, open] {
        assert_eq!(
            events(&pool, "platform.admin_act_archived", "id", id).await,
            1,
            "act {id} is archived"
        );
    }
    assert_eq!(
        events(&pool, "platform.admin_act_executed", "act_id", act).await,
        1,
        "the act history stays"
    );

    let (y, _) = human(&pool, "second holder").await;
    let r = maint(
        &pool,
        "INSERT INTO role_assignments (role, holder_person_id, valid_from, granted_by, reason, \
                                       grant_act_id) \
         VALUES ('role:auditor', $1, now(), $2, 'audit', $3)",
        &[Some(y), Some(p.person), Some(act)],
    )
    .await;
    assert_code(&r, "CUS02", "123's refusal of a writer-supplied act id");
    maint(
        &pool,
        "SELECT public.epigraph_grant_role('role:auditor', $1, NULL, NULL, $2, 'audit')",
        &[Some(y), Some(p.person)],
    )
    .await
    .expect("a passkey-holding grantor grants unconfirmed again");

    sqlx::raw_sql(&undo_130())
        .execute(&pool)
        .await
        .expect("a second run applies");
    assert_eq!(catalog(&pool).await, before, "idempotent");
}

// =====================================================================
// THE RUST PROPOSAL PATH (ScopedPool::propose_admin_act, EL-12b)
// =====================================================================

/// `ScopedPool::propose_admin_act` proposes as an ELEVATED viewer in BOTH
/// session-setting modes (an elevated viewer otherwise gets only `BEGIN READ
/// ONLY`, where the definer's insert fails with 25006, or is refused
/// `begin_as` outright), the act naming the viewer's elevation; a viewer that
/// is not elevated reaches the definer and is refused there (ELV07), (a bypass
/// viewer is refused before any statement, by construction).
///
/// Verified to fail with the path opening `BEGIN READ ONLY` (25006) and with
/// its stamp skipped (ELV07 for the elevated viewer too).
#[sqlx::test(migrations = "../../migrations")]
async fn the_scoped_pool_proposes_only_as_an_elevated_viewer(pool: PgPool) {
    use epigraph_db::{DbError, ScopedPool, ScopedPoolOptions, SessionGucMode, Viewer};
    let p = elevated_custodian(&pool, "pool-proposer", 1).await;
    let (x, _) = human(&pool, "holder").await;
    let args: serde_json::Value =
        serde_json::from_str(&grant_args(AUDITOR, x, None, "pool path")).expect("json");
    for mode in [SessionGucMode::Session, SessionGucMode::Transaction] {
        let s = ScopedPool::connect_with_access_recorder_for_tests(
            &fixture::database_url_for(&pool).await,
            mode,
            ScopedPoolOptions {
                max_connections: 2,
                ..ScopedPoolOptions::default()
            },
            Some("epigraph_app"),
        )
        .await
        .expect("a recording application-role pool");
        let elevated = Viewer::resolve_elevated(&s, p.person, Some(p.session), p.family)
            .await
            .expect("resolve");
        assert!(elevated.is_elevated(), "CALIBRATION ({mode:?})");
        let act = s
            .propose_admin_act(&elevated, "role.grant", &args, "pool path", Some("jti-p"))
            .await
            .unwrap_or_else(|e| panic!("{mode:?}: {e}"));
        let (proposer, elevation, jti): (Uuid, Uuid, Option<String>) = sqlx::query_as(
            "SELECT proposed_by, elevation_id, jti FROM pending_admin_acts WHERE id = $1",
        )
        .bind(act)
        .fetch_one(&pool)
        .await
        .expect("the act");
        assert_eq!(
            (proposer, elevation, jti.as_deref()),
            (p.person, p.session, Some("jti-p")),
            "{mode:?}"
        );

        let plain = Viewer::resolve(s.inner(), p.person).await.expect("resolve");
        assert!(!plain.is_elevated(), "CALIBRATION");
        let refused = s
            .propose_admin_act(&plain, "role.grant", &args, "pool path", None)
            .await;
        let code = match &refused {
            Err(DbError::QueryFailed { source }) => source
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .map(|c| c.to_string()),
            _ => None,
        };
        assert_eq!(code.as_deref(), Some("ELV07"), "{mode:?}: {refused:?}");
    }
}

// =====================================================================
// MIGRATION 131: a person reads their own acts
// =====================================================================

/// One listed act: `(id, kind, outcome, consumed)`.
type Listed = (Uuid, String, Option<String>, bool);

/// The acts `epigraph_admin_acts_of_principal(limit)` lists on an app session
/// stamped as `who` (unstamped when `None`), in the order it lists them.
async fn listed(pool: &PgPool, who: Option<Uuid>, limit: Option<i32>) -> Vec<Listed> {
    as_app(pool, who, "", "", |mut conn| async move {
        let rows = sqlx::query_as::<_, Listed>(
            "SELECT id, kind, outcome, consumed_at IS NOT NULL \
               FROM public.epigraph_admin_acts_of_principal($1)",
        )
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .expect("list the acts");
        (conn, rows)
    })
    .await
}

/// A person's app session lists exactly the acts THAT PERSON proposed, newest
/// first, with each one's outcome; another person's acts never; an unstamped
/// session nothing. The limit is clamped to 1..=200 (NULL reads 50). The
/// reader returns no ceremony state, evidence, consuming login or result.
///
/// Verified to fail: the proposer clause dropped -> B lists P's acts; the
/// order reversed -> P's newest act is not first; the clamp's lower bound
/// dropped -> a limit of 0 lists nothing; `a.challenge_state` added to the
/// returned columns -> the column list differs.
#[sqlx::test(migrations = "../../migrations")]
async fn a_person_lists_only_their_own_acts(pool: PgPool) {
    let p = elevated_custodian(&pool, "lister-p", 1).await;
    let b = elevated_custodian(&pool, "lister-b", 2).await;
    let (x, _) = human(&pool, "holder").await;
    let older = propose(
        &pool,
        &p,
        true,
        "role.grant",
        &grant_args(AUDITOR, x, None, "list test"),
    )
    .await
    .expect("P's first act");
    // Distinct proposal times (`proposed_at` is the transaction's now()).
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let newer = confirmed(
        &pool,
        &p,
        "role.end",
        &format!(
            "{{\"assignment\": \"{}\", \"reason\": \"r\"}}",
            p.assignment
        ),
    )
    .await;
    let theirs = propose(
        &pool,
        &b,
        true,
        "role.grant",
        &grant_args(AUDITOR, x, None, "b's act"),
    )
    .await
    .expect("B's act");

    // The harness's view of who proposed what (a custodian's grant may ride a
    // stand-in act of the custodian that holds a passkey: `make_custodian`).
    let of = |who: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM pending_admin_acts WHERE proposed_by = $1 \
                  ORDER BY proposed_at DESC, id",
            )
            .bind(who)
            .fetch_all(&pool)
            .await
            .expect("the harness's view")
        }
    };
    let p_list = listed(&pool, Some(p.person), None).await;
    assert_eq!(
        p_list[..2],
        [
            (
                newer,
                "role.end".to_string(),
                Some("confirmed".to_string()),
                false
            ),
            (older, "role.grant".to_string(), None, false),
        ],
        "P lists its own acts, newest first, each with its outcome"
    );
    assert_eq!(
        p_list.iter().map(|r| r.0).collect::<Vec<_>>(),
        of(p.person).await,
        "P lists exactly the acts P proposed"
    );
    let b_list = listed(&pool, Some(b.person), None).await;
    assert!(b_list.contains(&(theirs, "role.grant".to_string(), None, false)));
    assert_eq!(
        b_list.iter().map(|r| r.0).collect::<Vec<_>>(),
        of(b.person).await,
        "B lists exactly the acts B proposed"
    );
    assert!(
        !p_list.iter().any(|r| r.0 == theirs) && !b_list.iter().any(|r| r.0 == newer),
        "neither lists the other's acts"
    );
    assert!(
        listed(&pool, None, None).await.is_empty(),
        "an unstamped session has no principal and lists nothing"
    );
    assert!(
        listed(&pool, Some(x), None).await.is_empty(),
        "a person who proposed nothing lists nothing"
    );
    assert_eq!(listed(&pool, Some(p.person), Some(1)).await.len(), 1);
    assert_eq!(
        listed(&pool, Some(p.person), Some(0)).await.len(),
        1,
        "a limit below 1 reads as 1"
    );

    let columns: Vec<String> = as_app(&pool, Some(p.person), "", "", |mut conn| async move {
        use sqlx::{Column, Row};
        let row = sqlx::query("SELECT * FROM public.epigraph_admin_acts_of_principal(1)")
            .fetch_one(&mut *conn)
            .await
            .expect("one row");
        let names = row.columns().iter().map(|c| c.name().to_string()).collect();
        (conn, names)
    })
    .await;
    assert_eq!(
        columns,
        [
            "id",
            "kind",
            "args",
            "args_digest",
            "target_type",
            "target_id",
            "reason",
            "elevation_id",
            "proposed_at",
            "expires_at",
            "asserted_at",
            "outcome",
            "refusal",
            "consumed_at"
        ],
        "no ceremony state, evidence, consuming login or result"
    );
}

fn undo_131() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/131-undo.sql"),
    )
    .expect("131-undo.sql")
}

/// `docs/runbooks/131-undo.sql`, applied to a database that went 130 -> 131
/// and holds an act, returns its catalog to 130's (the reader gone, the act
/// table and its acts untouched); a second run changes nothing.
///
/// Verified to fail: the undo's DROP removed -> the reader is left behind.
#[sqlx::test(migrations = false)]
async fn the_131_rollback_drops_only_the_reader(pool: PgPool) {
    migrate(&pool, &up_to(130)).await;
    fixture::open_elevated_access_gate(&pool).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(131)).await;
    let p = elevated_custodian(&pool, "P", 1).await;
    let (x, _) = human(&pool, "holder").await;
    let act = propose(
        &pool,
        &p,
        true,
        "role.grant",
        &grant_args(AUDITOR, x, None, "a"),
    )
    .await
    .expect("an act");
    assert_ne!(
        catalog(&pool).await,
        before,
        "CALIBRATION: 131 changed the catalog"
    );

    sqlx::raw_sql(&undo_131())
        .execute(&pool)
        .await
        .expect("the undo script applies");
    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&before).collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the catalog is not 130's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM pending_admin_acts WHERE id = $1")
        .bind(act)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(kept, 1, "the acts stay");
    sqlx::raw_sql(&undo_131())
        .execute(&pool)
        .await
        .expect("a second run applies");
    assert_eq!(catalog(&pool).await, before, "idempotent");
}

// =====================================================================
// THE REGISTERS
// =====================================================================

/// The functions a migration file creates, by name: `(definers, all)`.
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

/// Every SECURITY DEFINER migration 130 creates is on
/// `epigraph-tenancy-backfill verify`'s ownership list (a NEW name at 130; a
/// re-bodied or overloaded 123 / 124 name at its own migration), every
/// application-callable one and every act-taking overload is on its grant
/// register, and `docs/runbooks/130-undo.sql` drops every function 130 adds
/// (each overload by its full signature) and restores each body it replaced.
///
/// Verified to fail: the `("epigraph_has_live_passkey", 130)` entry removed
/// from `DEFERRED_DEFINER_FUNCTIONS` -> named here.
#[test]
fn every_130_object_is_registered() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    };
    let migration = read("migrations/130_pending_admin_acts.sql");
    let backfill = read("crates/epigraph-cli/src/bin/tenancy_backfill.rs");
    let undo = read("docs/runbooks/130-undo.sql");

    const REBODIED: &[(&str, i64)] = &[
        ("epigraph_role_assignments_guard_insert", 123),
        ("epigraph_role_assignments_guard_update", 123),
        ("epigraph_role_assignments_audit", 123),
        ("epigraph_grant_role", 123),
        ("epigraph_end_role_assignment", 123),
        ("epigraph_record_custodial_act", 123),
        ("epigraph_passkey_enrollments_guard_insert", 124),
        ("epigraph_create_passkey_enrollment", 124),
    ];
    let (definers, all) = functions_of(&migration);
    assert_eq!(
        definers.len(),
        18,
        "CALIBRATION: 130 creates or re-bodies 18 SECURITY DEFINER names; the scan found \
         {definers:?}"
    );
    assert_eq!(all.len(), 22, "CALIBRATION: and 4 pure helpers: {all:?}");
    let missing: Vec<String> = definers
        .iter()
        .filter_map(|n| {
            let at = REBODIED
                .iter()
                .find(|(r, _)| r == n)
                .map_or(130, |(_, v)| *v);
            let entry = format!("(\"{n}\", {at})");
            (!backfill.contains(&entry)).then_some(entry)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "130 definers missing from tenancy_backfill.rs's ownership list: {missing:?}"
    );
    for signature in [
        "public.epigraph_propose_admin_act(text, jsonb, text, text)",
        "public.epigraph_act_for_ceremony(uuid)",
        "public.epigraph_set_admin_act_challenge(uuid, jsonb)",
        "public.epigraph_passkeys_for_act(uuid)",
        "public.epigraph_confirm_admin_act(uuid, bytea, bigint, boolean, jsonb)",
        "public.epigraph_consume_admin_act(uuid, text, bytea, uuid, jsonb)",
        "public.epigraph_has_live_passkey(uuid)",
        "public.epigraph_grant_role(text, uuid, timestamp with time zone, timestamp with time \
         zone, uuid, text, uuid)",
        "public.epigraph_end_role_assignment(uuid, text, uuid)",
        "public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb, uuid)",
        "public.epigraph_create_passkey_enrollment(uuid, text, text, uuid)",
    ] {
        assert!(
            backfill.contains(&format!("\"{signature}\"")),
            "{signature} is missing from tenancy_backfill.rs's grant register"
        );
    }
    let new_names: Vec<&String> = all
        .iter()
        .filter(|n| !REBODIED.iter().any(|(r, _)| r == n))
        .collect();
    let undropped: Vec<&&String> = new_names
        .iter()
        .filter(|n| !undo.contains(&format!("DROP FUNCTION IF EXISTS public.{n}(")))
        .collect();
    assert!(
        undropped.is_empty(),
        "130-undo.sql does not drop: {undropped:?}"
    );
    for (overload, _) in REBODIED.iter().filter(|(n, _)| {
        n.starts_with("epigraph_grant_role")
            || n.starts_with("epigraph_end_role_assignment")
            || n.starts_with("epigraph_record_custodial_act")
            || n.starts_with("epigraph_create_passkey_enrollment")
    }) {
        assert!(
            undo.contains(&format!("DROP FUNCTION IF EXISTS public.{overload}(")),
            "130-undo.sql does not drop the act-taking {overload}"
        );
    }
    for (rebodied, _) in REBODIED
        .iter()
        .filter(|(n, _)| n.contains("guard") || n.ends_with("audit"))
    {
        assert!(
            undo.contains(&format!("CREATE OR REPLACE FUNCTION public.{rebodied}()")),
            "130-undo.sql does not restore {rebodied}"
        );
    }
    assert!(
        undo.contains("DROP TABLE IF EXISTS public.pending_admin_acts;"),
        "130-undo.sql does not drop the act table"
    );
}

/// Migration 131's one SECURITY DEFINER is on `epigraph-tenancy-backfill
/// verify`'s ownership list at 131 and on its grant register, and
/// `docs/runbooks/131-undo.sql` drops it.
///
/// Verified to fail: the `("epigraph_admin_acts_of_principal", 131)` entry
/// removed from `DEFERRED_DEFINER_FUNCTIONS` -> named here.
#[test]
fn every_131_object_is_registered() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    };
    let migration = read("migrations/131_admin_acts_of_principal.sql");
    let backfill = read("crates/epigraph-cli/src/bin/tenancy_backfill.rs");
    let undo = read("docs/runbooks/131-undo.sql");
    let (definers, all) = functions_of(&migration);
    assert_eq!(
        (definers.as_slice(), all.as_slice()),
        (
            ["epigraph_admin_acts_of_principal".to_string()].as_slice(),
            ["epigraph_admin_acts_of_principal".to_string()].as_slice()
        ),
        "CALIBRATION: 131 creates exactly one function, a SECURITY DEFINER"
    );
    for n in &definers {
        assert!(
            backfill.contains(&format!("(\"{n}\", 131)")),
            "{n} is missing from tenancy_backfill.rs's ownership list at 131"
        );
        assert!(
            undo.contains(&format!("DROP FUNCTION IF EXISTS public.{n}(")),
            "131-undo.sql does not drop {n}"
        );
    }
    assert!(
        backfill.contains("\"public.epigraph_admin_acts_of_principal(integer)\""),
        "the reader is missing from tenancy_backfill.rs's grant register"
    );
}
