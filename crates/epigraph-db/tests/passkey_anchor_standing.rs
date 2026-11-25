//! Migration 285 (backlog 09ca9ab0): an anchored (`none`) passkey's row
//! records the passkey that admitted it, the ceremony readers serve that
//! anchor, and a standing refusal is audited.
//!
//! * `an_anchored_passkey_records_its_anchor_once`: a `none` passkey enrolled
//!   on a `passkey.register` act records the act's confirming passkey; an
//!   attested one on an act, and a maintenance-enrolled one, record none; no
//!   login changes it afterwards (ELV03); both readers serve it.
//! * `a_written_anchor_is_replaced_by_the_enrollments_own`: an anchor named
//!   by a direct INSERT is overwritten with the enrollment's own.
//! * `the_285_backfill_records_the_anchor_of_every_anchored_row`: rows
//!   written below 285 (revoked ones included) get theirs from the
//!   enrollment's act, the attested and maintenance rows stay NULL, and 124's
//!   update guard is enabled again afterwards.
//! * `a_standing_refusal_is_audited_only_for_a_live_ceremony_and_its_persons_passkey`:
//!   the audit definer's row and every gate (a live ticket or act, a live
//!   passkey of ITS person, the two codes, the reason's bound, the ceremony
//!   names), on the application role.
//! * `the_285_undo_returns_the_catalog_below_285`: the undo runbook, twice.
//!
//! Driven through the real definers (124's enrollment, 125's ticket, 130's
//! act) with synthetic evidence, as `pending_admin_acts.rs` does: what is
//! held here is the database's half.
//!
//! Verified to fail: the trigger's `none` test dropped -> the attested row
//! records an anchor (and violates the CHECK: 23514); the keep-anchor trigger
//! dropped -> the UPDATE succeeds; the backfill UPDATE dropped -> the
//! pre-285 rows read NULL; the guard left disabled -> the `tgenabled` probe;
//! the definer's person filter dropped -> another person's passkey is
//! audited; its live-ticket test dropped -> the confirmed ticket's audit
//! succeeds.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::BTreeSet;

use sqlx::PgPool;
use uuid::Uuid;

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
/// session-level SETs behind.
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

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

/// Run `f` as `epigraph_app` with the session GUCs stamped as given
/// (`pending_admin_acts.rs`' helper), cleared afterwards.
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

/// One statement on a MAINTENANCE session, binding the given uuids in order.
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

/// Complete `enrollment` through 124's definers (the unstamped app) as a
/// passkey of attestation `format`; its id.
async fn complete_enrollment(pool: &PgPool, enrollment: Uuid, n: u8, format: &str) -> Uuid {
    let format = format.to_string();
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
                    $3, true, false)",
        )
        .bind(enrollment)
        .bind(credential(n))
        .bind(&format)
        .fetch_one(&mut *conn)
        .await
        .expect("complete the enrollment");
        (conn, key)
    })
    .await
}

/// A person's FIRST passkey: a maintenance enrollment, completed attested.
async fn first_passkey(pool: &PgPool, person: Uuid, n: u8) -> Uuid {
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'anchor test', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("enroll");
        (conn, e)
    })
    .await;
    complete_enrollment(pool, e, n, "packed").await
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

/// A custodian with an attested first passkey and a LIVE elevation session.
#[derive(Clone, Debug)]
struct Elevated {
    person: Uuid,
    client: Uuid,
    passkey: Uuid,
    cred: Vec<u8>,
    family: Uuid,
    session: Uuid,
}

/// A started ticket of `person` on `family` (unconfirmed); its id.
async fn started_ticket(pool: &PgPool, person: Uuid, client: Uuid, family: Uuid) -> Uuid {
    as_app(pool, Some(person), "", "", |mut conn| async move {
        let t: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, 'connector', 'anchor test', \
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
    .await
}

async fn elevated_custodian(pool: &PgPool, label: &str, n: u8) -> Elevated {
    let (person, client) = human(pool, label).await;
    fixture::make_custodian(pool, person).await;
    let passkey = first_passkey(pool, person, n).await;
    let family = family(pool, client).await;
    let ticket = started_ticket(pool, person, client, family).await;
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
        client,
        passkey,
        cred,
        family,
        session,
    }
}

/// A proposed and STARTED (unconfirmed) act of `e`; its id.
async fn started_act(pool: &PgPool, e: &Elevated, kind: &str, args: &str) -> Uuid {
    let (kind, args) = (kind.to_string(), args.to_string());
    let (elv, fam) = (e.session.to_string(), e.family.to_string());
    let act: Uuid = as_app(pool, Some(e.person), &elv, &fam, |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_propose_admin_act($1, $2::jsonb, 'anchor test: why', 'jti')",
        )
        .bind(&kind)
        .bind(&args)
        .fetch_one(&mut *conn)
        .await
        .expect("propose");
        (conn, r)
    })
    .await;
    as_app(pool, None, "", "", |mut conn| async move {
        sqlx::query("SELECT public.epigraph_set_admin_act_challenge($1, '{\"act\": 1}'::jsonb)")
            .bind(act)
            .execute(&mut *conn)
            .await
            .expect("the act's challenge");
        (conn, ())
    })
    .await;
    act
}

/// A `passkey.register` act of `e`, confirmed by its passkey `cred`; its id.
async fn register_act(pool: &PgPool, e: &Elevated, cred: &[u8]) -> Uuid {
    let args = format!(
        "{{\"person\": \"{}\", \"label\": \"key 2\", \"reason\": \"a second key\"}}",
        e.person
    );
    let act = started_act(pool, e, "passkey.register", &args).await;
    let cred = cred.to_vec();
    let outcome: String = as_app(pool, None, "", "", |mut conn| async move {
        let o = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_confirm_admin_act($1, $2, 0, false, \
                    '{\"ev\": 1}'::jsonb)",
        )
        .bind(act)
        .bind(cred)
        .fetch_one(&mut *conn)
        .await
        .expect("confirm the act");
        (conn, o)
    })
    .await;
    assert_eq!(
        outcome, "confirmed",
        "CALIBRATION: the register act confirms"
    );
    act
}

/// The passkey enrolled on `act` (`passkey-enroll --act`), completed with
/// attestation `format`; its id.
async fn passkey_on_act(pool: &PgPool, person: Uuid, act: Uuid, n: u8, format: &str) -> Uuid {
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'a second key', 'key 2', $2)",
        )
        .bind(person)
        .bind(act)
        .fetch_one(&mut *conn)
        .await
        .expect("the act's enrollment");
        (conn, e)
    })
    .await;
    complete_enrollment(pool, e, n, format).await
}

async fn anchor_of(pool: &PgPool, passkey: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT anchor_authenticator_id FROM person_authenticators WHERE id = $1")
        .bind(passkey)
        .fetch_one(pool)
        .await
        .expect("the passkey")
}

/// A `none` passkey on a confirmed `passkey.register` act records the act's
/// confirming passkey, once; an attested passkey on an act and the
/// maintenance-enrolled first passkey record none; nobody changes it (ELV03,
/// a superuser included); both ceremony readers serve it on the application
/// role.
#[sqlx::test(migrations = "../../migrations")]
async fn an_anchored_passkey_records_its_anchor_once(pool: PgPool) {
    let p = elevated_custodian(&pool, "custodian", 1).await;
    let act = register_act(&pool, &p, &p.cred).await;
    let synced = passkey_on_act(&pool, p.person, act, 2, "none").await;
    let act2 = register_act(&pool, &p, &p.cred).await;
    let backup = passkey_on_act(&pool, p.person, act2, 3, "packed").await;

    assert_eq!(anchor_of(&pool, synced).await, Some(p.passkey));
    assert_eq!(anchor_of(&pool, backup).await, None, "an attested passkey");
    assert_eq!(anchor_of(&pool, p.passkey).await, None, "a first passkey");

    // Shaped as a USE (stamped now()), which 124's update guard admits, so
    // only the keep-anchor trigger can refuse it. CALIBRATION: the bare use.
    let reuse = |target: Option<Uuid>, also_anchor: bool| {
        let pool = pool.clone();
        async move {
            let sql = if also_anchor {
                "UPDATE person_authenticators SET last_used_at = now(), \
                        anchor_authenticator_id = $2 WHERE id = $1"
            } else {
                "UPDATE person_authenticators SET last_used_at = now() WHERE id = $1 \
                    AND $2::uuid IS NULL"
            };
            sqlx::query(sql)
                .bind(synced)
                .bind(target)
                .execute(&pool)
                .await
                .map(|d| d.rows_affected())
        }
    };
    assert_eq!(
        reuse(None, false).await.expect("CALIBRATION: a use"),
        1,
        "CALIBRATION: a use of the row passes 124's guard"
    );
    for target in [Some(backup), None] {
        assert_code(
            &reuse(target, true).await,
            "ELV03",
            &format!("re-anchoring to {target:?}"),
        );
    }
    assert_eq!(anchor_of(&pool, synced).await, Some(p.passkey), "unchanged");

    // The readers serve it, on the application role.
    let ticket = started_ticket(&pool, p.person, p.client, family(&pool, p.client).await).await;
    let listed = started_act(&pool, &p, "role.grant", &grant_args(p.person)).await;
    let (by_ticket, by_act) = as_app(&pool, None, "", "", |mut conn| async move {
        let t: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT authenticator_id, anchor_authenticator_id \
               FROM public.epigraph_passkeys_for_ticket($1)",
        )
        .bind(ticket)
        .fetch_all(&mut *conn)
        .await
        .expect("the ticket's passkeys");
        let a: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT authenticator_id, anchor_authenticator_id \
               FROM public.epigraph_passkeys_for_act($1)",
        )
        .bind(listed)
        .fetch_all(&mut *conn)
        .await
        .expect("the act's passkeys");
        (conn, (t, a))
    })
    .await;
    let expected = vec![(p.passkey, None), (synced, Some(p.passkey)), (backup, None)];
    assert_eq!(by_ticket, expected);
    assert_eq!(by_act, expected);
}

/// A live, started enrollment of `person` (on `act` when given; a
/// maintenance enrollment otherwise), its challenge stored by the app.
async fn started_enrollment(pool: &PgPool, person: Uuid, act: Option<Uuid>) -> Uuid {
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = match act {
            Some(act) => sqlx::query_scalar(
                "SELECT public.epigraph_create_passkey_enrollment($1, 'a second key', 'key 2', $2)",
            )
            .bind(person)
            .bind(act)
            .fetch_one(&mut *conn)
            .await
            .expect("the act's enrollment"),
            None => sqlx::query_scalar(
                "SELECT public.epigraph_create_passkey_enrollment($1, 'written', 'key w')",
            )
            .bind(person)
            .fetch_one(&mut *conn)
            .await
            .expect("a maintenance enrollment"),
        };
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
        (conn, ())
    })
    .await;
    e
}

/// `person`'s passkey n of attestation `format` on `enrollment`, by a direct
/// INSERT on a privileged session that NAMES `named` as its anchor; its id.
async fn insert_naming_anchor(
    pool: &PgPool,
    person: Uuid,
    enrollment: Uuid,
    n: u8,
    format: &str,
    named: Uuid,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO person_authenticators (person_agent_id, credential_id, passkey, \
             aaguid, attestation_format, user_verified, backup_eligible, enrollment_id, \
             anchor_authenticator_id) \
         VALUES ($1, $2, '{}'::jsonb, gen_random_uuid(), $3, true, true, $4, $5) \
         RETURNING id",
    )
    .bind(person)
    .bind(credential(n))
    .bind(format)
    .bind(enrollment)
    .bind(named)
    .fetch_one(pool)
    .await
    .expect("a direct insert")
}

/// A writer cannot supply the anchor: a privileged direct INSERT (past 124's
/// completion definer, which never names the column) that NAMES an anchor
/// has it replaced by the enrollment's own: NULL for a `none` passkey on a
/// maintenance enrollment (a person's first passkey; 124 opens one only for
/// a person with no live passkey), though the named anchor is a live
/// attested passkey (which both CHECKs admit); the act's confirming passkey
/// for a `none` passkey on an act's enrollment, not the one named; and NULL
/// for an attested passkey on an act's enrollment (cleared, not refused by
/// the only-`none` CHECK).
/// Mutations: the trigger keeping a supplied anchor (`IF ... AND
/// NEW.anchor_authenticator_id IS NULL`) -> the maintenance row keeps the
/// one it named; the trigger's `NEW.anchor_authenticator_id := NULL` removed
/// -> the attested insert fails the CHECK (23514).
#[sqlx::test(migrations = "../../migrations")]
async fn a_written_anchor_is_replaced_by_the_enrollments_own(pool: PgPool) {
    let p = elevated_custodian(&pool, "custodian", 1).await;
    let act = register_act(&pool, &p, &p.cred).await;
    let backup = passkey_on_act(&pool, p.person, act, 2, "packed").await;

    let (first, _) = human(&pool, "first passkey").await;
    let maintenance = started_enrollment(&pool, first, None).await;
    let written = insert_naming_anchor(&pool, first, maintenance, 3, "none", backup).await;
    assert_eq!(
        anchor_of(&pool, written).await,
        None,
        "a maintenance enrollment records no anchor, whatever was written"
    );

    let act2 = register_act(&pool, &p, &p.cred).await;
    let on_act = started_enrollment(&pool, p.person, Some(act2)).await;
    let written = insert_naming_anchor(&pool, p.person, on_act, 4, "none", backup).await;
    assert_eq!(
        anchor_of(&pool, written).await,
        Some(p.passkey),
        "an act's enrollment records the act's confirming passkey, not the one written"
    );

    let act3 = register_act(&pool, &p, &p.cred).await;
    let attested = started_enrollment(&pool, p.person, Some(act3)).await;
    let written = insert_naming_anchor(&pool, p.person, attested, 5, "packed", backup).await;
    assert_eq!(
        anchor_of(&pool, written).await,
        None,
        "an attested passkey records no anchor, whatever was written"
    );
}

fn grant_args(holder: Uuid) -> String {
    format!(
        "{{\"role\": \"role:auditor\", \"holder\": \"{holder}\", \"valid_from\": null, \
          \"valid_to\": null, \"reason\": \"anchor test\"}}"
    )
}

/// Rows written BELOW 285 get their anchor from the enrollment's act: a live
/// and a REVOKED `none` passkey on acts the first passkey confirmed record
/// it; the attested passkey on an act and the first passkey stay NULL. 124's
/// update guard, disabled for the backfill, is enabled again, and the
/// keep-anchor trigger exists.
#[sqlx::test(migrations = false)]
async fn the_285_backfill_records_the_anchor_of_every_anchored_row(pool: PgPool) {
    migrate(&pool, &up_to(284)).await;
    let p = elevated_custodian(&pool, "custodian", 1).await;
    let act = register_act(&pool, &p, &p.cred).await;
    let synced = passkey_on_act(&pool, p.person, act, 2, "none").await;
    let act2 = register_act(&pool, &p, &p.cred).await;
    let backup = passkey_on_act(&pool, p.person, act2, 3, "packed").await;
    let act3 = register_act(&pool, &p, &p.cred).await;
    let lost = passkey_on_act(&pool, p.person, act3, 4, "none").await;
    maint(
        &pool,
        "SELECT public.epigraph_revoke_passkey($1, 'lost')",
        &[Some(lost)],
    )
    .await
    .expect("revoke the lost passkey");

    migrate(&pool, &MIGRATOR).await;
    assert_eq!(anchor_of(&pool, synced).await, Some(p.passkey), "live");
    assert_eq!(anchor_of(&pool, lost).await, Some(p.passkey), "revoked");
    assert_eq!(anchor_of(&pool, backup).await, None, "attested");
    assert_eq!(anchor_of(&pool, p.passkey).await, None, "first");

    let enabled: Vec<(String, String)> = sqlx::query_as(
        "SELECT t.tgname::text, t.tgenabled::text FROM pg_trigger t \
          WHERE t.tgrelid = 'public.person_authenticators'::regclass \
            AND t.tgname IN ('person_authenticators_guard_update', \
                             'person_authenticators_keep_anchor', \
                             'person_authenticators_record_anchor') \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("triggers");
    assert_eq!(
        enabled,
        vec![
            ("person_authenticators_guard_update".into(), "O".into()),
            ("person_authenticators_keep_anchor".into(), "O".into()),
            ("person_authenticators_record_anchor".into(), "O".into()),
        ]
    );
    assert_code(
        &sqlx::query("UPDATE person_authenticators SET label = 'renamed' WHERE id = $1")
            .bind(synced)
            .execute(&pool)
            .await,
        "ELV03",
        "124's update guard is back",
    );
}

/// `epigraph_record_passkey_standing_refusal(ceremony, id, passkey, code,
/// reason)` on the APPLICATION role: one `platform.passkey_standing_refused`
/// row (success false) per call, under the ticket's person or the act's
/// proposer, naming the passkey, its credential, its format and its RECORDED
/// anchor (from the row, not the caller); refused for another person's or a
/// revoked passkey (ELV02), a ticket or act that is not live (ELV06 /
/// ELV08), an unknown code or ceremony (22023) and a reason over 2000
/// characters (22001); PUBLIC may not call it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_standing_refusal_is_audited_only_for_a_live_ceremony_and_its_persons_passkey(
    pool: PgPool,
) {
    let p = elevated_custodian(&pool, "custodian", 1).await;
    let q = elevated_custodian(&pool, "someone else", 9).await;
    let act = register_act(&pool, &p, &p.cred).await;
    let synced = passkey_on_act(&pool, p.person, act, 2, "none").await;
    let ticket = started_ticket(&pool, p.person, p.client, family(&pool, p.client).await).await;
    let live_act = started_act(&pool, &p, "role.grant", &grant_args(q.person)).await;

    let call = |ceremony: &'static str,
                id: Uuid,
                key: Uuid,
                code: &'static str,
                reason: Option<String>| {
        let pool = pool.clone();
        async move {
            as_app(&pool, None, "", "", |mut conn| async move {
                let r = sqlx::query_scalar::<_, Uuid>(
                    "SELECT public.epigraph_record_passkey_standing_refusal($1, $2, $3, $4, $5)",
                )
                .bind(ceremony)
                .bind(id)
                .bind(key)
                .bind(code)
                .bind(reason)
                .fetch_one(&mut *conn)
                .await;
                (conn, r)
            })
            .await
        }
    };
    const LISTED: &str = "attestation_not_in_good_standing";
    const UNKNOWN: &str = "attestation_status_unavailable";

    let event = call("elevation", ticket, synced, LISTED, Some("listed".into()))
        .await
        .expect("an elevation refusal is audited");
    let (event_type, agent, success, details): (String, Uuid, Option<bool>, serde_json::Value) =
        sqlx::query_as(
            "SELECT event_type::text, agent_id, success, details FROM security_events \
              WHERE id = $1",
        )
        .bind(event)
        .fetch_one(&pool)
        .await
        .expect("the audit row");
    assert_eq!(event_type, "platform.passkey_standing_refused");
    assert_eq!((agent, success), (p.person, Some(false)));
    assert_eq!(
        details,
        serde_json::json!({
            "ceremony": "elevation", "ticket_id": ticket, "person": p.person,
            "authenticator_id": synced, "credential_id": hex(&credential(2)),
            "attestation_format": "none", "anchor_authenticator_id": p.passkey,
            "code": LISTED, "reason": "listed",
        })
    );
    let event = call("admin_act", live_act, p.passkey, UNKNOWN, None)
        .await
        .expect("an act refusal is audited");
    let details: serde_json::Value =
        sqlx::query_scalar("SELECT details FROM security_events WHERE id = $1")
            .bind(event)
            .fetch_one(&pool)
            .await
            .expect("the audit row");
    assert_eq!(details["act_id"], live_act.to_string());
    assert_eq!(details["ceremony"], "admin_act");
    assert!(details["anchor_authenticator_id"].is_null(), "{details}");
    assert!(details["reason"].is_null(), "{details}");

    assert_code(
        &call("elevation", ticket, q.passkey, LISTED, None).await,
        "ELV02",
        "another person's passkey",
    );
    assert_code(
        &call("admin_act", live_act, q.passkey, LISTED, None).await,
        "ELV02",
        "another person's passkey on the act",
    );
    assert_code(
        &call("elevation", ticket, p.passkey, "anything_else", None).await,
        "22023",
        "an unknown code",
    );
    assert_code(
        &call("ticket", ticket, p.passkey, LISTED, None).await,
        "22023",
        "an unknown ceremony",
    );
    assert_code(
        &call(
            "elevation",
            ticket,
            p.passkey,
            LISTED,
            Some("x".repeat(2001)),
        )
        .await,
        "22001",
        "a reason over 2000 characters",
    );
    assert!(
        call(
            "elevation",
            ticket,
            p.passkey,
            LISTED,
            Some("x".repeat(2000))
        )
        .await
        .is_ok(),
        "CALIBRATION: a reason of 2000 characters"
    );
    assert_code(
        &call("elevation", Uuid::new_v4(), p.passkey, LISTED, None).await,
        "ELV06",
        "no such ticket",
    );
    assert_code(
        &call("admin_act", act, p.passkey, LISTED, None).await,
        "ELV08",
        "a confirmed (no longer live) act",
    );
    assert_code(
        &call("admin_act", ticket, p.passkey, LISTED, None).await,
        "ELV08",
        "a ticket id named as an act",
    );
    maint(
        &pool,
        "SELECT public.epigraph_revoke_passkey($1, 'gone')",
        &[Some(synced)],
    )
    .await
    .expect("revoke");
    assert_code(
        &call("elevation", ticket, synced, LISTED, None).await,
        "ELV02",
        "a revoked passkey",
    );

    let public_may: bool = sqlx::query_scalar(
        "SELECT has_function_privilege('public', \
           'public.epigraph_record_passkey_standing_refusal(text, uuid, uuid, text, text)', \
           'EXECUTE')",
    )
    .fetch_one(&pool)
    .await
    .expect("privilege");
    assert!(!public_may, "PUBLIC may not call it");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `public` catalog by name (`bug_report_intake_marker.rs`' probe), plus
/// `person_authenticators`' columns.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text || ' ' \
                || COALESCE(c.relacl::text, '-') \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname || ' ' || t.tgenabled::text \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'col person_authenticators.' || a.attname || ' ' \
                || format_type(a.atttypid, a.atttypmod) \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.person_authenticators'::regclass \
            AND a.attnum > 0 AND NOT a.attisdropped",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// `docs/runbooks/285-undo.sql`, run twice, returns the `public` catalog
/// (relations, functions by definition, owner and ACL, policies, triggers
/// and their enabled state, constraints, and `person_authenticators`'
/// columns) to exactly the one below 285.
#[sqlx::test(migrations = false)]
async fn the_285_undo_returns_the_catalog_below_285(pool: PgPool) {
    migrate(&pool, &up_to(284)).await;
    let before = catalog(&pool).await;
    // Through 285 only, not the head: a later migration's objects are not
    // 285's to undo, and would show up as a difference from "below 285".
    migrate(&pool, &up_to(285)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    for name in [
        "col person_authenticators.anchor_authenticator_id",
        "fn epigraph_record_passkey_standing_refusal(",
        "fn epigraph_person_authenticators_anchor(",
        "fn epigraph_passkeys_for_ticket(",
        "fn epigraph_passkeys_for_act(",
        "trg person_authenticators.person_authenticators_record_anchor",
        "trg person_authenticators.person_authenticators_keep_anchor",
    ] {
        assert!(
            added.iter().any(|e| e.starts_with(name)),
            "CALIBRATION: 285 adds or re-states {name}: {added:?}"
        );
    }

    let undo = repo_file("docs/runbooks/285-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 285"
        );
    }
}
