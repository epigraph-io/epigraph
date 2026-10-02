//! Migration 124: a registered human's passkeys (`person_authenticators`) and
//! the maintenance enrollment tickets that admit them (`passkey_enrollments`).
//!
//! Writes that only a maintenance act may make run through the maintenance
//! role (`fixture::as_role`), the role the write policies and the definers'
//! EXECUTE grants admit. The ceremony half (the challenge, the reader, the
//! completion) runs as `epigraph_app` under `SET SESSION AUTHORIZATION`,
//! UNSTAMPED, because the enrollment page is unauthenticated by design: the
//! enrollment id and the authenticator are its credentials. Every refusal is
//! asserted by its SQLSTATE, never by "it failed": several rules sit behind a
//! second rule that also refuses (a UNIQUE index, a CHECK), and only the code
//! tells which one held. Each test names the mutation of
//! `migrations/124_person_authenticators.sql` it was run against.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;

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

/// `epigraph_create_passkey_enrollment` on a maintenance session.
async fn enroll(pool: &PgPool, person: Uuid) -> Result<Uuid, sqlx::Error> {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'passkey test', 'test key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await;
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

/// Run `f` as `epigraph_app`, stamped as `principal` (unstamped when `None`),
/// with an empty group set; the stamp is cleared afterwards.
async fn as_app<F, Fut, T>(pool: &PgPool, principal: Option<Uuid>, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let principal = principal.map(|p| p.to_string()).unwrap_or_default();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
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

/// The ceremony's first step, as the unauthenticated API runs it: store the
/// library's registration state on the enrollment.
async fn set_challenge(pool: &PgPool, enrollment: Uuid) -> Result<(), sqlx::Error> {
    as_app(pool, None, |mut conn| async move {
        let r = sqlx::query(
            "SELECT public.epigraph_set_passkey_enrollment_challenge($1, \
                    '{\"rs\": {\"challenge\": \"test-challenge\"}}'::jsonb)",
        )
        .bind(enrollment)
        .execute(&mut *conn)
        .await
        .map(|_| ());
        (conn, r)
    })
    .await
}

/// A credential id of WebAuthn's minimum length, distinct per `n`.
fn credential(n: u8) -> Vec<u8> {
    let mut id = vec![0xA5_u8; 16];
    id[0] = n;
    id
}

/// The ceremony's last step, as the unauthenticated API runs it once the
/// library has verified the authenticator's response.
async fn complete(
    pool: &PgPool,
    enrollment: Uuid,
    credential_id: Vec<u8>,
    user_verified: bool,
) -> Result<Uuid, sqlx::Error> {
    as_app(pool, None, |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_complete_passkey_enrollment($1, $2, \
                    '{\"cred\": {\"counter\": 0}}'::jsonb, \
                    '00000000-0000-0000-0000-000000000000'::uuid, 'none', $3, true)",
        )
        .bind(enrollment)
        .bind(credential_id)
        .bind(user_verified)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// A live passkey for `person`: enrolled, challenged and completed.
async fn registered_passkey(pool: &PgPool, person: Uuid, n: u8) -> Uuid {
    let e = enroll(pool, person).await.expect("enroll");
    set_challenge(pool, e).await.expect("challenge");
    complete(pool, e, credential(n), true)
        .await
        .expect("complete")
}

/// A bare agent: no registry row, no human client, no link.
async fn bare_agent(pool: &PgPool) -> Uuid {
    fixture::seed_agent_with_group(pool, "bare-agent").await.0
}

/// Link `agent` to `operator` as its agent: a plain superuser INSERT, so
/// every `operator_links` trigger runs (`agent` holds no role, so 123's
/// role-holder guard admits it).
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

/// Age an enrollment past its expiry. Superuser with triggers off: the guards
/// refuse every change to a row's times, which is the point of them. The
/// CHECK still holds (created_at and expires_at move together).
async fn age_enrollment(pool: &PgPool, enrollment: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .expect("triggers off");
    sqlx::query(
        "UPDATE passkey_enrollments SET created_at = created_at - interval '1 hour', \
                                        expires_at = expires_at - interval '1 hour' \
          WHERE id = $1",
    )
    .bind(enrollment)
    .execute(&mut *conn)
    .await
    .expect("age the enrollment");
    sqlx::query("SET session_replication_role = DEFAULT")
        .execute(&mut *conn)
        .await
        .expect("triggers on");
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

// =====================================================================
// ELV01. Only a registered human that is no other human's agent holds a
// passkey, checked when the enrollment is created AND when it completes.
// =====================================================================

/// An enrollment names a REGISTERED HUMAN (`epigraph_is_human_operator`) that
/// is not linked as another human's agent: a bare agent, a linked agent and a
/// registered human linked as an agent are refused `ELV01`, through the
/// definer and through a raw maintenance INSERT alike (the rule is the
/// table's). A registered human is admitted, and the creation is audited.
///
/// Verified to fail: the enrollment guard's `operator_links` clause dropped ->
/// the linked registered human's enrollment lands; its
/// `epigraph_is_human_operator` clause dropped -> the bare agent's lands; the
/// enrollment audit trigger not created -> no `platform.passkey_enrollment_created`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_enrollment_names_a_registered_human_that_is_no_agent(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "passkey-human").await;
    let (linked_human, _) = fixture::seed_human_operator(&pool, "linked-human").await;
    link_as_agent(&pool, linked_human, human).await;
    let (linked_agent, _) = fixture::seed_agent_with_group(&pool, "linked-agent").await;
    link_as_agent(&pool, linked_agent, human).await;
    let bare = bare_agent(&pool).await;

    for (who, what) in [
        (bare, "a bare agent"),
        (linked_agent, "an agent linked to a human"),
        (
            linked_human,
            "a registered human linked as another human's agent",
        ),
    ] {
        assert_code(&enroll(&pool, who).await, "ELV01", what);
        let raw = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query(
                "INSERT INTO passkey_enrollments (person_agent_id, reason, expires_at) \
                 VALUES ($1, 'raw', now() + interval '5 minutes')",
            )
            .bind(who)
            .execute(&mut *conn)
            .await;
            (conn, r)
        })
        .await;
        assert_code(&raw, "ELV01", &format!("{what}, raw maintenance INSERT"));
    }

    let e = enroll(&pool, human)
        .await
        .expect("a registered human enrolls");
    let (ttl_ok, via, by): (bool, String, String) = sqlx::query_as(
        "SELECT expires_at > now() AND expires_at <= created_at + interval '15 minutes', \
                created_via, created_by FROM passkey_enrollments WHERE id = $1",
    )
    .bind(e)
    .fetch_one(&pool)
    .await
    .expect("the enrollment");
    assert!(ttl_ok, "an enrollment lives at most 15 minutes");
    assert_eq!(via, "maintenance");
    assert_eq!(
        by, "epigraph_maintenance",
        "created_by is the writing login"
    );
    assert_eq!(
        events(
            &pool,
            "platform.passkey_enrollment_created",
            "enrollment_id",
            e
        )
        .await,
        1,
        "the creation is audited"
    );
}

/// The subject is checked again at COMPLETION: a human enrolled while
/// registered, then linked as another human's agent, cannot complete
/// (`ELV01`), and no passkey lands.
///
/// Verified to fail: the ELV01 check dropped from the AUTHENTICATOR guard only
/// (the enrollment guard keeps it) -> the completion lands.
#[sqlx::test(migrations = "../../migrations")]
async fn completion_rechecks_the_subject(pool: PgPool) {
    let (operator, _) = fixture::seed_human_operator(&pool, "operator").await;
    let (human, _) = fixture::seed_human_operator(&pool, "later-linked").await;
    let e = enroll(&pool, human).await.expect("enroll while registered");
    set_challenge(&pool, e).await.expect("challenge");
    link_as_agent(&pool, human, operator).await;
    assert_code(
        &complete(&pool, e, credential(1), true).await,
        "ELV01",
        "completion after the subject was linked as an agent",
    );
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM person_authenticators WHERE person_agent_id = $1")
            .bind(human)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(n, 0, "no passkey landed");
}

// =====================================================================
// The application role creates nothing and reads nothing.
// =====================================================================

/// The application role cannot create an enrollment, by the definer or by a
/// raw INSERT, nor write a passkey or an enrollment directly, whether stamped
/// as the human or not: enrollment is a maintenance act (D3 not yet), and the
/// request DSN mints no ticket.
///
/// Two layers hold the definer call, and each alone is covered by the other:
/// the GRANT alone (`GRANT EXECUTE ON epigraph_create_passkey_enrollment TO
/// epigraph_app`) still meets the bypass-only INSERT policy (42501, measured:
/// an equivalent mutant here), and the policy widened to definer frames alone
/// still meets the missing EXECUTE.
///
/// Verified to fail: that GRANT together with
/// `passkey_enrollments_maintenance_insert` widened to
/// `epigraph_definer_bypass()` -> the app's definer call lands; INSERT on
/// `passkey_enrollments` granted to the app with an INSERT policy of
/// `epigraph_principal_id() IS NOT NULL` -> the stamped raw INSERT lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_create_an_enrollment(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    for principal in [None, Some(human)] {
        let via_definer = as_app(&pool, principal, |mut conn| async move {
            let r = sqlx::query_scalar::<_, Uuid>(
                "SELECT public.epigraph_create_passkey_enrollment($1, 'from the app', NULL)",
            )
            .bind(human)
            .fetch_one(&mut *conn)
            .await;
            (conn, r)
        })
        .await;
        assert_code(&via_definer, "42501", "the app calls the create definer");
        let raw = as_app(&pool, principal, |mut conn| async move {
            let r = sqlx::query(
                "INSERT INTO passkey_enrollments (person_agent_id, reason, expires_at) \
                 VALUES ($1, 'raw', now() + interval '5 minutes')",
            )
            .bind(human)
            .execute(&mut *conn)
            .await;
            (conn, r)
        })
        .await;
        assert_code(&raw, "42501", "the app INSERTs an enrollment");
        let e = enroll(&pool, human)
            .await
            .expect("a maintenance enrollment");
        let raw_key = as_app(&pool, principal, |mut conn| async move {
            let r = sqlx::query(
                "INSERT INTO person_authenticators (person_agent_id, credential_id, passkey, \
                     aaguid, attestation_format, user_verified, backup_eligible, enrollment_id) \
                 VALUES ($1, $2, '{}'::jsonb, gen_random_uuid(), 'none', true, true, $3)",
            )
            .bind(human)
            .bind(credential(9))
            .bind(e)
            .execute(&mut *conn)
            .await;
            (conn, r)
        })
        .await;
        assert_code(&raw_key, "42501", "the app INSERTs a passkey");
        let raw_consume = as_app(&pool, principal, |mut conn| async move {
            let r = sqlx::query("UPDATE passkey_enrollments SET consumed_at = now() WHERE id = $1")
                .bind(e)
                .execute(&mut *conn)
                .await;
            (conn, r)
        })
        .await;
        assert_code(&raw_consume, "42501", "the app UPDATEs an enrollment");
    }
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM passkey_enrollments WHERE created_by <> 'epigraph_maintenance'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(n, 0, "every enrollment is the maintenance role's");
}

/// The application role reads no passkey and no enrollment row, stamped as
/// the passkey's own person or not: the table is a privileged session's
/// alone. The ceremony gets the ONE thing it needs through the reader, and
/// only while the enrollment is live: its person, reason, expiry and stored
/// challenge, and nothing once it is consumed.
///
/// Verified to fail: `person_authenticators_read` widened to `USING (true)` ->
/// the app reads the passkey; `passkey_enrollments_read` widened likewise ->
/// the app reads the enrollment; the reader's `consumed_at IS NULL` dropped ->
/// the consumed enrollment is still served.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_reads_no_passkey_and_the_ceremony_reads_only_a_live_enrollment(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    let e = enroll(&pool, human).await.expect("enroll");
    set_challenge(&pool, e).await.expect("challenge");

    let read = |e: Uuid| {
        let pool = pool.clone();
        async move {
            as_app(&pool, None, |mut conn| async move {
                let r: Vec<(Uuid, String, bool, serde_json::Value)> = sqlx::query_as(
                    "SELECT person_agent_id, reason, expires_at > now(), challenge_state \
                       FROM public.epigraph_enrollment_for_ceremony($1)",
                )
                .bind(e)
                .fetch_all(&mut *conn)
                .await
                .expect("the ceremony reader");
                (conn, r)
            })
            .await
        }
    };
    let live = read(e).await;
    assert_eq!(live.len(), 1, "the live enrollment is served");
    assert_eq!(live[0].0, human);
    assert_eq!(live[0].1, "passkey test");
    assert!(live[0].2);
    assert_eq!(
        live[0].3["rs"]["challenge"], "test-challenge",
        "the stored challenge"
    );
    assert!(
        read(Uuid::new_v4()).await.is_empty(),
        "an unknown id is no row"
    );

    complete(&pool, e, credential(1), true)
        .await
        .expect("complete");
    assert!(
        read(e).await.is_empty(),
        "a consumed enrollment is not served"
    );

    for principal in [None, Some(human)] {
        let (keys, enrollments) = as_app(&pool, principal, |mut conn| async move {
            let k: i64 = sqlx::query_scalar("SELECT count(*) FROM person_authenticators")
                .fetch_one(&mut *conn)
                .await
                .expect("the app holds SELECT; RLS narrows it");
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM passkey_enrollments")
                .fetch_one(&mut *conn)
                .await
                .expect("the app holds SELECT; RLS narrows it");
            (conn, (k, n))
        })
        .await;
        assert_eq!(keys, 0, "the app reads no passkey (stamped {principal:?})");
        assert_eq!(
            enrollments, 0,
            "the app reads no enrollment (stamped {principal:?})"
        );
    }
    let all: i64 = sqlx::query_scalar("SELECT count(*) FROM person_authenticators")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(all, 1, "CALIBRATION: the passkey exists");
}

// =====================================================================
// ELV04. An enrollment completes once, and never after it expires.
// =====================================================================

/// A completion consumes its enrollment: the passkey lands with user
/// verification recorded, the enrollment names it, and
/// `platform.passkey_registered` is written. A second completion of the same
/// enrollment (another credential) is refused `ELV04`, and so is a new
/// challenge on it. A completion with no ceremony started is refused `ELV04`,
/// and one without user verification is refused by the CHECK (D5).
///
/// Verified to fail: the authenticator guard's `consumed_at IS NULL` test
/// dropped -> the second completion meets the UNIQUE `enrollment_id` instead
/// (23505, not ELV04); the enrollment guard's consumed test dropped -> the
/// challenge on a consumed enrollment lands; the consume in the audit trigger
/// removed -> the enrollment stays unconsumed; the `challenge_state IS NOT
/// NULL` test dropped -> the unchallenged completion lands.
#[sqlx::test(migrations = "../../migrations")]
async fn an_enrollment_completes_once(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;

    let unchallenged = enroll(&pool, human).await.expect("enroll");
    assert_code(
        &complete(&pool, unchallenged, credential(7), true).await,
        "ELV04",
        "a completion with no ceremony started",
    );

    let e = enroll(&pool, human).await.expect("enroll");
    set_challenge(&pool, e).await.expect("challenge");
    set_challenge(&pool, e)
        .await
        .expect("a restarted ceremony overwrites the challenge");
    assert_code(
        &complete(&pool, e, credential(1), false).await,
        "23514",
        "a credential registered without user verification (D5)",
    );
    let key = complete(&pool, e, credential(1), true)
        .await
        .expect("the first completion");

    let (uv, consumed_by, at): (bool, Option<Uuid>, bool) = sqlx::query_as(
        "SELECT a.user_verified, en.authenticator_id, en.consumed_at IS NOT NULL \
           FROM person_authenticators a JOIN passkey_enrollments en ON en.id = a.enrollment_id \
          WHERE a.id = $1",
    )
    .bind(key)
    .fetch_one(&pool)
    .await
    .expect("the passkey and its enrollment");
    assert!(uv, "user verification is recorded");
    assert_eq!(consumed_by, Some(key), "the enrollment names its passkey");
    assert!(at, "the enrollment is consumed");
    assert_eq!(
        events(
            &pool,
            "platform.passkey_registered",
            "authenticator_id",
            key
        )
        .await,
        1,
        "the registration is audited"
    );

    assert_code(
        &complete(&pool, e, credential(2), true).await,
        "ELV04",
        "a second completion of a consumed enrollment",
    );
    assert_code(
        &set_challenge(&pool, e).await,
        "ELV04",
        "a new challenge on a consumed enrollment",
    );
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM person_authenticators WHERE person_agent_id = $1")
            .bind(human)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(n, 1, "one passkey per enrollment");
}

/// An expired enrollment takes no challenge and no completion (`ELV04`), and
/// the ceremony reader no longer serves it.
///
/// The completion's expiry is held twice: by the authenticator guard, and by
/// the enrollment guard that the consumption (the audit trigger's UPDATE)
/// meets. Either alone is covered by the other (the authenticator guard's test
/// dropped alone: measured, still ELV04).
///
/// Verified to fail: both expiry tests dropped together -> the completion of
/// the expired enrollment lands; the enrollment guard's expiry test dropped
/// -> the challenge on it lands; the reader's expiry test dropped -> it is
/// still served.
#[sqlx::test(migrations = "../../migrations")]
async fn an_expired_enrollment_is_refused(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    let challenged = enroll(&pool, human).await.expect("enroll");
    set_challenge(&pool, challenged).await.expect("challenge");
    let fresh = enroll(&pool, human).await.expect("enroll");
    age_enrollment(&pool, challenged).await;
    age_enrollment(&pool, fresh).await;

    assert_code(
        &complete(&pool, challenged, credential(1), true).await,
        "ELV04",
        "completion of an expired enrollment",
    );
    assert_code(
        &set_challenge(&pool, fresh).await,
        "ELV04",
        "a challenge on an expired enrollment",
    );
    let served: i64 = as_app(&pool, None, |mut conn| async move {
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.epigraph_enrollment_for_ceremony($1)")
                .bind(challenged)
                .fetch_one(&mut *conn)
                .await
                .expect("reader");
        (conn, n)
    })
    .await;
    assert_eq!(served, 0, "an expired enrollment is not served");
}

// =====================================================================
// ELV03. Append-only shapes.
// =====================================================================

/// An enrollment is written by the database's rules, never the writer's: no
/// confirmed-act path exists yet, a writer supplies no consumption, challenge
/// or provenance, an enrollment lives at most 15 minutes, and its identity
/// never changes after the insert.
///
/// Verified to fail: the insert guard's `created_via` refusal removed -> the
/// confirmed-act row lands; its provenance test removed -> the back-dated row
/// lands; the update guard's column comparison removed -> the reason edit
/// lands.
#[sqlx::test(migrations = "../../migrations")]
async fn an_enrollment_is_append_only(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    for (sql, code, what) in [
        (
            "INSERT INTO passkey_enrollments (person_agent_id, reason, expires_at, created_via, \
                                              act_id) \
             VALUES ($1, 'raw', now() + interval '5 minutes', 'confirmed_act', gen_random_uuid())",
            "ELV03",
            "a confirmed-act enrollment before the act batch exists",
        ),
        (
            "INSERT INTO passkey_enrollments (person_agent_id, reason, expires_at, created_at) \
             VALUES ($1, 'raw', now() - interval '1 minute', now() - interval '5 minutes')",
            "ELV03",
            "a back-dated enrollment",
        ),
        (
            "INSERT INTO passkey_enrollments (person_agent_id, reason, expires_at, created_by) \
             VALUES ($1, 'raw', now() + interval '5 minutes', 'someone-else')",
            "ELV03",
            "an enrollment naming another login",
        ),
        (
            "INSERT INTO passkey_enrollments (person_agent_id, reason, expires_at, \
                                              challenge_state) \
             VALUES ($1, 'raw', now() + interval '5 minutes', '{}'::jsonb)",
            "ELV03",
            "an enrollment born with a challenge",
        ),
        (
            "INSERT INTO passkey_enrollments (person_agent_id, reason, expires_at) \
             VALUES ($1, 'raw', now() + interval '16 minutes')",
            "23514",
            "an enrollment of more than 15 minutes",
        ),
    ] {
        assert_code(&maint_exec(&pool, sql, human).await, code, what);
    }

    // Challenged first, so each edit below carries a well-formed challenge
    // and only the identity comparison stands between it and the row.
    let e = enroll(&pool, human).await.expect("enroll");
    set_challenge(&pool, e).await.expect("challenge");
    for (sql, what) in [
        (
            "UPDATE passkey_enrollments SET reason = 'edited' WHERE id = $1",
            "an edit of the reason",
        ),
        (
            "UPDATE passkey_enrollments SET expires_at = expires_at + interval '1 minute' \
              WHERE id = $1",
            "an extension",
        ),
        (
            "UPDATE passkey_enrollments SET person_agent_id = person_agent_id, \
                    created_by = 'someone-else' WHERE id = $1",
            "a rewritten provenance",
        ),
    ] {
        assert_code(&maint_exec(&pool, sql, e).await, "ELV03", what);
    }
    let deleted = maint_exec(&pool, "DELETE FROM passkey_enrollments WHERE id = $1", e).await;
    assert_code(
        &deleted,
        "42501",
        "the maintenance role deletes no enrollment",
    );
}

/// A passkey row is never edited: the only changes are one revoke (stamped
/// now(), by the revoking login, with a reason) and its use (`last_used_at`
/// now(), the counter never going back). A revoked passkey is final. The
/// revoke is audited, and a second revoke reports false.
///
/// Verified to fail: the authenticator update guard's column comparison
/// removed -> the passkey material edit lands; its counter test removed -> the
/// regressed counter lands; its revoked-row test removed -> the un-revoke
/// lands; the revoke audit removed -> no `platform.passkey_revoked`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_passkey_is_append_only(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    let key = registered_passkey(&pool, human, 1).await;

    // Each edit rides on a well-formed USE (`last_used_at = now()`), so only
    // the identity comparison stands between it and the row.
    for (sql, what) in [
        (
            "UPDATE person_authenticators SET passkey = '{\"forged\": true}'::jsonb, \
                    last_used_at = now() WHERE id = $1",
            "an edit of the passkey material",
        ),
        (
            "UPDATE person_authenticators SET credential_id = '\\x0102'::bytea || credential_id, \
                    last_used_at = now() WHERE id = $1",
            "an edit of the credential id",
        ),
        (
            "UPDATE person_authenticators SET created_at = created_at - interval '1 day', \
                    last_used_at = now() WHERE id = $1",
            "a back-dated creation",
        ),
        (
            "UPDATE person_authenticators SET revoked_at = now() - interval '1 hour', \
                    revoked_by = session_user, revoked_reason = 'x' WHERE id = $1",
            "a back-dated revoke",
        ),
    ] {
        assert_code(&maint_exec(&pool, sql, key).await, "ELV03", what);
    }

    maint_exec(
        &pool,
        "UPDATE person_authenticators SET last_used_at = now(), sign_count = 5 WHERE id = $1",
        key,
    )
    .await
    .expect("a use advances the counter");
    assert_code(
        &maint_exec(
            &pool,
            "UPDATE person_authenticators SET last_used_at = now(), sign_count = 4 WHERE id = $1",
            key,
        )
        .await,
        "ELV03",
        "a counter that goes back",
    );

    let revoke = |reason: &'static str| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
                let r =
                    sqlx::query_scalar::<_, bool>("SELECT public.epigraph_revoke_passkey($1, $2)")
                        .bind(key)
                        .bind(reason)
                        .fetch_one(&mut *conn)
                        .await;
                (conn, r)
            })
            .await
        }
    };
    assert!(revoke("lost the key").await.expect("revoke"), "revoked");
    assert!(
        !revoke("again").await.expect("revoke again"),
        "a second revoke changes nothing"
    );
    assert_eq!(
        events(&pool, "platform.passkey_revoked", "authenticator_id", key).await,
        1,
        "the revoke is audited once"
    );
    assert_code(
        &maint_exec(
            &pool,
            "UPDATE person_authenticators SET last_used_at = now() WHERE id = $1",
            key,
        )
        .await,
        "ELV03",
        "a use of a revoked passkey",
    );
    // An un-revoke shaped as a well-formed use: only the revoked-row rule
    // refuses it.
    assert_code(
        &maint_exec(
            &pool,
            "UPDATE person_authenticators SET revoked_at = NULL, revoked_by = NULL, \
                    revoked_reason = NULL, last_used_at = now() WHERE id = $1",
            key,
        )
        .await,
        "ELV03",
        "an un-revoke",
    );
    let deleted = maint_exec(
        &pool,
        "DELETE FROM person_authenticators WHERE id = $1",
        key,
    )
    .await;
    assert_code(&deleted, "42501", "the maintenance role deletes no passkey");
}

/// The app role cannot call the revoke (break-glass is a maintenance act).
///
/// Verified to fail: `GRANT EXECUTE ON epigraph_revoke_passkey TO
/// epigraph_app` -> the app's revoke lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_revoke_a_passkey(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    let key = registered_passkey(&pool, human, 1).await;
    let r = as_app(&pool, Some(human), |mut conn| async move {
        let r = sqlx::query_scalar::<_, bool>("SELECT public.epigraph_revoke_passkey($1, 'app')")
            .bind(key)
            .fetch_one(&mut *conn)
            .await;
        (conn, r)
    })
    .await;
    assert_code(&r, "42501", "the app revokes a passkey");
}

// =====================================================================
// The `platform.passkey_*` audit is unforgeable from the application.
// =====================================================================

/// An application session cannot write a `platform.passkey_registered` (or
/// `platform.passkey_revoked`) row of its own, stamped as the human it names
/// or not. A PIN of migration 123's `security_events_platform_privileged`
/// policy for this batch's event types: it holds before 124 exists, so its
/// red run is that policy's mutation, not 124's absence.
///
/// Verified to fail: 123's `security_events_platform_privileged` not created
/// -> the forged row lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_passkey_event_is_refused(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    for event in ["platform.passkey_registered", "platform.passkey_revoked"] {
        for principal in [None, Some(human)] {
            let r = as_app(&pool, principal, |mut conn| async move {
                let r = sqlx::query(
                    "INSERT INTO security_events (event_type, agent_id, success, details) \
                     VALUES ($1, $2, true, jsonb_build_object('authenticator_id', gen_random_uuid()))",
                )
                .bind(event)
                .bind(human)
                .execute(&mut *conn)
                .await;
                (conn, r)
            })
            .await;
            assert_code(
                &r,
                "42501",
                &format!("a forged {event} (stamped {principal:?})"),
            );
        }
    }
}

// =====================================================================
// The undo takes 124 back out.
// =====================================================================

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The catalog facts 124 could leave behind, by name: relations, functions
/// (body and owner), policies and triggers in `public`.
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
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

/// `docs/runbooks/124-undo.sql`, applied to a database that went 123 -> 124
/// and holds a live passkey, a consumed and an open ticket, returns its
/// catalog (relations, function bodies and owners, policies, triggers) to the
/// same database's at 123, and keeps the `platform.passkey_*` history.
///
/// Verified to fail: the undo's DROP of
/// `epigraph_set_passkey_enrollment_challenge` removed -> that function is
/// left behind; the table DROP narrowed to `person_authenticators` -> the
/// enrollments table and its policies are left behind.
#[sqlx::test(migrations = false)]
async fn the_rollback_returns_the_catalog_to_123(pool: PgPool) {
    let at_123 = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= 123)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    // One connection, reset afterwards: 001's pg_dump header leaves
    // session-level SETs behind (viewer_fixture::db_at_122_then_head).
    let mut conn = pool.acquire().await.expect("acquire");
    at_123.run(&mut *conn).await.expect("migrate 001 -> 123");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    drop(conn);
    let before = catalog(&pool).await;

    let mut conn = pool.acquire().await.expect("acquire");
    MIGRATOR.run(&mut *conn).await.expect("migrate 123 -> head");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    drop(conn);
    let (human, _) = fixture::seed_human_operator(&pool, "human").await;
    let key = registered_passkey(&pool, human, 1).await;
    enroll(&pool, human).await.expect("an open ticket");
    assert_ne!(
        catalog(&pool).await,
        before,
        "CALIBRATION: 124 changed the catalog"
    );

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/124-undo.sql"),
    )
    .expect("124-undo.sql");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo script applies");

    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&before).collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the catalog is not 123's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
    assert_eq!(
        events(
            &pool,
            "platform.passkey_registered",
            "authenticator_id",
            key
        )
        .await,
        1,
        "the audit history stays"
    );
}
