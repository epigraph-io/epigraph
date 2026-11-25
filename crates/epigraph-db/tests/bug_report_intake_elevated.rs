//! Migration 207's BUG02: the bug-report intake refuses an ELEVATED session,
//! in the write (`epigraph_submit_bug_report`) and in its preflight
//! (`epigraph_bug_report_preflight`) alike (backlog 64584278, part 4).
//!
//! Both definers are owned by the maintenance role, so 126's
//! `*_elevated_no_insert` policies, which name the application role, do not
//! apply inside them; without their own `epigraph_is_elevated()` refusal an
//! elevated session would file through them. `ScopedPool::begin_as` already
//! refuses an elevated viewer a transaction, so this is pinned BELOW it, on
//! the real elevation machinery (the fixtures are `bba_retract_elevated.rs`'s,
//! the minimal subset of `elevated_arms.rs`'s): a session-mode checkout
//! stamped from the elevated viewer and switched to `epigraph_app`.
//!
//! Pinned: the custodian human operator, elevated, is refused BUG02 by the
//! preflight and by the write, with nothing written (no claim, no marker);
//! the same human unelevated passes the preflight and files (the
//! calibration: the refusal is the elevation, not the caller or the report).
//!
//! Verified to fail with the `epigraph_is_elevated()` refusal removed from
//! the latest bodies of both definers (the elevated preflight passes and the
//! elevated write files).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{
    BugReportInput, BugReportRepository, DbError, RefusalKind, ScopedPool, ScopedPoolOptions,
    SessionGucMode, Viewer,
};
use sqlx::{Executor, PgPool};
use uuid::Uuid;

/// Run `f` as `epigraph_app` with the principal stamped and no elevation.
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

struct Holder {
    person: Uuid,
    client: Uuid,
    cred: Vec<u8>,
    family: Uuid,
}

/// A custodian with a passkey and a refresh family.
async fn holder(pool: &PgPool, label: &str, n: u8) -> Holder {
    let (person, _) = fixture::seed_human_operator(pool, label).await;
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
            "SELECT public.epigraph_create_passkey_enrollment($1, 'bug report elevated', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("enroll");
        (conn, e)
    })
    .await;
    let mut cred = vec![0xB7_u8; 16];
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
async fn session(pool: &PgPool, h: &Holder) -> Uuid {
    let (client, fam) = (h.client, h.family);
    let ticket: Uuid = as_app(pool, Some(h.person), |mut conn| async move {
        let t = sqlx::query_scalar(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, 'grant', \
                    'bug report elevated', sha256('a bug report secret'::bytea))",
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

/// Declares the per-access recorder, standing in, with [`holder`]'s open
/// gate, for a build that records elevated accesses.
async fn scoped(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_with_access_recorder_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        ScopedPoolOptions {
            max_connections: 2,
            ..ScopedPoolOptions::default()
        },
        None,
    )
    .await
    .expect("ScopedPool")
}

/// P elevated (a live session on its family) and P unelevated, both resolved
/// on an application-role pool.
async fn viewers(pool: &PgPool, p: &Holder, live: Uuid) -> (Viewer, Viewer) {
    let s = &ScopedPool::connect_with_access_recorder_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        ScopedPoolOptions::default(),
        Some("epigraph_app"),
    )
    .await
    .expect("application-role ScopedPool");
    let elevated = Viewer::resolve_elevated(s, p.person, Some(live), p.family)
        .await
        .expect("resolve_elevated");
    assert!(elevated.is_elevated(), "CALIBRATION: P resolves elevated");
    let plain = Viewer::resolve_elevated(s, p.person, None, p.family)
        .await
        .expect("resolve");
    assert!(
        !plain.is_elevated(),
        "CALIBRATION: no claim resolves scoped"
    );
    (elevated, plain)
}

/// A session-mode checkout stamped from `v`, switched to `epigraph_app`, with
/// its state asserted.
async fn app_conn<'a>(s: &'a ScopedPool, v: &Viewer) -> epigraph_db::ScopedConn<'a> {
    let mut conn = s.acquire_as(v).await.expect("acquire_as");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("as epigraph_app");
    let (role, elevated): (String, bool) =
        sqlx::query_as("SELECT current_user::text, public.epigraph_is_elevated()")
            .fetch_one(&mut *conn)
            .await
            .expect("connection state");
    assert_eq!(role, "epigraph_app", "CALIBRATION: the application role");
    assert_eq!(
        elevated,
        v.is_elevated(),
        "CALIBRATION: the database agrees the connection is (not) elevated"
    );
    conn
}

async fn release(mut conn: epigraph_db::ScopedConn<'_>) {
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
}

/// The intake's group: a team group run by its own human, configured at the
/// default limits; the database armed for operator binding (122), as every
/// fixture of `bug_report_intake.rs` is.
async fn configure_intake(pool: &PgPool) -> Uuid {
    let (ops, _) = fixture::seed_human_operator(pool, "bri-elv-ops").await;
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'bri-elv-intake', 'did:test:team:' || $1::text, $2, 'team', $3)",
    )
    .bind(id)
    .bind(&key)
    .bind(ops)
    .execute(pool)
    .await
    .expect("team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(id)
    .bind(ops)
    .execute(pool)
    .await
    .expect("membership");
    sqlx::query("INSERT INTO bug_report_intake_settings (intake_group_id) VALUES ($1)")
        .bind(id)
        .execute(pool)
        .await
        .expect("configure the intake");
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm");
    id
}

fn report(title: &str) -> BugReportInput {
    BugReportInput {
        title: title.to_string(),
        description: format!("{title}: what happened"),
        severity: Some("minor".into()),
        component: None,
        repro: None,
        evidence: None,
        embedding: None,
    }
}

/// `(claims authored by, intake markers of)` `agent`.
async fn written_by(pool: &PgPool, agent: Uuid) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM claims WHERE agent_id = $1), \
                (SELECT count(*) FROM security_events \
                  WHERE agent_id = $1 AND event_type = 'bug_report.submitted')",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("count")
}

fn bug02<T: std::fmt::Debug>(what: &str, r: Result<T, DbError>) {
    match r {
        Err(DbError::Refused { kind, message }) => {
            assert_eq!(kind, RefusalKind::Authority, "{what}: {message}");
            assert!(message.starts_with("BUG02:"), "{what}: {message}");
        }
        other => panic!("{what}: expected BUG02, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_session_files_no_bug_report(pool: PgPool) {
    configure_intake(&pool).await;
    let p = holder(&pool, "bri-elv-p", 31).await;
    let s = scoped(&pool).await;
    let live = session(&pool, &p).await;
    let (elevated, plain) = viewers(&pool, &p, live).await;
    let before = written_by(&pool, p.person).await;

    let mut conn = app_conn(&s, &elevated).await;
    let pre = BugReportRepository::preflight_conn(&mut conn).await;
    let write = BugReportRepository::submit_conn(&mut conn, &report("elevated")).await;
    release(conn).await;
    bug02("the elevated preflight", pre);
    bug02("the elevated write", write);
    assert_eq!(
        written_by(&pool, p.person).await,
        before,
        "nothing written elevated: no claim, no marker"
    );

    let mut conn = app_conn(&s, &plain).await;
    let pre = BugReportRepository::preflight_conn(&mut conn).await;
    let write = BugReportRepository::submit_conn(&mut conn, &report("unelevated")).await;
    release(conn).await;
    pre.expect("CALIBRATION: the same human unelevated passes the preflight");
    let receipt = write.expect("CALIBRATION: the same human unelevated files");
    assert_eq!(
        written_by(&pool, p.person).await,
        (before.0 + 1, before.1 + 1),
        "one report and its marker"
    );
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(receipt.claim_id)
        .fetch_one(&pool)
        .await
        .expect("the report");
    assert_eq!(author, p.person);
}
