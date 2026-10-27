//! Migration 184 (ruling R-79): the BBA retract definer refuses an ELEVATED
//! session (RT05).
//!
//! 126's `mass_functions_elevated_no_update` refuses an elevated
//! application session every UPDATE of `mass_functions`. The retract definer
//! is owned by the maintenance role, which that policy does not name, so
//! without its own refusal it would be the way around 126. Pinned here on the
//! real elevation machinery (the fixtures are the minimal subset of
//! `elevated_arms.rs`'s): the BBA's OWNER, elevated, is refused with nothing
//! written (no retraction, no audit row, no stored scoped belief deleted); the
//! same owner unelevated retracts it (the calibration: the refusal is the
//! elevation, not a malformed call).
//!
//! Verified to fail with the definer's `epigraph_is_elevated()` refusal
//! removed (the elevated call lands).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::mass_function::{BbaRetractStatus, MassFunctionRepository};
use epigraph_db::{ScopedPool, ScopedPoolOptions, SessionGucMode, Viewer};
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
    group: Uuid,
    client: Uuid,
    cred: Vec<u8>,
    family: Uuid,
}

/// A custodian with a passkey and a refresh family.
async fn holder(pool: &PgPool, label: &str, n: u8) -> Holder {
    let (person, group) = fixture::seed_human_operator(pool, label).await;
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
            "SELECT public.epigraph_create_passkey_enrollment($1, 'bba retract elevated', 'key')",
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
        group,
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
                    'bba retract elevated', sha256('a bba retract secret'::bytea))",
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

#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_owner_retracts_no_bba(pool: PgPool) {
    let p = holder(&pool, "bba-retract-elevated-p", 21).await;
    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'P public claim', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(claim)
    .bind(&hash)
    .bind(p.person)
    .bind(p.group)
    .execute(&pool)
    .await
    .expect("P's public claim");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("r79-elevated-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("frame");
    let bba: Uuid = sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"0\": 0.8, \"0,1\": 0.2}'::jsonb) RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(p.person)
    .fetch_one(&pool)
    .await
    .expect("P's BBA");
    let owner_group: Uuid =
        sqlx::query_scalar("SELECT owner_group_id FROM mass_functions WHERE id = $1")
            .bind(bba)
            .fetch_one(&pool)
            .await
            .expect("the BBA's owner");
    assert_eq!(owner_group, p.group, "CALIBRATION: the BBA is P's group's");
    sqlx::query(
        "INSERT INTO ds_combined_beliefs (frame_id, claim_id, scope_type, belief, plausibility) \
         VALUES ($1, $2, 'global', 0.8, 1.0)",
    )
    .bind(frame)
    .bind(claim)
    .execute(&pool)
    .await
    .expect("a stored scoped belief");

    let s = scoped(&pool).await;
    let live = session(&pool, &p).await;
    let (elevated, plain) = viewers(&pool, &p, live).await;

    let mut conn = app_conn(&s, &elevated).await;
    let refused: Result<serde_json::Value, sqlx::Error> = sqlx::query_scalar(
        "SELECT public.epigraph_retract_mass_function($1, 'elevated', NULL, NULL)",
    )
    .bind(bba)
    .fetch_one(&mut *conn)
    .await;
    release(conn).await;
    let e = refused.expect_err("an elevated session retracts no BBA");
    let d = e.as_database_error().expect("a database error");
    assert_eq!(d.code().as_deref(), Some("42501"), "{e}");
    assert!(d.message().contains("RT05"), "refused as elevated: {e}");
    let state: (bool, i64, i64) = sqlx::query_as(
        "SELECT (SELECT retracted_at IS NOT NULL FROM mass_functions WHERE id = $1), \
                (SELECT count(*) FROM security_events \
                  WHERE event_type = 'mass_functions.retract' \
                    AND details->>'mass_function_id' = $1::text), \
                (SELECT count(*) FROM ds_combined_beliefs WHERE claim_id = $2)",
    )
    .bind(bba)
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("state");
    assert_eq!(
        state,
        (false, 0, 1),
        "nothing written elevated: not retracted, no audit row, the stored belief kept"
    );

    let mut conn = app_conn(&s, &plain).await;
    let landed = MassFunctionRepository::retract_conn(&mut conn, bba, "unelevated", None).await;
    release(conn).await;
    let landed = landed.expect("CALIBRATION: P unelevated retracts its own BBA");
    assert_eq!(landed.status, BbaRetractStatus::Retracted);
    assert_eq!(landed.retracted_by, p.person);
}
