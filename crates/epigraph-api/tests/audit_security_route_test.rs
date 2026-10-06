#![cfg(feature = "db")]
//! `GET /api/v1/audit/security` on the APPLICATION ROLE.
//!
//! The route's only per-principal narrowing is the `security_events_read` RLS
//! policy (migration 083): bypass, definer bypass, `agent_id =
//! epigraph_principal_id()`, or `epigraph_is_instance_admin(principal)`. Every
//! arm but the two bypasses reads the session's STAMPED principal, so the
//! handler has to read on the viewer's stamped connection. On an unstamped
//! application-role connection every arm is false and the route answers `[]`
//! to everyone, the owner of the rows included, with a 200.
//!
//! # Why these tests run as `epigraph_app` on BOTH pools
//!
//! `#[sqlx::test]` connects as a superuser, which holds `BYPASSRLS`: on that
//! pool no policy filters anything, so an unstamped read returns every row and
//! a stamped one returns every row too. Nothing here would distinguish the
//! scoped read from the unscoped one. The state below is built from a
//! `ScopedPool` downgraded to `epigraph_app`, and `AppState::with_scoped_pool`
//! derives `db_pool` from the same pool, so a regression back onto the raw
//! pool is observed as the empty answer it produces in a real deployment.
//! `app_role_state` asserts both pools' `session_user` before any test relies
//! on it.
//!
//! Seeding (agents, events, the `instance_admins` row) runs on the superuser
//! pool. Each test uses its own `event_type` and passes it as a filter, so the
//! exact-set assertions cannot be disturbed by rows that triggers write while
//! the fixtures are seeded.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// An `AppState` whose stamped reads AND raw `db_pool` both run as
/// `epigraph_app`, with RLS live.
async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "CALIBRATION: epigraph_app holds BYPASSRLS, so every arm here is vacuous"
    );

    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());

    let stamped_side: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(state.scoped.as_ref().expect("scoped pool").inner())
        .await
        .expect("session_user on the scoped pool");
    let raw_side: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&state.db_pool)
        .await
        .expect("session_user on db_pool");
    assert_eq!(
        (stamped_side.as_str(), raw_side.as_str()),
        ("epigraph_app", "epigraph_app"),
        "CALIBRATION: both pools must be the application role, or a read on the raw pool \
         would not show the empty answer it gives in a real deployment"
    );
    state
}

/// A unique `event_type` for one test (the column is `varchar(50)`).
fn event_type() -> String {
    format!("audit_route_test_{}", Uuid::new_v4().simple())
}

/// One `security_events` row, written on the superuser pool.
async fn seed_event(pool: &PgPool, agent: Option<Uuid>, event_type: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO security_events (id, event_type, agent_id, success, details) \
         VALUES ($1, $2, $3, true, '{}'::jsonb)",
    )
    .bind(id)
    .bind(event_type)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed security event");
    id
}

async fn grant_instance_admin(pool: &PgPool, agent: Uuid) {
    sqlx::query("INSERT INTO instance_admins (agent_id, note) VALUES ($1, 'audit route test')")
        .bind(agent)
        .execute(pool)
        .await
        .expect("seed instance_admins row");
}

/// Every row of `event_type`, read on the superuser pool: proves the seeds
/// exist, so an empty or narrow route answer is the policy and not a fixture.
async fn seeded_ids(pool: &PgPool, event_type: &str) -> BTreeSet<Uuid> {
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM security_events WHERE event_type = $1")
        .bind(event_type)
        .fetch_all(pool)
        .await
        .expect("read seeded events");
    ids.into_iter().collect()
}

async fn get_events(app: &Router, bearer: &str, query: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/audit/security?{query}"))
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, body)
}

/// The ids of a 200 response body, which must be a JSON array of rows.
fn ids_of(status: StatusCode, body: &Value) -> BTreeSet<Uuid> {
    assert_eq!(status, StatusCode::OK, "expected 200, got {status}: {body}");
    body.as_array()
        .unwrap_or_else(|| panic!("the body must be an array of rows: {body}"))
        .iter()
        .map(|row| {
            row["id"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("a row without a uuid id: {row}"))
        })
        .collect()
}

fn audit_reader(agent: Uuid) -> String {
    common::mint_token_with_agent(&["audit:read"], agent)
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_app_role_viewer_sees_their_own_security_events(pool: PgPool) {
    let x = common::seed_system_agent(&pool).await;
    let y = common::seed_system_agent(&pool).await;
    let et = event_type();
    let x1 = seed_event(&pool, Some(x), &et).await;
    let x2 = seed_event(&pool, Some(x), &et).await;
    let y1 = seed_event(&pool, Some(y), &et).await;
    let null1 = seed_event(&pool, None, &et).await;
    assert_eq!(
        seeded_ids(&pool, &et).await,
        BTreeSet::from([x1, x2, y1, null1]),
        "CALIBRATION: all four rows exist"
    );

    let app = create_router(app_role_state(&pool).await);
    let (status, body) = get_events(&app, &audit_reader(x), &format!("event_type={et}")).await;

    assert_eq!(
        ids_of(status, &body),
        BTreeSet::from([x1, x2]),
        "X must see exactly its own two rows; an empty answer means the read ran on an \
         unstamped connection, where every arm of security_events_read is false. body: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_viewer_never_sees_another_agents_events(pool: PgPool) {
    // The over-reach twin. Its positive half is the test above (same fixture
    // shape, X sees exactly its own rows); this one pins that a fix which reads
    // on a privileged or unfiltered connection is caught, including through the
    // caller-controlled `agent_id` filter and for unattributed rows.
    let x = common::seed_system_agent(&pool).await;
    let y = common::seed_system_agent(&pool).await;
    let et = event_type();
    let x1 = seed_event(&pool, Some(x), &et).await;
    let y1 = seed_event(&pool, Some(y), &et).await;
    let y2 = seed_event(&pool, Some(y), &et).await;
    let null1 = seed_event(&pool, None, &et).await;
    assert_eq!(
        seeded_ids(&pool, &et).await,
        BTreeSet::from([x1, y1, y2, null1]),
        "CALIBRATION: all four rows exist"
    );

    let app = create_router(app_role_state(&pool).await);
    let token = audit_reader(x);

    let (status, body) = get_events(&app, &token, &format!("event_type={et}")).await;
    let seen = ids_of(status, &body);
    for (who, id) in [("Y's", y1), ("Y's", y2), ("the unattributed", null1)] {
        assert!(
            !seen.contains(&id),
            "{who} row must not reach a viewer who is neither its agent nor an instance \
             admin. body: {body}"
        );
    }

    let (status, body) = get_events(&app, &token, &format!("event_type={et}&agent_id={y}")).await;
    assert!(
        ids_of(status, &body).is_empty(),
        "naming another agent in the agent_id filter must not widen what the viewer reads. \
         body: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_instance_admin_sees_every_agents_rows_including_null_agent(pool: PgPool) {
    // Pins migration 083's admin arm as it stands on main. A later redefinition
    // of `epigraph_is_instance_admin` changes what this asserts, on purpose.
    let admin = common::seed_system_agent(&pool).await;
    let x = common::seed_system_agent(&pool).await;
    let y = common::seed_system_agent(&pool).await;
    grant_instance_admin(&pool, admin).await;
    let et = event_type();
    let x1 = seed_event(&pool, Some(x), &et).await;
    let y1 = seed_event(&pool, Some(y), &et).await;
    let null1 = seed_event(&pool, None, &et).await;
    assert_eq!(
        seeded_ids(&pool, &et).await,
        BTreeSet::from([x1, y1, null1]),
        "CALIBRATION: all three rows exist"
    );

    let app = create_router(app_role_state(&pool).await);
    let (status, body) = get_events(&app, &audit_reader(admin), &format!("event_type={et}")).await;

    assert_eq!(
        ids_of(status, &body),
        BTreeSet::from([x1, y1, null1]),
        "a live instance admin reads every agent's rows and the unattributed one; an empty \
         answer means the read ran on an unstamped connection. body: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn audit_read_scope_is_still_required(pool: PgPool) {
    let x = common::seed_system_agent(&pool).await;
    let et = event_type();
    let x1 = seed_event(&pool, Some(x), &et).await;

    let app = create_router(app_role_state(&pool).await);
    let without_scope = common::mint_token_with_agent(&["claims:read"], x);
    let (status, body) = get_events(&app, &without_scope, &format!("event_type={et}")).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token without audit:read is refused, even for the caller's own rows. body: {body}"
    );
    assert!(
        !body.to_string().contains(&x1.to_string()),
        "a refusal carries no row. body: {body}"
    );

    // Calibration: the same caller WITH the scope is served, so the 403 above is
    // the scope gate and not a broken route.
    let (status, body) = get_events(&app, &audit_reader(x), &format!("event_type={et}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: with audit:read the route answers 200. body: {body}"
    );
}
