#![cfg(feature = "db")]
//! `PUT /api/v1/perspectives/:id/source-reliability` on the APPLICATION ROLE
//! (backlog 0f2f9ddb).
//!
//! The handler used to call the pool form of
//! `PerspectiveRepository::set_source_reliability` on the unstamped `db_pool`
//! and check no scope. Both pools of the `AppState` here are `epigraph_app` (no
//! BYPASSRLS, `perspectives` row security FORCEd), as in production, so:
//!
//! * the owner's own write, which the unstamped UPDATE could never make
//!   (migration 117's owner-scoped UPDATE sees an empty writable set), now
//!   succeeds and is stored;
//! * a caller without `claims:write` is refused before anything runs;
//! * a caller who can read the perspective but does not write its owner group
//!   is 403, and a perspective that does not exist is 404, with nothing
//!   written on either.
//!
//! Fixtures are seeded and read back on the superuser `#[sqlx::test]` pool.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod viewer_fixture;

async fn app_role_router(pool: &PgPool) -> axum::Router {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let (enabled, forced): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
          WHERE relnamespace = 'public'::regnamespace AND relname = 'perspectives'",
    )
    .fetch_one(pool)
    .await
    .expect("read row security flags");
    assert!(
        enabled && forced,
        "perspectives: row security enabled={enabled} forced={forced}; every arm here is vacuous"
    );
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    create_router(state)
}

fn token(agent_id: Uuid, scopes: &[&str]) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (t, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT issued");
    t
}

async fn put_reliability(
    app: axum::Router,
    perspective: Uuid,
    bearer: &str,
    map: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!(
            "/api/v1/perspectives/{perspective}/source-reliability"
        ))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "source_reliability": map }).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A PUBLIC perspective owned by `group`: every caller can read it, only a
/// writer of `group` may update it.
async fn seed_perspective(pool: &PgPool, owner: Uuid, group: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id, perspective_type, visibility, \
                                   owner_group_id) \
         VALUES ('a lens', $1, 'analytical', 'public', $2) RETURNING id",
    )
    .bind(owner)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed perspective")
}

async fn stored_reliability(pool: &PgPool, perspective: Uuid) -> Option<Value> {
    sqlx::query_scalar("SELECT properties -> 'source_reliability' FROM perspectives WHERE id = $1")
        .bind(perspective)
        .fetch_one(pool)
        .await
        .expect("read the perspective")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_sets_its_own_perspectives_source_reliability(pool: PgPool) {
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "sr-owner").await;
    let perspective = seed_perspective(&pool, owner, group).await;

    let (status, body) = put_reliability(
        app_role_router(&pool).await,
        perspective,
        &token(owner, &["claims:write"]),
        json!({ "western_clinical": 0.25 }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the owner writes its own perspective's group, so the stamped UPDATE must \
         be admitted; a 403/404 here is the unstamped-pool refusal: {body}"
    );
    assert_eq!(
        stored_reliability(&pool, perspective).await,
        Some(json!({ "western_clinical": 0.25 })),
        "a 204 must mean the map was stored"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_without_claims_write_is_refused_and_writes_nothing(pool: PgPool) {
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "sr-readonly").await;
    let perspective = seed_perspective(&pool, owner, group).await;

    let (status, body) = put_reliability(
        app_role_router(&pool).await,
        perspective,
        &token(owner, &["claims:read"]),
        json!({ "western_clinical": 0.25 }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the route writes, so it needs claims:write (the scope MCP \
         set_source_reliability is mapped to), even for the owner: {body}"
    );
    assert_eq!(stored_reliability(&pool, perspective).await, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_is_403_and_a_missing_perspective_is_404(pool: PgPool) {
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "sr-owner2").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "sr-stranger").await;
    let perspective = seed_perspective(&pool, owner, group).await;
    let bearer = token(stranger, &["claims:write"]);

    let (status, body) = put_reliability(
        app_role_router(&pool).await,
        perspective,
        &bearer,
        json!({ "western_clinical": 0.25 }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the stranger can read the public perspective but does not write its owner \
         group: a denial, never a 204 that changed no row: {body}"
    );
    assert_eq!(
        stored_reliability(&pool, perspective).await,
        None,
        "a refused write stores nothing"
    );

    let (status, body) = put_reliability(
        app_role_router(&pool).await,
        Uuid::new_v4(),
        &bearer,
        json!({ "western_clinical": 0.25 }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a perspective id that matches no row is 404, not 204: {body}"
    );
}
