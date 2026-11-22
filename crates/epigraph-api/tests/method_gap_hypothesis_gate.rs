#![cfg(feature = "db")]
//! `GET /api/v1/methods/gap-analysis?hypothesis_id=` on the APPLICATION ROLE
//! (backlog b6273fb9).
//!
//! Both of the route's answers (the no-capabilities early return and the full
//! analysis) name `hypothesis_id` as their subject. The handler echoed it
//! without reading it, so a hypothesis the caller cannot see answered 200,
//! while its sibling `POST /api/v1/experiments/design` answers such a
//! hypothesis as a missing one. Now it reads the hypothesis through the
//! caller's viewer first, before either answer: hidden and missing are one
//! identical 404.
//!
//! The arm drives the no-capabilities answer. The full analysis is not
//! reachable over HTTP as the route stands: `required_capabilities` is an
//! `Option<Vec<String>>` read by axum's `Query`, whose urlencoded decoder
//! takes no sequence, so any value for it is a 400 before the handler runs
//! (measured: the owner's own request with one capability is 400). The gate
//! sits above both answers, so the one arm covers the handler's check.
//!
//! Both pools of the `AppState` are `epigraph_app` (no BYPASSRLS, `claims` row
//! security FORCEd), as in production. Fixtures are seeded on the superuser
//! `#[sqlx::test]` pool. Every arm carries a calibration call by the
//! hypothesis's owner that must answer 200 and echo the id, so a 404 cannot
//! come from a broken fixture.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
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
          WHERE relnamespace = 'public'::regnamespace AND relname = 'claims'",
    )
    .fetch_one(pool)
    .await
    .expect("read row security flags");
    assert!(
        enabled && forced,
        "claims: row security enabled={enabled} forced={forced}; every arm here is vacuous"
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

fn token(agent_id: Uuid) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (t, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "agent",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT issued");
    t
}

async fn gaps(app: axum::Router, caller: Uuid, uri: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {}", token(caller)))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn uri(hypothesis: Uuid) -> String {
    format!("/api/v1/methods/gap-analysis?hypothesis_id={hypothesis}")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_hypothesis_is_the_missing_hypothesis_404(pool: PgPool) {
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "b627-owner").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "b627-stranger").await;
    let hypothesis = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("b6273fb9 hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let app = app_role_router(&pool).await;

    // Calibration: the owner reads its own hypothesis and gets the analysis.
    let (status, body) = gaps(app.clone(), owner, &uri(hypothesis)).await;
    assert_eq!(status, StatusCode::OK, "the owner analyses: {body}");
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(v["hypothesis_id"], hypothesis.to_string(), "{body}");

    let (hidden_status, hidden_body) = gaps(app.clone(), stranger, &uri(hypothesis)).await;
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) = gaps(app.clone(), stranger, &uri(missing)).await;
    assert_eq!(
        hidden_status,
        StatusCode::NOT_FOUND,
        "a hypothesis the caller cannot read is 404, got {hidden_status} {hidden_body}"
    );
    assert_eq!(missing_status, StatusCode::NOT_FOUND, "{missing_body}");
    assert_eq!(
        hidden_body.replace(&hypothesis.to_string(), "<id>"),
        missing_body.replace(&missing.to_string(), "<id>"),
        "a hidden hypothesis answers exactly as a missing one"
    );
}
