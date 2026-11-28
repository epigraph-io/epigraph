#![cfg(feature = "db")]
//! `GET /api/v1/agents/me` (backlog 076e94cc): the bearer's own agent id and
//! display name, through the full router (bearer middleware, scope check,
//! viewer extractor, `read_as`) on the APPLICATION ROLE.
//!
//! A client that acts for an agent (`decompose_claims --as-agent`) asks this
//! route which agent its token writes as, and refuses to run on a mismatch.
//! The route must therefore answer the TOKEN's agent, never one named in the
//! request, and must not be swallowed by `/api/v1/agents/:id` (where `me`
//! is not a UUID). All names are invented.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool};

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

async fn named(pool: &PgPool, name: &str) -> Uuid {
    let (a, _) = viewer_fixture::seed_agent_with_group(pool, name).await;
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(a)
        .bind(name)
        .execute(pool)
        .await
        .expect("name");
    a
}

async fn get_me(state: &AppState, caller: Option<(Uuid, &[&str])>) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/agents/me");
    if let Some((agent, scopes)) = caller {
        let token = common::mint_token_with_agent(scopes, agent);
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let resp = create_router(state.clone())
        .oneshot(req.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_route_answers_the_tokens_own_agent_and_nothing_else(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let alice = named(&pool, "Orla Fenwick").await;
    let bob = named(&pool, "Teodor Vashti").await;

    let (status, body) = get_me(&state, Some((alice, &["claims:read"]))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"agent_id": alice, "display_name": "Orla Fenwick"}),
        "exactly the token's agent id and name, no other field"
    );

    // A second agent's token answers that agent: the id comes from the token.
    let (status, body) = get_me(&state, Some((bob, &["claims:read"]))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["agent_id"], json!(bob));
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_route_refuses_a_caller_without_a_token_or_without_claims_read(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let alice = named(&pool, "Orla Fenwick").await;

    let (status, body) = get_me(&state, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = get_me(&state, Some((alice, &["claims:write"]))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Positive control on the same agent.
    let (status, _) = get_me(&state, Some((alice, &["claims:read", "claims:write"]))).await;
    assert_eq!(status, StatusCode::OK);
}
