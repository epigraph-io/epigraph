#![cfg(feature = "db")]
//! `GET /api/v1/agents/search` (backlog 94cc12db): find an agent by name over
//! HTTP, through the full router (bearer middleware, scope check, viewer
//! extractor, `read_as`), with both pools of the `AppState` on the
//! APPLICATION ROLE: on the superuser pool `#[sqlx::test]` hands out,
//! `epigraph_bypass()` is true and every gate would admit every caller, so a
//! "the outsider cannot tell" assertion could not fail.
//!
//! The repository's own rules are pinned in
//! `epigraph-db/tests/agent_lookup.rs`; these tests pin that the route serves
//! them as the CALLER, and that it is registered where its path says (not
//! swallowed by `/api/v1/agents/:id`). Every refusal has a positive control.
//! All names are invented.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{as_role, database_url_for, downgraded_pool};

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(scoped.inner())
        .await
        .expect("epigraph_bypass on the scoped pool");
    assert!(
        !bypass,
        "CALIBRATION: the scoped pool must not be privileged"
    );
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

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("link");
    assert!(out.link_live);
}

async fn get(state: &AppState, caller: Option<(Uuid, &[&str])>, uri: &str) -> (StatusCode, Value) {
    let mut req = Request::builder().method(Method::GET).uri(uri);
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

fn strip(mut v: Value) -> Value {
    let o = v.as_object_mut().expect("object");
    o.remove("id");
    o.remove("display_name");
    o.remove("created_at");
    v
}

const READ: &[&str] = &["claims:read"];

#[sqlx::test(migrations = "../../migrations")]
async fn the_route_serves_the_callers_view_and_hides_the_link_from_an_outsider(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let outsider = named(&pool, "outsider").await;
    let human = named(&pool, "Talia Brennick").await;
    viewer_fixture::make_human_operator(&pool, human).await;
    let linked = named(&pool, "helper-bot").await;
    let unlinked = named(&pool, "helper-bot").await;
    link(&pool, linked, human).await;

    let uri = "/api/v1/agents/search?name=Helper-Bot";
    let (status, body) = get(&state, Some((outsider, READ)), uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = body["results"].as_array().expect("results");
    assert_eq!(results.len(), 2, "{body}");
    let ids: Vec<&str> = results.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert!(
        ids.contains(&linked.to_string().as_str()) && ids.contains(&unlinked.to_string().as_str())
    );
    assert_eq!(
        strip(results[0].clone()),
        strip(results[1].clone()),
        "an outsider cannot tell the linked agent from the unlinked one"
    );
    assert_eq!(results[0]["tier"], "exact");
    assert_eq!(results[0]["kind"], "unknown");
    assert!(results[0]["operator_human"].is_null());

    // The linked human is admitted by the D4 gate.
    let (status, body) = get(&state, Some((human, READ)), uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mine = body["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == linked.to_string())
        .expect("linked agent listed")
        .clone();
    assert_eq!(mine["operator_human"]["id"], human.to_string());
    assert_eq!(mine["operator_human"]["display_name"], "Talia Brennick");
    assert_eq!(mine["kind"], "llm_agent");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_route_validates_requires_auth_and_scope(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let caller = named(&pool, "caller").await;

    // Positive control: the route exists and answers (not `/:id`'s uuid 400).
    let (status, body) = get(
        &state,
        Some((caller, READ)),
        "/api/v1/agents/search?name=nobody-here",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["results"], serde_json::json!([]));
    assert_eq!(body["candidates_truncated"], false);

    let (status, _) = get(&state, Some((caller, READ)), "/api/v1/agents/search?name=a").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a 1-character name is refused"
    );
    let (status, _) = get(
        &state,
        Some((caller, READ)),
        "/api/v1/agents/search?name=ab&kind=wizard",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown kind is refused"
    );

    let (status, _) = get(&state, None, "/api/v1/agents/search?name=caller").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = get(
        &state,
        Some((caller, &["edges:read"])),
        "/api/v1/agents/search?name=caller",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "claims:read is required");

    // The existing `/api/v1/agents/:id` is unchanged.
    let (status, body) = get(
        &state,
        Some((caller, READ)),
        &format!("/api/v1/agents/{caller}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], caller.to_string());
}
