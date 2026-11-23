#![cfg(feature = "db")]
//! `GET /api/v1/agents?public_key=<hex>` (backlog 8946be59): resolve ONE agent
//! by its exact Ed25519 public key in one request, instead of paging the whole
//! list, over the full router (bearer middleware, viewer extractor, `read_as`)
//! with both pools of the `AppState` on the APPLICATION ROLE.
//!
//! The fixture is PAGED: the target is older than a full page of newer agents,
//! so the unfiltered list's first page (newest first, at most 100) does not
//! hold it. That calibration is asserted, so the filtered answer cannot be
//! passing by reading the first page. On a server that ignores the parameter
//! the "filtered" request returns that unfiltered page, and every assertion on
//! `total` and on the single item fails. All names are invented.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool};

/// More newer agents than one page of the list holds (its limit is clamped to 100).
const NEWER_AGENTS: usize = 130;

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

async fn get(state: &AppState, caller: Uuid, uri: &str) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

/// Insert an agent with a distinct key, created `age_days` ago, carrying `labels`.
async fn insert_agent(pool: &PgPool, key: [u8; 32], age_days: i32, labels: &[&str]) -> Uuid {
    let labels: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, labels, created_at, updated_at) \
         VALUES ($1, 'paged-fixture', $2, now() - make_interval(days => $3), \
                 now() - make_interval(days => $3)) \
         RETURNING id",
    )
    .bind(key.as_slice())
    .bind(&labels)
    .bind(age_days)
    .fetch_one(pool)
    .await
    .expect("insert agent")
}

fn key_of(n: u32) -> [u8; 32] {
    let mut k = [0x7Eu8; 32];
    k[..4].copy_from_slice(&n.to_be_bytes());
    k
}

fn ids(body: &Value) -> Vec<String> {
    body["items"]
        .as_array()
        .unwrap_or_else(|| panic!("items array: {body}"))
        .iter()
        .map(|i| i["id"].as_str().expect("id").to_string())
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn public_key_filter_resolves_one_agent_past_the_first_page(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (caller, _) = viewer_fixture::seed_agent_with_group(&pool, "list-caller").await;

    // The target is the OLDEST row; a full page and more of newer agents sit
    // in front of it.
    let target_key = key_of(u32::MAX);
    let target = insert_agent(&pool, target_key, 30, &["software_agent"]).await;
    for n in 0..NEWER_AGENTS {
        insert_agent(&pool, key_of(n as u32), 0, &[]).await;
    }
    let target_hex = hex::encode(target_key);

    // CALIBRATION: the unfiltered first page does not reach the target, so
    // the filtered answer below cannot be the first page read verbatim.
    let (status, body) = get(&state, caller, "/api/v1/agents?limit=100").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body).len(), 100, "a full first page: {body}");
    assert!(
        !ids(&body).contains(&target.to_string()),
        "CALIBRATION: the target must lie past the first page"
    );
    assert!(body["total"].as_i64().expect("total") > 100, "{body}");

    // ONE request finds it, and only it.
    let (status, body) = get(
        &state,
        caller,
        &format!("/api/v1/agents?public_key={target_hex}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body), vec![target.to_string()], "{body}");
    assert_eq!(body["total"], 1, "{body}");
    assert_eq!(body["items"][0]["public_key"], target_hex, "{body}");

    // Hex case does not matter (the host compares case-insensitively).
    let (status, body) = get(
        &state,
        caller,
        &format!(
            "/api/v1/agents?public_key={}",
            target_hex.to_ascii_uppercase()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body), vec![target.to_string()], "{body}");

    // `label` is ANDed with the key, never dropped.
    let (status, body) = get(
        &state,
        caller,
        &format!("/api/v1/agents?public_key={target_hex}&label=software_agent"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body), vec![target.to_string()], "{body}");
    let (status, body) = get(
        &state,
        caller,
        &format!("/api/v1/agents?public_key={target_hex}&label=person"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        ids(&body).is_empty(),
        "label must narrow the key match: {body}"
    );
    assert_eq!(body["total"], 0, "{body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn public_key_filter_answers_absent_and_refuses_a_malformed_key(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (caller, _) = viewer_fixture::seed_agent_with_group(&pool, "list-caller").await;
    for n in 0..5 {
        insert_agent(&pool, key_of(n), 0, &[]).await;
    }

    // A well-formed key nobody holds: an empty answer, not the list.
    let unknown = hex::encode([0x11u8; 32]);
    let (status, body) = get(
        &state,
        caller,
        &format!("/api/v1/agents?public_key={unknown}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        ids(&body).is_empty(),
        "an unknown key lists nothing: {body}"
    );
    assert_eq!(body["total"], 0, "{body}");

    // A malformed key is the caller's error, never "absent".
    for bad in ["abc", "zz".repeat(32).as_str(), "00".repeat(33).as_str()] {
        let (status, body) = get(&state, caller, &format!("/api/v1/agents?public_key={bad}")).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "malformed key {bad:?} must be a 400: {body}"
        );
    }
}
