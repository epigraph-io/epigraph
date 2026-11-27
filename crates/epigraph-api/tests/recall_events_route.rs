#![cfg(feature = "db")]
//! `GET /api/v1/recall-events` (backlog 2cf7b6a1): the caller's own recall
//! history, and nobody else's.
//!
//! Every request goes through the full router (`create_router`) with a real
//! bearer, so the route registration, the bearer middleware, the scope check
//! and the viewer extractor are all on the path. Both pools of the `AppState`
//! are the APPLICATION ROLE, as in production: on the superuser pool
//! `#[sqlx::test]` hands out, row security never refuses anything, and "B does
//! not see A's rows" would rest on the repo filter alone (the repo test
//! `recall_event_test.rs::list_own_never_returns_another_agents_rows` pins
//! that half on its own).
//!
//! Every refusal is paired with a positive control in the same test: before
//! the route exists the router answers 404 to everything, and a leak test
//! without its control would pass on a tree with no route at all.

#[allow(dead_code)]
mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{NewRecallEvent, RecallEventRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// An `AppState` whose scoped and raw pools are both the application role.
async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = viewer_fixture::database_url_for(pool).await;
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
        "CALIBRATION: the scoped pool must not be privileged, or row security admits every row"
    );
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

/// Log one recall for `agent`, owned by its personal group, as production
/// writes it. Written on the harness (superuser) pool.
async fn log(pool: &PgPool, agent: Uuid, query: &str, ids: Vec<Uuid>) -> Uuid {
    let group = epigraph_db::ClaimRepository::personal_group_of_pool(pool, agent)
        .await
        .expect("resolve the author's personal group");
    RecallEventRepository::log(
        pool,
        NewRecallEvent {
            id: Uuid::new_v4(),
            agent_id: Some(agent),
            tool: "recall".to_string(),
            query_text: query.to_string(),
            query_pgvector: Some("[0.25,0.5]".to_string()),
            params: serde_json::json!({"limit": 10}),
            returned_claim_ids: ids,
            owner_group_id: Some(group),
        },
    )
    .await
    .expect("log a recall")
}

/// `GET uri` through the full router, with `token` as the bearer when given.
async fn get_with(state: &AppState, token: Option<&str>, uri: &str) -> (StatusCode, Value) {
    let mut req = Request::builder().method(Method::GET).uri(uri);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = create_router(state.clone())
        .oneshot(req.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

async fn get_as(state: &AppState, caller: Uuid, uri: &str) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    get_with(state, Some(&token), uri).await
}

fn ids_of(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("no items in {page}"))
        .iter()
        .map(|i| i["id"].as_str().expect("item id").to_string())
        .collect()
}

/// Agent B's token never reads agent A's rows, whatever it asks for; A's own
/// read (the positive control) does see them, with the MCP tool's fields.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_never_reads_another_agents_recall_history(pool: PgPool) {
    let (a, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-a").await;
    let (b, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-b").await;
    let shared = Uuid::new_v4();
    let a_row = log(&pool, a, "A's secret query", vec![shared]).await;
    let b_row = log(&pool, b, "B's own query", vec![shared]).await;
    let state = app_role_state(&pool).await;

    // Positive control: A reads its own row, with every MCP field.
    let (status, page) = get_as(&state, a, "/api/v1/recall-events").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(ids_of(&page), vec![a_row.to_string()]);
    let item = &page["items"][0];
    assert_eq!(item["agent_id"], a.to_string());
    assert_eq!(item["tool"], "recall");
    assert_eq!(item["query_text"], "A's secret query");
    assert_eq!(item["returned_claim_ids"][0], shared.to_string());
    assert_eq!(item["params"]["limit"], 10);
    assert_eq!(
        item["query_embedding_hash"].as_str().map(str::len),
        Some(64),
        "hex BLAKE3 of the query vector: {item}"
    );
    assert!(item["created_at"].as_str().is_some());
    assert!(page["next_cursor"].is_null());

    // B, with every crafted parameter that could aim at A's row.
    let a_micros: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM created_at) * 1000000)::bigint FROM recall_events \
         WHERE id = $1",
    )
    .bind(a_row)
    .fetch_one(&pool)
    .await
    .unwrap();
    let crafted = [
        "/api/v1/recall-events".to_string(),
        format!("/api/v1/recall-events?claim_id={shared}"),
        "/api/v1/recall-events?since=2000-01-01T00:00:00Z&until=2999-01-01T00:00:00Z".to_string(),
        format!(
            "/api/v1/recall-events?after=k1.{}.{}",
            a_micros + 1_000_000,
            Uuid::max().simple()
        ),
        format!("/api/v1/recall-events?limit=200&agent_id={b}"),
        format!("/api/v1/recall-events?owner={a}&agent={a}&principal={a}"),
    ];
    for uri in &crafted {
        let (status, page) = get_as(&state, b, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {page}");
        assert_eq!(
            ids_of(&page),
            vec![b_row.to_string()],
            "{uri}: B reads exactly its own row"
        );
        assert!(
            !page.to_string().contains("A's secret query"),
            "{uri}: A's query text leaked"
        );
    }

    // Naming A outright is refused, not silently answered with B's rows.
    let (status, body) = get_as(&state, b, &format!("/api/v1/recall-events?agent_id={a}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(!body.to_string().contains("A's secret query"));
}

/// No bearer is a 401; a bearer without `claims:read` is a 403. The positive
/// control is the same caller with the scope.
#[sqlx::test(migrations = "../../migrations")]
async fn the_route_requires_a_bearer_with_claims_read(pool: PgPool) {
    let (a, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-auth").await;
    let row = log(&pool, a, "a query", vec![]).await;
    let state = app_role_state(&pool).await;

    let (status, body) = get_with(&state, None, "/api/v1/recall-events").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(!body.to_string().contains("a query"));

    let unscoped = common::mint_token_with_agent(&["edges:write"], a);
    let (status, body) = get_with(&state, Some(&unscoped), "/api/v1/recall-events").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, page) = get_as(&state, a, "/api/v1/recall-events").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(ids_of(&page), vec![row.to_string()]);
}

/// Pages: newest first, `limit` rows each, `next_cursor` passed back as
/// `after` until it is `null`, every row exactly once.
#[sqlx::test(migrations = "../../migrations")]
async fn pages_walk_the_history_newest_first_and_end_with_a_null_cursor(pool: PgPool) {
    let (a, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-pages").await;
    let mut logged = Vec::new();
    for i in 0..5 {
        let id = log(&pool, a, &format!("query {i}"), vec![]).await;
        // Distinct, increasing times, so "newest first" is a checkable order.
        sqlx::query(
            "UPDATE recall_events SET created_at = now() - make_interval(mins => $2) \
             WHERE id = $1",
        )
        .bind(id)
        .bind(10 - i)
        .execute(&pool)
        .await
        .unwrap();
        logged.push(id.to_string());
    }
    logged.reverse();
    let state = app_role_state(&pool).await;

    let mut seen = Vec::new();
    let mut uri = "/api/v1/recall-events?limit=2".to_string();
    let mut pages = 0;
    loop {
        let (status, page) = get_as(&state, a, &uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {page}");
        pages += 1;
        let ids = ids_of(&page);
        assert!(ids.len() <= 2, "{uri}: {ids:?}");
        seen.extend(ids);
        match page["next_cursor"].as_str() {
            Some(c) => uri = format!("/api/v1/recall-events?limit=2&after={c}"),
            None => break,
        }
        assert!(pages < 10, "the cursor never ended");
    }
    assert_eq!(seen, logged, "every row once, newest first");
    assert_eq!(
        pages, 3,
        "2 + 2 + 1: the last page is short and ends the walk"
    );

    let (status, body) = get_as(&state, a, "/api/v1/recall-events?after=not-a-cursor").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = get_as(&state, a, "/api/v1/recall-events?since=yesterday").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
