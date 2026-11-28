#![cfg(feature = "db")]
//! The political-monitoring routes are gone from the kernel router (backlog
//! bd13e0e0, closing fc12975c).
//!
//! The product (propaganda techniques, coalitions, the inflation index,
//! position timelines, talking-point genealogy, originated claims, agent
//! comparison and two stub endpoints) was mounted unconditionally in the kernel
//! API. Two of its tables, `propaganda_techniques` and `coalitions`, are
//! created by no migration, so on a database built from `migrations/` the
//! technique and coalition routes answered 500. The product was deleted from
//! the kernel; the one route a kernel client reads,
//! `GET /api/v1/agents/:id/epistemic-profile`, moved to `routes/agents.rs`
//! (backlog a1dd9225) and is still served.
//!
//! Each arm sends the request with a `claims:read` + `claims:write` token
//! bound to a real agent and asserts it is not routed (404). The kept profile
//! route answering 200 to the same token is the control: it shows the 404s are
//! the router's answer, not an auth refusal. On the old router every listed
//! route was mounted and answered something other than 404 (200, or 500 for
//! the two tables no migration creates).

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

const READER_WRITER: &[&str] = &["claims:read", "claims:write"];

async fn send(
    router: &axum::Router,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> StatusCode {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match body {
        Some(v) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    router
        .clone()
        .oneshot(req.body(body).expect("request"))
        .await
        .expect("router")
        .status()
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_political_routes_are_not_routed(pool: sqlx::PgPool) {
    let url = viewer_fixture::database_url_for(&pool).await;
    let router = epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds for tests");
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "political-removed").await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "a claim to ask about").await;
    let token = common::mint_token_with_agent(READER_WRITER, agent);

    // Why the technique and coalition routes could never work: no migration
    // creates their tables.
    let missing: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT to_regclass('public.propaganda_techniques')::text, \
                to_regclass('public.coalitions')::text",
    )
    .fetch_one(&pool)
    .await
    .expect("probe the two tables");
    assert_eq!(
        missing,
        (None, None),
        "CALIBRATION: a database migrated from empty has neither table"
    );

    // Control: the kept route answers this token.
    let kept = send(
        &router,
        &token,
        Method::GET,
        &format!("/api/v1/agents/{agent}/epistemic-profile"),
        None,
    )
    .await;
    assert_eq!(
        kept,
        StatusCode::OK,
        "CONTROL: the epistemic profile stays mounted (now in routes/agents.rs) and \
         serves this token, so a 404 below is the router's answer, not an auth refusal"
    );

    let technique = serde_json::json!({ "name": "t", "category": "c" });
    let coalition = serde_json::json!({ "name": "c" });
    let removed: Vec<(Method, String, Option<serde_json::Value>)> = vec![
        (Method::GET, "/api/v1/propaganda-techniques".into(), None),
        (
            Method::POST,
            "/api/v1/propaganda-techniques".into(),
            Some(technique),
        ),
        (Method::GET, "/api/v1/coalitions".into(), None),
        (Method::POST, "/api/v1/coalitions".into(), Some(coalition)),
        (
            Method::GET,
            format!("/api/v1/claims/{claim}/techniques"),
            None,
        ),
        (
            Method::GET,
            format!("/api/v1/claims/{claim}/genealogy"),
            None,
        ),
        (
            Method::GET,
            format!("/api/v1/agents/{agent}/position-timeline"),
            None,
        ),
        (
            Method::GET,
            format!("/api/v1/agents/{agent}/originated-claims"),
            None,
        ),
        (
            Method::GET,
            format!("/api/v1/agents/{agent}/inflation-index"),
            None,
        ),
        (
            Method::GET,
            "/api/v1/inflation-index/leaderboard".into(),
            None,
        ),
        (Method::GET, "/api/v1/counter-narrative-gaps".into(), None),
        (Method::GET, "/api/v1/mirror-narratives".into(), None),
    ];
    let mut routed = Vec::new();
    for (method, uri, body) in removed {
        let status = send(&router, &token, method.clone(), &uri, body).await;
        if status != StatusCode::NOT_FOUND {
            routed.push(format!("{method} {uri} -> {status}"));
        }
    }
    assert!(
        routed.is_empty(),
        "the political routes are removed and must answer 404; still routed: {routed:#?}"
    );

    // `/api/v1/agents/compare` had a static segment beside `/api/v1/agents/:id`;
    // without it the path falls to the agent lookup, whose `:id` is not a UUID.
    // Either way it no longer serves a comparison.
    let compare = send(
        &router,
        &token,
        Method::GET,
        &format!("/api/v1/agents/compare?ids={agent},{}", Uuid::new_v4()),
        None,
    )
    .await;
    assert!(
        compare == StatusCode::NOT_FOUND || compare == StatusCode::BAD_REQUEST,
        "GET /api/v1/agents/compare is removed, got {compare}"
    );
}
