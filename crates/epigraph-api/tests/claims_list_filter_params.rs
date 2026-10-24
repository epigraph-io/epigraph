//! The claim-listing endpoints refuse filters they cannot honour instead of
//! silently dropping them.
//!
//! `GET /claims` deserialises `PaginationParams` (limit, offset, search,
//! agent_id, group_id) without `deny_unknown_fields`, so `?created_after=`,
//! `?label=` or `?date=` were dropped and the response was the unfiltered
//! newest-first page with the whole visible corpus as `total` — an answer that
//! looks filtered and is not. `GET /api/v1/claims` honours the time and truth
//! filters but has no label predicate, so `?labels=` was dropped there too.
//!
//! Only the filters a handler cannot honour are refused. Unknown keys in
//! general stay accepted (a blanket `deny_unknown_fields` would break callers
//! sending harmless extras), and `agent_id` on `/claims` stays accepted and
//! ignored for wire compatibility.
#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod common;

async fn get(addr: &std::net::SocketAddr, token: &str, path: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn app_and_token(
    scopes: &[&str],
) -> (
    sqlx::PgPool,
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    String,
    Uuid,
) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, shutdown) = common::spawn_app(&url).await;
    let (token, client) = common::test_bearer_token_with_seeded_client(&pool, scopes).await;
    (pool, addr, shutdown, token, client)
}

/// Legacy `GET /claims`: each of these used to answer 200 with an unfiltered
/// page. The key is matched after trimming a trailing `[]` and ignoring ASCII
/// case, so `label[]=` and `Label=` are refused like `label=`.
#[tokio::test(flavor = "multi_thread")]
async fn legacy_claims_refuses_filters_it_cannot_honor() {
    let (_pool, addr, _shutdown, token, _) = app_and_token(&["claims:read"]).await;

    for (path, field) in [
        (
            "/claims?created_after=2999-01-01T00:00:00Z",
            "created_after",
        ),
        ("/claims?label=backlog&limit=5", "label"),
        ("/claims?limit=5&date=2026-09-07", "date"),
        ("/claims?is_current=false", "is_current"),
        ("/claims?labels[]=backlog", "labels"),
        ("/claims?Label=backlog", "label"),
    ] {
        let (status, body) = get(&addr, &token, path).await;
        assert_eq!(
            status, 400,
            "GET {path} must refuse a filter it cannot honour, not return an unfiltered \
             page; got {status} body={body}"
        );
        assert_eq!(body["error"], "ValidationError", "{path}: {body}");
        assert_eq!(body["details"]["field"], field, "{path}: {body}");
        let reason = body["details"]["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("/api/v1/claims"),
            "{path}: the refusal must name the endpoint that honours it; got {reason}"
        );
    }
}

/// `GET /api/v1/claims` has no label predicate: refuse rather than drop.
#[tokio::test(flavor = "multi_thread")]
async fn v1_claims_refuses_label_filters_it_cannot_honor() {
    let (_pool, addr, _shutdown, token, _) = app_and_token(&["claims:read"]).await;

    for (path, field) in [
        ("/api/v1/claims?labels=backlog", "labels"),
        ("/api/v1/claims?limit=5&label=backlog", "label"),
        ("/api/v1/claims?tags[]=backlog", "tags"),
    ] {
        let (status, body) = get(&addr, &token, path).await;
        assert_eq!(
            status, 400,
            "GET {path} must refuse a label filter it cannot honour; got {status} body={body}"
        );
        assert_eq!(body["error"], "ValidationError", "{path}: {body}");
        assert_eq!(body["details"]["field"], field, "{path}: {body}");
        let reason = body["details"]["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("/api/v1/claims/by-labels"),
            "{path}: the refusal must point at /api/v1/claims/by-labels; got {reason}"
        );
    }
}

/// Controls: the parameters each endpoint DOES accept still answer 200, so the
/// refusals above are a targeted list, not a blanket deny. And the time filter
/// `/api/v1/claims` keeps is really applied, calibrated in both directions on a
/// claim this token's viewer can see.
#[tokio::test(flavor = "multi_thread")]
async fn claim_listings_still_accept_the_parameters_they_honor() {
    let (pool, addr, _shutdown, token, client) = app_and_token(&["claims:read"]).await;
    common::seed_claim_writable_by_client(
        &pool,
        &format!("filter params visible claim {}", Uuid::new_v4()),
        client,
    )
    .await;

    let agent = Uuid::new_v4();
    for path in [
        format!("/claims?agent_id={agent}&limit=5"),
        "/claims?search=zzq-filter-params&limit=5&offset=0".to_string(),
        "/claims?limit=5&unrelated_extra=1".to_string(),
        "/api/v1/claims?created_after=2999-01-01T00:00:00Z&limit=5".to_string(),
        "/api/v1/claims?is_current=true&truth_min=0.1&sort_by=created_at&limit=5".to_string(),
    ] {
        let (status, body) = get(&addr, &token, &path).await;
        assert_eq!(status, 200, "GET {path} must still succeed; body={body}");
    }

    let total = |body: &Value| body["total"].as_i64().unwrap_or(-1);
    let (_, unfiltered) = get(&addr, &token, "/api/v1/claims?limit=5").await;
    assert!(
        total(&unfiltered) >= 1,
        "CALIBRATION: the seeded public claim is visible unfiltered: {unfiltered}"
    );
    let (_, since_1970) = get(
        &addr,
        &token,
        "/api/v1/claims?created_after=1970-01-01T00:00:00Z&limit=5",
    )
    .await;
    assert!(
        total(&since_1970) >= 1,
        "CALIBRATION: a created_after every claim satisfies keeps it: {since_1970}"
    );
    let (_, since_2999) = get(
        &addr,
        &token,
        "/api/v1/claims?created_after=2999-01-01T00:00:00Z&limit=5",
    )
    .await;
    assert_eq!(
        total(&since_2999),
        0,
        "created_after is honoured on /api/v1/claims: nothing is created after 2999: \
         {since_2999}"
    );
}
