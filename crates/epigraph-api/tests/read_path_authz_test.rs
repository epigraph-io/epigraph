#![cfg(feature = "db")]
//! A3 read-path authorization: a private claim must be redacted for anyone
//! who is not the authenticated owner — and the spoofable ?agent_id wire
//! value must be ignored. Tests go through spawn_app → build_app_for_tests →
//! create_router (the production middleware layering); a handler-unit test
//! that hand-passes auth_ctx cannot catch this bug (spec §7.3).
mod common;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool_and_app() -> (sqlx::PgPool, std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, shutdown) = common::spawn_app(&url).await;
    (pool, addr, shutdown)
}

/// Extract the `content` field from a get_claim JSON response.
fn content_of(v: &serde_json::Value) -> String {
    v.get("content")
        .and_then(|c| c.as_str())
        .unwrap_or("<missing>")
        .to_string()
}

/// DISCRIMINATING REGRESSION: no token + ?agent_id=<owner_uuid> (spoof) must
/// redact. Pre-fix: handler trusts params.agent_id == owner → returns full
/// content. Post-fix: requester is None (no auth) → Redacted.
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_no_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "TOP SECRET private claim body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}?agent_id={owner}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "private claim still returns 200, just redacted");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        content_of(&body),
        "[REDACTED]",
        "no-token spoof of owner agent_id must NOT reveal private content"
    );
}

/// Stranger token + spoofed ?agent_id=<owner> → still redacted.
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_stranger_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "TOP SECRET private claim body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let stranger_token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}?agent_id={owner}"))
        .bearer_auth(&stranger_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(content_of(&body), "[REDACTED]");
}

/// Owner token, even with a RANDOM spoofed ?agent_id, sees full content —
/// proving the decision uses the token's agent_id, not the wire param.
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_owner_token_ignores_wire_param_and_sees_full() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let claim_id =
        common::seed_claim_with_agent(&pool, "TOP SECRET private claim body", owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let random = Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}?agent_id={random}"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        content_of(&body),
        "TOP SECRET private claim body",
        "owner token must see full content even with a spoofed wire agent_id"
    );
}

/// Non-regression: anonymous GET of a public / ownership-less claim returns
/// 200 + full content (optional-bearer did not turn public reads into 401s).
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_anonymous_public_claim_is_full() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let claim_id = common::seed_claim(&pool, "public ownership-less claim body").await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(content_of(&body), "public ownership-less claim body");
}

/// Invalid Bearer token on a public read → 401 (spec §7.4 default).
#[tokio::test(flavor = "multi_thread")]
async fn get_claim_invalid_token_is_401() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let claim_id = common::seed_claim(&pool, "public claim for invalid-token test").await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims/{claim_id}"))
        .bearer_auth("not-a-real-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "present-but-invalid Bearer must 401 even on a public read");
}

/// list_claims (GET /claims) must redact a private claim's content for a
/// no-token caller spoofing ?agent_id=<owner>. We constrain the page with
/// `search` so the freshly-seeded claim is the only match, avoiding paging
/// flakiness on a shared test DB.
#[tokio::test(flavor = "multi_thread")]
async fn list_claims_no_token_spoofed_owner_is_redacted() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let owner = Uuid::new_v4();
    let secret = format!("LIST private secret body {}", Uuid::new_v4());
    let claim_id = common::seed_claim_with_agent(&pool, &secret, owner).await;
    common::seed_private_ownership(&pool, claim_id, owner).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/claims"))
        .query(&[
            ("limit", "100"),
            ("agent_id", owner.to_string().as_str()),
            ("search", secret.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let items = body.get("items").and_then(|i| i.as_array()).expect("items array");
    let found = items
        .iter()
        .find(|it| it.get("id").and_then(|v| v.as_str()) == Some(claim_id.to_string().as_str()))
        .expect("seeded claim present in first page");
    assert_eq!(
        content_of(found),
        "[REDACTED]",
        "no-token spoof must not reveal private content in list_claims"
    );
}
