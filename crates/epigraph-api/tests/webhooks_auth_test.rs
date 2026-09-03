//! Auth/authz regression guards for the webhook routes.
//!
//! # PR-10 changed what these tests have to do to reach the handler
//!
//! `register_webhook` now persists to `webhook_subscriptions` (migration 085),
//! whose `agent_id` is `NOT NULL REFERENCES agents(id)`. The two tests below
//! that register a real webhook used `common::test_bearer_token_with_scopes`,
//! which mints a **fresh random uuid** and uses it for `client_id`, `owner_id`
//! and `agent_id` alike — a principal that names no `agents` row. Against the
//! persisted handler that is a 23503 foreign-key violation and a 500, which
//! reads exactly like a regression and is not one.
//!
//! They now seed real agents (`common::seed_system_agent`) and mint tokens
//! bound to them (`common::mint_token_with_agent`). That also makes the
//! owner-vs-stranger distinction explicit: PR-10 compares ownership on
//! `agent_id`, and the old tokens differed in all three fields at once by
//! accident of construction, so the test could not have told you WHICH field
//! the handler was comparing.
#![cfg(feature = "db")]
mod common;

use sqlx::postgres::PgPoolOptions;

const VALID_SECRET: &str = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"; // 32 chars

fn webhook_body() -> serde_json::Value {
    serde_json::json!({
        "url": "https://example.com/webhook",
        "event_types": ["ClaimSubmitted"],
        "secret": VALID_SECRET
    })
}

// ---------------------------------------------------------------------------
// 401 — no token
// ---------------------------------------------------------------------------

/// POST /api/v1/webhooks without a Bearer token → 401
#[tokio::test(flavor = "multi_thread")]
async fn register_webhook_no_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/webhooks"))
        .json(&webhook_body())
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// DELETE /api/v1/webhooks/:id without a Bearer token → 401
#[tokio::test(flavor = "multi_thread")]
async fn delete_webhook_no_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_id = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/webhooks/{fake_id}"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// 403 — wrong scope on register
// ---------------------------------------------------------------------------

/// POST /api/v1/webhooks with token lacking `webhooks:write` → 403
#[tokio::test(flavor = "multi_thread")]
async fn register_webhook_missing_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Token with claims:read but NOT webhooks:write
    let token = common::test_bearer_token_with_scopes(&["claims:read"]);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/webhooks"))
        .bearer_auth(&token)
        .json(&webhook_body())
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// 200 register, then delete by another caller → 403
// ---------------------------------------------------------------------------

/// Owner registers a webhook; a different principal with webhooks:write tries to
/// delete it → 403.
#[tokio::test(flavor = "multi_thread")]
async fn delete_webhook_by_different_caller_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("pool");

    // Two REAL agents. `webhook_subscriptions.agent_id` is a foreign key, and
    // PR-10 compares ownership on that column, so "a different caller" must be
    // a different AGENT, not merely a different oauth client.
    let owner_agent = common::seed_system_agent(&pool).await;
    let other_agent = common::seed_system_agent(&pool).await;
    assert_ne!(owner_agent, other_agent);

    // Token for caller A (owner)
    let owner_token = common::mint_token_with_agent(&["webhooks:write"], owner_agent);
    // Token for caller B (different agent, also has webhooks:write)
    let other_token = common::mint_token_with_agent(&["webhooks:write"], other_agent);

    // Register webhook as caller A
    let reg_resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/webhooks"))
        .bearer_auth(&owner_token)
        .json(&webhook_body())
        .send()
        .await
        .unwrap();

    assert_eq!(
        reg_resp.status(),
        201,
        "register failed: {} — {}",
        reg_resp.status(),
        reg_resp.text().await.unwrap_or_default()
    );

    let sub: serde_json::Value = reg_resp.json().await.unwrap();
    let webhook_id = sub["id"].as_str().unwrap();

    // Caller B attempts to delete
    let del_resp = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/webhooks/{webhook_id}"))
        .bearer_auth(&other_token)
        .send()
        .await
        .unwrap();

    assert_eq!(
        del_resp.status(),
        403,
        "expected 403 for cross-owner delete, got {} — {}",
        del_resp.status(),
        del_resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// 204 register then delete by same caller
// ---------------------------------------------------------------------------

/// Owner registers a webhook; same principal deletes it → 204.
#[tokio::test(flavor = "multi_thread")]
async fn delete_webhook_by_owner_returns_204() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("pool");

    let agent = common::seed_system_agent(&pool).await;
    let token = common::mint_token_with_agent(&["webhooks:write"], agent);

    // Register
    let reg_resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/webhooks"))
        .bearer_auth(&token)
        .json(&webhook_body())
        .send()
        .await
        .unwrap();

    assert_eq!(
        reg_resp.status(),
        201,
        "register failed: {} — {}",
        reg_resp.status(),
        reg_resp.text().await.unwrap_or_default()
    );

    let sub: serde_json::Value = reg_resp.json().await.unwrap();
    let webhook_id = sub["id"].as_str().unwrap();

    // Same caller deletes
    let del_resp = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/webhooks/{webhook_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(
        del_resp.status(),
        204,
        "expected 204 for owner delete, got {} — {}",
        del_resp.status(),
        del_resp.text().await.unwrap_or_default()
    );
}
