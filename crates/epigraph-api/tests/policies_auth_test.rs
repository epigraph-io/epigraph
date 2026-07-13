#![cfg(feature = "db")]
mod common;

use uuid::Uuid;

// ── record_outcome ────────────────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn record_outcome_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let claim_id = Uuid::new_v4();
    let body = serde_json::json!({ "supports": true, "strength": 0.1 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/{claim_id}/outcome"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:write token (insufficient) → 403.
#[tokio::test(flavor = "multi_thread")]
async fn record_outcome_with_wrong_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let claim_id = Uuid::new_v4();
    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let body = serde_json::json!({ "supports": true, "strength": 0.1 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/{claim_id}/outcome"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 Forbidden; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:admin token + valid policy claim → 200.
#[tokio::test(flavor = "multi_thread")]
async fn record_outcome_with_admin_scope_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Seed a policy:active claim so the UPDATE WHERE finds a row.
    let claim_id = common::seed_claim_with_labels(
        &pool,
        "test network policy record_outcome",
        &["policy:active", "policy:network"],
    )
    .await;

    let token = common::test_bearer_token_with_scopes(&["claims:admin"]);
    let body = serde_json::json!({ "supports": true, "strength": 0.05 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/{claim_id}/outcome"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ── decay_sweep ───────────────────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn decay_sweep_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/decay-sweep"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:admin token → 200.
#[tokio::test(flavor = "multi_thread")]
async fn decay_sweep_with_admin_scope_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:admin"]);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/decay-sweep"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ── create_challenge ──────────────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn create_challenge_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let body = serde_json::json!({ "host": "example.com", "port": 443 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policy-challenges"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:write token → 200 (create_challenge needs claims:write).
#[tokio::test(flavor = "multi_thread")]
async fn create_challenge_with_claims_write_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let body = serde_json::json!({ "host": "example.com", "port": 443 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policy-challenges"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ── resolve_challenge ─────────────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn resolve_challenge_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let challenge_id = Uuid::new_v4();
    let body = serde_json::json!({ "approved": true });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/policy-challenges/{challenge_id}/resolve"
        ))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:write token (insufficient) → 403.
#[tokio::test(flavor = "multi_thread")]
async fn resolve_challenge_with_wrong_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let challenge_id = Uuid::new_v4();
    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let body = serde_json::json!({ "approved": true });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/policy-challenges/{challenge_id}/resolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 Forbidden; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:admin token + valid challenge claim → 200.
#[tokio::test(flavor = "multi_thread")]
async fn resolve_challenge_with_admin_scope_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Seed a challenge claim directly.
    let challenge_id = common::seed_claim_with_labels(
        &pool,
        "test policy challenge resolve_challenge",
        &["policy", "policy:challenge"],
    )
    .await;
    // Set status=pending in properties.
    sqlx::query(
        "UPDATE claims SET properties = '{\"host\":\"test.com\",\"port\":443,\"status\":\"pending\"}'::jsonb WHERE id = $1",
    )
    .bind(challenge_id)
    .execute(&pool)
    .await
    .unwrap();

    let token = common::test_bearer_token_with_scopes(&["claims:admin"]);
    let body = serde_json::json!({ "approved": true });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/policy-challenges/{challenge_id}/resolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ── decide_match_candidate ──────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn decide_candidate_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let candidate_id = Uuid::new_v4();
    let body = serde_json::json!({ "verdict": "reject" });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/match_candidates/{candidate_id}/decide"
        ))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}
