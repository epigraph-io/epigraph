#![cfg(feature = "db")]
mod common;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// Seed an agent row and one active agent_key row.
/// Returns (agent_id, key_id).
async fn seed_agent_with_key(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
    let agent_id = Uuid::new_v4();
    // Derive a unique 32-byte public key from agent_id
    let pk: Vec<u8> = agent_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();

    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");

    let key_id = Uuid::new_v4();
    // Use a distinct 32-byte public key for the key row
    let key_pk: Vec<u8> = key_id.as_bytes().iter().copied().cycle().take(32).collect();

    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'signing', 'active', now())",
    )
    .bind(key_id)
    .bind(agent_id)
    .bind(&key_pk)
    .execute(pool)
    .await
    .expect("seed agent_key");

    (agent_id, key_id)
}

/// Issue a JWT where agent_id claim == target_agent_id (caller IS the agent).
fn token_as_agent(agent_id: Uuid, scopes: &[&str]) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(), // client_id (distinct from agent_id)
            scopes.iter().map(|s| s.to_string()).collect(),
            "agent",
            None,
            Some(agent_id), // agent_id claim = target agent
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    token
}

// ---------------------------------------------------------------------------
// update_agent — 401
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn update_agent_no_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_id = Uuid::new_v4();
    let body = serde_json::json!({"display_name": "x"});

    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/agents/{fake_id}"))
        .json(&body)
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
// update_agent — 403 (wrong agent_id)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn update_agent_wrong_agent_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Seed the target agent
    let (agent_id, _) = seed_agent_with_key(&pool).await;

    // Token claims a DIFFERENT agent_id
    let different_agent_id = Uuid::new_v4();
    let token = token_as_agent(different_agent_id, &["agents:write"]);

    let body = serde_json::json!({"display_name": "new name"});
    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/agents/{agent_id}"))
        .bearer_auth(&token)
        .json(&body)
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
// update_agent — 200 (caller == target_agent_id)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn update_agent_self_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, _) = seed_agent_with_key(&pool).await;

    // Token: agent_id claim == target agent
    let token = token_as_agent(agent_id, &["agents:write"]);

    let body = serde_json::json!({"display_name": "updated name"});
    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/agents/{agent_id}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// update_agent — 200 (admin override)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn update_agent_admin_override_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, _) = seed_agent_with_key(&pool).await;

    // Admin token with a DIFFERENT agent_id (or None), but has claims:admin
    let token = common::test_bearer_token_with_scopes(&["agents:write", "claims:admin"]);

    let body = serde_json::json!({"display_name": "admin updated"});
    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/agents/{agent_id}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 for admin override, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// revoke_agent_key — 401
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_no_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_agent = Uuid::new_v4();
    let fake_key = Uuid::new_v4();
    let body = serde_json::json!({"reason": "test"});

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{fake_agent}/keys/{fake_key}/revoke"
        ))
        .json(&body)
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
// revoke_agent_key — 403 (wrong agent_id)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_wrong_agent_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, key_id) = seed_agent_with_key(&pool).await;

    // Token claims a different agent_id
    let different_agent_id = Uuid::new_v4();
    let token = token_as_agent(different_agent_id, &["agents:write"]);

    let body = serde_json::json!({"reason": "test revocation"});
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{agent_id}/keys/{key_id}/revoke"
        ))
        .bearer_auth(&token)
        .json(&body)
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
// revoke_agent_key — 200 (caller == target_agent_id)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_self_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, key_id) = seed_agent_with_key(&pool).await;

    // Token with agent_id == target agent
    let token = token_as_agent(agent_id, &["agents:write"]);

    let body = serde_json::json!({"reason": "self-revocation test"});
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{agent_id}/keys/{key_id}/revoke"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 for self-revocation, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// revoke_agent_key — 200 (admin override)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_admin_override_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, key_id) = seed_agent_with_key(&pool).await;

    // Admin token — different agent_id but has claims:admin
    let token = common::test_bearer_token_with_scopes(&["agents:write", "claims:admin"]);

    let body = serde_json::json!({"reason": "admin revocation test"});
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{agent_id}/keys/{key_id}/revoke"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 for admin revocation, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}
