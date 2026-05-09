#![cfg(feature = "db")]
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
mod common;

// ── negative / error-path tests ──────────────────────────────────────────────

/// No Authorization header → 401.
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_id = Uuid::new_v4();
    let body = serde_json::json!({
        "parent_id": fake_id,
        "content": "updated step",
        "edge_type": "supersedes",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{fake_id}/evolve"
        ))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 without token; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Token with only `graph:read` (no `claims:write`) → 403.
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_with_read_only_token_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["graph:read"]);
    let fake_id = Uuid::new_v4();
    let body = serde_json::json!({
        "parent_id": fake_id,
        "content": "updated step",
        "edge_type": "supersedes",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{fake_id}/evolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 for graph:read-only token; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// `parent_id` in JSON body differs from `{id}` in path → 400.
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_mismatched_parent_id_returns_400() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let path_id = Uuid::new_v4();
    let body_id = Uuid::new_v4(); // deliberately different
    let body = serde_json::json!({
        "parent_id": body_id,
        "content": "updated step",
        "edge_type": "supersedes",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{path_id}/evolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        400,
        "expected 400 for path/body parent_id mismatch; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Valid `claims:write` token but parent claim does not exist → 404.
#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_nonexistent_parent_returns_404() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let nonexistent = Uuid::new_v4();
    let body = serde_json::json!({
        "parent_id": nonexistent,
        "content": "updated step",
        "edge_type": "supersedes",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{nonexistent}/evolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        404,
        "expected 404 for non-existent parent; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn evolve_step_supersedes_creates_new_claim_and_edge() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Seed an agent so the new claim's agent_id FK is satisfied.
    let agent_id = common::seed_system_agent(&pool).await;

    let parent = common::seed_claim(&pool, "parent step").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['workflow_step']::text[] WHERE id = $1")
        .bind(parent)
        .execute(&pool)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Issue a token bound to the seeded agent so agent_id FK on the new claim passes.
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _) = cfg
        .issue_access_token(
            agent_id,
            vec!["claims:write".into()],
            "service",
            None,
            None,
            chrono::Duration::minutes(60),
        )
        .expect("test JWT");

    let body = serde_json::json!({
        "parent_id": parent,
        "content": "improved step",
        "edge_type": "supersedes",
        "reason": "tightened wording",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/workflows/steps/{parent}/evolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "body={text}");

    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let new_id: Uuid = json["claim_id"].as_str().unwrap().parse().unwrap();

    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!parent_current);

    let edge_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'supersedes'"
    ).bind(new_id).bind(parent).fetch_one(&pool).await.unwrap();
    assert_eq!(edge_count, 1);
}
