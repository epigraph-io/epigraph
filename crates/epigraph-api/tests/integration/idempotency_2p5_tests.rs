//! Plan 2.5 — Server-side ingestion idempotency (TDD)
//!
//! These tests drive durable, cross-process idempotency for agent
//! registration and `POST /api/v1/submit/packet` claim insertion, so the
//! per-PR-process commit ingester can find-or-create repo/PR/commit nodes and
//! author/orchestrator agents without 500s on run 2+.
//!
//! # Running
//!
//! ```bash
//! DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
//!   cargo test -p epigraph-api --test idempotency_2p5_tests
//! ```

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use epigraph_api::middleware::SignatureVerificationState;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_core::Agent;
use epigraph_db::{AgentRepository, PgPool};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// Create an agent with a fixed (deterministic) 32-byte public key so two
/// calls collide on `agents_public_key_unique`.
fn fixed_agent(seed: u8, display_name: &str) -> Agent {
    let key = [seed; 32];
    Agent::new(key, Some(display_name.to_string()))
}

/// `create_or_get` is idempotent on `public_key`: the first call creates the
/// agent, the second returns the same row without inserting a duplicate.
#[sqlx::test(migrations = "../../migrations")]
async fn agent_create_or_get_is_idempotent_on_public_key(pool: PgPool) {
    let agent = fixed_agent(7, "idem-agent");

    let (first, created_first) = AgentRepository::create_or_get(&pool, &agent)
        .await
        .expect("first create_or_get should succeed");
    assert!(created_first, "first call must report a fresh creation");

    let (second, created_second) = AgentRepository::create_or_get(&pool, &agent)
        .await
        .expect("second create_or_get should succeed");
    assert!(!created_second, "second call must report find (not create)");

    assert_eq!(
        first.id, second.id,
        "both calls must resolve to the same agent id"
    );

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(agent.public_key.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count query should succeed");
    assert_eq!(count, 1, "exactly one agents row for the fixed public key");
}

// =============================================================================
// HTTP test harness (each integration file is its own `[[test]]` crate, so
// `create_test_router` from `submit_persistence_tests.rs` is not importable;
// replicate the minimal pieces here).
// =============================================================================

/// Build a router on `pool` with signature verification bypassed, mirroring
/// `submit_persistence_tests::create_test_router`.
fn create_test_router(pool: PgPool) -> Router {
    let config = ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
    };
    let signature_state = SignatureVerificationState::with_bypass_routes(vec!["/".to_string()]);
    let state = AppState::with_db_and_signature_state(pool, config, signature_state);
    create_router(state)
}

/// Mint a Bearer token carrying `agents:write` so it clears the `create_agent`
/// scope gate (the generic `submit` token lacks `agents:write` → 403). The
/// secret matches `default_jwt_config()`'s fallback so no env setup is needed.
fn agents_write_bearer_token() -> String {
    use epigraph_api::oauth::JwtConfig;
    let jwt_config = JwtConfig::from_secret(b"epigraph-dev-secret-change-in-production!!");
    let (token, _) = jwt_config
        .issue_access_token(
            uuid::Uuid::new_v4(),
            vec!["agents:write".to_string(), "agents:read".to_string()],
            "service",
            None,
            None,
            chrono::Duration::seconds(300),
        )
        .expect("issue_access_token must succeed for tests");
    token
}

/// POST a JSON body to `uri` through `router`, returning (status, body string).
async fn post_json(router: &Router, uri: &str, body: serde_json::Value) -> (StatusCode, String) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", agents_write_bearer_token()),
        )
        .body(Body::from(body.to_string()))
        .expect("Failed to build request");

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();
    let body_string = String::from_utf8(body_bytes.to_vec()).expect("Body is not valid UTF-8");
    (status, body_string)
}

/// `POST /api/v1/agents` is find-or-create on `public_key`: re-POSTing the same
/// key returns the same agent id with a success status (not 400), and leaves
/// exactly one `agents` row. Before the fix the second POST hit
/// `agents_public_key_unique` → `DbError::DuplicateKey` → 400.
#[sqlx::test(migrations = "../../migrations")]
async fn create_agent_is_idempotent_on_public_key(pool: PgPool) {
    let router = create_test_router(pool.clone());
    // 64 hex chars == 32-byte Ed25519 public key, fixed so both POSTs collide.
    let public_key_hex = "ab".repeat(32);
    let request_body = serde_json::json!({
        "public_key": public_key_hex,
        "display_name": "idem-http-agent",
    });

    let (status_1, body_1) = post_json(&router, "/api/v1/agents", request_body.clone()).await;
    assert!(
        status_1.is_success(),
        "first POST /api/v1/agents should succeed, got {status_1}: {body_1}"
    );
    let json_1: serde_json::Value =
        serde_json::from_str(&body_1).expect("first response should be JSON");
    let id_1 = json_1["id"].as_str().expect("first response must carry id");

    let (status_2, body_2) = post_json(&router, "/api/v1/agents", request_body).await;
    assert!(
        status_2.is_success(),
        "second POST with the same public_key must succeed (not 400), got {status_2}: {body_2}"
    );
    let json_2: serde_json::Value =
        serde_json::from_str(&body_2).expect("second response should be JSON");
    let id_2 = json_2["id"]
        .as_str()
        .expect("second response must carry id");

    assert_eq!(
        id_1, id_2,
        "both POSTs must resolve to the same agent id (find-or-create)"
    );

    let key_bytes = hex::decode(&public_key_hex).expect("public key hex should decode");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(key_bytes.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count query should succeed");
    assert_eq!(count, 1, "exactly one agents row for the fixed public key");
}
