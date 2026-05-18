//! POST /api/v1/claims must embed the claim inline post-commit, best-effort.
//! Regression guard for backlog item 92eedc8b (embedding gap).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::{create_router, state::AppState, ApiConfig};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Mint a test Bearer token valid against the dev JWT secret (matches the
/// fallback used by `default_jwt_config()` in state.rs when
/// `EPIGRAPH_JWT_SECRET` is not set). Same pattern as
/// `integration/submit_persistence_tests.rs::test_bearer_token`.
fn test_bearer_token() -> String {
    use epigraph_api::oauth::JwtConfig;
    let jwt_config = JwtConfig::from_secret(b"epigraph-dev-secret-change-in-production!!");
    let (token, _) = jwt_config
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:write".to_string(), "epigraph:write".to_string()],
            "service",
            None,
            None,
            chrono::Duration::seconds(300),
        )
        .expect("issue_access_token must succeed for tests");
    token
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_claim_embeds_inline(pool: PgPool) {
    let provider = MockProvider::new(EmbeddingConfig::local(1536));
    let service: Arc<dyn EmbeddingService> = Arc::new(provider);
    let state = AppState::with_db(pool.clone(), ApiConfig::default())
        .with_embedding_service(service.clone());
    let app = create_router(state);

    // Create an agent row the route can reference.
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind([0u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();

    let body = json!({
        "agent_id": agent_id,
        "content": "regression: embedding must be populated on create",
        "privacy_tier": "public",
        "initial_truth": 0.5,
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/claims")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", test_bearer_token()),
        )
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let claim_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();

    let has_embedding: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        has_embedding,
        "claim {claim_id} should have embedding populated by create_claim"
    );
}
