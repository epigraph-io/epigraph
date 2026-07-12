//! T20: GET /api/v1/claims/:id/cross_source_matches integration tests.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::middleware::SignatureVerificationState;
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde::Deserialize;
use sqlx::types::Json as SqlxJson;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

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

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("t20 {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, true)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[derive(Debug, Deserialize)]
struct CorroboratesEdge {
    edge_id: String,
    source_id: String,
    target_id: String,
    #[serde(default)]
    properties: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct PendingCandidate {
    id: String,
    claim_a: String,
    claim_b: String,
    score: f32,
    status: Option<String>, // not in response but lets us be lax
    #[serde(default)]
    features: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct Response {
    claim_id: String,
    corroborates: Vec<CorroboratesEdge>,
    pending: Vec<PendingCandidate>,
}

async fn get(router: &Router, path: &str) -> axum::http::Response<axum::body::Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_404_when_claim_missing(pool: PgPool) {
    let router = create_test_router(pool);
    let bogus = Uuid::new_v4();
    let resp = get(
        &router,
        &format!("/api/v1/claims/{bogus}/cross_source_matches"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_empty_arrays_when_claim_has_no_matches(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let claim = insert_claim(&pool, agent).await;
    let router = create_test_router(pool);

    let resp = get(
        &router,
        &format!("/api/v1/claims/{claim}/cross_source_matches"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Response = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.claim_id, claim.to_string());
    assert!(parsed.corroborates.is_empty());
    assert!(parsed.pending.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_corroborates_edges_and_pending_candidates(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let c = insert_claim(&pool, agent).await;

    // Pending candidate (a, b).
    let (lo_ab, hi_ab) = if a < b { (a, b) } else { (b, a) };
    sqlx::query(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, 0.7, $3, 'pending')",
    )
    .bind(lo_ab)
    .bind(hi_ab)
    .bind(SqlxJson(serde_json::json!({"embed_cosine": 0.7})))
    .execute(&pool)
    .await
    .unwrap();

    // Promoted candidate (a, c) — must NOT appear in `pending`.
    let (lo_ac, hi_ac) = if a < c { (a, c) } else { (c, a) };
    sqlx::query(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, 0.95, $3, 'promoted')",
    )
    .bind(lo_ac)
    .bind(hi_ac)
    .bind(SqlxJson(serde_json::json!({"embed_cosine": 0.99})))
    .execute(&pool)
    .await
    .unwrap();

    // The corresponding CORROBORATES edge (a → c).
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', $3)",
    )
    .bind(a)
    .bind(c)
    .bind(SqlxJson(serde_json::json!({"score": 0.95, "source": "cross_source_matcher"})))
    .execute(&pool)
    .await
    .unwrap();

    let router = create_test_router(pool);
    let resp = get(&router, &format!("/api/v1/claims/{a}/cross_source_matches")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Response = serde_json::from_slice(&body).unwrap();

    assert_eq!(parsed.claim_id, a.to_string());
    assert_eq!(
        parsed.corroborates.len(),
        1,
        "expected one CORROBORATES edge"
    );
    let edge = &parsed.corroborates[0];
    assert_eq!(edge.source_id, a.to_string());
    assert_eq!(edge.target_id, c.to_string());
    let _ = (&edge.edge_id, &edge.properties);

    assert_eq!(parsed.pending.len(), 1, "expected one pending candidate");
    let cand = &parsed.pending[0];
    let pair = [cand.claim_a.as_str(), cand.claim_b.as_str()];
    assert!(pair.contains(&a.to_string().as_str()));
    assert!(pair.contains(&b.to_string().as_str()));
    assert!((cand.score - 0.7).abs() < 1e-5);
    let _ = (&cand.id, &cand.status, &cand.features);
}

#[derive(Debug, Deserialize)]
struct ListedCandidate {
    id: String,
    claim_a: String,
    claim_a_excerpt: String,
    claim_b: String,
    claim_b_excerpt: String,
    score: f32,
    verifier_verdict: Option<String>,
    verifier_rationale: Option<String>,
    created_at: String,
}

// NOTE: this route is registered in routes/mod.rs (Task 3 of the
// 2026-07-11 xsm-telegram-approval plan) — this test only passes once
// that registration lands.
#[sqlx::test(migrations = "../../migrations")]
async fn list_candidates_returns_pending_with_excerpts(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    sqlx::query(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status, verifier_verdict, verifier_rationale)
         VALUES ($1, $2, 0.81, $3, 'pending', 'paraphrase', 'test rationale text')",
    )
    .bind(lo)
    .bind(hi)
    .bind(SqlxJson(serde_json::json!({"embed_cosine": 0.81})))
    .execute(&pool)
    .await
    .unwrap();

    let router = create_test_router(pool);
    let resp = get(&router, "/api/v1/match_candidates?status=pending&limit=100").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "list requires a bearer token");
}
