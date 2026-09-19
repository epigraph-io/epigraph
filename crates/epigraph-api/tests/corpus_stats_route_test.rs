#![cfg(feature = "db")]
//! `GET /api/v1/stats` (plan §2.4).
//!
//! Counts are asserted as deltas around a baseline read: a migrated database
//! may already contain rows, and the point of the route is that the numbers
//! track the corpus, not that they start at zero.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn router(pool: PgPool) -> Router {
    create_router(AppState::with_db(pool, ApiConfig::default()))
}

async fn stats(router: &Router) -> Value {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("stats body is JSON")
}

fn count(body: &Value, key: &str) -> i64 {
    body[key]
        .as_i64()
        .unwrap_or_else(|| panic!("{key} missing or not an integer in {body}"))
}

async fn seed_evidence(pool: &PgPool, claim_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO evidence (id, raw_content, content_hash, evidence_type, claim_id) \
         VALUES ($1, 'ev', $2, 'document', $3)",
    )
    .bind(id)
    .bind(&hash)
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("seed evidence");
    id
}

async fn seed_frame(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO frames (id, name, hypotheses) VALUES ($1, $2, ARRAY['h0','h1'])")
        .bind(id)
        .bind(format!("stats-test-frame-{id}"))
        .execute(pool)
        .await
        .expect("seed frame");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn counts_track_the_rows_that_were_seeded(pool: PgPool) {
    let app = router(pool.clone());
    let before = stats(&app).await;

    // 3 claims (one of them a labelled workflow, one of them embedded),
    // 1 agent, 1 edge, 1 evidence row, 1 frame.
    let a = common::seed_claim(&pool, "stats claim a").await;
    let b = common::seed_claim(&pool, "stats claim b").await;
    let _workflow = common::seed_claim_with_labels(&pool, "a workflow", &["workflow"]).await;
    let agent = common::seed_system_agent(&pool).await;
    common::insert_edge(&pool, a, b, "claim", "claim", "supports").await;
    seed_evidence(&pool, a).await;
    seed_frame(&pool).await;
    sqlx::query(
        "UPDATE claims SET embedding = \
         ('[' || array_to_string(array_fill(0.1::double precision, ARRAY[1536]), ',') || ']')::vector \
         WHERE id = $1",
    )
    .bind(a)
    .execute(&pool)
    .await
    .expect("set an embedding");

    let after = stats(&app).await;

    // `seed_claim` also inserts a system agent per call, so claims and agents
    // move together; assert the deltas rather than absolute numbers.
    assert_eq!(count(&after, "claims") - count(&before, "claims"), 3);
    assert_eq!(count(&after, "edges") - count(&before, "edges"), 1);
    assert_eq!(count(&after, "evidence") - count(&before, "evidence"), 1);
    assert_eq!(count(&after, "frames") - count(&before, "frames"), 1);
    assert_eq!(
        count(&after, "embeddings") - count(&before, "embeddings"),
        1
    );
    assert_eq!(count(&after, "workflows") - count(&before, "workflows"), 1);
    // 3 seed_claim/seed_claim_with_labels agents + the explicit one.
    assert_eq!(count(&after, "agents") - count(&before, "agents"), 4);
    let _ = agent;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_response_has_exactly_the_documented_keys(pool: PgPool) {
    let app = router(pool);
    let body = stats(&app).await;

    let mut keys: Vec<&str> = body
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "agents",
            "claims",
            "computed_at",
            "edges",
            "embeddings",
            "evidence",
            "frames",
            "workflows",
        ]
    );
    for key in [
        "claims",
        "edges",
        "evidence",
        "embeddings",
        "agents",
        "frames",
        "workflows",
    ] {
        assert!(
            body[key].is_i64(),
            "{key} should be an integer, got {}",
            body[key]
        );
    }
    let computed_at = body["computed_at"].as_str().expect("computed_at string");
    chrono::DateTime::parse_from_rfc3339(computed_at)
        .unwrap_or_else(|e| panic!("computed_at {computed_at} is not RFC3339: {e}"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_is_a_labelled_claim_not_a_workflows_row(pool: PgPool) {
    let app = router(pool.clone());
    let before = count(&stats(&app).await, "workflows");

    // The definition MCP `system_stats` has always used. A claim with some
    // other label must not move the number.
    common::seed_claim_with_labels(&pool, "not a workflow", &["method"]).await;
    assert_eq!(count(&stats(&app).await, "workflows"), before);

    common::seed_claim_with_labels(&pool, "a workflow", &["workflow", "method"]).await;
    assert_eq!(count(&stats(&app).await, "workflows"), before + 1);
}
