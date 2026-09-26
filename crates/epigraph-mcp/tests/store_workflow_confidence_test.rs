//! `store_workflow` must honour `params.confidence` (default 0.8) for every
//! step claim instead of hard-coding 0.8.

use epigraph_mcp::types::StoreWorkflowParams;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::*;

#[path = "viewer_fixture.rs"]
mod fixture;

async fn stored_step_truth(pool: &PgPool, confidence: Option<f64>) -> f64 {
    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(pool).await;
    let step = format!("confidence probe step {}", Uuid::new_v4());
    epigraph_mcp::tools::workflows::store_workflow(
        &server,
        &viewer,
        StoreWorkflowParams {
            goal: format!("confidence probe goal {}", Uuid::new_v4()),
            steps: vec![step.clone()],
            prerequisites: None,
            expected_outcome: None,
            confidence,
            tags: None,
        },
    )
    .await
    .expect("store_workflow");

    sqlx::query_scalar("SELECT truth_value FROM claims WHERE content = $1")
        .bind(&step)
        .fetch_one(pool)
        .await
        .expect("step claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn explicit_confidence_is_stored_on_step_claims(pool: PgPool) {
    let tv = stored_step_truth(&pool, Some(0.3)).await;
    assert!((tv - 0.3).abs() < 1e-9, "expected 0.3, got {tv}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn omitted_confidence_defaults_to_0_8(pool: PgPool) {
    let tv = stored_step_truth(&pool, None).await;
    assert!((tv - 0.8).abs() < 1e-9, "expected 0.8, got {tv}");
}
