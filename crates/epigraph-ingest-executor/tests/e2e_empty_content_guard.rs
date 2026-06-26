//! E2E test for the pre-flight empty-content guard in `execute_workflow_ingest_plan`.
//!
//! Unlike `#[sqlx::test]` fixtures this test connects to the DATABASE_URL pool
//! directly, so it works with a restricted user (no CREATE DATABASE needed).
//! Run with:
//!   DATABASE_URL=postgres://epigraph_dev:epigraph_dev@127.0.0.1:5432/epigraph \
//!     cargo test -p epigraph-ingest-executor --test e2e_empty_content_guard

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::builder::build_ingest_plan;
use epigraph_ingest::workflow::schema::{Phase, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_ingest_executor::error::IngestExecutorError;
use epigraph_ingest_executor::execute_workflow_ingest_plan;

fn pool_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph".to_string())
}

/// Verify the pre-flight guard catches an empty thesis BEFORE any DB write.
/// Connects directly to the live DB pool; works with the restricted dev user.
#[tokio::test]
async fn e2e_empty_thesis_rejected_before_db_write() {
    let pool = sqlx::PgPool::connect(&pool_url())
        .await
        .expect("connect to dev DB");

    let canonical = "e2e-guard-test-empty-thesis-xyzzy-000";
    let extraction = WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: "E2E guard test".to_string(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some(String::new()), // empty thesis → pre-flight must catch this
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Phase A".to_string(),
            summary: "Non-empty summary".to_string(),
            steps: vec![],
        }],
        relationships: vec![],
    };

    let plan = build_ingest_plan(&extraction);

    let result = execute_workflow_ingest_plan(&pool, &plan, &extraction).await;

    assert!(result.is_err(), "empty thesis must be rejected");
    match result.unwrap_err() {
        IngestExecutorError::InvalidContent { path } => {
            assert!(
                path.contains("thesis"),
                "error path should mention 'thesis'; got: {path}"
            );
        }
        other => panic!("expected InvalidContent, got: {other:?}"),
    }

    // No zombie row should have been written.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workflows WHERE canonical_name = $1")
        .bind(canonical)
        .fetch_one(&pool)
        .await
        .expect("count query");

    assert_eq!(
        count, 0,
        "no workflows row should exist after a guard rejection"
    );
}
