//! Regression tests for `report_workflow_outcome` dispatch.
//!
//! `store_workflow` was migrated to the hierarchical ingest pipeline and now
//! returns an id that lives in the `workflows` table (not `claims`). Before
//! this fix, `report_workflow_outcome` only looked in `claims`, so every
//! freshly-stored workflow returned "workflow not found".
//!
//! Resolves backlog claims 61840f12, 53b19ee1, 6d3fc460 (same defect, triple-filed).
//!
//! Two cases:
//!   1. New-style flow: `store_workflow` → `report_workflow_outcome` must
//!      succeed against the returned id and write a `behavioral_executions`
//!      row + update `workflows.metadata` counters.
//!   2. Legacy compat: a flat workflow-labeled claim id (no row in
//!      `workflows`) must still flow through the legacy claims-table path.
mod common;
use common::*;

use epigraph_mcp::types::{ReportWorkflowOutcomeParams, StepExecution, StoreWorkflowParams};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn report_outcome_dispatches_to_hierarchical_when_id_is_a_workflows_row(pool: PgPool) {
    let server = build_test_server(pool.clone());

    // Use a unique goal so canonical_name is unique across reruns / DB sharing.
    let goal = format!("dispatch regression test {}", Uuid::new_v4());
    let store_result = epigraph_mcp::tools::workflows::store_workflow(
        &server,
        StoreWorkflowParams {
            goal: goal.clone(),
            steps: vec!["alpha step".to_string(), "beta step".to_string()],
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
    )
    .await
    .expect("store_workflow must succeed");

    let store_json = first_text(&store_result);
    let workflow_id = parse_uuid_field(&store_json, "workflow_id");

    // Sanity: the id must live in `workflows`, NOT in `claims`. If this
    // assertion ever flips, the dispatch logic in report_workflow_outcome
    // needs to be revisited.
    let in_workflows: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1)")
            .bind(workflow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        in_workflows,
        "store_workflow_id ({workflow_id}) should live in `workflows` table"
    );

    // The actual regression: this used to return "workflow not found".
    let report_result = epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        ReportWorkflowOutcomeParams {
            workflow_id: workflow_id.to_string(),
            success: true,
            execution_log: vec![
                StepExecution {
                    step_index: 0,
                    planned: "alpha step".to_string(),
                    actual: "alpha step — completed".to_string(),
                    deviated: false,
                    deviation_reason: None,
                },
                StepExecution {
                    step_index: 1,
                    planned: "beta step".to_string(),
                    actual: "beta step — adapted".to_string(),
                    deviated: true,
                    deviation_reason: Some("ran out of foo".to_string()),
                },
            ],
            outcome_details: "test outcome".to_string(),
            quality: None,
            goal_text: Some(goal.clone()),
        },
    )
    .await
    .expect("report_workflow_outcome must succeed for hierarchical id");

    // Behavioral side-effect: a row per step_execution under workflow_id.
    let exec_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM behavioral_executions WHERE workflow_id = $1")
            .bind(workflow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        exec_count, 2,
        "two behavioral_executions rows (one per step_execution)"
    );

    // Metadata counters bumped on `workflows`.
    let (metadata,): (serde_json::Value,) =
        sqlx::query_as("SELECT metadata FROM workflows WHERE id = $1")
            .bind(workflow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(metadata["use_count"].as_i64(), Some(1));
    assert_eq!(metadata["success_count"].as_i64(), Some(1));
    assert_eq!(metadata["failure_count"].as_i64(), Some(0));

    // Response payload sanity: it's the hierarchical shape (use_count etc.),
    // not the legacy flat shape (truth_before / truth_after / evidence_id).
    let report_json = first_text(&report_result);
    assert_eq!(report_json["use_count"].as_i64(), Some(1));
}

#[sqlx::test(migrations = "../../migrations")]
async fn report_outcome_still_handles_legacy_flat_workflow_claim_id(pool: PgPool) {
    let server = build_test_server(pool.clone());

    // Seed a flat workflow-labeled claim — id lives in `claims`, NOT in
    // `workflows`. This is the legacy shape for the ~144 pre-migration rows.
    let claim_id = seed_workflow_claim(&pool, "legacy flat workflow", &["s1", "s2"]).await;

    let not_in_workflows: bool =
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM workflows WHERE id = $1)")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        not_in_workflows,
        "legacy seed must not collide with workflows table"
    );

    // Must succeed via the legacy claims-table path. Pre-fix this also worked;
    // the test exists to catch a regression where the new dispatch
    // accidentally drops the fallback.
    epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        ReportWorkflowOutcomeParams {
            workflow_id: claim_id.to_string(),
            success: true,
            execution_log: vec![StepExecution {
                step_index: 0,
                planned: "s1".to_string(),
                actual: "s1".to_string(),
                deviated: false,
                deviation_reason: None,
            }],
            outcome_details: "legacy path test".to_string(),
            quality: Some(0.8),
            goal_text: None,
        },
    )
    .await
    .expect("legacy flat workflow path must still succeed");

    // Legacy path writes Evidence + behavioral_executions row keyed on claim id.
    let evidence_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(evidence_count, 1, "legacy path writes one Evidence row");

    let exec_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM behavioral_executions WHERE workflow_id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        exec_count, 1,
        "legacy path writes one behavioral_executions row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn report_outcome_404s_for_truly_unknown_id(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let bogus = Uuid::new_v4();

    let err = epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        ReportWorkflowOutcomeParams {
            workflow_id: bogus.to_string(),
            success: true,
            execution_log: vec![],
            outcome_details: "x".to_string(),
            quality: None,
            goal_text: None,
        },
    )
    .await
    .expect_err("unknown id must error");

    // Error message names both tables so caller can debug.
    let msg = err.message.to_string();
    assert!(
        msg.contains("workflows") && msg.contains("claims"),
        "error must reference both tables, got: {msg}"
    );
}
