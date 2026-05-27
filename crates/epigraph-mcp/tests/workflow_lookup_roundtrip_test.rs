//! Regression test for bug `6d3fc460-2d64-48a8-b9cc-7ce23a5710b8`.
//!
//! After the 2026-05-12 hierarchical-store migration (commit `acaca80`),
//! `store_workflow` writes a row to the `workflows` table (not a flat
//! claim labeled `workflow`) and returns a `workflows.id`. Three peer
//! tools — `find_workflow`, `report_workflow_outcome`, and `recall` —
//! still assumed flat-claim semantics, so every workflow stored after
//! May 12 was invisible to lookup.
//!
//! Adversarial-critic note: this test deliberately exercises the
//! production data flow that broke (`do_ingest_workflow_via_pool` ->
//! `find_workflow` MCP tool -> `report_workflow_outcome` MCP tool). It
//! does NOT mock repositories. The embedder is unconfigured (no API key),
//! so the semantic path errors and the test exercises the ILIKE / DB
//! fallback path — exactly the path scheduled agents hit in production.

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool;
use epigraph_mcp::types::{
    FindWorkflowParams, ReportWorkflowOutcomeParams, StepExecution,
};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::{build_test_server, first_text};

fn extraction(canonical_name: &str, goal: &str, steps: &[&str]) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.to_string(),
            goal: goal.to_string(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some(goal.to_string()),
        thesis_derivation: ThesisDerivation::default(),
        phases: vec![Phase {
            title: "Body".to_string(),
            summary: "Body".to_string(),
            steps: steps
                .iter()
                .map(|t| Step {
                    compound: (*t).to_string(),
                    rationale: String::new(),
                    operations: vec![],
                    generality: vec![],
                    confidence: 0.8,
                })
                .collect(),
        }],
        relationships: vec![],
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_surfaces_hierarchical_row(pool: PgPool) {
    let unique = format!("roundtrip-find-{}", Uuid::new_v4().simple());
    let goal = format!("hierarchical lookup regression {unique}");

    let response = do_ingest_workflow_via_pool(
        &pool,
        &extraction(&unique, &goal, &["alpha", "beta"]),
    )
    .await
    .expect("ingest hierarchical workflow");
    let workflow_id = Uuid::parse_str(&response.workflow_id).expect("workflow_id is a UUID");

    // Sanity: the row exists in `workflows` (hierarchical), not in `claims`
    // under that id — confirming the contract drift surface.
    let in_workflows: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1)")
            .bind(workflow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let in_claims: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM claims WHERE id = $1)")
        .bind(workflow_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(in_workflows, "hierarchical ingest must populate workflows row");
    assert!(
        !in_claims,
        "workflows.id is its own UUID namespace — must NOT collide with claims.id"
    );

    let server = build_test_server(pool.clone());
    let result = epigraph_mcp::tools::workflows::find_workflow(
        &server,
        FindWorkflowParams {
            goal: goal.clone(),
            limit: Some(5),
            min_truth: Some(0.0),
        },
    )
    .await
    .expect("find_workflow");

    let json = first_text(&result);
    let arr = json.as_array().expect("find_workflow returns a JSON array");
    let ids: Vec<String> = arr
        .iter()
        .filter_map(|v| v.get("workflow_id").and_then(|x| x.as_str()).map(String::from))
        .collect();
    assert!(
        ids.iter().any(|id| id == &workflow_id.to_string()),
        "find_workflow must surface the hierarchical workflow_id; got ids: {ids:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn report_workflow_outcome_accepts_hierarchical_id(pool: PgPool) {
    let unique = format!("roundtrip-outcome-{}", Uuid::new_v4().simple());
    let goal = format!("hierarchical outcome regression {unique}");

    let response = do_ingest_workflow_via_pool(
        &pool,
        &extraction(&unique, &goal, &["step-a", "step-b"]),
    )
    .await
    .expect("ingest hierarchical workflow");
    let workflow_id = Uuid::parse_str(&response.workflow_id).expect("workflow_id is a UUID");

    let server = build_test_server(pool.clone());
    epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        ReportWorkflowOutcomeParams {
            workflow_id: workflow_id.to_string(),
            success: true,
            execution_log: vec![
                StepExecution {
                    step_index: 0,
                    planned: "step-a".to_string(),
                    actual: "step-a done".to_string(),
                    deviated: false,
                    deviation_reason: None,
                },
                StepExecution {
                    step_index: 1,
                    planned: "step-b".to_string(),
                    actual: "step-b done".to_string(),
                    deviated: false,
                    deviation_reason: None,
                },
            ],
            outcome_details: "smoke run".to_string(),
            quality: Some(1.0),
            goal_text: Some(goal.clone()),
        },
    )
    .await
    .expect("report_workflow_outcome must accept the hierarchical workflow_id");

    // Verify the hierarchical metadata counters moved — proves we routed to
    // the hierarchical outcome path, not silently no-op'd.
    let (metadata,): (serde_json::Value,) =
        sqlx::query_as("SELECT metadata FROM workflows WHERE id = $1")
            .bind(workflow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        metadata.get("use_count").and_then(|v| v.as_i64()),
        Some(1),
        "hierarchical metadata.use_count must increment after report_workflow_outcome"
    );
    assert_eq!(
        metadata.get("success_count").and_then(|v| v.as_i64()),
        Some(1),
        "hierarchical metadata.success_count must increment on success=true"
    );

    let exec_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM behavioral_executions WHERE workflow_id = $1")
            .bind(workflow_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        exec_count, 2,
        "one behavioral_executions row per step_execution (hierarchical semantics)"
    );
}
