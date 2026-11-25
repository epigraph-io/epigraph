//! A flat workflow claim's run counters come from its persisted runs
//! (backlog b2ac99f2).
//!
//! A flat workflow claim's content is signed and immutable. The counters used
//! to be read from that content: `report_workflow_outcome` answered
//! `total_uses` as the content's `use_count` plus one and persisted nothing,
//! so every report of a flat workflow said `total_uses: 1`, and
//! `find_workflow` listed every flat workflow with `use_count: 0`. Each report
//! records one `behavioral_executions` row keyed on the claim id; that is the
//! history both now count.

#[path = "viewer_fixture.rs"]
mod fixture;

// rustfmt 1.8 sorts __test_only differently than older CI rustfmt; opt out so
// both versions accept the file (mirrors find_workflow_semantic_test.rs).
#[rustfmt::skip]
use epigraph_mcp::tools::workflows::__test_only::find_workflow_with_pgvec;
use epigraph_mcp::types::{FindWorkflowParams, ReportWorkflowOutcomeParams, StepExecution};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::*;

/// A 1536-d pgvector literal: component [0] is 1.0, the rest 0.0.
fn unit_pgvec_1536() -> String {
    let mut v = vec!["0.0"; 1536];
    v[0] = "1.0";
    format!("[{}]", v.join(","))
}

fn report(workflow_id: Uuid, success: bool) -> ReportWorkflowOutcomeParams {
    ReportWorkflowOutcomeParams {
        idempotency_key: None,
        workflow_id: workflow_id.to_string(),
        success,
        execution_log: vec![StepExecution {
            step_index: 0,
            planned: "build image".to_string(),
            actual: "build image".to_string(),
            deviated: false,
            deviation_reason: None,
        }],
        outcome_details: format!("flat run counter test, success={success}"),
        quality: None,
        goal_text: Some("deploy containerised service".to_string()),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_reports_on_a_flat_workflow_count_two_uses(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    // A legacy flat workflow claim (no `workflows` row), with the zeroed
    // counters the legacy store wrote into its content, and an embedding so
    // `find_workflow`'s semantic path can find it.
    let agent = seed_agent(&pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    let content = serde_json::json!({
        "goal": "deploy containerised service",
        "steps": ["build image", "push to registry", "restart service"],
        "generation": 0,
        "use_count": 0,
        "success_count": 0,
    })
    .to_string();
    let pgvec = unit_pgvec_1536();
    sqlx::query(
        "INSERT INTO claims \
         (id, content, content_hash, truth_value, agent_id, is_current, labels, embedding) \
         VALUES ($1, $2, $3, 0.7, $4, true, ARRAY['workflow']::text[], $5::vector)",
    )
    .bind(id)
    .bind(&content)
    .bind(&hash)
    .bind(agent)
    .bind(&pgvec)
    .execute(&pool)
    .await
    .expect("seed flat workflow claim");

    let first = epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        report(id, true),
        None,
    )
    .await
    .expect("first report");
    let first = first_text(&first);
    assert_eq!(first["total_uses"].as_i64(), Some(1), "{first}");
    assert_eq!(first["success_rate"].as_f64(), Some(1.0), "{first}");

    let second = epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        report(id, false),
        None,
    )
    .await
    .expect("second report");
    let second = first_text(&second);
    assert_eq!(
        second["total_uses"].as_i64(),
        Some(2),
        "the second report of a flat workflow counts two uses: {second}"
    );
    assert_eq!(
        second["success_rate"].as_f64(),
        Some(0.5),
        "one success in two uses: {second}"
    );

    // The runs are persisted, and `find_workflow` reports them.
    let runs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM behavioral_executions WHERE workflow_id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(runs, 2, "one behavioral_executions row per report");

    let found = find_workflow_with_pgvec(
        &server,
        &viewer,
        FindWorkflowParams {
            goal: "flat run counter probe".to_string(),
            limit: Some(5),
            min_truth: Some(0.0),
        },
        Some(pgvec),
    )
    .await
    .expect("find_workflow");
    let found = first_text(&found);
    let hit = found
        .as_array()
        .expect("result is an array")
        .iter()
        .find(|r| r["workflow_id"].as_str() == Some(id.to_string().as_str()))
        .unwrap_or_else(|| panic!("find_workflow returns the flat workflow: {found}"));
    assert_eq!(hit["use_count"].as_i64(), Some(2), "{hit}");
    assert_eq!(hit["success_count"].as_i64(), Some(1), "{hit}");
}
