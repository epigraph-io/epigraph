//! Integration test for the `improve_workflow_hierarchy` MCP tool.
//!
//! Verifies that calling the tool against an existing canonical workflow
//! resolves the max generation, ingests the new extraction at generation
//! `parent_max + 1`, and links it via `parent_canonical_name`. Also
//! confirms that each call produces a fresh generation (no implicit
//! idempotent no-op when the new generation hasn't been written yet).

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;

fn parent_extraction(canonical: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: "Original flat-mapped workflow".to_string(),
            generation: 1,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: None,
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Body".to_string(),
            summary: "Flat steps as a single phase".to_string(),
            steps: vec![Step {
                compound: "do thing".to_string(),
                rationale: "because".to_string(),
                operations: vec!["step 1".to_string()],
                generality: vec![1],
                confidence: 0.5,
            }],
        }],
        relationships: vec![],
    }
}

fn improved_extraction() -> WorkflowExtraction {
    // Caller leaves canonical_name / generation / parent_canonical_name
    // arbitrary; the tool overwrites them.
    let mut e = parent_extraction("ignored-by-tool");
    e.source.goal = "Refined hierarchical re-authoring".to_string();
    e.phases = vec![
        Phase {
            title: "Setup".to_string(),
            summary: "Prepare prerequisites".to_string(),
            steps: vec![Step {
                compound: "install deps".to_string(),
                rationale: "code needs them".to_string(),
                operations: vec!["pip install".to_string()],
                generality: vec![2],
                confidence: 0.9,
            }],
        },
        Phase {
            title: "Execute".to_string(),
            summary: "Run the workflow".to_string(),
            steps: vec![Step {
                compound: "run".to_string(),
                rationale: "main work".to_string(),
                operations: vec!["./run.sh".to_string()],
                generality: vec![2],
                confidence: 0.9,
            }],
        },
    ];
    e
}

#[sqlx::test(migrations = "../../migrations")]
async fn improve_workflow_hierarchy_increments_generation(pool: sqlx::PgPool) {
    let canonical = "test-improve-hier-increments";

    // Ingest parent at generation 1.
    epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(
        &pool,
        &parent_extraction(canonical),
    )
    .await
    .expect("parent ingest");

    // First improve: parent_max=1, new_generation=2.
    let new_gen = epigraph_mcp::tools::workflow_ingest::improve_workflow_hierarchy_via_pool(
        &pool,
        canonical,
        improved_extraction(),
    )
    .await
    .expect("improve");

    assert_eq!(new_gen.parent_generation, 1);
    assert_eq!(new_gen.new_generation, 2);
    assert!(!new_gen.already_ingested);

    // Verify the workflows row was created at generation 2 with the parent
    // linkage in place via the executor's variant_of edge logic.
    let row: (i32, Option<uuid::Uuid>) =
        sqlx::query_as("SELECT generation, parent_id FROM workflows WHERE id = $1::uuid")
            .bind(&new_gen.workflow_id)
            .fetch_one(&pool)
            .await
            .expect("workflows row exists");
    assert_eq!(row.0, 2);
    assert!(
        row.1.is_some(),
        "variant should have parent_id pointing at gen 1 root"
    );

    // Second improve: parent_max is now 2, so new_generation=3. Each call
    // produces a fresh variant; idempotency is on (canonical_name, generation),
    // not on the tool entrypoint.
    let new_gen2 = epigraph_mcp::tools::workflow_ingest::improve_workflow_hierarchy_via_pool(
        &pool,
        canonical,
        improved_extraction(),
    )
    .await
    .expect("second improve");
    assert_eq!(new_gen2.parent_generation, 2);
    assert_eq!(new_gen2.new_generation, 3);
    assert!(!new_gen2.already_ingested);
}

#[sqlx::test(migrations = "../../migrations")]
async fn improve_workflow_hierarchy_errors_when_parent_missing(pool: sqlx::PgPool) {
    let result = epigraph_mcp::tools::workflow_ingest::improve_workflow_hierarchy_via_pool(
        &pool,
        "nonexistent-canonical-name-xyzzy",
        improved_extraction(),
    )
    .await;

    assert!(
        result.is_err(),
        "improving a non-existent canonical_name should error"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("no workflow with canonical_name"),
        "error message should mention missing canonical_name; got: {err_msg}"
    );
}
