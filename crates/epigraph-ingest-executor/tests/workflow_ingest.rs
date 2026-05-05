//! Integration tests for [`epigraph_ingest_executor::execute_workflow_ingest_plan`].
//!
//! Migrated from the duplicate-site tests in `epigraph-mcp::tools::workflow_ingest`
//! and `epigraph-api::routes::workflows`. The executor crate owns the canonical
//! contract going forward.

use sqlx::PgPool;

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;

fn build_minimal_workflow_extraction(canonical_name: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.to_string(),
            goal: "Validate the executor crate ingests workflows idempotently".to_string(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some("Executor must be idempotent across repeat calls".to_string()),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Phase 1".to_string(),
            summary: "Run the executor twice and assert no duplicates".to_string(),
            steps: vec![Step {
                compound: "Invoke executor".to_string(),
                rationale: "Idempotency contract".to_string(),
                operations: vec![
                    "Call execute_workflow_ingest_plan".to_string(),
                    "Verify counters and edge counts".to_string(),
                ],
                generality: vec![2, 1],
                confidence: 0.9,
            }],
        }],
        relationships: vec![],
    }
}

/// Re-running the executor with the same plan must short-circuit on the
/// idempotency gate: no new claims, no duplicated edges.
#[sqlx::test(migrations = "../../migrations")]
async fn execute_is_idempotent(pool: PgPool) {
    let extraction = build_minimal_workflow_extraction("executor-idempotent-test");
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);

    let r1 = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("first call");
    assert!(
        !r1.already_ingested,
        "first ingest should not short-circuit"
    );
    assert!(r1.claims_ingested > 0, "first ingest should write claims");
    assert!(
        r1.executes_edges_created > 0,
        "first ingest should write executes edges"
    );

    let r2 = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("second call");
    assert!(
        r2.already_ingested,
        "second ingest should hit the idempotency gate"
    );
    assert_eq!(r2.workflow_id, r1.workflow_id);
    assert_eq!(r2.claims_ingested, 0);
    assert_eq!(r2.claims_skipped_dedup, 0);
    assert_eq!(r2.relationship_edges_created, 0);

    // Edge count in DB must be unchanged.
    let edge_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges \
         WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
    )
    .bind(r1.workflow_id)
    .fetch_one(&pool)
    .await
    .expect("edge count");
    assert_eq!(
        edge_count, r1.executes_edges_created as i64,
        "re-ingest must not duplicate executes edges"
    );

    // Claim count under the workflow must be unchanged.
    let claim_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims WHERE id IN \
         (SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'executes')",
    )
    .bind(r1.workflow_id)
    .fetch_one(&pool)
    .await
    .expect("claim count");
    assert_eq!(claim_count, r1.executes_edges_created as i64);
}

/// First-call sanity: counters reflect what was actually written.
#[sqlx::test(migrations = "../../migrations")]
async fn execute_smoke(pool: PgPool) {
    let extraction = build_minimal_workflow_extraction("executor-smoke-test");
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);

    let r = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("ingest must succeed");

    assert!(!r.already_ingested);
    assert!(
        !r.variant_of_edge_created,
        "phase 4.2 leaves variant_of for phase 4.3"
    );
    assert!(r.claims_ingested > 0);
    assert!(r.executes_edges_created > 0);

    // Workflow row exists.
    let workflow_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1)")
            .bind(r.workflow_id)
            .fetch_one(&pool)
            .await
            .expect("workflow exists query");
    assert!(workflow_exists);

    // workflow_id is deterministic from canonical_name + generation.
    let recomputed = epigraph_ingest::workflow::builder::root_workflow_id(&extraction);
    assert_eq!(r.workflow_id, recomputed);
}
