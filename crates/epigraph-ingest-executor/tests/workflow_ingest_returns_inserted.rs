//! execute_workflow_ingest_plan must return (claim_id, content) for every
//! newly inserted claim so callers can embed them. Regression guard for the
//! is_current=true → has-embedding invariant (CLAUDE.md "Embedding policy").

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use sqlx::PgPool;

fn build_extraction(canonical_name: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.to_string(),
            goal: "verify executor surfaces (id, content) for caller-side embed".into(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some("Executor must surface inserts for embedding".into()),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Phase 1".into(),
            summary: "Single phase with one step and two operations".into(),
            steps: vec![Step {
                compound: "Invoke executor and check returned inserts".into(),
                rationale: "Embedding contract".into(),
                operations: vec![
                    "Call execute_workflow_ingest_plan".into(),
                    "Assert result.inserted contains every inserted claim".into(),
                ],
                generality: vec![2, 1],
                confidence: 0.9,
            }],
        }],
        relationships: vec![],
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_inserted_claim_ids_and_content(pool: PgPool) {
    let extraction = build_extraction("executor-embed-surfacing-test");
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let planned_count = plan.claims.len();
    assert!(planned_count > 0, "fixture should produce at least one planned claim");

    // First run: every planned claim is newly inserted and must be surfaced.
    let r1 = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("first call");
    assert!(!r1.already_ingested);
    assert_eq!(r1.claims_ingested, planned_count);
    assert_eq!(
        r1.inserted.len(),
        planned_count,
        "executor must surface (id, content) for every newly inserted claim"
    );
    // Cross-check content matches the planned input order-insensitively.
    let planned_contents: std::collections::HashSet<&str> =
        plan.claims.iter().map(|c| c.content.as_str()).collect();
    for (id, content) in &r1.inserted {
        assert!(planned_contents.contains(content.as_str()), "{id} content mismatch");
    }

    // Second run: idempotency gate fires; no new surfacing.
    let r2 = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("second call");
    assert!(r2.already_ingested);
    assert!(r2.inserted.is_empty(), "idempotent re-run must surface no new inserts");
}

/// Regression guard for the partial-dedup resume case: an interrupted first
/// run can leave the workflow row in place but with zero `executes` edges
/// (process killed between WorkflowRepository::insert_root and the edge-
/// creation loop). On resume the idempotency gate at lines 65-89 of
/// workflow.rs does NOT fire (edge_count == 0), so the executor falls
/// through to the claim-walk loop. Every claim already exists in the DB,
/// so `was_new == false` for all of them and `inserted` is empty — but
/// for a fundamentally different reason than the full-idempotency path.
/// This test pins that behaviour so a future refactor that conflates the
/// two empty-inserted cases (e.g. by surfacing pre-existing claims from
/// the `was_new == false` branch) gets caught.
#[sqlx::test(migrations = "../../migrations")]
async fn returns_empty_inserted_on_partial_dedup(pool: PgPool) {
    let extraction = build_extraction("executor-partial-dedup-test");
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
    let planned_count = plan.claims.len();
    assert!(planned_count > 0, "fixture should produce at least one planned claim");

    // First run: writes workflow row + claims + executes edges normally.
    let r1 = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("first call");
    assert!(!r1.already_ingested);
    assert_eq!(r1.claims_ingested, planned_count);
    assert_eq!(r1.inserted.len(), planned_count);

    // Simulate the partial-state crash window: workflow row + claims still
    // present, but the executes edges never made it (or were rolled back).
    // Use DELETE on `executes` edges only so the workflow_id row stays put.
    let workflow_id = r1.workflow_id;
    let deleted: u64 = sqlx::query(
        "DELETE FROM edges \
         WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
    )
    .bind(workflow_id)
    .execute(&pool)
    .await
    .expect("delete executes edges")
    .rows_affected();
    assert_eq!(
        deleted as usize, planned_count,
        "should delete one executes edge per planned claim"
    );

    // Re-run: idempotency gate must NOT fire (edge_count == 0), executor
    // falls through to claim-walk where every claim hits was_new=false.
    let r2 = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("second call after edge wipe");
    assert!(
        !r2.already_ingested,
        "gate must not fire when executes edges are absent"
    );
    assert_eq!(
        r2.claims_ingested, 0,
        "no new claims inserted — all dedup-skipped"
    );
    assert_eq!(
        r2.claims_skipped_dedup, planned_count,
        "every planned claim already exists, so every walk-loop iteration is a dedup skip"
    );
    assert!(
        r2.inserted.is_empty(),
        "inserted must only surface was_new=true claims, not dedup-skipped ones"
    );
}
