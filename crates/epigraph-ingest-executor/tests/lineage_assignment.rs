//! Verify the executor injects `step_lineage_id` for level=2/3 claims at ingest
//! and leaves level=0/1 (thesis/phase) NULL — see spec
//! `docs/superpowers/specs/2026-05-05-step-level-versioning-design.md` §6.1,
//! §6.2, §9.6, §9.7, §9.8.

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;

/// One thesis (L0), one phase (L1), one step (L2), one operation (L3).
/// `op_text` is parameterized so callers can keep operation `claim_id`s unique
/// across tests sharing a DB pool (atom-namespace ID is content-hash derived).
fn build_one_of_each_extraction(canonical_name: &str, op_text: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.to_string(),
            goal: "Validate step_lineage_id injection for level=2/3 claims".to_string(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some(format!("thesis content for {canonical_name}")),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Phase A".to_string(),
            summary: format!("phase summary for {canonical_name}"),
            steps: vec![Step {
                compound: format!("step compound for {canonical_name}"),
                rationale: "step rationale".to_string(),
                operations: vec![op_text.to_string()],
                generality: vec![1],
                confidence: 0.9,
            }],
        }],
        relationships: vec![],
    }
}

/// Resolve the `claim_id` at a given path index (`thesis`, `phases[0]`,
/// `phases[0].steps[0]`, `phases[0].steps[0].operations[0]`).
fn id_at(plan: &epigraph_ingest::common::plan::IngestPlan, path: &str) -> Uuid {
    *plan
        .path_index
        .get(path)
        .unwrap_or_else(|| panic!("path_index missing key {path}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn lineage_assigned_to_level_2_and_3_only(pool: PgPool) {
    let extraction = build_one_of_each_extraction(
        "lineage-l23-only-test",
        "operation text for lineage-l23-only-test",
    );
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);

    let thesis_id = id_at(&plan, "thesis");
    let phase_id = id_at(&plan, "phases[0]");
    let step_id = id_at(&plan, "phases[0].steps[0]");
    let op_id = id_at(&plan, "phases[0].steps[0].operations[0]");

    let result = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("ingest plan");
    assert!(!result.already_ingested);
    assert!(
        result.claims_ingested >= 4,
        "expected at least 4 claims (thesis/phase/step/op), got {}",
        result.claims_ingested
    );

    // Level=0 (thesis) — column is NULL.
    let row: (Option<Uuid>,) = sqlx::query_as("SELECT step_lineage_id FROM claims WHERE id = $1")
        .bind(thesis_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        row.0.is_none(),
        "thesis (level=0) must have NULL step_lineage_id, got {:?}",
        row.0
    );

    // Level=1 (phase) — column is NULL.
    let row: (Option<Uuid>,) = sqlx::query_as("SELECT step_lineage_id FROM claims WHERE id = $1")
        .bind(phase_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        row.0.is_none(),
        "phase (level=1) must have NULL step_lineage_id, got {:?}",
        row.0
    );

    // Level=2 (step) — column populated.
    let row: (Option<Uuid>,) = sqlx::query_as("SELECT step_lineage_id FROM claims WHERE id = $1")
        .bind(step_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let step_lineage = row.0.expect("step (level=2) must have step_lineage_id");

    // Level=3 (operation) — column populated.
    let row: (Option<Uuid>,) = sqlx::query_as("SELECT step_lineage_id FROM claims WHERE id = $1")
        .bind(op_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let op_lineage = row
        .0
        .expect("operation (level=3) must have step_lineage_id");

    // Properties JSONB must mirror the column for level=2/3.
    let row: (serde_json::Value, Option<Uuid>) =
        sqlx::query_as("SELECT properties, step_lineage_id FROM claims WHERE id = $1")
            .bind(step_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let prop_lineage = row
        .0
        .get("step_lineage_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    assert_eq!(
        prop_lineage,
        Some(step_lineage),
        "step properties.step_lineage_id must mirror the column"
    );
    assert_eq!(row.1, Some(step_lineage));

    let row: (serde_json::Value, Option<Uuid>) =
        sqlx::query_as("SELECT properties, step_lineage_id FROM claims WHERE id = $1")
            .bind(op_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let prop_lineage = row
        .0
        .get("step_lineage_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    assert_eq!(
        prop_lineage,
        Some(op_lineage),
        "operation properties.step_lineage_id must mirror the column"
    );
    assert_eq!(row.1, Some(op_lineage));
}

#[sqlx::test(migrations = "../../migrations")]
async fn caller_supplied_lineage_uuid_preserved(pool: PgPool) {
    let preset = Uuid::new_v4();

    let extraction = build_one_of_each_extraction(
        "lineage-caller-supplied-test",
        "operation text for lineage-caller-supplied-test",
    );
    let mut plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);

    // Inject the caller-supplied lineage UUID into the level=2 step's
    // properties. The executor reads `planned.properties.get("step_lineage_id")`
    // and preserves valid values rather than minting a fresh one.
    let step_id = id_at(&plan, "phases[0].steps[0]");
    let step_planned = plan
        .claims
        .iter_mut()
        .find(|c| c.id == step_id)
        .expect("plan must contain the step claim");
    assert_eq!(step_planned.level, 2);
    step_planned
        .properties
        .as_object_mut()
        .expect("PlannedClaim.properties is a JSON object")
        .insert(
            "step_lineage_id".to_string(),
            serde_json::Value::String(preset.to_string()),
        );

    let _result = epigraph_ingest_executor::execute_workflow_ingest_plan(&pool, &plan, &extraction)
        .await
        .expect("ingest plan");

    let row: (Option<Uuid>,) = sqlx::query_as("SELECT step_lineage_id FROM claims WHERE id = $1")
        .bind(step_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        row.0,
        Some(preset),
        "caller-supplied step_lineage_id must be preserved"
    );

    // Properties JSONB must also reflect the preset.
    let props: (serde_json::Value,) = sqlx::query_as("SELECT properties FROM claims WHERE id = $1")
        .bind(step_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let prop_lineage = props
        .0
        .get("step_lineage_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    assert_eq!(prop_lineage, Some(preset));
}
