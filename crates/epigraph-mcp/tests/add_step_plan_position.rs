//! `add_step(position = i)` places the step at plan slot `i` for EVERY
//! plan-order reader (backlog ca30e645, operator ruling R-38).
//!
//! # The defect this pins
//!
//! `add_step` rewires the `step_follows` chain so the new step sits at slot
//! `position`, but a middle insert's `executes` edge carries no `plan_index`
//! (R-38 accepts that: "position does not change plan_index"). Every reader
//! that turns a plan into step order sorted on `plan_index` with an
//! `ELSE 2147483647` fallback, so the inserted step came back LAST: from
//! `find_workflow`, from `find_workflow_hierarchical`, and from the
//! `step_index` resolution of `report_workflow_outcome` /
//! `report_hierarchical_outcome`, where an outcome reported against slot 1 was
//! attributed to a different step. The readers now walk `step_follows`.
//!
//! # Precondition
//!
//! The insert is asserted to be unindexed (`plan_index: null`), so a reader
//! keyed on `plan_index` alone would list it last and fail here.
//!
//! The frozen-plan read (`get_workflow_plan`) is deliberately NOT asserted: its
//! contract is the STORED `plan_index` order, with an unindexed edge counted
//! (`unindexed_edges`) and never given a synthetic slot.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::tools::step_ops::AddStepParams;
use epigraph_mcp::types::{
    FindWorkflowHierarchicalParams, FindWorkflowParams, ReportWorkflowOutcomeParams, StepExecution,
    StoreWorkflowParams,
};
use sqlx::PgPool;
use uuid::Uuid;

const STEPS: [&str; 3] = [
    "first: gather the inputs",
    "second: run the transform",
    "third: publish the output",
];
const INSERTED: &str = "inserted: validate the inputs";

/// The claim id of each step text under `workflow_id`.
async fn step_ids(pool: &PgPool, workflow_id: Uuid, texts: &[&str]) -> Vec<Uuid> {
    let mut out = Vec::new();
    for t in texts {
        let id: Uuid = sqlx::query_scalar(
            "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
             WHERE e.source_id = $1 AND e.relationship = 'executes' AND c.content = $2",
        )
        .bind(workflow_id)
        .bind(*t)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("step {t:?} under {workflow_id}: {e}"));
        out.push(id);
    }
    out
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_inserted_step_is_at_its_position_for_every_plan_order_reader(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let scoped = fixture::scoped_pool(&pool).await;
    let goal = format!("add step position probe {}", Uuid::new_v4());

    let stored = epigraph_mcp::tools::workflows::store_workflow(
        &server,
        &viewer,
        StoreWorkflowParams {
            goal: goal.clone(),
            steps: STEPS.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
        None,
    )
    .await
    .expect("store_workflow");
    let stored = first_text(&stored);
    let workflow_id = parse_uuid_field(&stored, "workflow_id");
    let canonical_name = stored["canonical_name"]
        .as_str()
        .expect("canonical_name")
        .to_string();

    let added = epigraph_mcp::tools::step_ops::add_step(
        &server,
        &viewer,
        AddStepParams {
            canonical_name: canonical_name.clone(),
            step_text: INSERTED.to_string(),
            position: Some(1),
        },
        None,
    )
    .await
    .expect("add_step at position 1");
    let added = first_text(&added);
    assert_eq!(added["step_index"], serde_json::json!(1), "{added}");
    assert_eq!(
        added["plan_index"],
        serde_json::Value::Null,
        "PRECONDITION: a middle insert is unindexed (R-38), so a plan_index-keyed reader \
         lists it last: {added}"
    );

    let want_texts = [STEPS[0], INSERTED, STEPS[1], STEPS[2]];
    let want_ids = step_ids(&pool, workflow_id, &want_texts).await;

    // MCP `find_workflow`: the hierarchical hit's steps, in plan order.
    let found = epigraph_mcp::tools::workflows::find_workflow(
        &server,
        &viewer,
        FindWorkflowParams {
            goal: goal.clone(),
            limit: Some(5),
            min_truth: Some(0.0),
        },
    )
    .await
    .expect("find_workflow");
    let found = first_text(&found);
    let hit = found
        .as_array()
        .expect("find_workflow returns an array")
        .iter()
        .find(|r| r["workflow_id"].as_str() == Some(&workflow_id.to_string()))
        .unwrap_or_else(|| panic!("find_workflow returns the stored workflow: {found}"))
        .clone();
    let steps: Vec<&str> = hit["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .map(|s| s.as_str().expect("step text"))
        .collect();
    assert_eq!(steps, want_texts, "find_workflow step order");

    // MCP `find_workflow_hierarchical(resolve_to_latest)`: resolved_steps.
    let found = epigraph_mcp::tools::workflow_hierarchical::find_workflow_hierarchical(
        &server,
        &viewer,
        FindWorkflowHierarchicalParams {
            query: goal.clone(),
            limit: Some(5),
            resolve_to_latest: Some(true),
            min_truth: Some(0.0),
        },
    )
    .await
    .expect("find_workflow_hierarchical");
    let found = first_text(&found);
    let entry = found["workflows"]
        .as_array()
        .expect("workflows")
        .iter()
        .find(|w| w["workflow_id"].as_str() == Some(&workflow_id.to_string()))
        .unwrap_or_else(|| panic!("the stored workflow is found: {found}"))
        .clone();
    let resolved: Vec<(u64, Uuid)> = entry["resolved_steps"]
        .as_array()
        .expect("resolved_steps")
        .iter()
        .map(|s| {
            (
                s["step_index"].as_u64().expect("step_index"),
                Uuid::parse_str(s["frozen_claim_id"].as_str().expect("frozen_claim_id"))
                    .expect("uuid"),
            )
        })
        .collect();
    let want_resolved: Vec<(u64, Uuid)> = want_ids
        .iter()
        .enumerate()
        .map(|(i, id)| (i as u64, *id))
        .collect();
    assert_eq!(
        resolved, want_resolved,
        "find_workflow_hierarchical resolved_steps"
    );

    // The readers behind the REST twins: `resolve_steps_to_heads_batched`
    // (GET find_workflow_hierarchical) and `plan_step_claim_ids` (POST
    // hierarchical outcome), on one viewer-stamped transaction.
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped tx");
    let batched = epigraph_db::WorkflowRepository::resolve_steps_to_heads_batched(
        &mut tx,
        &viewer,
        &[workflow_id],
    )
    .await
    .expect("batched resolution");
    let batched: Vec<(usize, Uuid)> = batched[&workflow_id]
        .iter()
        .map(|s| (s.step_index, s.frozen_claim_id))
        .collect();
    assert_eq!(
        batched,
        want_ids.iter().copied().enumerate().collect::<Vec<_>>(),
        "resolve_steps_to_heads_batched"
    );
    let planned =
        epigraph_db::WorkflowRepository::plan_step_claim_ids(&mut tx, &viewer, workflow_id)
            .await
            .expect("plan_step_claim_ids");
    assert_eq!(planned, want_ids, "plan_step_claim_ids");
    drop(tx);

    // `resolve_step_claim` (evolve_step / update_with_evidence by name+index).
    let slot1 = epigraph_db::WorkflowRepository::resolve_step_claim(
        &pool,
        &viewer,
        &canonical_name,
        1,
        false,
    )
    .await
    .expect("resolve_step_claim");
    assert_eq!(
        slot1,
        Some(want_ids[1]),
        "resolve_step_claim(step_index = 1)"
    );

    // MCP `report_workflow_outcome`: each step_index attributed to its slot.
    let execution_log: Vec<StepExecution> = want_texts
        .iter()
        .enumerate()
        .map(|(i, s)| StepExecution {
            step_index: i,
            planned: (*s).to_string(),
            actual: "done".to_string(),
            deviated: false,
            deviation_reason: None,
        })
        .collect();
    epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        ReportWorkflowOutcomeParams {
            workflow_id: workflow_id.to_string(),
            success: true,
            execution_log,
            outcome_details: "add_step position probe".to_string(),
            quality: None,
            goal_text: None,
        },
        None,
    )
    .await
    .expect("report_workflow_outcome");
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT b.tool_pattern[1], c.content \
         FROM behavioral_executions b LEFT JOIN claims c ON c.id = b.step_claim_id \
         WHERE b.workflow_id = $1 ORDER BY b.tool_pattern[1]",
    )
    .bind(workflow_id)
    .fetch_all(&pool)
    .await
    .expect("rows");
    assert_eq!(rows.len(), 4, "one row per reported step");
    let misattributed: Vec<String> = rows
        .iter()
        .filter(|(planned, got)| got.as_deref() != Some(planned.as_str()))
        .map(|(planned, got)| format!("{planned:?} -> {got:?}"))
        .collect();
    assert!(
        misattributed.is_empty(),
        "report_workflow_outcome attributed step_index values to the wrong step: \
         {misattributed:?}"
    );
}

fn extraction(canonical: &str, steps: &[&str]) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("{canonical} goal"),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some(format!("{canonical} thesis")),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Body".to_string(),
            summary: "Body".to_string(),
            steps: steps
                .iter()
                .map(|s| Step {
                    compound: (*s).to_string(),
                    rationale: String::new(),
                    operations: vec![],
                    generality: vec![],
                    confidence: 0.9,
                    evidence_type: None,
                })
                .collect(),
        }],
        relationships: vec![],
    }
}

/// Two generations of one `canonical_name` that keep the same step texts in a
/// DIFFERENT order share their step claims (ids are scoped to the name, not
/// the generation) and therefore each other's `step_follows` edges, which
/// together form a cycle over the shared set. Walking that would scramble
/// both; each generation's readers must still return its OWN plan order.
#[sqlx::test(migrations = "../../migrations")]
async fn generations_that_share_steps_keep_their_own_order(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let canonical = format!("shared-step-generations-{}", Uuid::new_v4());
    let gen1 = ["alpha step", "bravo step", "charlie step"];
    let gen2 = ["charlie step", "alpha step", "bravo step"];

    epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(
        &pool,
        &viewer,
        &extraction(&canonical, &gen1),
    )
    .await
    .expect("generation 0");
    let improved = epigraph_mcp::tools::workflow_ingest::improve_workflow_hierarchy_via_pool(
        &pool,
        &viewer,
        &canonical,
        extraction(&canonical, &gen2),
    )
    .await
    .expect("generation 1");
    let gen2_id = Uuid::parse_str(&improved.workflow_id).expect("uuid");
    let gen1_id: Uuid =
        sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1 AND generation = 0")
            .bind(&canonical)
            .fetch_one(&pool)
            .await
            .expect("generation 0 row");

    let shared: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges a JOIN edges b ON a.target_id = b.target_id \
         WHERE a.source_id = $1 AND b.source_id = $2 \
           AND a.relationship = 'executes' AND b.relationship = 'executes'",
    )
    .bind(gen1_id)
    .bind(gen2_id)
    .fetch_one(&pool)
    .await
    .expect("shared count");
    assert!(
        shared >= 3,
        "PRECONDITION: the generations share their step claims ({shared})"
    );
    // PRECONDITION: the shared `step_follows` pairs over the three shared
    // steps are a cycle (gen 0 writes a->b, b->c; gen 1 writes c->a, a->b), so
    // a naive chain walk has no head. Without this the assertions below would
    // pass vacuously if no chain had been written at all.
    let shared_steps = step_ids(&pool, gen1_id, &gen1).await;
    let pairs: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT DISTINCT source_id, target_id FROM edges \
         WHERE relationship = 'step_follows' \
           AND source_id = ANY($1) AND target_id = ANY($1)",
    )
    .bind(&shared_steps)
    .fetch_all(&pool)
    .await
    .expect("step_follows pairs");
    let (a, b, c) = (shared_steps[0], shared_steps[1], shared_steps[2]);
    for (from, to) in [(a, b), (b, c), (c, a)] {
        assert!(
            pairs.contains(&(from, to)),
            "PRECONDITION: the shared step_follows pairs form the cycle a->b->c->a; got {pairs:?}"
        );
    }

    for (id, want) in [(gen1_id, gen1), (gen2_id, gen2)] {
        let texts: Vec<String> = epigraph_db::WorkflowRepository::step_texts_for_hierarchical(
            &mut pool.acquire().await.expect("acquire"),
            &viewer,
            &[id],
        )
        .await
        .expect("step texts")
        .remove(&id)
        .unwrap_or_default();
        assert_eq!(texts, want, "step_texts_for_hierarchical for {id}");
        let resolved = epigraph_db::WorkflowRepository::resolve_steps_to_heads(&pool, &viewer, id)
            .await
            .expect("resolve");
        assert_eq!(
            resolved
                .iter()
                .map(|s| s.frozen_claim_id)
                .collect::<Vec<_>>(),
            step_ids(&pool, id, &want).await,
            "resolve_steps_to_heads for {id}"
        );
    }
}
