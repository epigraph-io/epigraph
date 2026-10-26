//! Regression tests for the pre-flight *empty-generation* guard in
//! [`epigraph_ingest_executor::execute_workflow_ingest_plan`] (U032, backlog
//! 28fb40c4 / 1e6872e7).
//!
//! `WorkflowExtraction::thesis` and `::phases` are `#[serde(default)]` and the
//! schema has no `deny_unknown_fields`, so a payload that puts its steps under
//! an unrecognised key parses as an extraction with no steps. Two shapes were
//! accepted before U032:
//!
//! * a NEW generation (> 0) planning only its thesis (and maybe phase
//!   headers): it committed as a step-less generation, and because
//!   `improve_workflow_hierarchy` mints `max(generation) + 1` on every call, an
//!   agent retrying it minted a fresh empty head per attempt (the
//!   `weekly-capability-audit-…` gens 3-9 and `design-or-improve-…` gens 4-6);
//! * a plan with NO claims at all: a bare `workflows` row with no `executes`
//!   edges, which the step-1 idempotency gate (`edge_count > 0`) then treats as
//!   "not yet processed" forever.
//!
//! Generation 0 with a thesis and no steps stays legal: `store_workflow` and
//! `POST /workflows` build exactly that scaffold for `steps: []`, and
//! `add_step` fills it in place without minting a generation.

use sqlx::PgPool;

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::builder::build_ingest_plan;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_ingest_executor::error::IngestExecutorError;
use epigraph_ingest_executor::{execute_workflow_ingest_plan, WorkflowIngestExecutionResult};

fn extraction(canonical_name: &str, generation: u32) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical_name.to_string(),
            goal: "Scan the capability registry and diff against the live tool list".to_string(),
            generation,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some("The capability registry must match the live tool list".to_string()),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Scan".to_string(),
            summary: "Enumerate the live tools".to_string(),
            steps: vec![Step {
                compound: format!("List every registered MCP tool (generation {generation})"),
                rationale: "Establish the live baseline".to_string(),
                operations: vec!["Call list_mcp_tools".to_string()],
                generality: vec![1],
                confidence: 0.9,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

async fn run(
    pool: &PgPool,
    x: &WorkflowExtraction,
) -> Result<WorkflowIngestExecutionResult, IngestExecutorError> {
    let plan = build_ingest_plan(x);
    execute_workflow_ingest_plan(&mut pool.acquire().await.expect("acquire"), &plan, x).await
}

async fn rows(pool: &PgPool, canonical: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM workflows WHERE canonical_name = $1")
        .bind(canonical)
        .fetch_one(pool)
        .await
        .expect("count workflows")
}

fn assert_empty_generation(err: IngestExecutorError, canonical: &str, generation: i32) {
    match err {
        IngestExecutorError::EmptyGeneration {
            canonical_name,
            generation: g,
            level2,
            ..
        } => {
            assert_eq!(canonical_name, canonical);
            assert_eq!(g, generation);
            assert_eq!(level2, 0, "the refused plan has no step claims");
        }
        other => panic!("expected EmptyGeneration, got: {other:?}"),
    }
}

/// A new generation that plans only its thesis (the shape a payload with its
/// steps under an unrecognised key parses into) is refused, and no stub row is
/// written — so a retry cannot mint another one either.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_generation_with_no_steps_is_refused_and_writes_nothing(pool: PgPool) {
    let canonical = "u032-empty";
    run(&pool, &extraction(canonical, 0))
        .await
        .expect("generation 0 with one step ingests");

    let mut stub = extraction(canonical, 1);
    stub.source.parent_canonical_name = Some(canonical.to_string());
    stub.phases = vec![];
    for _retry in 0..2 {
        let err = run(&pool, &stub)
            .await
            .expect_err("a step-less generation above 0 must be refused");
        assert_empty_generation(err, canonical, 1);
    }
    assert_eq!(rows(&pool, canonical).await, 1, "no stub generation row");
}

/// Phase headers with no steps under them are still a step-less generation.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_generation_with_phases_but_no_steps_is_refused(pool: PgPool) {
    let canonical = "u032-empty-phases";
    run(&pool, &extraction(canonical, 0))
        .await
        .expect("generation 0 with one step ingests");

    let mut stub = extraction(canonical, 1);
    stub.phases[0].steps = vec![];
    let plan = build_ingest_plan(&stub);
    assert!(
        plan.claims.iter().any(|c| c.level == 1),
        "precondition: the stub plans a level-1 phase claim, so only the step count can refuse it"
    );
    let err = run(&pool, &stub)
        .await
        .expect_err("a generation above 0 with phase headers but no steps must be refused");
    assert_empty_generation(err, canonical, 1);
    assert_eq!(rows(&pool, canonical).await, 1, "no stub generation row");
}

/// Over-correction guard: generation 0 with a thesis and no steps is the
/// `store_workflow` / `POST /workflows` `steps: []` scaffold and must ingest.
#[sqlx::test(migrations = "../../migrations")]
async fn generation_zero_scaffold_with_no_steps_is_still_accepted(pool: PgPool) {
    let canonical = "u032-scaffold";
    let mut scaffold = extraction(canonical, 0);
    scaffold.phases = vec![];
    let r = run(&pool, &scaffold)
        .await
        .expect("the gen-0 thesis-only scaffold must ingest");
    assert_eq!(r.claims_ingested, 1, "the thesis is written");
    assert_eq!(
        r.executes_edges_created, 1,
        "the thesis is executed by the row"
    );
    assert_eq!(rows(&pool, canonical).await, 1);
}

/// A plan with no claims at all is refused at ANY generation: it would write a
/// bare row that the idempotency gate never recognises as processed.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_plan_is_refused_at_any_generation(pool: PgPool) {
    let canonical = "u032-contentless";
    let mut empty = extraction(canonical, 0);
    empty.thesis = None;
    empty.phases = vec![];
    assert!(
        build_ingest_plan(&empty).claims.is_empty(),
        "precondition: no thesis and no phases plans zero claims"
    );
    let err = run(&pool, &empty)
        .await
        .expect_err("a plan with zero claims must be refused even at generation 0");
    assert_empty_generation(err, canonical, 0);
    assert_eq!(rows(&pool, canonical).await, 0, "no bare workflows row");
}

/// The blank-content pre-flight still runs FIRST: a blank thesis with a
/// step-less phase keeps its `InvalidContent` error (which
/// `improve_workflow_hierarchy_rejects_empty_thesis` asserts on), rather than
/// being reported as an empty generation.
#[sqlx::test(migrations = "../../migrations")]
async fn blank_content_is_still_reported_before_an_empty_generation(pool: PgPool) {
    let canonical = "u032-blank-first";
    let mut bad = extraction(canonical, 1);
    bad.thesis = Some(String::new());
    bad.phases[0].steps = vec![];
    match run(&pool, &bad).await {
        Err(IngestExecutorError::InvalidContent { path }) => assert_eq!(path, "thesis"),
        other => panic!("expected InvalidContent at thesis, got: {other:?}"),
    }
}

/// The guard runs BEFORE the step-1 idempotency gate: re-ingesting a
/// generation that is already processed (it has its `executes` edges) with an
/// empty plan is refused as `EmptyGeneration`, not reported
/// `already_ingested` — the caller's payload is malformed either way, and a
/// silent "already done" would hide that its steps were dropped.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_reingest_of_a_processed_generation_is_refused_not_already_ingested(pool: PgPool) {
    let canonical = "u032-empty-reingest";
    run(&pool, &extraction(canonical, 0))
        .await
        .expect("generation 0 with one step ingests");
    let g1 = run(&pool, &extraction(canonical, 1))
        .await
        .expect("generation 1 with one step ingests");
    assert!(
        g1.executes_edges_created > 0,
        "precondition: gen 1 is processed"
    );

    let mut stub = extraction(canonical, 1);
    stub.phases = vec![];
    let err = run(&pool, &stub)
        .await
        .expect_err("an empty re-ingest must be refused before the idempotency gate");
    assert_empty_generation(err, canonical, 1);
    assert_eq!(rows(&pool, canonical).await, 2, "nothing new written");
}
