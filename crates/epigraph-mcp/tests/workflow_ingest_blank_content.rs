//! A workflow ingest whose payload carries blank claim content is the
//! CALLER's error: INVALID_PARAMS, naming the field, with nothing written.
//!
//! The executor's pre-flight (`IngestExecutorError::InvalidContent`) refuses
//! a blank thesis, phase, step or operation before any write, but the MCP
//! mapping (`errors::executor_caller_error`) had no arm for it, so the
//! caller's payload error came back as INTERNAL_ERROR: a server fault an
//! agent retries. Three blank shapes the builder passes through unchanged are
//! covered: a phase with a blank title AND summary (the title is the
//! fallback), a blank step `compound`, and a blank operation.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;

fn extraction(canonical: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: "Blank-content refusal probe".to_string(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some("A valid thesis".to_string()),
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "A phase".to_string(),
            summary: "A valid summary".to_string(),
            steps: vec![Step {
                compound: "do the thing".to_string(),
                rationale: "because".to_string(),
                operations: vec!["run it".to_string()],
                generality: vec![1],
                confidence: 0.8,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

async fn workflows_named(pool: &sqlx::PgPool, canonical: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
        .bind(canonical)
        .fetch_one(pool)
        .await
        .expect("count workflows")
}

#[sqlx::test(migrations = "../../migrations")]
async fn blank_claim_content_is_invalid_params_and_writes_nothing(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;

    let mut blank_phase = extraction("blank-content-phase");
    blank_phase.phases[0].title = "  ".to_string();
    blank_phase.phases[0].summary = String::new();
    let mut blank_step = extraction("blank-content-step");
    blank_step.phases[0].steps[0].compound = " ".to_string();
    let mut blank_op = extraction("blank-content-op");
    blank_op.phases[0].steps[0].operations = vec![String::new()];

    for (case, payload, path) in [
        ("blank phase title+summary", blank_phase, "phases[0]"),
        ("blank step compound", blank_step, "phases[0].steps[0]"),
        (
            "blank operation",
            blank_op,
            "phases[0].steps[0].operations[0]",
        ),
    ] {
        let canonical = payload.source.canonical_name.clone();
        let err = epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(
            &pool, &viewer, &payload,
        )
        .await
        .expect_err(case);
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "{case}: the caller's payload error, not a server fault; got {err:?}"
        );
        assert!(
            err.message
                .contains(&format!("blank claim content at {path}:")),
            "{case}: the refusal names the field; got: {}",
            err.message
        );
        assert_eq!(
            workflows_named(&pool, &canonical).await,
            0,
            "{case}: nothing was written"
        );
    }

    // Positive control: the same payload with its content intact ingests.
    epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(
        &pool,
        &viewer,
        &extraction("blank-content-control"),
    )
    .await
    .expect("a payload with content ingests");
    assert_eq!(workflows_named(&pool, "blank-content-control").await, 1);
}
