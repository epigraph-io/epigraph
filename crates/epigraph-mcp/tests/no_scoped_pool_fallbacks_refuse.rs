//! A server built WITHOUT a `ScopedPool` refuses `evolve_step`,
//! `improve_workflow_hierarchy` and `report_workflow_outcome` before any
//! claim, edge or workflow row is read or written (backlog 4cbd4192).
//! (`evolve_step` still resolves the server's own signer agent first, which
//! `agent_id` does on the raw pool for every server; that is a separate
//! register class, not one of the fallback arms removed here.)
//!
//! Each of the three used to carry a fallback arm for that server: the evolve
//! wrote its step on a `server.pool.begin()` transaction, the generation
//! lookup read `max_generation_by_canonical` on the raw pool, and the outcome
//! dispatch probed `WorkflowRepository::exists` there. A deployed server
//! always has a `ScopedPool`, so those arms only ever ran in a fixture, and on
//! the application role they would have read public rows only (a member's
//! own group-private workflow answered as unknown) or written with no
//! principal stamped. They now take the stamped path unconditionally, and the
//! stamped path's own guard (`EpiGraphMcpFull::read_as`,
//! `claim_helper::begin_author_stamped_tx`) refuses by name with nothing read
//! or written, as every content read and claim write already did.
//!
//! Every case is a superuser `#[sqlx::test]` database, where the raw pool
//! filters nothing, so the old fallback SUCCEEDED (the evolve wrote its step)
//! or answered from the raw pool (an unknown lineage was `invalid_params`
//! "no workflow with canonical_name", a non-workflows id with an
//! idempotency key was `invalid_params`). That is what makes each arm fail on
//! the old code: the refusal is an INTERNAL error naming the tool and
//! `ScopedPool`, reached before any claim, edge or workflow row is read or
//! written.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, build_unscoped_test_server, seed_caller};
use epigraph_auth::AuthContext;
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::tools;
use epigraph_mcp::tools::evolve_step::EvolveStepParams;
use epigraph_mcp::types::{
    ImproveWorkflowHierarchyParams, IngestWorkflowParams, ReportWorkflowOutcomeParams,
    StepExecution,
};
use epigraph_mcp::EpiGraphMcpFull;
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

fn extraction(canonical: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("no-scoped-pool goal {canonical}"),
            generation: 0,
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
            summary: format!("phase of {canonical}"),
            steps: vec![Step {
                compound: format!("first step of {canonical}"),
                rationale: "because".to_string(),
                operations: vec![format!("op of {canonical}")],
                generality: vec![1],
                confidence: 0.7,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

/// Ingest `canonical` on a SCOPED server as the token's agent, public in its
/// own group; returns the workflow id and its level-2 step.
async fn seed_workflow(
    pool: &PgPool,
    canonical: &str,
    viewer: &epigraph_db::visibility::Viewer,
    auth: &AuthContext,
) -> (Uuid, Uuid) {
    let scoped = build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await);
    tools::workflow_ingest::ingest_workflow(
        &scoped,
        viewer,
        IngestWorkflowParams {
            extraction: extraction(canonical),
            tenancy: Some(common::public_tenancy_for(viewer)),
            embed: None,
        },
        Some(auth),
    )
    .await
    .expect("seed ingest on the scoped server");
    sqlx::query_as(
        "SELECT w.id, e.target_id FROM workflows w \
           JOIN edges e ON e.source_id = w.id AND e.relationship = 'executes' \
           JOIN claims c ON c.id = e.target_id \
          WHERE w.canonical_name = $1 AND (c.properties->>'level')::int = 2",
    )
    .bind(canonical)
    .fetch_one(pool)
    .await
    .expect("the workflow's step")
}

/// The no-`ScopedPool` refusal: an INTERNAL error naming `tool` and the
/// missing `ScopedPool`, not an answer computed on the raw pool.
fn assert_no_scoped_pool_refusal(err: &epigraph_mcp::errors::McpError, tool: &str) {
    let msg = err.message.to_string();
    assert_eq!(
        err.code,
        ErrorCode::INTERNAL_ERROR,
        "{tool}: expected the no-ScopedPool refusal, got {:?}: {msg}",
        err.code
    );
    assert!(
        msg.starts_with(&format!("{tool}:")),
        "the refusal names {tool}: {msg}"
    );
    assert!(msg.contains("ScopedPool"), "names the missing pool: {msg}");
}

async fn count(pool: &PgPool, sql: &str, bind: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(bind)
        .fetch_one(pool)
        .await
        .expect("count")
}

/// `evolve_step` by its workflow's own submitter: admitted on a scoped
/// server, refused on an unscoped one with nothing written. The old fallback
/// wrote the step on `server.pool.begin()` and returned success.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_without_a_scoped_pool_is_refused_and_writes_nothing(pool: PgPool) {
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_wf, step) = seed_workflow(&pool, "no-scoped-evolve", &viewer, &token).await;
    let content = "an evolve attempted on a server with no ScopedPool";
    let claims_before: i64 = sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(&pool)
        .await
        .unwrap();
    let edges_into_step_before = count(
        &pool,
        "SELECT count(*) FROM edges WHERE target_id = $1 OR source_id = $1",
        step,
    )
    .await;

    let unscoped: EpiGraphMcpFull = build_unscoped_test_server(pool.clone());
    let err = tools::evolve_step::evolve_step(
        &unscoped,
        &viewer,
        EvolveStepParams {
            parent_id: step.to_string(),
            canonical_name: None,
            step_index: None,
            step_lineage_id: String::new(),
            content: content.to_string(),
            edge_type: "supersedes".to_string(),
            rationale: Some("no scoped pool".to_string()),
            level: Some(2),
        },
        Some(&token),
    )
    .await
    .expect_err("a server with no ScopedPool must refuse evolve_step");
    assert_no_scoped_pool_refusal(&err, "evolve_step");

    let with_content: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(with_content, 0, "no step claim was written");
    let claims_after: i64 = sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(claims_after, claims_before, "no claim of any kind");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM edges WHERE target_id = $1 OR source_id = $1",
            step,
        )
        .await,
        edges_into_step_before,
        "no edge on the parent step"
    );
    let current: bool =
        sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
            .bind(step)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(current, "the parent step is not retired");
}

/// `improve_workflow_hierarchy` reads the lineage's head generation on the
/// caller's stamp or not at all. The old fallback read it on the raw pool, so
/// an unknown lineage came back `invalid_params` ("no workflow with
/// canonical_name"), an answer computed from unstamped rows; a known one gets
/// the same refusal and no new generation.
#[sqlx::test(migrations = "../../migrations")]
async fn improve_workflow_hierarchy_without_a_scoped_pool_is_refused(pool: PgPool) {
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let unscoped = build_unscoped_test_server(pool.clone());

    let err = tools::workflow_ingest::improve_workflow_hierarchy(
        &unscoped,
        &viewer,
        ImproveWorkflowHierarchyParams {
            parent_canonical_name: "no-scoped-improve-unknown".to_string(),
            extraction: extraction("ignored"),
        },
        Some(&token),
    )
    .await
    .expect_err("a server with no ScopedPool must refuse improve_workflow_hierarchy");
    assert_no_scoped_pool_refusal(&err, "improve_workflow_hierarchy");

    let (_wf, _step) = seed_workflow(&pool, "no-scoped-improve", &viewer, &token).await;
    let err = tools::workflow_ingest::improve_workflow_hierarchy(
        &unscoped,
        &viewer,
        ImproveWorkflowHierarchyParams {
            parent_canonical_name: "no-scoped-improve".to_string(),
            extraction: extraction("ignored"),
        },
        Some(&token),
    )
    .await
    .expect_err("refused for a known lineage too");
    assert_no_scoped_pool_refusal(&err, "improve_workflow_hierarchy");
    let generations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
            .bind("no-scoped-improve")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(generations, 1, "no new generation was written");
}

fn outcome(workflow_id: Uuid, key: Option<&str>) -> ReportWorkflowOutcomeParams {
    ReportWorkflowOutcomeParams {
        workflow_id: workflow_id.to_string(),
        success: true,
        execution_log: vec![StepExecution {
            step_index: 0,
            planned: "plan".to_string(),
            actual: "did".to_string(),
            deviated: false,
            deviation_reason: None,
        }],
        outcome_details: "no scoped pool".to_string(),
        idempotency_key: key.map(str::to_string),
        quality: None,
        goal_text: None,
    }
}

/// `report_workflow_outcome` probes `workflows` on the caller's stamp or not
/// at all. The old fallback probed `WorkflowRepository::exists` on the raw
/// pool: an id that is not a `workflows` row, sent with an idempotency key,
/// came back `invalid_params` from that probe's answer. A real workflow id is
/// refused the same way, with no run row and no counter moved.
#[sqlx::test(migrations = "../../migrations")]
async fn report_workflow_outcome_without_a_scoped_pool_is_refused(pool: PgPool) {
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let unscoped = build_unscoped_test_server(pool.clone());

    let err = tools::workflows::report_workflow_outcome(
        &unscoped,
        &viewer,
        outcome(Uuid::new_v4(), Some("no-scoped-key")),
        Some(&token),
    )
    .await
    .expect_err("a server with no ScopedPool must refuse report_workflow_outcome");
    assert_no_scoped_pool_refusal(&err, "report_workflow_outcome");

    let (wf, _step) = seed_workflow(&pool, "no-scoped-report", &viewer, &token).await;
    let err = tools::workflows::report_workflow_outcome(
        &unscoped,
        &viewer,
        outcome(wf, None),
        Some(&token),
    )
    .await
    .expect_err("refused for a workflows-table id too");
    assert_no_scoped_pool_refusal(&err, "report_workflow_outcome");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM behavioral_executions WHERE workflow_id = $1",
            wf,
        )
        .await,
        0,
        "no run row"
    );
    let use_count: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT metadata->'use_count' FROM workflows WHERE id = $1")
            .bind(wf)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(use_count.is_none(), "no counter moved: {use_count:?}");
}
