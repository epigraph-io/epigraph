//! Workflow structural claims must be content-addressed PER WORKFLOW
//! (backlog 6178a205).
//!
//! Every workflow claim is authored by the one `workflow-ingest-system` agent,
//! and migration 013 puts `UNIQUE (content_hash, agent_id)`
//! (`uq_claims_content_hash_agent`) on `claims`. The workflow builder and
//! `add_step` used to store the PLAIN `blake3(text)` on level 0–2 nodes, so any
//! thesis, phase or step text that a second workflow shared collided on that
//! constraint even though its row id (`compound_claim_id(hash, canonical_name)`)
//! was distinct. `store_workflow` files every workflow's steps under a constant
//! "Body" phase, so the SECOND `store_workflow` on a database always failed
//! ("Duplicate entity already exists") and wrote nothing.
//!
//! These drive the real writers (`store_workflow`, `do_ingest_workflow_via_pool`,
//! `add_step`) against a freshly migrated database with the constraint IN FORCE
//! — asserted up front, because `tests/common::drop_unique_constraint` exists
//! and a dropped constraint would make every assertion here vacuous.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_ingest::common::ids::{compound_content_hash, content_hash};
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::verify_claim;
use epigraph_mcp::tools::step_ops::AddStepParams;
use epigraph_mcp::types::{StoreWorkflowParams, VerifyClaimParams};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const SHARED_STEP: &str = "Run tests";

async fn assert_constraint_in_force(pool: &PgPool) {
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint \
                        WHERE conname = 'uq_claims_content_hash_agent')",
    )
    .fetch_one(pool)
    .await
    .expect("read pg_constraint");
    assert!(
        present,
        "uq_claims_content_hash_agent must be in force, or no collision can happen"
    );
}

async fn server(pool: &PgPool) -> EpiGraphMcpFull {
    // Stamped: the workflow ingest path refuses a server with no ScopedPool.
    build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await)
}

/// `store_workflow` and return `(workflow_id, canonical_name)`.
async fn store(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    goal: &str,
    steps: &[&str],
) -> Result<(Uuid, String), String> {
    let viewer = fixture::public_viewer(pool).await;
    let result = epigraph_mcp::tools::workflows::store_workflow(
        server,
        &viewer,
        StoreWorkflowParams {
            goal: goal.to_string(),
            steps: steps.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
        None,
    )
    .await
    .map_err(|e| format!("{e:?}"))?;
    let workflow_id = parse_uuid_field(&first_text(&result), "workflow_id");
    let name: String = sqlx::query_scalar("SELECT canonical_name FROM workflows WHERE id = $1")
        .bind(workflow_id)
        .fetch_one(pool)
        .await
        .expect("workflow row");
    Ok((workflow_id, name))
}

/// `(id, content_hash, agent_id)` of the level-`level` claim with `content`
/// that workflow `workflow_id` executes.
async fn executed_claim(
    pool: &PgPool,
    workflow_id: Uuid,
    level: i32,
    content: &str,
) -> (Uuid, Vec<u8>, Uuid) {
    sqlx::query_as(
        "SELECT c.id, c.content_hash, c.agent_id FROM claims c \
           JOIN edges e ON e.target_id = c.id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND c.content = $2 AND (c.properties->>'level')::int = $3",
    )
    .bind(workflow_id)
    .bind(content)
    .bind(level)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("workflow {workflow_id} level-{level} {content:?}: {e}"))
}

/// The bug as reported: a second `store_workflow` (same "Body" phase, and here
/// also the same step text) must succeed and write its own rows.
#[sqlx::test(migrations = "../../migrations")]
async fn second_store_workflow_sharing_phase_and_step_text_succeeds(pool: PgPool) {
    assert_constraint_in_force(&pool).await;
    let server = server(&pool).await;

    let (wf_a, _name_a) = store(
        &server,
        &pool,
        &format!("goal A {}", Uuid::new_v4()),
        &[SHARED_STEP],
    )
    .await
    .expect("first store_workflow");
    let (wf_b, name_b) = store(
        &server,
        &pool,
        &format!("goal B {}", Uuid::new_v4()),
        &[SHARED_STEP],
    )
    .await
    .expect("second store_workflow sharing the 'Body' phase and a step text");

    let (body_a, _, agent_a) = executed_claim(&pool, wf_a, 1, "Body").await;
    let (body_b, body_b_hash, agent_b) = executed_claim(&pool, wf_b, 1, "Body").await;
    assert_eq!(
        agent_a, agent_b,
        "both workflows must author as the same agent, or this test does not \
         exercise uq_claims_content_hash_agent"
    );
    assert_ne!(body_a, body_b, "each workflow gets its own Body phase row");
    assert_eq!(
        body_b_hash,
        compound_content_hash(&content_hash("Body"), &name_b).to_vec(),
        "the phase row must store compound_content_hash(blake3(text), canonical_name)"
    );

    let (step_a, _, _) = executed_claim(&pool, wf_a, 2, SHARED_STEP).await;
    let (step_b, step_b_hash, _) = executed_claim(&pool, wf_b, 2, SHARED_STEP).await;
    assert_ne!(step_a, step_b, "each workflow gets its own step row");
    assert_eq!(
        step_b_hash,
        compound_content_hash(&content_hash(SHARED_STEP), &name_b).to_vec(),
        "the step row must store compound_content_hash(blake3(text), canonical_name)"
    );

    let bodies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE content = 'Body' \
            AND (properties->>'level')::int = 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bodies, 2, "one Body phase row per stored workflow");
}

fn extraction_with_step(canonical: &str, step: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("goal of {canonical}"),
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
            // Unique to this workflow, so it cannot collide with B's "Body"
            // phase on main: the only shared text is the step.
            title: format!("phase of {canonical}"),
            summary: format!("phase of {canonical}"),
            steps: vec![Step {
                compound: step.to_string(),
                rationale: String::new(),
                operations: vec![],
                generality: vec![],
                confidence: 0.8,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

/// `add_step` with a step text another workflow already uses must write a new,
/// distinct step row.
///
/// Workflow A is created with `ingest_workflow` and a phase unique to it, so
/// B's `store_workflow` (the first "Body" phase in this database) succeeds even
/// before the fix — what fails is exactly `add_step`'s INSERT.
#[sqlx::test(migrations = "../../migrations")]
async fn add_step_text_already_used_by_another_workflow_succeeds(pool: PgPool) {
    assert_constraint_in_force(&pool).await;
    let server = server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;

    let name_a = format!("hash-scope-a-{}", Uuid::new_v4());
    epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(
        &pool,
        &viewer,
        &extraction_with_step(&name_a, SHARED_STEP),
    )
    .await
    .expect("ingest workflow A");
    let wf_a: Uuid = sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1")
        .bind(&name_a)
        .fetch_one(&pool)
        .await
        .expect("workflow A row");

    let (wf_b, name_b) = store(
        &server,
        &pool,
        &format!("goal B {}", Uuid::new_v4()),
        &["Prepare the fixture"],
    )
    .await
    .expect("store workflow B");

    let stdio = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("the server agent's stdio viewer");
    let added = epigraph_mcp::tools::step_ops::add_step(
        &server,
        &stdio,
        AddStepParams {
            canonical_name: name_b.clone(),
            step_text: SHARED_STEP.to_string(),
            position: None,
        },
        None,
    )
    .await
    .expect("add_step with a step text workflow A already uses");
    let added_id = parse_uuid_field(&first_text(&added), "step_claim_id");

    let (step_a, _, agent_a) = executed_claim(&pool, wf_a, 2, SHARED_STEP).await;
    let (step_b, step_b_hash, agent_b) = executed_claim(&pool, wf_b, 2, SHARED_STEP).await;
    assert_eq!(
        agent_a, agent_b,
        "both workflows' steps must author as the same agent, or this test does \
         not exercise uq_claims_content_hash_agent"
    );
    assert_eq!(step_b, added_id, "add_step reports the row it wrote");
    assert_ne!(step_a, step_b, "B's step is its own row, not A's");
    assert_eq!(
        step_b_hash,
        compound_content_hash(&content_hash(SHARED_STEP), &name_b).to_vec(),
        "add_step must store compound_content_hash(blake3(text), canonical_name)"
    );
}

/// Run `verify_claim` as the claim's own author.
async fn run_verify(pool: &PgPool, claim_id: Uuid) -> Value {
    let agent_id: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("claim must exist");
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent_id)
        .await
        .expect("resolve author viewer");
    let server = build_test_server(pool.clone());
    let result = verify_claim(
        &server,
        &viewer,
        VerifyClaimParams {
            claim_id: claim_id.to_string(),
        },
    )
    .await
    .expect("verify_claim");
    first_text(&result)
}

/// An UNTAMPERED step written by `store_workflow` stores a digest that is not
/// `blake3(content)` by construction, so `verify_claim` must answer
/// `not_applicable`, never accuse it of tampering with `mismatch`.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_claim_on_stored_workflow_step_is_not_a_mismatch(pool: PgPool) {
    let server = server(&pool).await;
    let step = format!("verify probe step {}", Uuid::new_v4());
    let (wf, _) = store(
        &server,
        &pool,
        &format!("verify probe goal {}", Uuid::new_v4()),
        &[step.as_str()],
    )
    .await
    .expect("store_workflow");
    let (step_id, _, _) = executed_claim(&pool, wf, 2, &step).await;

    let resp = run_verify(&pool, step_id).await;
    assert_eq!(
        resp["hash_check"],
        Value::String("not_applicable".to_string()),
        "a workflow step's stored digest is scoped to its canonical_name: {resp}"
    );
    assert_eq!(resp["hash_matches"], Value::Null, "{resp}");
}

/// Workflow rows written BEFORE this change keep their plain digest and must
/// keep verifying `match`: `verify_claim` compares before it classifies.
#[sqlx::test(migrations = "../../migrations")]
async fn legacy_plain_hash_workflow_step_still_matches(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let body = "Legacy step with a plain digest";
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, \
                             is_current, properties) \
         VALUES ($1, $2, $3, 0.5, $4, ARRAY[]::text[], true, $5)",
    )
    .bind(id)
    .bind(body)
    .bind(content_hash(body).as_slice())
    .bind(agent)
    .bind(serde_json::json!({"level": 2, "source_type": "workflow", "kind": "workflow_step"}))
    .execute(&pool)
    .await
    .expect("seed legacy workflow step");

    let resp = run_verify(&pool, id).await;
    assert_eq!(
        resp["hash_check"],
        Value::String("match".to_string()),
        "a legacy plain-digest workflow row must still verify: {resp}"
    );
}
