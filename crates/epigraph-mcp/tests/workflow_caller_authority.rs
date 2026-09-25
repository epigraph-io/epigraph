//! Batch H-b, H3 (backlog 84b2a98d): a system-stamped workflow mutation checks
//! the CALLER's authority over the workflow it names.
//!
//! The rule is forward-only, and these arms pin both halves of that:
//! a workflow CREATED through an ingest records its submitter and is then
//! mutable only by that submitter, its operator, or `claims:admin`; a workflow
//! with NO record (every workflow written before this change — nothing recorded
//! who created them) keeps today's behaviour. See
//! `src/tools/workflow_authority.rs` for the measurement.
//!
//! The decision is Rust-side and data-driven (`workflows.metadata`), so this
//! superuser harness observes it faithfully.
//!
//! Load-bearing, verified by reverting: `require_workflow_authority` returning
//! `Ok(owner)` without the gate fails
//! `a_stranger_cannot_add_or_delete_steps_on_a_submitted_workflow` and
//! `improving_someone_elses_workflow_is_refused`; recording the submitter
//! unconditionally (dropping the `creating` guard) fails
//! `a_reingest_by_another_caller_does_not_take_the_workflow_over`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_admin_grant, seed_caller};
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::tools;
use epigraph_mcp::tools::step_ops::{AddStepParams, DeleteStepParams};
use epigraph_mcp::types::{ImproveWorkflowHierarchyParams, IngestWorkflowParams};
use sqlx::PgPool;
use uuid::Uuid;

fn extraction(canonical: &str, metadata: serde_json::Value) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("H3 workflow {canonical}"),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata,
        },
        thesis: None,
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Body".to_string(),
            summary: format!("H3 phase for {canonical}"),
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

async fn submitter(pool: &PgPool, canonical: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT metadata->>'epigraph_submitted_by' FROM workflows \
          WHERE canonical_name = $1 ORDER BY generation DESC LIMIT 1",
    )
    .bind(canonical)
    .fetch_one(pool)
    .await
    .expect("workflow row")
}

async fn steps(pool: &PgPool, canonical: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges e JOIN workflows w ON w.id = e.source_id \
          WHERE w.canonical_name = $1 AND e.relationship = 'executes'",
    )
    .bind(canonical)
    .fetch_one(pool)
    .await
    .expect("count executes edges")
}

fn add(canonical: &str, text: &str) -> AddStepParams {
    AddStepParams {
        canonical_name: canonical.to_string(),
        step_text: text.to_string(),
        position: None,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_ingest_records_its_caller_and_strips_a_forged_submitter(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let forged = Uuid::new_v4();

    tools::workflow_ingest::ingest_workflow(
        &server,
        &viewer,
        IngestWorkflowParams {
            extraction: extraction(
                "h3-forged",
                serde_json::json!({"epigraph_submitted_by": forged.to_string(), "keep": 1}),
            ),
        },
        Some(&token),
    )
    .await
    .expect("ingest");
    assert_eq!(
        submitter(&pool, "h3-forged").await,
        Some(owner.to_string()),
        "the submitter is the caller, never a value the caller supplied"
    );
    let keep: Option<String> = sqlx::query_scalar(
        "SELECT metadata->>'keep' FROM workflows WHERE canonical_name = 'h3-forged'",
    )
    .fetch_one(&pool)
    .await
    .expect("metadata");
    assert_eq!(
        keep.as_deref(),
        Some("1"),
        "the caller's other metadata survives"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_cannot_add_or_delete_steps_on_a_submitted_workflow(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        &server,
        &owner_viewer,
        IngestWorkflowParams {
            extraction: extraction("h3-owned", serde_json::json!({})),
        },
        Some(&owner_token),
    )
    .await
    .expect("ingest");
    let before = steps(&pool, "h3-owned").await;

    let err = tools::step_ops::add_step(
        &server,
        &stranger_viewer,
        add("h3-owned", "a stranger's step"),
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger must not add a step to another caller's workflow");
    assert!(err.message.contains("cannot retire it"), "{}", err.message);
    assert_eq!(steps(&pool, "h3-owned").await, before, "nothing written");

    let lineage: Uuid = sqlx::query_scalar(
        "SELECT c.step_lineage_id FROM claims c JOIN edges e ON e.target_id = c.id \
           JOIN workflows w ON w.id = e.source_id \
          WHERE w.canonical_name = 'h3-owned' AND c.step_lineage_id IS NOT NULL LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("a step lineage");
    tools::step_ops::delete_step(
        &server,
        &stranger_viewer,
        DeleteStepParams {
            canonical_name: "h3-owned".to_string(),
            step_lineage_id: lineage.to_string(),
        },
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger must not delete another caller's step");

    // CALIBRATION: the submitter may, and so may a claims:admin holder.
    tools::step_ops::add_step(
        &server,
        &owner_viewer,
        add("h3-owned", "the owner's step"),
        Some(&owner_token),
    )
    .await
    .expect("the submitter adds a step");
    let (admin_token, admin_viewer) = common::server_admin(&server).await;
    seed_admin_grant(&pool, &admin_token).await;
    tools::step_ops::add_step(
        &server,
        &admin_viewer,
        add("h3-owned", "an admin's step"),
        Some(&admin_token),
    )
    .await
    .expect("claims:admin adds a step");
    assert_eq!(steps(&pool, "h3-owned").await, before + 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_workflow_with_no_record_keeps_todays_behaviour(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        &server,
        &owner_viewer,
        IngestWorkflowParams {
            extraction: extraction("h3-legacy", serde_json::json!({})),
        },
        Some(&owner_token),
    )
    .await
    .expect("ingest");
    // The shape of every workflow written before batch H-b.
    sqlx::query(
        "UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' \
          WHERE canonical_name = 'h3-legacy'",
    )
    .execute(&pool)
    .await
    .expect("forget the submitter");

    tools::step_ops::add_step(
        &server,
        &stranger_viewer,
        add("h3-legacy", "anyone's step, as before"),
        Some(&stranger_token),
    )
    .await
    .expect("a workflow with no recorded submitter stays open, as before H-b");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reingest_by_another_caller_does_not_take_the_workflow_over(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_other, other_token, other_viewer) = seed_caller(&pool, &["claims:write"]).await;
    for (viewer, token) in [(&owner_viewer, &owner_token), (&other_viewer, &other_token)] {
        tools::workflow_ingest::ingest_workflow(
            &server,
            viewer,
            IngestWorkflowParams {
                extraction: extraction("h3-reingest", serde_json::json!({})),
            },
            Some(token),
        )
        .await
        .expect("ingest (the second is an idempotent re-ingest)");
    }
    assert_eq!(
        submitter(&pool, "h3-reingest").await,
        Some(owner.to_string())
    );

    // And a re-ingest of a LEGACY row must not claim it either.
    sqlx::query(
        "UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' \
          WHERE canonical_name = 'h3-reingest'",
    )
    .execute(&pool)
    .await
    .expect("forget the submitter");
    tools::workflow_ingest::ingest_workflow(
        &server,
        &other_viewer,
        IngestWorkflowParams {
            extraction: extraction("h3-reingest", serde_json::json!({})),
        },
        Some(&other_token),
    )
    .await
    .expect("re-ingest of a legacy row");
    assert_eq!(
        submitter(&pool, "h3-reingest").await,
        None,
        "re-ingesting a legacy workflow must not make the caller its owner"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn improving_someone_elses_workflow_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        &server,
        &owner_viewer,
        IngestWorkflowParams {
            extraction: extraction("h3-improve", serde_json::json!({})),
        },
        Some(&owner_token),
    )
    .await
    .expect("ingest");
    let improve = |ex: WorkflowExtraction| ImproveWorkflowHierarchyParams {
        parent_canonical_name: "h3-improve".to_string(),
        extraction: ex,
    };

    tools::workflow_ingest::improve_workflow_hierarchy(
        &server,
        &stranger_viewer,
        improve(extraction("ignored", serde_json::json!({}))),
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger must not add a generation to another caller's lineage");
    let generations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = 'h3-improve'")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(generations, 1, "nothing written");

    let mut refined = extraction("ignored", serde_json::json!({}));
    refined.phases[0].summary = "a refined phase".to_string();
    tools::workflow_ingest::improve_workflow_hierarchy(
        &server,
        &owner_viewer,
        improve(refined),
        Some(&owner_token),
    )
    .await
    .expect("the owner improves its own workflow");
    assert_eq!(
        submitter(&pool, "h3-improve").await,
        Some(owner.to_string()),
        "the new generation inherits its parent's submitter"
    );
}

/// An extraction with no metadata stores a JSON `null`, which `jsonb_set`
/// refuses as a scalar (measured: the HTTP ingest 500'd on it before the repo
/// normalised it). The submitter must still be recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn an_ingest_with_null_metadata_still_records_its_caller(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        &server,
        &viewer,
        IngestWorkflowParams {
            extraction: extraction("h3-null-metadata", serde_json::Value::Null),
        },
        Some(&token),
    )
    .await
    .expect("ingest with null metadata");
    assert_eq!(
        submitter(&pool, "h3-null-metadata").await,
        Some(owner.to_string())
    );
}

/// stdio is unchanged (the batch H-b bar changes stdio only for #374): a stdio
/// caller is not checked against the recorded submitter, as `patch_claim`'s
/// whole-patch ownership check is HTTP-only. The submitter IS still recorded
/// for a stdio ingest, so an HTTP stranger cannot take the workflow over.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_is_unchanged_but_a_stdio_ingest_is_still_owned(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = server.server_agent_id().await.expect("server agent");
    let public = fixture::public_viewer(&pool).await;
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        &server,
        &owner_viewer,
        IngestWorkflowParams {
            extraction: extraction("h3-http-owned-stdio", serde_json::json!({})),
        },
        Some(&owner_token),
    )
    .await
    .expect("ingest over HTTP");
    tools::step_ops::add_step(
        &server,
        &public,
        add("h3-http-owned-stdio", "a stdio step"),
        None,
    )
    .await
    .expect("stdio is not checked, as before batch H-b");

    tools::workflow_ingest::ingest_workflow(
        &server,
        &public,
        IngestWorkflowParams {
            extraction: extraction("h3-stdio-owned", serde_json::json!({})),
        },
        None,
    )
    .await
    .expect("ingest over stdio");
    assert_eq!(
        submitter(&pool, "h3-stdio-owned").await,
        Some(server_agent.to_string())
    );
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    tools::step_ops::add_step(
        &server,
        &stranger_viewer,
        add("h3-stdio-owned", "an HTTP stranger's step"),
        Some(&stranger_token),
    )
    .await
    .expect_err("an HTTP stranger must not add to a stdio agent's workflow");
}
