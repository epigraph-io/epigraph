//! Batch H-b, H3 (backlog 84b2a98d): a system-stamped workflow mutation checks
//! the CALLER's authority over the workflow it names.
//!
//! These arms pin both halves of the rule: a workflow CREATED through an
//! ingest records its submitter and is then mutable, over the authenticated
//! transport, only by that submitter, its operator, or the audited
//! `claims:admin` path; a workflow with NO record (every workflow written
//! before batch H-b — nothing recorded who created them) is platform corpus
//! (U005, default decision A) and is mutable over that transport ONLY through
//! the audited `claims:admin` path. stdio is unchanged for both. See
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
//! `a_reingest_by_another_caller_does_not_take_the_workflow_over`; restoring
//! the WARN-and-allow arm for a workflow with no record fails
//! `a_legacy_workflow_with_no_record_is_refused_to_a_non_admin_http_caller` and
//! `a_legacy_workflow_is_mutable_only_through_the_audited_admin_arm`.

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
    assert!(
        err.message.contains("was submitted by agent"),
        "{}",
        err.message
    );
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

/// Ingest `canonical` as `owner`, then strip the recorded submitter: the shape
/// of every workflow written before batch H-b (nothing recorded who created
/// them). Returns the lineage of its one step.
async fn legacy_workflow(
    pool: &PgPool,
    server: &epigraph_mcp::EpiGraphMcpFull,
    owner_viewer: &epigraph_db::visibility::Viewer,
    owner_token: &epigraph_auth::AuthContext,
    canonical: &str,
) -> Uuid {
    tools::workflow_ingest::ingest_workflow(
        server,
        owner_viewer,
        IngestWorkflowParams {
            extraction: extraction(canonical, serde_json::json!({})),
        },
        Some(owner_token),
    )
    .await
    .expect("ingest");
    sqlx::query(
        "UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' \
          WHERE canonical_name = $1",
    )
    .bind(canonical)
    .execute(pool)
    .await
    .expect("forget the submitter");
    assert_eq!(submitter(pool, canonical).await, None, "a legacy row");
    sqlx::query_scalar(
        "SELECT c.step_lineage_id FROM claims c JOIN edges e ON e.target_id = c.id \
           JOIN workflows w ON w.id = e.source_id \
          WHERE w.canonical_name = $1 AND c.step_lineage_id IS NOT NULL LIMIT 1",
    )
    .bind(canonical)
    .fetch_one(pool)
    .await
    .expect("a step lineage")
}

/// The truth of every claim of a step lineage, in id order.
async fn lineage_truths(pool: &PgPool, lineage: Uuid) -> Vec<f64> {
    sqlx::query_scalar("SELECT truth_value FROM claims WHERE step_lineage_id = $1 ORDER BY id")
        .bind(lineage)
        .fetch_all(pool)
        .await
        .expect("lineage truths")
}

/// U005 (backlog 84b2a98d), default decision A: a workflow with no recorded
/// submitter is PLATFORM corpus. Over the authenticated transport a
/// `claims:write` caller may not mutate it — not a stranger, and not the agent
/// that happened to ingest it, since nothing records that it did. Before this
/// change every arm below was admitted with a WARN (`delete_step` drove the
/// step's truth to 0.05).
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_workflow_with_no_record_is_refused_to_a_non_admin_http_caller(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let lineage = legacy_workflow(&pool, &server, &owner_viewer, &owner_token, "h3-legacy").await;
    let before = steps(&pool, "h3-legacy").await;
    let truths = lineage_truths(&pool, lineage).await;

    let err = tools::step_ops::add_step(
        &server,
        &stranger_viewer,
        add("h3-legacy", "a stranger's step"),
        Some(&stranger_token),
    )
    .await
    .expect_err("a legacy workflow is platform corpus: claims:write alone may not mutate it");
    assert!(
        err.message.contains("no recorded submitter"),
        "the refusal names the legacy rule: {}",
        err.message
    );
    assert!(
        err.message.contains("audited claims:admin path"),
        "the refusal names the one arm that admits: {}",
        err.message
    );
    assert_eq!(steps(&pool, "h3-legacy").await, before, "nothing written");

    // The ORIGINAL ingester is refused too: no record says it submitted it.
    let err = tools::step_ops::add_step(
        &server,
        &owner_viewer,
        add("h3-legacy", "the ingester's step"),
        Some(&owner_token),
    )
    .await
    .expect_err("no record means no submitter arm");
    assert!(
        err.message.contains("no recorded submitter"),
        "{}",
        err.message
    );
    assert_eq!(steps(&pool, "h3-legacy").await, before, "nothing written");

    tools::step_ops::delete_step(
        &server,
        &stranger_viewer,
        DeleteStepParams {
            canonical_name: "h3-legacy".to_string(),
            step_lineage_id: lineage.to_string(),
        },
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger must not soft-delete a legacy workflow's step");
    assert_eq!(
        lineage_truths(&pool, lineage).await,
        truths,
        "the step's truth is untouched (not driven to 0.05)"
    );

    tools::workflow_ingest::improve_workflow_hierarchy(
        &server,
        &stranger_viewer,
        ImproveWorkflowHierarchyParams {
            parent_canonical_name: "h3-legacy".to_string(),
            extraction: extraction("ignored", serde_json::json!({})),
        },
        Some(&stranger_token),
    )
    .await
    .expect_err("a stranger must not add a generation to a legacy lineage");
    assert_eq!(
        generation_rows(&pool, "h3-legacy").await,
        vec![(0, None)],
        "no generation-1 row"
    );
}

/// The arm that DOES admit a legacy workflow over the authenticated transport:
/// the audited admin path, exactly as for a submitted workflow — the token's
/// `claims:admin` re-checked against its client record (ADM02), and the write
/// recorded as `workflows.admin_write` with `"submitter": null`. A new
/// generation of a legacy lineage inherits no record, so platform lineage stays
/// platform.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_workflow_is_mutable_only_through_the_audited_admin_arm(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    legacy_workflow(
        &pool,
        &server,
        &owner_viewer,
        &owner_token,
        "h3-legacy-admin",
    )
    .await;
    let before = steps(&pool, "h3-legacy-admin").await;

    let (grantless, admin_viewer) = common::server_admin(&server).await;
    let admin = grantless.agent_id.expect("admin agent");
    let err = tools::step_ops::add_step(
        &server,
        &admin_viewer,
        add("h3-legacy-admin", "a grantless admin's step"),
        Some(&grantless),
    )
    .await
    .expect_err("claims:admin in the token alone does not admit a legacy workflow either");
    assert!(err.message.contains("ADM02"), "{}", err.message);
    assert!(
        err.message.contains("no recorded submitter"),
        "{}",
        err.message
    );
    assert_eq!(
        steps(&pool, "h3-legacy-admin").await,
        before,
        "nothing written"
    );
    assert_eq!(workflow_admin_audits(&pool, admin).await, 0);

    let (granted, _) = common::server_admin(&server).await;
    seed_admin_grant(&pool, &granted).await;
    tools::step_ops::add_step(
        &server,
        &admin_viewer,
        add("h3-legacy-admin", "an audited admin's step"),
        Some(&granted),
    )
    .await
    .expect("a live claims:admin grant adds a step to a legacy workflow");
    assert_eq!(steps(&pool, "h3-legacy-admin").await, before + 1);
    assert_eq!(
        workflow_admin_audits(&pool, admin).await,
        1,
        "the admin write on a legacy workflow is audited"
    );
    let head: Uuid =
        sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = 'h3-legacy-admin'")
            .fetch_one(&pool)
            .await
            .expect("workflow id");
    // `->>` cannot tell a JSON null from a missing key; the record must carry
    // the key, null.
    let (workflow, submitter_kind): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT details->>'workflow_id', jsonb_typeof(details->'submitter') \
           FROM security_events WHERE event_type = 'workflows.admin_write' AND agent_id = $1",
    )
    .bind(admin)
    .fetch_one(&pool)
    .await
    .expect("audit row");
    assert_eq!(workflow, Some(head.to_string()));
    assert_eq!(
        submitter_kind.as_deref(),
        Some("null"),
        "\"submitter\": null"
    );

    // A new generation through the admin arm: admitted, audited, and it
    // inherits NO record, so the lineage stays platform corpus.
    let mut refined = extraction("ignored", serde_json::json!({}));
    refined.phases[0].summary = "an admin's refined phase".to_string();
    tools::workflow_ingest::improve_workflow_hierarchy(
        &server,
        &admin_viewer,
        ImproveWorkflowHierarchyParams {
            parent_canonical_name: "h3-legacy-admin".to_string(),
            extraction: refined,
        },
        Some(&granted),
    )
    .await
    .expect("the audited admin arm improves a legacy lineage");
    assert_eq!(
        generation_rows(&pool, "h3-legacy-admin").await,
        vec![(0, None), (1, None)],
        "the new generation records no submitter: platform lineage stays platform"
    );
    assert_eq!(workflow_admin_audits(&pool, admin).await, 2);
}

/// stdio is unchanged (the batch H-b bar): a stdio caller is not checked, on a
/// legacy workflow as on a submitted one. Passes before and after U005; it
/// pins that the legacy rule did not reach stdio.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_still_mutates_a_legacy_workflow(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let public = fixture::public_viewer(&pool).await;
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    legacy_workflow(
        &pool,
        &server,
        &owner_viewer,
        &owner_token,
        "h3-legacy-stdio",
    )
    .await;
    let before = steps(&pool, "h3-legacy-stdio").await;
    tools::step_ops::add_step(
        &server,
        &public,
        add("h3-legacy-stdio", "a stdio step"),
        None,
    )
    .await
    .expect("stdio is not checked, legacy or not");
    assert_eq!(steps(&pool, "h3-legacy-stdio").await, before + 1);
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

async fn generation_rows(pool: &PgPool, canonical: &str) -> Vec<(i32, Option<String>)> {
    sqlx::query_as(
        "SELECT generation, metadata->>'epigraph_submitted_by' FROM workflows \
          WHERE canonical_name = $1 ORDER BY generation",
    )
    .bind(canonical)
    .fetch_all(pool)
    .await
    .expect("generations")
}

async fn workflow_admin_audits(pool: &PgPool, admin: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'workflows.admin_write' AND agent_id = $1",
    )
    .bind(admin)
    .fetch_one(pool)
    .await
    .expect("count audit rows")
}

/// Batch H-b review (authority-attack, high), reproduced on the real binary:
/// ingesting `generation + 1` of another agent's lineage with NO
/// `parent_canonical_name` needed no authority and recorded the ATTACKER as
/// submitter, after which every head-keyed check admitted the attacker and
/// refused the real submitter. A new generation of an existing name is a
/// generation of that lineage, parent or no parent, and a gap generation is no
/// exception.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_generation_cannot_take_a_lineage_over_without_naming_a_parent(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_attacker, attacker_token, attacker_viewer) = seed_caller(&pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        &server,
        &owner_viewer,
        IngestWorkflowParams {
            extraction: extraction("h3-lineage", serde_json::json!({})),
        },
        Some(&owner_token),
    )
    .await
    .expect("the owner ingests generation 0");

    for generation in [1_u32, 5] {
        let mut hijack = extraction("h3-lineage", serde_json::json!({}));
        hijack.source.generation = generation;
        hijack.phases[0].summary = format!("the attacker's generation {generation}");
        let err = tools::workflow_ingest::ingest_workflow(
            &server,
            &attacker_viewer,
            IngestWorkflowParams { extraction: hijack },
            Some(&attacker_token),
        )
        .await
        .expect_err("a stranger must not add a generation to another agent's lineage");
        assert!(
            err.message.contains("was submitted by agent"),
            "a workflow-specific refusal, not the claim gate's: {}",
            err.message
        );
    }
    assert_eq!(
        generation_rows(&pool, "h3-lineage").await,
        vec![(0, Some(owner.to_string()))],
        "nothing written: no attacker generation, no attacker submitter"
    );
    // The real submitter keeps its lineage.
    tools::step_ops::add_step(
        &server,
        &owner_viewer,
        add("h3-lineage", "the owner's step after the attempt"),
        Some(&owner_token),
    )
    .await
    .expect("the submitter still mutates its own lineage");

    // CALIBRATION: the owner's own parentless new generation is admitted and
    // INHERITS the lineage's submitter.
    let mut next = extraction("h3-lineage", serde_json::json!({}));
    next.source.generation = 1;
    next.phases[0].summary = "the owner's generation 1".to_string();
    tools::workflow_ingest::ingest_workflow(
        &server,
        &owner_viewer,
        IngestWorkflowParams { extraction: next },
        Some(&owner_token),
    )
    .await
    .expect("the submitter adds a generation to its own lineage");
    assert_eq!(
        generation_rows(&pool, "h3-lineage").await,
        vec![(0, Some(owner.to_string())), (1, Some(owner.to_string()))]
    );
}

/// A variant is checked against EXACTLY the row the executor links as
/// `parent_id` (`parent_canonical_name` at `generation - 1`), and a brand-new
/// name forked from someone else's workflow needs authority over that parent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fork_under_a_new_name_needs_authority_over_the_linked_parent(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (stranger, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        &server,
        &owner_viewer,
        IngestWorkflowParams {
            extraction: extraction("h3-fork-parent", serde_json::json!({})),
        },
        Some(&owner_token),
    )
    .await
    .expect("ingest the parent");
    let mut fork = extraction("h3-fork-child", serde_json::json!({}));
    fork.source.generation = 1;
    fork.source.parent_canonical_name = Some("h3-fork-parent".to_string());
    tools::workflow_ingest::ingest_workflow(
        &server,
        &stranger_viewer,
        IngestWorkflowParams {
            extraction: fork.clone(),
        },
        Some(&stranger_token),
    )
    .await
    .expect_err("a variant linked to another agent's workflow needs authority over it");
    assert!(generation_rows(&pool, "h3-fork-child").await.is_empty());

    // Naming a parent generation that does not exist links nothing, so it is a
    // brand-new lineage of the stranger's own.
    fork.source.generation = 7;
    tools::workflow_ingest::ingest_workflow(
        &server,
        &stranger_viewer,
        IngestWorkflowParams { extraction: fork },
        Some(&stranger_token),
    )
    .await
    .expect("no linked parent: the stranger's own new lineage");
    assert_eq!(
        generation_rows(&pool, "h3-fork-child").await,
        vec![(7, Some(stranger.to_string()))]
    );
}

/// Batch H-b review (authority-attack, high): the admin arm admitted on the
/// token's SCOPE alone, and the write ran on the system stamp, so a token whose
/// client record grants nothing kept cross-owner workflow mutation and no
/// audit row was written. Now the client record is re-checked and an admitted
/// write records `workflows.admin_write` on its own transaction.
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_admin_write_is_audited_and_a_grantless_admin_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        &server,
        &owner_viewer,
        IngestWorkflowParams {
            extraction: extraction("h3-admin", serde_json::json!({})),
        },
        Some(&owner_token),
    )
    .await
    .expect("ingest");
    let before = steps(&pool, "h3-admin").await;

    // A claims:admin token whose `sub` is no granting client record.
    let (grantless, admin_viewer) = common::server_admin(&server).await;
    let admin = grantless.agent_id.expect("admin agent");
    let err = tools::step_ops::add_step(
        &server,
        &admin_viewer,
        add("h3-admin", "a grantless admin's step"),
        Some(&grantless),
    )
    .await
    .expect_err("claims:admin in the token alone is not the audited admin path");
    assert!(err.message.contains("ADM02"), "{}", err.message);
    assert_eq!(steps(&pool, "h3-admin").await, before, "nothing written");
    assert_eq!(workflow_admin_audits(&pool, admin).await, 0);

    // The same agent with a live grant on its client record: admitted, audited.
    let (granted, _) = common::server_admin(&server).await;
    seed_admin_grant(&pool, &granted).await;
    tools::step_ops::add_step(
        &server,
        &admin_viewer,
        add("h3-admin", "an audited admin's step"),
        Some(&granted),
    )
    .await
    .expect("a live claims:admin grant adds a step");
    assert_eq!(steps(&pool, "h3-admin").await, before + 1);
    assert_eq!(workflow_admin_audits(&pool, admin).await, 1);
    let (workflow, submitter, client): (Option<String>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT details->>'workflow_id', details->>'submitter', details->>'client_id' \
               FROM security_events WHERE event_type = 'workflows.admin_write' AND agent_id = $1",
        )
        .bind(admin)
        .fetch_one(&pool)
        .await
        .expect("audit row");
    let head: Uuid =
        sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = 'h3-admin'")
            .fetch_one(&pool)
            .await
            .expect("workflow id");
    assert_eq!(workflow, Some(head.to_string()));
    assert_eq!(submitter, Some(owner.to_string()));
    assert_eq!(client, Some(granted.client_id.to_string()));

    // The submitter's own write is not an admin write and records nothing.
    tools::step_ops::add_step(
        &server,
        &owner_viewer,
        add("h3-admin", "the owner's step"),
        Some(&owner_token),
    )
    .await
    .expect("the submitter");
    assert_eq!(workflow_admin_audits(&pool, owner).await, 0);
}
