//! The MCP workflow writers keep the caller's `tags`.
//!
//! `store_workflow` takes `tags` and `ingest_workflow` takes `source.tags`, and
//! both used to hand them to `WorkflowSource.tags`, a field no ingest step read:
//! the `workflows` row stored only the caller's metadata (for `store_workflow`,
//! just `prerequisites`), so the tags were unrecoverable after the call.
//!
//! The tags are now recorded on the row as `metadata.tags` (trimmed, empties
//! dropped, de-duplicated in first-seen order), next to every metadata key the
//! caller supplied. The REST twins are pinned in
//! `epigraph-api/tests/workflow_rest_tags_persisted.rs`.
//!
//! # Verified to fail
//!
//! At origin/main 9af9db2a the three tag-carrying arms failed on the
//! `metadata.tags` assertion. With no caller `metadata.tags`, the stored
//! metadata had no `tags` key at all (only `prerequisites` and the submitter
//! key); with a caller `metadata.tags: ["legacy"]`, it stayed `["legacy"]` and
//! every `source.tags` entry was lost.

use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::types::{IngestWorkflowParams, StoreWorkflowParams};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::*;

#[path = "viewer_fixture.rs"]
mod fixture;

/// The stored `workflows.metadata` for the row with this goal. Read on the
/// harness superuser, so row security hides nothing.
async fn metadata_for_goal(pool: &PgPool, goal: &str) -> Value {
    sqlx::query_scalar("SELECT metadata FROM workflows WHERE goal = $1")
        .bind(goal)
        .fetch_one(pool)
        .await
        .expect("the workflow row")
}

/// `store_workflow`: the tags land on the row, normalised, and the
/// `prerequisites` key the tool writes is kept beside them.
#[sqlx::test(migrations = "../../migrations")]
async fn store_workflow_persists_tags(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = fixture::public_viewer(&pool).await;
    let goal = format!("tags probe goal {}", Uuid::new_v4());
    let r = epigraph_mcp::tools::workflows::store_workflow(
        &server,
        &viewer,
        StoreWorkflowParams {
            goal: goal.clone(),
            steps: vec![format!("tags probe step {}", Uuid::new_v4())],
            prerequisites: Some(vec!["cargo installed".into()]),
            expected_outcome: None,
            confidence: None,
            tags: Some(vec![
                "deployment".into(),
                " rust ".into(),
                "".into(),
                "deployment".into(),
            ]),
        },
        None,
    )
    .await
    .expect("store_workflow");
    assert_ne!(r.is_error, Some(true), "{r:?}");

    let meta = metadata_for_goal(&pool, &goal).await;
    assert_eq!(
        meta.get("tags"),
        Some(&json!(["deployment", "rust"])),
        "store_workflow must record its tags on the workflows row: {meta}"
    );
    assert_eq!(
        meta.get("prerequisites"),
        Some(&json!(["cargo installed"])),
        "the prerequisites key is kept beside the tags: {meta}"
    );
}

/// `store_workflow` with no tags writes no `tags` key, so a tagless workflow
/// reads exactly as it did before.
#[sqlx::test(migrations = "../../migrations")]
async fn store_workflow_without_tags_writes_no_tags_key(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = fixture::public_viewer(&pool).await;
    let goal = format!("tagless probe goal {}", Uuid::new_v4());
    epigraph_mcp::tools::workflows::store_workflow(
        &server,
        &viewer,
        StoreWorkflowParams {
            goal: goal.clone(),
            steps: vec![format!("tagless probe step {}", Uuid::new_v4())],
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
        None,
    )
    .await
    .expect("store_workflow");

    let meta = metadata_for_goal(&pool, &goal).await;
    assert!(meta.get("tags").is_none(), "no tags, no tags key: {meta}");
    assert_eq!(meta.get("prerequisites"), Some(&json!([])), "{meta}");
}

/// A hierarchical extraction for `ingest_workflow` carrying `source.tags` and,
/// when given, a caller `source.metadata`. Returns the extraction and its goal.
fn tagged_extraction(tags: Value, metadata: Option<Value>) -> (WorkflowExtraction, String) {
    let tag = Uuid::new_v4();
    let goal = format!("ingest tags probe goal {tag}");
    let mut source = json!({
        "canonical_name": format!("ingest-tags-probe-{tag}"),
        "goal": goal,
        "generation": 0,
        "authors": [],
        "tags": tags,
    });
    if let Some(m) = metadata {
        source["metadata"] = m;
    }
    let extraction = serde_json::from_value(json!({
        "source": source,
        "thesis": format!("ingest tags probe thesis {tag}"),
        "thesis_derivation": "TopDown",
        "phases": [{
            "title": "Phase One",
            "summary": format!("ingest tags probe phase {tag}"),
            "steps": [{
                "compound": format!("ingest tags probe step {tag}"),
                "rationale": "",
                "operations": [],
                "generality": [],
                "confidence": 0.8
            }]
        }],
        "relationships": []
    }))
    .expect("a well-formed extraction");
    (extraction, goal)
}

/// Runs the MCP `ingest_workflow` tool and returns the stored row's metadata.
async fn ingest_and_read_metadata(pool: &PgPool, tags: Value, metadata: Option<Value>) -> Value {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await);
    let (_caller, token, viewer) = seed_caller(pool, &["claims:write"]).await;
    let (extraction, goal) = tagged_extraction(tags, metadata);
    let r = epigraph_mcp::tools::workflow_ingest::ingest_workflow(
        &server,
        &viewer,
        IngestWorkflowParams {
            extraction,
            tenancy: None,
            embed: Some(false),
        },
        Some(&token),
    )
    .await
    .expect("ingest_workflow");
    assert_ne!(r.is_error, Some(true), "{r:?}");
    metadata_for_goal(pool, &goal).await
}

/// `ingest_workflow` with `source.tags` and no `metadata` (the shape callers
/// send): the row gains a `tags` key holding the normalised tags.
#[sqlx::test(migrations = "../../migrations")]
async fn ingest_workflow_persists_source_tags(pool: PgPool) {
    let meta =
        ingest_and_read_metadata(&pool, json!(["rust", " deployment ", "rust", ""]), None).await;
    assert_eq!(
        meta.get("tags"),
        Some(&json!(["rust", "deployment"])),
        "ingest_workflow must record source.tags on the workflows row: {meta}"
    );
}

/// Merge policy when the caller ALSO sent `metadata`: every caller key is kept,
/// and a caller `metadata.tags` array is extended with the `source.tags` it
/// lacks (its own entries first), never replaced.
#[sqlx::test(migrations = "../../migrations")]
async fn ingest_workflow_merges_source_tags_into_caller_metadata(pool: PgPool) {
    let meta = ingest_and_read_metadata(
        &pool,
        json!(["rust", "deployment", "legacy"]),
        Some(json!({ "owner_team": "infra", "tags": ["legacy"] })),
    )
    .await;
    assert_eq!(
        meta.get("tags"),
        Some(&json!(["legacy", "rust", "deployment"])),
        "source.tags are merged into the caller's metadata.tags: {meta}"
    );
    assert_eq!(
        meta.get("owner_team"),
        Some(&json!("infra")),
        "the caller's own metadata keys are kept: {meta}"
    );
}

/// Runs MCP `store_workflow` from wire-shaped JSON (so the `tags` deserializer
/// runs as it does for a real client) and returns the response body.
async fn store_from_wire(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    goal: &str,
    tags: Value,
) -> Value {
    let params: StoreWorkflowParams = serde_json::from_value(json!({
        "goal": goal,
        "steps": [format!("restore probe step for {goal}")],
        "tags": tags,
    }))
    .expect("wire-shaped store_workflow params");
    let r = epigraph_mcp::tools::workflows::store_workflow(server, viewer, params, None)
        .await
        .expect("store_workflow");
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let text = r
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("a text body");
    serde_json::from_str(&text).expect("a JSON body")
}

/// Re-storing the same goal is the existing idempotent no-op: the second call
/// reports `already_ingested` and the row keeps the tags of the FIRST store.
/// Tags on a re-store are not merged; this pins that documented behaviour so a
/// later change cannot start partially overwriting them unnoticed.
#[sqlx::test(migrations = "../../migrations")]
async fn store_workflow_restore_keeps_first_store_tags(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = fixture::public_viewer(&pool).await;
    let goal = format!("restore tags probe goal {}", Uuid::new_v4());

    let first = store_from_wire(&server, &viewer, &goal, json!(["alpha"])).await;
    assert_eq!(
        first.get("already_ingested"),
        Some(&json!(false)),
        "{first}"
    );

    let second = store_from_wire(&server, &viewer, &goal, json!(["beta"])).await;
    assert_eq!(
        second.get("already_ingested"),
        Some(&json!(true)),
        "a re-store of the same goal is the idempotent no-op: {second}"
    );
    assert_eq!(
        second.get("workflow_id"),
        first.get("workflow_id"),
        "same row: {first} vs {second}"
    );

    let meta = metadata_for_goal(&pool, &goal).await;
    assert_eq!(
        meta.get("tags"),
        Some(&json!(["alpha"])),
        "a re-store keeps the first store's tags: {meta}"
    );
}
