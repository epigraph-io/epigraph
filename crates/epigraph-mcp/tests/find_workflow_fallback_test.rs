//! Verifies that `find_workflow` falls back to ILIKE text search on the
//! `claims` table (filtered by `labels @> ['workflow']`) when semantic search
//! over evidence embeddings returns fewer than `limit / 2` hits. Workflow
//! claims are the canonical storage; the legacy `workflows` table holds only
//! a handful of test rows in production. Without this fallback every
//! scheduled-agent first action returned an empty list. Resolves claim 903e5120.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_falls_back_to_text_search_when_semantic_empty(pool: PgPool) {
    // Unique phrase guarantees no other seeded data interferes.
    let unique_phrase = format!("test-find-fallback-{}", Uuid::new_v4());

    // Seed a workflow claim. seed_workflow_claim sets labels=['workflow'],
    // truth_value=0.5 (above the test's min_truth=0.0), and content that
    // begins with the unique phrase, so ILIKE '%phrase%' matches it.
    let workflow_id = seed_workflow_claim(
        &pool,
        &unique_phrase,
        &["step-one for fallback test", "step-two for fallback test"],
    )
    .await;

    // Sanity: DB-level ILIKE on workflow-labeled claims finds it.
    let direct = ClaimRepository::search_by_label_and_text(
        &pool,
        &["workflow".to_string()],
        &unique_phrase,
        0.0,
        5,
    )
    .await
    .expect("search_by_label_and_text");
    assert!(
        !direct.is_empty(),
        "DB-level ILIKE on workflow-labeled claims must find the seeded workflow"
    );

    // Drive the MCP find_workflow path. Semantic search will return zero
    // (no evidence embeddings seeded) so the fallback must surface this row.
    let server = build_test_server(pool.clone());
    let params = epigraph_mcp::types::FindWorkflowParams {
        goal: unique_phrase.clone(),
        limit: Some(5),
        min_truth: Some(0.0),
    };
    let result = epigraph_mcp::tools::workflows::find_workflow(&server, params)
        .await
        .expect("find_workflow");

    let json = first_text(&result);
    let body = serde_json::to_string(&json).expect("re-serialize");
    assert!(
        body.contains(&unique_phrase),
        "expected ILIKE fallback to surface the seeded workflow; got: {body}"
    );

    // The id must round-trip too — guards against the fallback emitting only
    // canonical_name without enriching from the claim.
    assert!(
        body.contains(&workflow_id.to_string()),
        "expected fallback result to include the workflow id; got: {body}"
    );
}
