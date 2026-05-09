//! Verifies that `find_workflow` falls back to ILIKE text search on the
//! `workflows` table when semantic search (over evidence embeddings) returns
//! fewer than `limit / 2` hits. Workflows usually have no associated evidence
//! with embeddings, so without this fallback every scheduled-agent first
//! action returned an empty list. Resolves claim 903e5120.

use epigraph_db::WorkflowRepository;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_falls_back_to_text_search_when_semantic_empty(pool: PgPool) {
    // Unique phrase guarantees no other seeded data interferes.
    let unique_phrase = format!("test-find-fallback-{}", Uuid::new_v4());

    // Seed the claims half (workflow shape, JSON content with goal/steps so
    // `parse_workflow_content` can extract them inside the fallback loop).
    let workflow_id = seed_workflow_claim(
        &pool,
        &unique_phrase,
        &["step-one for fallback test", "step-two for fallback test"],
    )
    .await;

    // Seed the workflows-table half with the same id. The fallback queries
    // `workflows` via ILIKE, then resolves the matching id back to the claim.
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, metadata) \
         VALUES ($1, $2, 0, $3, '{}'::jsonb)",
    )
    .bind(workflow_id)
    .bind(&unique_phrase)
    .bind(&unique_phrase)
    .execute(&pool)
    .await
    .expect("seed workflows row");

    // Sanity: DB-level ILIKE finds it.
    let direct = WorkflowRepository::search_hierarchical_by_text(&pool, &unique_phrase, 5)
        .await
        .expect("search_hierarchical_by_text");
    assert!(
        !direct.is_empty(),
        "DB-level ILIKE must find the seeded workflow"
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
