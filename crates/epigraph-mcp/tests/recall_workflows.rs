//! Regression test for Task 6.3 (backlog claim 88a09fd2): `recall()` must
//! optionally search `workflows.goal_embedding` alongside `claims`, RRF-merged
//! with the existing dense+lexical claims leg, and tag workflow hits with
//! `result_type: "workflow"`.
//!
//! Boundary/fallback note: `build_test_server` wires a mock `McpEmbedder`
//! (no OpenAI API key — see `common::build_test_server`), so the MCP test
//! process cannot generate a *real* embedding for the query text in-process.
//! We therefore drive the deterministic `__test_only::recall_with_pgvec` seam
//! (mirrors the established `find_workflow_with_pgvec` pattern in
//! `workflows.rs`) with a hand-built pgvector literal, and seed the workflow's
//! `goal_embedding` with that SAME literal so the ANN leg has an exact (distance
//! 0) match. This exercises the real RRF-merge/tagging logic end-to-end; only
//! the OpenAI HTTP call is stubbed out, matching the precedent set by
//! `find_workflow_semantic_test.rs` for the same embedder constraint.

#[rustfmt::skip]
use epigraph_mcp::tools::memory::__test_only::recall_with_pgvec;
use epigraph_mcp::types::RecallParams;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::*;

/// Build a 1536-d unit pgvector literal so the workflow's `goal_embedding`
/// (seeded with the same literal) is an exact ANN match (cosine distance 0).
fn unit_pgvec_1536() -> String {
    let mut v = vec!["0.0"; 1536];
    v[0] = "1.0";
    format!("[{}]", v.join(","))
}

async fn seed_workflow_with_goal_embedding(pool: &PgPool, goal: &str, pgvec: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, metadata, truth_value, goal_embedding) \
         VALUES ($1, $2, 0, $3, '{}'::jsonb, 1.0, $4::vector)",
    )
    .bind(id)
    .bind(format!("wf-{id}"))
    .bind(goal)
    .bind(pgvec)
    .execute(pool)
    .await
    .expect("seed workflow with goal_embedding");
    id
}

/// Seed a claim with `embedding` set to the given pgvec literal, so it is a
/// real hit on the claims dense leg of `search_hybrid_scoped`
/// (`WHERE c.embedding IS NOT NULL AND c.is_current`). `seed_claim` in
/// `common` does NOT set `embedding`, so a plain `seed_claim` never appears
/// in a pgvec-driven dense search — using it here would make the
/// `include_workflows` assertions vacuously true over an empty results
/// array. Mirrors the seed pattern in `find_workflow_semantic_test.rs`.
async fn seed_claim_with_embedding(pool: &PgPool, content: &str, pgvec: &str) -> Uuid {
    let agent_id = seed_agent(pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, embedding) \
         VALUES ($1, $2, $3, 0.8, $4, true, ARRAY[]::text[], $5::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent_id)
    .bind(pgvec)
    .execute(pool)
    .await
    .expect("seed claim with embedding");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_include_workflows_true_returns_matching_workflow(pool: PgPool) {
    // A workflow whose goal text does NOT appear in any claim content, so a
    // lexical/claims-only path can never surface it — only the workflows ANN
    // leg can.
    let goal = "orchestrate zylophonic beacon calibration";
    let pgvec = unit_pgvec_1536();
    let workflow_id = seed_workflow_with_goal_embedding(&pool, goal, &pgvec).await;

    // A claim seeded with the SAME embedding, so the claims dense leg is
    // non-empty and the merge actually interleaves two populated ranked
    // lists (not degenerately merging one populated list against an empty
    // one). Without this, `hits` would be empty (plain `seed_claim` sets no
    // `embedding`) and the test would pass even if the RRF-merge/interleave
    // logic were broken.
    let claim_id = seed_claim_with_embedding(&pool, "an unrelated matched claim", &pgvec).await;

    let server = build_test_server(pool);
    let params = RecallParams {
        query: "zylophonic beacon".to_string(),
        min_truth: Some(0.0),
        limit: Some(10),
        tags: vec![],
        agent_id: None,
        frame_id: None,
        perspective_id: None,
        include_workflows: true,
    };

    let out = recall_with_pgvec(&server, params, Some(pgvec))
        .await
        .expect("recall_with_pgvec ok");
    let json = first_text(&out);
    let arr = json.as_array().expect("array");

    let claim_hit = arr
        .iter()
        .find(|r| r["claim_id"] == claim_id.to_string())
        .unwrap_or_else(|| panic!("claim {claim_id} not found in recall results: {arr:?}"));
    assert!(
        claim_hit.get("result_type").is_none(),
        "claim hit must NOT carry result_type (omitted, not null): {claim_hit:?}"
    );

    let workflow_hit = arr
        .iter()
        .find(|r| r["claim_id"] == workflow_id.to_string())
        .unwrap_or_else(|| panic!("workflow {workflow_id} not found in recall results: {arr:?}"));
    assert_eq!(
        workflow_hit["result_type"],
        serde_json::json!("workflow"),
        "workflow hit must be tagged result_type=\"workflow\""
    );
    assert_eq!(
        workflow_hit["content"],
        serde_json::json!(goal),
        "workflow hit content must be the workflow's goal text"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_include_workflows_false_excludes_workflow_only_match(pool: PgPool) {
    let goal = "orchestrate zylophonic beacon calibration";
    let pgvec = unit_pgvec_1536();
    let workflow_id = seed_workflow_with_goal_embedding(&pool, goal, &pgvec).await;

    // Same embedded-claim seed as the true-case test: proves the claims leg
    // is genuinely populated (non-vacuous exclusion check) rather than the
    // whole results array being empty regardless of `include_workflows`.
    let claim_id = seed_claim_with_embedding(&pool, "an unrelated matched claim", &pgvec).await;

    let server = build_test_server(pool);
    let params = RecallParams {
        query: "zylophonic beacon".to_string(),
        min_truth: Some(0.0),
        limit: Some(10),
        tags: vec![],
        agent_id: None,
        frame_id: None,
        perspective_id: None,
        include_workflows: false,
    };

    // include_workflows defaults false: the workflows leg must not even be
    // queried, so the workflow can never appear regardless of pgvec.
    let out = recall_with_pgvec(&server, params, Some(pgvec))
        .await
        .expect("recall_with_pgvec ok");
    let json = first_text(&out);
    let arr = json.as_array().expect("array");

    assert!(
        !arr.is_empty(),
        "sanity: the claims leg must still return the seeded embedded claim \
         (proves this isn't a vacuous empty-array pass): {arr:?}"
    );
    assert!(
        arr.iter().any(|r| r["claim_id"] == claim_id.to_string()),
        "matching claim must still be present when include_workflows is false: {arr:?}"
    );
    assert!(
        arr.iter().all(|r| r["claim_id"] != workflow_id.to_string()),
        "workflow must NOT appear when include_workflows is false: {arr:?}"
    );
}
