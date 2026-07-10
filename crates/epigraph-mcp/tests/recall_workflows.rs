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

#[sqlx::test(migrations = "../../migrations")]
async fn recall_include_workflows_true_returns_matching_workflow(pool: PgPool) {
    // A workflow whose goal text does NOT appear in any claim content, so a
    // lexical/claims-only path can never surface it — only the workflows ANN
    // leg can.
    let goal = "orchestrate zylophonic beacon calibration";
    let pgvec = unit_pgvec_1536();
    let workflow_id = seed_workflow_with_goal_embedding(&pool, goal, &pgvec).await;

    // A couple of unrelated claims so the claims leg is non-empty (recall's
    // normal path keeps working alongside the workflows leg).
    seed_claim(&pool, "completely unrelated claim about lichens", 0.8).await;
    seed_claim(&pool, "another unrelated claim about tectonic plates", 0.8).await;

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

    let hit = arr
        .iter()
        .find(|r| r["claim_id"] == workflow_id.to_string())
        .unwrap_or_else(|| panic!("workflow {workflow_id} not found in recall results: {arr:?}"));

    assert_eq!(
        hit["result_type"],
        serde_json::json!("workflow"),
        "workflow hit must be tagged result_type=\"workflow\""
    );
    assert_eq!(
        hit["content"],
        serde_json::json!(goal),
        "workflow hit content must be the workflow's goal text"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_include_workflows_false_excludes_workflow_only_match(pool: PgPool) {
    let goal = "orchestrate zylophonic beacon calibration";
    let pgvec = unit_pgvec_1536();
    let workflow_id = seed_workflow_with_goal_embedding(&pool, goal, &pgvec).await;

    seed_claim(&pool, "completely unrelated claim about lichens", 0.8).await;

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
        arr.iter().all(|r| r["claim_id"] != workflow_id.to_string()),
        "workflow must NOT appear when include_workflows is false: {arr:?}"
    );
}
