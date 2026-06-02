//! Regression test: find_workflow must surface workflow claims via semantic
//! search over claims.embedding (not evidence.embedding, which is empty).
//!
//! Fails on the old code (EvidenceRepository::search_by_embedding -> zero hits
//! on the semantic path because evidence.embedding is 100% NULL in prod).
//! Passes on the fixed code (ClaimRepository::search_by_embedding_scoped).
//!
//! The goal string is intentionally NOT a substring of the claim content,
//! so ILIKE cannot match it and any result with similarity > 0 can only have
//! come from the semantic (vector) path.

// rustfmt 1.8 sorts __test_only differently than older CI rustfmt; opt out so
// both versions accept the file (mirrors recall_with_context.rs's header fix).
#[rustfmt::skip]
use epigraph_mcp::tools::workflows::__test_only::find_workflow_with_pgvec;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::*;

/// Build a 1536-d unit-ish pgvector literal. Component [0] is 1.0, rest 0.0.
fn unit_pgvec_1536() -> String {
    let mut v = vec!["0.0"; 1536];
    v[0] = "1.0";
    format!("[{}]", v.join(","))
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_semantic_path_uses_claims_embedding(pool: PgPool) {
    // Seed agent + workflow claim.
    let agent_id = seed_agent(&pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();

    // Content is valid JSON so parse_workflow_content returns a non-empty goal
    // and non-empty steps, which enrich_workflow_result requires to emit Some.
    // The content string intentionally contains NO substring that could match
    // the query text "xyzzy_semantic_probe_42" via ILIKE.
    let content = serde_json::json!({
        "goal": "deploy containerised service",
        "steps": ["build image", "push to registry", "restart service"],
        "generation": 0,
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 0.0,
    })
    .to_string();

    let pgvec = unit_pgvec_1536();

    // Insert with claims.embedding set — this is what the fix queries.
    sqlx::query(
        "INSERT INTO claims \
         (id, content, content_hash, truth_value, agent_id, is_current, labels, embedding) \
         VALUES ($1, $2, $3, 0.7, $4, true, ARRAY['workflow']::text[], $5::vector)",
    )
    .bind(id)
    .bind(&content)
    .bind(&hash)
    .bind(agent_id)
    .bind(&pgvec)
    .execute(&pool)
    .await
    .expect("seed workflow claim with embedding");

    // Drive the post-embed pipeline directly (no OpenAI call, no API key needed).
    // pgvec_opt = Some(pgvec) forces the semantic path.
    // The query text "xyzzy_semantic_probe_42" does not appear in the claim, so
    // any result arriving here came through the vector path, not ILIKE.
    let server = build_test_server(pool.clone());
    let params = epigraph_mcp::types::FindWorkflowParams {
        goal: "xyzzy_semantic_probe_42".to_string(),
        limit: Some(5),
        min_truth: Some(0.0),
    };
    let result = find_workflow_with_pgvec(&server, params, Some(pgvec))
        .await
        .expect("find_workflow_with_pgvec");

    let json = first_text(&result);
    let arr = json.as_array().expect("result is array");
    assert!(
        !arr.is_empty(),
        "semantic path must return the seeded workflow claim; got empty array. \
         Old code (EvidenceRepository::search_by_embedding) returns zero because \
         evidence.embedding is NULL. New code (ClaimRepository::search_by_embedding_scoped) \
         finds the claim via claims.embedding."
    );

    let first = &arr[0];
    assert_eq!(
        first["workflow_id"].as_str().unwrap(),
        id.to_string(),
        "returned workflow id must match the seeded claim"
    );

    let similarity = first["similarity"].as_f64().unwrap_or(0.0);
    assert!(
        similarity > 0.0,
        "similarity must be > 0 (semantic hit); ILIKE fallback emits 0.0 so \
         similarity > 0 proves the vector path fired: got {similarity}"
    );
}
