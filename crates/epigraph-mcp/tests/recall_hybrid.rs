//! `recall` embedder-down behavior: with a mock embedder (no API key) the
//! hybrid embed leg fails, so `recall` must serve scope-honoring lexical-only
//! results (the regression that previously returned [] for scoped queries).

use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::types::RecallParams;
use sqlx::PgPool;
use uuid::Uuid;

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock → embed leg errors
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

fn parse_results(result: rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    serde_json::from_str(&text).expect("parse Vec<RecallResult> JSON")
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_falls_back_to_scope_honoring_lexical_when_embedder_down(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let h = |tag: u8| {
        let mut x = vec![0u8; 32];
        x[0] = tag;
        x
    };
    // In-scope lexical match.
    let keep = Uuid::new_v4();
    sqlx::query("INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, labels) \
                 VALUES ($1, 'zubuzonium synthesis route', $2, $3, 0.8, true, ARRAY['keep'])")
        .bind(keep).bind(h(1)).bind(agent).execute(&pool).await.expect("keep");
    // Out-of-scope lexical match (different label).
    let drop = Uuid::new_v4();
    sqlx::query("INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, labels) \
                 VALUES ($1, 'zubuzonium elsewhere', $2, $3, 0.8, true, ARRAY['other'])")
        .bind(drop).bind(h(2)).bind(agent).execute(&pool).await.expect("drop");

    let server = build_test_server(pool);
    let params = RecallParams {
        query: "zubuzonium".to_string(),
        min_truth: None,
        limit: None,
        tags: vec!["keep".to_string()],
        agent_id: None,
        frame_id: None,
        perspective_id: None,
    };
    let out = recall(&server, params).await.expect("recall ok");
    let arr = parse_results(out);
    let arr = arr.as_array().expect("array");

    let ids: Vec<&str> = arr
        .iter()
        .map(|r| r["claim_id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&keep.to_string().as_str()),
        "in-scope lexical hit returned"
    );
    assert!(
        !ids.contains(&drop.to_string().as_str()),
        "out-of-scope hit excluded (the old bug)"
    );

    let keep_row = arr
        .iter()
        .find(|r| r["claim_id"] == keep.to_string())
        .unwrap();
    assert_eq!(keep_row["matched_via"], serde_json::json!(["lexical"]));
    assert_eq!(keep_row["similarity"], serde_json::json!(0.0)); // lexical-only
}
