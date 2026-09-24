//! `get_provenance_chain` MCP tool wiring (backlog 3216b086 / design F2).
//!
//! The repo-layer traversal contract is pinned in
//! `epigraph-db/tests/provenance_chain_test.rs`. This test covers what those
//! cannot see: that the tool is actually reachable, that a mixed-direction
//! chain survives serialization, and that topological order is preserved in
//! the JSON a caller receives.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::provenance_chain::get_provenance_chain;
use epigraph_mcp::types::GetProvenanceChainParams;
use sqlx::PgPool;
use uuid::Uuid;

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-provchain-mcp', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool).await.expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.7, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(rel)
    .execute(pool)
    .await
    .expect("seed edge");
}

/// End-to-end: a chain mixing an INCOMING `supports` hop with an OUTGOING
/// `supersedes` hop must come back through the tool in evidence-first order.
/// This is the shape that breaks if the frontier is wired single-direction.
#[sqlx::test(migrations = "../../migrations")]
async fn tool_returns_mixed_direction_chain_in_topological_order(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let root = seed_claim(&pool, agent, "final conclusion").await;
    let evidence = seed_claim(&pool, agent, "supporting evidence").await;
    let predecessor = seed_claim(&pool, agent, "earlier version").await;

    seed_edge(&pool, evidence, root, "supports").await; // incoming
    seed_edge(&pool, root, predecessor, "supersedes").await; // outgoing

    let server = build_test_server(pool);
    let out = get_provenance_chain(
        &server,
        &viewer,
        GetProvenanceChainParams {
            claim_id: root.to_string(),
            max_depth: Some(4),
            relationships: None,
        },
    )
    .await
    .expect("tool call ok");

    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    let json: serde_json::Value = serde_json::from_str(&text).expect("parse JSON");

    assert_eq!(json["root"], serde_json::json!(root.to_string()));
    let nodes = json["nodes"].as_array().expect("nodes array");
    assert_eq!(
        nodes.len(),
        3,
        "root + supports ancestor + supersedes ancestor"
    );

    let order: Vec<String> = nodes
        .iter()
        .map(|n| n["id"].as_str().unwrap().to_string())
        .collect();
    let idx = |id: Uuid| order.iter().position(|x| *x == id.to_string()).unwrap();
    assert!(
        idx(root) == order.len() - 1,
        "the conclusion must sort LAST: {order:?}"
    );
    assert!(
        idx(evidence) < idx(root) && idx(predecessor) < idx(root),
        "both ancestors precede the conclusion"
    );

    assert_eq!(json["truncated"], serde_json::json!(false));
    assert!(json["cycles"].as_array().unwrap().is_empty());
    assert_eq!(json["edges"].as_array().unwrap().len(), 2);
}

/// The `relationships` filter narrows the walk: restricting to `supports`
/// must drop the supersedes ancestor.
#[sqlx::test(migrations = "../../migrations")]
async fn relationships_filter_narrows_the_walk(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let root = seed_claim(&pool, agent, "conclusion b").await;
    let evidence = seed_claim(&pool, agent, "evidence b").await;
    let predecessor = seed_claim(&pool, agent, "predecessor b").await;
    seed_edge(&pool, evidence, root, "supports").await;
    seed_edge(&pool, root, predecessor, "supersedes").await;

    let server = build_test_server(pool);
    let out = get_provenance_chain(
        &server,
        &viewer,
        GetProvenanceChainParams {
            claim_id: root.to_string(),
            max_depth: Some(4),
            relationships: Some(vec!["supports".to_string()]),
        },
    )
    .await
    .expect("tool call ok");

    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let ids: Vec<String> = json["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_str().unwrap().to_string())
        .collect();

    assert!(
        ids.contains(&evidence.to_string()),
        "supports ancestor kept"
    );
    assert!(
        !ids.contains(&predecessor.to_string()),
        "supersedes ancestor dropped when the filter excludes it"
    );
}

/// A bad UUID is a parameter error, not a 500.
#[sqlx::test(migrations = "../../migrations")]
async fn invalid_uuid_is_rejected(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool);
    let err = get_provenance_chain(
        &server,
        &viewer,
        GetProvenanceChainParams {
            claim_id: "not-a-uuid".to_string(),
            max_depth: None,
            relationships: None,
        },
    )
    .await
    .expect_err("invalid uuid must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.to_lowercase().contains("uuid") || msg.to_lowercase().contains("invalid"),
        "{msg}"
    );
}
