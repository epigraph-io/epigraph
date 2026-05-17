//! End-to-end smoke test for the `link_hierarchical` MCP tool.
//!
//! Drives `do_link_hierarchical` directly against a sqlx::test pool so the
//! happy / idempotent / validation / 404-equivalent paths all exercise the
//! same repo layer the production rmcp dispatcher uses.

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::types::LinkHierarchicalParams;
use sqlx::PgPool;
use uuid::Uuid;

/// Lightweight mirror of `LinkHierarchicalResponse` for test deserialization.
/// (The production struct is Serialize-only — adding Deserialize purely to make
/// tests easier is gold-plating; parsing into a local mirror keeps the prod
/// type focused on its one direction of the wire contract.)
#[derive(serde::Deserialize)]
struct LinkHierarchicalResponse {
    edge_id: String,
    created: bool,
}

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

/// Minimal seeded claim — bypasses the full submit_claim pipeline because
/// this test cares about the edge-wiring code path, not claim ingestion.
async fn seed_claim(pool: &PgPool, content: &str) -> Uuid {
    // Each claim needs a unique agent (unique public_key) and unique content_hash.
    let agent_id = Uuid::new_v4();
    let agent_pk: Vec<u8> = agent_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .bind(&agent_pk)
    .execute(pool)
    .await
    .expect("seed agent");

    let claim_id = Uuid::new_v4();
    // content_hash must be unique per claim row — derive from the claim UUID
    // so concurrent sqlx::test pools don't collide.
    let hash: Vec<u8> = claim_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[])",
    )
    .bind(claim_id)
    .bind(content)
    .bind(&hash)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    claim_id
}

fn parse_response(result: &rmcp::model::CallToolResult) -> LinkHierarchicalResponse {
    let text = result
        .content
        .first()
        .expect("at least one content block")
        .as_text()
        .expect("text content")
        .text
        .clone();
    serde_json::from_str(&text).expect("LinkHierarchicalResponse JSON")
}

#[sqlx::test(migrations = "../../migrations")]
async fn happy_path_creates_edge_and_is_idempotent(pool: PgPool) {
    let server = make_server(pool.clone());
    let source = seed_claim(&pool, "chapter 1 thesis").await;
    let target = seed_claim(&pool, "book thesis").await;

    // First call — fresh insert.
    let first = do_link_hierarchical(
        &server,
        LinkHierarchicalParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "decomposes_to".to_string(),
            properties: Some(serde_json::json!({"chapter": 1})),
        },
    )
    .await
    .expect("happy path succeeds");
    let first_resp = parse_response(&first);
    assert!(first_resp.created, "first call must report created=true");

    // Edge exists in DB with the expected triple and properties.
    let row: (Uuid, serde_json::Value) = sqlx::query_as(
        "SELECT id, properties FROM edges \
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'decomposes_to' \
           AND source_type = 'claim' AND target_type = 'claim'",
    )
    .bind(source)
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("edge row");
    assert_eq!(row.0.to_string(), first_resp.edge_id);
    assert_eq!(row.1, serde_json::json!({"chapter": 1}));

    // Second call with the same args — dedup hit, no new edge row.
    let second = do_link_hierarchical(
        &server,
        LinkHierarchicalParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "decomposes_to".to_string(),
            properties: Some(serde_json::json!({"chapter": 1})),
        },
    )
    .await
    .expect("idempotent re-run succeeds");
    let second_resp = parse_response(&second);
    assert!(
        !second_resp.created,
        "second call must report created=false (dedup hit)"
    );
    assert_eq!(
        second_resp.edge_id, first_resp.edge_id,
        "dedup hit must return the existing edge_id"
    );

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges \
         WHERE source_id = $1 AND target_id = $2 AND relationship = 'decomposes_to'",
    )
    .bind(source)
    .bind(target)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1, "must have exactly one edge after re-run");
}

#[sqlx::test(migrations = "../../migrations")]
async fn invalid_relationship_is_rejected(pool: PgPool) {
    let server = make_server(pool.clone());
    let source = seed_claim(&pool, "atomA").await;
    let target = seed_claim(&pool, "atomB").await;

    let err = do_link_hierarchical(
        &server,
        LinkHierarchicalParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "supports".to_string(), // valid for generic POST, rejected here
            properties: None,
        },
    )
    .await
    .expect_err("supports must be rejected by the tight allow-list");
    let msg = err.message.to_string();
    assert!(
        msg.contains("invalid relationship"),
        "error should name the relationship problem; got: {msg}"
    );
    assert!(
        msg.contains("decomposes_to"),
        "error should list the valid types; got: {msg}"
    );

    // No edge written.
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2")
            .bind(source)
            .bind(target)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_source_claim_returns_404_equivalent(pool: PgPool) {
    let server = make_server(pool.clone());
    let target = seed_claim(&pool, "real target").await;
    let bogus = Uuid::new_v4();

    let err = do_link_hierarchical(
        &server,
        LinkHierarchicalParams {
            source_claim_id: bogus.to_string(),
            target_claim_id: target.to_string(),
            relationship: "section_follows".to_string(),
            properties: None,
        },
    )
    .await
    .expect_err("missing source claim must error");
    let msg = err.message.to_string();
    assert!(
        msg.contains("source_claim_id") && msg.contains(&bogus.to_string()),
        "error should identify the missing side and its UUID; got: {msg}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_target_claim_returns_404_equivalent(pool: PgPool) {
    let server = make_server(pool.clone());
    let source = seed_claim(&pool, "real source").await;
    let bogus = Uuid::new_v4();

    let err = do_link_hierarchical(
        &server,
        LinkHierarchicalParams {
            source_claim_id: source.to_string(),
            target_claim_id: bogus.to_string(),
            relationship: "continues_argument".to_string(),
            properties: None,
        },
    )
    .await
    .expect_err("missing target claim must error");
    let msg = err.message.to_string();
    assert!(
        msg.contains("target_claim_id") && msg.contains(&bogus.to_string()),
        "error should identify the missing side and its UUID; got: {msg}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn self_loop_is_rejected(pool: PgPool) {
    let server = make_server(pool.clone());
    let claim = seed_claim(&pool, "loop").await;

    let err = do_link_hierarchical(
        &server,
        LinkHierarchicalParams {
            source_claim_id: claim.to_string(),
            target_claim_id: claim.to_string(),
            relationship: "decomposes_to".to_string(),
            properties: None,
        },
    )
    .await
    .expect_err("self-loops must be rejected before hitting the DB CHECK");
    let msg = err.message.to_string();
    assert!(
        msg.to_lowercase().contains("self-loop"),
        "error should mention self-loops; got: {msg}"
    );
}
