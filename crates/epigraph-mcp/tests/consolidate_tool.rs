//! `consolidate_claims` MCP tool wiring (backlog 44b19521 / design F1).
//!
//! Repo semantics are pinned in `epigraph-db/tests/consolidate_test.rs`. This
//! covers the tool layer: that it is reachable, that it is gated as a WRITE
//! (the three tools added alongside it are reads), and that the default
//! confidence never exceeds the best source.

use epigraph_mcp::tools::consolidate::consolidate_claims;
use epigraph_mcp::types::ConsolidateClaimsParams;
use sqlx::PgPool;
use uuid::Uuid;

fn build_server(pool: PgPool, read_only: bool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, read_only)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-consolidate-mcp', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool).await.expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), $2, $3, true) RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

fn params(ids: &[Uuid], content: &str, confidence: Option<f64>) -> ConsolidateClaimsParams {
    ConsolidateClaimsParams {
        source_claim_ids: ids.iter().map(ToString::to_string).collect(),
        merged_content: content.to_string(),
        mode: "merge".to_string(),
        reason: "test consolidation".to_string(),
        confidence,
    }
}

fn json_of(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// End-to-end merge through the tool, with the default confidence rule.
#[sqlx::test(migrations = "../../migrations")]
async fn tool_merges_and_caps_confidence_at_best_source(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "tool src one", 0.6).await;
    let s2 = seed_claim(&pool, agent, "tool src two", 0.9).await;

    let server = build_server(pool.clone(), false);
    let out = consolidate_claims(&server, params(&[s1, s2], "tool merged", None))
        .await
        .expect("consolidate ok");
    let j = json_of(out);

    assert_eq!(j["superseded_ids"].as_array().unwrap().len(), 2);
    assert_eq!(j["already_existed"], serde_json::json!(false));

    let merged_id = Uuid::parse_str(j["merged_claim_id"].as_str().unwrap()).unwrap();
    let tv: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id=$1")
        .bind(merged_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        (tv - 0.9 * 0.95).abs() < 1e-9,
        "default confidence = best source (0.9) * 0.95, got {tv} — a merge must not \
         claim more certainty than its strongest input"
    );
}

/// This is a WRITE tool, unlike the reads added alongside it
/// (`get_provenance_chain`, `get_recall_events`). Copying a read's
/// registration would silently drop the write gating, so pin the scope
/// mapping: `claims:read` credentials must NOT satisfy it.
#[test]
fn consolidate_is_gated_as_a_write() {
    assert_eq!(
        epigraph_mcp::scope_map::required_scope("consolidate_claims"),
        Some("claims:write"),
        "consolidate_claims mutates claims and edges; it must require claims:write"
    );
    // Contrast with the reads landed in the same series.
    assert_eq!(
        epigraph_mcp::scope_map::required_scope("get_provenance_chain"),
        Some("claims:read")
    );
    assert_eq!(
        epigraph_mcp::scope_map::required_scope("get_recall_events"),
        Some("claims:read")
    );
}

/// An unknown mode is a parameter error, not a 500.
#[sqlx::test(migrations = "../../migrations")]
async fn unknown_mode_is_rejected(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s1 = seed_claim(&pool, agent, "mode a", 0.6).await;
    let s2 = seed_claim(&pool, agent, "mode b", 0.6).await;

    let server = build_server(pool, false);
    let mut p = params(&[s1, s2], "x", None);
    p.mode = "obliterate".to_string();
    let err = consolidate_claims(&server, p)
        .await
        .expect_err("bad mode rejected");
    let msg = format!("{err:?}").to_lowercase();
    assert!(msg.contains("mode") || msg.contains("invalid"), "{msg}");
}
