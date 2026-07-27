//! `recall` dispute-awareness surface (backlog 34d3400d / design F3).
//!
//! The repo-layer contract is pinned in
//! `epigraph-db/tests/dispute_batch_test.rs`; these tests pin the MCP wiring
//! that the repo tests cannot see:
//!
//! - the annotation actually reaches the JSON a caller receives,
//! - an uncontested hit stays byte-identical to pre-F3 output (fields omitted,
//!   not emitted as `0`/`false`/`[]`),
//! - `exclude_contested` drops contested hits and returns a SHORT page rather
//!   than back-filling with worse-ranked material.
//!
//! Uses the lexical (embedder-down) leg, per `recall_hybrid.rs` — no API key
//! is available in CI, and dispute annotation is orthogonal to which retrieval
//! leg produced the page.

use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::types::RecallParams;
use sqlx::PgPool;
use uuid::Uuid;

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock → lexical leg
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-dispute-mcp', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels)
         VALUES ($1, sha256($1::bytea), $2, $3, true, ARRAY['f3fixture'])
         RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

fn params(query: &str, exclude_contested: bool) -> RecallParams {
    RecallParams {
        query: query.to_string(),
        min_truth: Some(0.0),
        limit: Some(10),
        tags: vec!["f3fixture".to_string()],
        agent_id: None,
        frame_id: None,
        perspective_id: None,
        include_workflows: false,
        exclude_contested,
    }
}

fn parse_results(result: rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    serde_json::from_str::<serde_json::Value>(&text).expect("parse recall envelope")["results"]
        .clone()
}

/// A contested hit carries the dispute annotation through to the caller's
/// JSON, and an uncontested hit in the SAME page omits the fields entirely —
/// pre-F3 callers see byte-identical output for uncontested results.
#[sqlx::test(migrations = "../../migrations")]
async fn contested_hit_annotated_uncontested_hit_unchanged(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let contested = seed_claim(&pool, agent, "quorbulator alpha routing", 0.8).await;
    let clean = seed_claim(&pool, agent, "quorbulator beta routing", 0.8).await;

    let strong = seed_claim(&pool, agent, "quorbulator refutation strong", 0.9).await;
    let weak = seed_claim(&pool, agent, "quorbulator refutation weak", 0.4).await;
    seed_edge(&pool, strong, contested, "contradicts").await;
    seed_edge(&pool, weak, contested, "refutes").await;

    let server = build_test_server(pool);
    let out = recall(&server, params("quorbulator routing", false))
        .await
        .expect("recall ok");
    let arr = parse_results(out);
    let arr = arr.as_array().expect("array");

    let contested_row = arr
        .iter()
        .find(|r| r["claim_id"] == contested.to_string())
        .expect("contested claim returned");
    assert_eq!(contested_row["dispute_count"], serde_json::json!(2));
    assert_eq!(contested_row["is_contested"], serde_json::json!(true));
    let ids = contested_row["contesting_claim_ids"]
        .as_array()
        .expect("contesting ids present");
    assert_eq!(
        ids[0],
        serde_json::json!(strong.to_string()),
        "strongest contester ranks first"
    );

    let clean_row = arr
        .iter()
        .find(|r| r["claim_id"] == clean.to_string())
        .expect("uncontested claim returned");
    assert!(
        clean_row.get("dispute_count").is_none(),
        "uncontested hit omits dispute_count entirely (byte-identical to pre-F3)"
    );
    assert!(
        clean_row.get("is_contested").is_none(),
        "uncontested hit omits is_contested"
    );
    assert!(
        clean_row.get("contesting_claim_ids").is_none(),
        "uncontested hit omits contesting_claim_ids"
    );
}

/// `exclude_contested` drops the contested hit and returns a SHORT page —
/// it must not back-fill from further down the ranking. This mirrors how
/// `min_truth` already behaves (truncate-then-drop).
#[sqlx::test(migrations = "../../migrations")]
async fn exclude_contested_drops_hit_without_backfilling(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let contested = seed_claim(&pool, agent, "zarnthex primary finding", 0.9).await;
    let clean = seed_claim(&pool, agent, "zarnthex secondary finding", 0.8).await;

    let contester = seed_claim(&pool, agent, "zarnthex rebuttal", 0.7).await;
    seed_edge(&pool, contester, contested, "contradicts").await;

    let server = build_test_server(pool);

    // Baseline: without the flag, both fixtures come back.
    let before = parse_results(
        recall(&server, params("zarnthex finding", false))
            .await
            .expect("recall ok"),
    );
    let before_ids: Vec<String> = before
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["claim_id"].as_str().unwrap().to_string())
        .collect();
    assert!(before_ids.contains(&contested.to_string()));
    assert!(before_ids.contains(&clean.to_string()));

    // With the flag: the contested one is gone, the clean one survives.
    let after = parse_results(
        recall(&server, params("zarnthex finding", true))
            .await
            .expect("recall ok"),
    );
    let after_arr = after.as_array().unwrap();
    let after_ids: Vec<String> = after_arr
        .iter()
        .map(|r| r["claim_id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !after_ids.contains(&contested.to_string()),
        "contested hit dropped by exclude_contested"
    );
    assert!(
        after_ids.contains(&clean.to_string()),
        "uncontested hit survives"
    );
    assert_eq!(
        after_arr.len(),
        before_ids.len() - 1,
        "page comes back exactly one shorter — no back-fill from lower ranks"
    );
}

/// A contester that is no longer `is_current` must not mark its target
/// contested at the MCP surface either — the same retraction semantics the
/// repo test pins, verified end-to-end so a future refactor that rebuilds the
/// query in the tool layer cannot silently lose the filter.
#[sqlx::test(migrations = "../../migrations")]
async fn retracted_contester_leaves_hit_uncontested(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let target = seed_claim(&pool, agent, "vothrium stability claim", 0.8).await;
    let retracted = seed_claim(&pool, agent, "vothrium stability rebuttal", 0.7).await;
    seed_edge(&pool, retracted, target, "contradicts").await;

    // Retract the challenger.
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(retracted)
        .execute(&pool)
        .await
        .expect("retract contester");

    let server = build_test_server(pool);
    let out = recall(&server, params("vothrium stability", false))
        .await
        .expect("recall ok");
    let arr = parse_results(out);
    let row = arr
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["claim_id"] == target.to_string())
        .expect("target returned")
        .clone();

    assert!(
        row.get("is_contested").is_none(),
        "a retracted contester leaves the target uncontested"
    );
}
