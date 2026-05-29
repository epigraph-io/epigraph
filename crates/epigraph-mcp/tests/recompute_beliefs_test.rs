//! Behavioral tests for the `recompute_beliefs` CDST-maintenance tool.
//!
//! Setup mirrors `source_strength_tests.rs`: `auto_wire_ds_update` writes a
//! real BBA on the canonical `binary_truth` frame and seeds the cached
//! `claims.pignistic_prob`. We then corrupt the cache and assert the tool
//! restores it (the 50ea636e ingest-initial-asymmetry use case), plus check
//! the target-selection, truncation, and no-BBA-skip reporting.

use epigraph_crypto::AgentSigner;
use epigraph_mcp::types::RecomputeBeliefsParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::RawContent;
use sqlx::PgPool;
use uuid::Uuid;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x2bu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn result_json(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let first = out.content.first().cloned().expect("first content");
    let text = match first.raw {
        RawContent::Text(t) => t.text,
        other => panic!("expected text content, got {other:?}"),
    };
    serde_json::from_str(&text).expect("result is JSON")
}

async fn insert_agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test'])
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn insert_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Give `claim_id` a real binary-frame BBA + cached belief.
async fn wire_bba(pool: &PgPool, claim_id: Uuid, agent_id: Uuid) {
    tools::ds_auto::auto_wire_ds_update(
        pool,
        claim_id,
        agent_id,
        0.9,  // confidence
        1.0,  // weight
        true, // supports
        Some("empirical"),
        None, // evidence_id
    )
    .await
    .expect("auto_wire_ds_update");
}

async fn pignistic(pool: &PgPool, claim_id: Uuid) -> f64 {
    sqlx::query_scalar::<_, f64>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Targeting by `claim_ids` restores a deliberately-corrupted cache to the
/// correct combine result and reports accurate counts.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_claim_ids_restores_stale_cache(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "recompute-stale").await;
    let claim = insert_claim(&pool, agent, &format!("recompute-stale-{}", Uuid::new_v4())).await;
    wire_bba(&pool, claim, agent).await;

    let correct = pignistic(&pool, claim).await;
    // Corrupt the cache to a value the combine path would never produce here.
    sqlx::query("UPDATE claims SET pignistic_prob = 0.123 WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .unwrap();
    assert!((pignistic(&pool, claim).await - 0.123).abs() < 1e-9);

    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");

    let j = result_json(out);
    assert_eq!(j["target"], "claim_ids");
    assert_eq!(j["claims_considered"], 1);
    assert_eq!(j["claims_recomputed"], 1);
    assert_eq!(j["claims_skipped_no_bba"], 0);
    assert!(j["frame_writes"].as_u64().unwrap() >= 1);
    assert_eq!(j["truncated"], false);
    assert!(j["errors"].as_array().unwrap().is_empty());

    // Cache is back to the correct combine result, not the corrupted value.
    let restored = pignistic(&pool, claim).await;
    assert!(
        (restored - correct).abs() < 1e-9,
        "expected restored {correct}, got {restored}"
    );
    assert!((restored - 0.123).abs() > 1e-6, "still corrupted");
}

/// A claim with no BBAs is counted as skipped, not recomputed, and is not an error.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_skips_claim_without_bbas(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "recompute-nobba").await;
    let bare = insert_claim(&pool, agent, &format!("recompute-nobba-{}", Uuid::new_v4())).await;

    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        RecomputeBeliefsParams {
            claim_ids: Some(vec![bare.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");

    let j = result_json(out);
    assert_eq!(j["claims_considered"], 1);
    assert_eq!(j["claims_recomputed"], 0);
    assert_eq!(j["claims_skipped_no_bba"], 1);
    assert_eq!(j["frame_writes"], 0);
    assert!(j["errors"].as_array().unwrap().is_empty());
}

/// The bulk path (no claim_ids/labels) enumerates claims-with-BBAs and sets
/// `truncated=true` when `limit` is smaller than the population.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_bulk_truncates_at_limit(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "recompute-bulk").await;
    // Two claims with BBAs; ephemeral DB so the bulk population is exactly 2.
    for i in 0..2 {
        let c = insert_claim(
            &pool,
            agent,
            &format!("recompute-bulk-{i}-{}", Uuid::new_v4()),
        )
        .await;
        wire_bba(&pool, c, agent).await;
    }

    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        RecomputeBeliefsParams {
            claim_ids: None,
            labels: None,
            limit: Some(1),
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");

    let j = result_json(out);
    assert_eq!(j["target"], "all_with_bbas");
    assert_eq!(j["claims_considered"], 1, "limit=1 caps the batch");
    assert_eq!(j["truncated"], true, "more claims remain past limit");

    // Page 2 picks up the remaining claim and is not truncated.
    let out2 = tools::cdst_maintenance::recompute_beliefs(
        &server,
        RecomputeBeliefsParams {
            claim_ids: None,
            labels: None,
            limit: Some(1),
            offset: Some(1),
        },
    )
    .await
    .expect("recompute_beliefs page 2");
    let j2 = result_json(out2);
    assert_eq!(j2["claims_considered"], 1);
    assert_eq!(j2["truncated"], false, "no claims remain after offset 1");
}
