//! Behavioral tests for CDST classification: recompute_combined_belief (driven
//! here via the recompute_beliefs MCP tool) writes claims.classification, and
//! get_claim surfaces it.
//!
//! Setup uses `auto_wire_ds_update` to stock real binary-frame BBAs; note that
//! path does NOT itself classify (only the recompute cascade does), so we then
//! call recompute_beliefs and assert the label.

use epigraph_crypto::AgentSigner;
use epigraph_db::ClaimRepository;
use epigraph_mcp::types::{GetClaimParams, RecomputeBeliefsParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::RawContent;
use sqlx::PgPool;
use uuid::Uuid;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x3cu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
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

async fn wire(pool: &PgPool, claim: Uuid, agent: Uuid, confidence: f64, supports: bool) {
    tools::ds_auto::auto_wire_ds_update(pool, claim, agent, confidence, 1.0, supports, None, None)
        .await
        .expect("auto_wire_ds_update");
}

/// Recompute classifies the claim and `get_classification` reads it back.
async fn recompute_and_label(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    claim: Uuid,
) -> Option<String> {
    tools::cdst_maintenance::recompute_beliefs(
        server,
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");
    ClaimRepository::get_classification(pool, claim)
        .await
        .expect("get_classification")
}

#[sqlx::test(migrations = "../../migrations")]
async fn strong_support_classifies_supported(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "classify-sup").await;
    let claim = insert_claim(&pool, agent, &format!("classify-sup-{}", Uuid::new_v4())).await;
    wire(&pool, claim, agent, 0.9, true).await;

    assert_eq!(
        recompute_and_label(&server, &pool, claim).await.as_deref(),
        Some("supported")
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn strong_opposition_classifies_contradicted(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "classify-con").await;
    let claim = insert_claim(&pool, agent, &format!("classify-con-{}", Uuid::new_v4())).await;
    // A strong FALSE-leaning BBA → betp_unsup dominates → contradicted.
    wire(&pool, claim, agent, 0.9, false).await;

    assert_eq!(
        recompute_and_label(&server, &pool, claim).await.as_deref(),
        Some("contradicted")
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn high_ignorance_classifies_not_enough_info(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "classify-nei").await;
    let claim = insert_claim(&pool, agent, &format!("classify-nei-{}", Uuid::new_v4())).await;
    // A single very-low-confidence BBA leaves most mass on Θ (theta > nei
    // threshold) with no conflict → not_enough_info.
    wire(&pool, claim, agent, 0.05, true).await;

    assert_eq!(
        recompute_and_label(&server, &pool, claim).await.as_deref(),
        Some("not_enough_info")
    );
}

/// A claim with no BBAs is never classified (recompute returns early), and the
/// label stays NULL.
#[sqlx::test(migrations = "../../migrations")]
async fn no_bba_leaves_classification_null(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "classify-null").await;
    let claim = insert_claim(&pool, agent, &format!("classify-null-{}", Uuid::new_v4())).await;

    assert_eq!(recompute_and_label(&server, &pool, claim).await, None);
}

/// get_claim surfaces the cached classification on the flattened response.
#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_exposes_classification(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "classify-getclaim").await;
    let claim = insert_claim(&pool, agent, &format!("classify-gc-{}", Uuid::new_v4())).await;
    wire(&pool, claim, agent, 0.9, true).await;
    let _ = recompute_and_label(&server, &pool, claim).await;

    let out = tools::claims::get_claim(
        &server,
        GetClaimParams {
            claim_id: claim.to_string(),
            frame_id: None,
            perspective_id: None,
        },
        None,
    )
    .await
    .expect("get_claim");
    let text = match out.content.first().cloned().expect("content").raw {
        RawContent::Text(t) => t.text,
        other => panic!("expected text, got {other:?}"),
    };
    let j: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(j["classification"], "supported");
    // Flatten preserves the base ClaimResponse fields.
    assert_eq!(j["id"], claim.to_string());
}
