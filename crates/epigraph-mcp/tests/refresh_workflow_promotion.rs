//! Behavioral test for the `refresh_workflow_promotion` apply-layer tool.
//!
//! The critical property is BIDIRECTIONALITY: the promotable flag is computed
//! over a window, so a variant promoted today can regress tomorrow. The pass
//! must overwrite the verdict each run — never leave a stale `promotable:true`.

use epigraph_core::ClaimId;
use epigraph_crypto::AgentSigner;
use epigraph_db::{BehavioralExecutionRepository, BehavioralExecutionRow, ClaimRepository};
use epigraph_mcp::types::EvaluateWorkflowPromotionParams;
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
    match first.raw {
        RawContent::Text(t) => serde_json::from_str(&t.text).expect("result is JSON"),
        other => panic!("expected text content, got {other:?}"),
    }
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

async fn seed_runs(pool: &PgPool, wf: Uuid, successes: usize, failures: usize) {
    let base = chrono::Utc::now();
    for (i, succ) in std::iter::repeat(true)
        .take(successes)
        .chain(std::iter::repeat(false).take(failures))
        .enumerate()
    {
        let i = i as i64;
        BehavioralExecutionRepository::create(
            pool,
            BehavioralExecutionRow {
                id: Uuid::new_v4(),
                workflow_id: wf,
                goal_text: "g".into(),
                success: succ,
                step_beliefs: serde_json::json!({}),
                tool_pattern: vec![],
                quality: None,
                deviation_count: 0,
                total_steps: 1,
                created_at: base + chrono::Duration::milliseconds(i),
                step_claim_id: None,
            },
            None,
        )
        .await
        .unwrap();
    }
}

async fn link_variant(pool: &PgPool, variant: Uuid, parent: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'variant_of')",
    )
    .bind(variant)
    .bind(parent)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_sets_then_clears_promotable(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "rwp-agent").await;
    let parent = insert_claim(&pool, agent, "rwp-parent").await;
    let variant = insert_claim(&pool, agent, "rwp-variant").await;
    link_variant(&pool, variant, parent).await;

    // Phase 1: variant 12/12 over a 0.5 parent → promotable. Flag written true.
    seed_runs(&pool, parent, 5, 5).await;
    seed_runs(&pool, variant, 12, 0).await;
    let j1 = result_json(
        tools::workflows::refresh_workflow_promotion(
            &server,
            EvaluateWorkflowPromotionParams {
                workflow_id: variant.to_string(),
                window: Some(50),
            },
        )
        .await
        .expect("refresh ok"),
    );
    assert_eq!(j1["refreshed"], true);
    assert_eq!(j1["promotable"], true);
    assert_eq!(
        ClaimRepository::promotion_flag(&pool, ClaimId::from_uuid(variant))
            .await
            .unwrap(),
        Some(true),
        "promotable flag persisted to properties"
    );

    // Phase 2: the variant regresses (20 failures → 12/32 = 0.375 < parent 0.5).
    // A second refresh must OVERWRITE the verdict to false — not leave a stale true.
    seed_runs(&pool, variant, 0, 20).await;
    let j2 = result_json(
        tools::workflows::refresh_workflow_promotion(
            &server,
            EvaluateWorkflowPromotionParams {
                workflow_id: variant.to_string(),
                window: Some(50),
            },
        )
        .await
        .expect("refresh ok"),
    );
    assert_eq!(
        j2["promotable"], false,
        "regressed variant is demoted on re-run"
    );
    assert_eq!(
        ClaimRepository::promotion_flag(&pool, ClaimId::from_uuid(variant))
            .await
            .unwrap(),
        Some(false),
        "flag cleared to false (bidirectional) — no stale promotable mark"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_skips_lineage_root(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "rwp-agent2").await;
    let root = insert_claim(&pool, agent, "rwp-root").await; // no variant_of edge

    let j = result_json(
        tools::workflows::refresh_workflow_promotion(
            &server,
            EvaluateWorkflowPromotionParams {
                workflow_id: root.to_string(),
                window: None,
            },
        )
        .await
        .expect("refresh ok"),
    );
    assert_eq!(j["refreshed"], false, "a lineage root is left untouched");
    assert_eq!(
        ClaimRepository::promotion_flag(&pool, ClaimId::from_uuid(root))
            .await
            .unwrap(),
        None,
        "no promotion flag written for a root"
    );
}
