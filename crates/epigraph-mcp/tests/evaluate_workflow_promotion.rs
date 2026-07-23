//! Behavioral test for the `evaluate_workflow_promotion` MCP tool — the
//! read-only autonomous-statistical-gate verdict. Resolves a variant's parent
//! via the variant_of edge, compares behavioral success over the same window
//! with the Wilson lower-bound gate, and returns whether the variant is
//! promotable WITHOUT acting on it.

use epigraph_crypto::AgentSigner;
use epigraph_db::{BehavioralExecutionRepository, BehavioralExecutionRow};
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
                created_at: base + chrono::Duration::seconds(i),
                step_claim_id: None,
            },
            None,
        )
        .await
        .unwrap();
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn promotes_confident_variant_over_weaker_parent(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "ewp-agent").await;
    let parent = insert_claim(&pool, agent, "ewp-parent").await;
    let variant = insert_claim(&pool, agent, "ewp-variant").await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'variant_of')",
    )
    .bind(variant)
    .bind(parent)
    .execute(&pool)
    .await
    .unwrap();

    // Parent: 5/10 (0.5). Variant: 12/12 (Wilson lower bound ~0.76 > 0.5).
    seed_runs(&pool, parent, 5, 5).await;
    seed_runs(&pool, variant, 12, 0).await;

    let json = result_json(
        tools::workflows::evaluate_workflow_promotion(
            &server,
            EvaluateWorkflowPromotionParams {
                workflow_id: variant.to_string(),
                window: Some(50),
            },
        )
        .await
        .expect("evaluate ok"),
    );

    assert_eq!(json["parent_id"], parent.to_string());
    assert_eq!(
        json["promotable"], true,
        "confident variant promotes over 0.5 parent"
    );
    assert!(json["variant_lower_bound"].as_f64().unwrap() > 0.5);
}

#[sqlx::test(migrations = "../../migrations")]
async fn does_not_promote_small_sample_variant(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "ewp-agent2").await;
    let parent = insert_claim(&pool, agent, "ewp-parent2").await;
    let variant = insert_claim(&pool, agent, "ewp-variant2").await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'variant_of')",
    )
    .bind(variant)
    .bind(parent)
    .execute(&pool)
    .await
    .unwrap();

    // Variant is 3/3 — perfect but below the min-sample floor → not promotable.
    seed_runs(&pool, parent, 1, 1).await;
    seed_runs(&pool, variant, 3, 0).await;

    let json = result_json(
        tools::workflows::evaluate_workflow_promotion(
            &server,
            EvaluateWorkflowPromotionParams {
                workflow_id: variant.to_string(),
                window: None,
            },
        )
        .await
        .expect("evaluate ok"),
    );
    assert_eq!(
        json["promotable"], false,
        "3 executions is below the min sample"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn lineage_root_has_nothing_to_promote_over(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "ewp-agent3").await;
    let root = insert_claim(&pool, agent, "ewp-root").await; // no variant_of edge

    let json = result_json(
        tools::workflows::evaluate_workflow_promotion(
            &server,
            EvaluateWorkflowPromotionParams {
                workflow_id: root.to_string(),
                window: None,
            },
        )
        .await
        .expect("evaluate ok"),
    );
    assert_eq!(json["promotable"], false);
    assert!(json["parent_id"].is_null(), "a root has no parent");
}
