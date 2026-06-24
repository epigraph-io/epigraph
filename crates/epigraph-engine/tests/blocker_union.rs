//! Integration test for union_block with source-filter.

use epigraph_engine::matching::blocker::{
    content_hash_prefix::ContentHashBlocker, embedding_ann::EmbeddingAnnBlocker, union_block,
    Blocker,
};
use epigraph_engine::matching::calibration::EligibilityConfig;
use epigraph_engine::matching::source_key::SourceFilterConfig;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.expect("test DB migrations failed — likely a description/version mismatch with existing _sqlx_migrations; use a fresh DB");
    Some(pool)
}
macro_rules! test_pool_or_skip {
    () => {
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test");
                return;
            }
        }
    };
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_claim_with_props_and_hash(
    pool: &PgPool,
    agent: Uuid,
    props: serde_json::Value,
    hash: &[u8; 32],
) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, properties)
         VALUES ($1, $2, $3, 0.5, $4, $5)",
    )
    .bind(id)
    .bind(&content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(props)
    .execute(pool)
    .await
    .expect("claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn same_paper_pairs_are_filtered_out(pool: PgPool) {
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let hash = [9u8; 32];
    let props = serde_json::json!({"paper_doi": "10.1/sameforboth"});
    let _seed = insert_claim_with_props_and_hash(&pool, a1, props.clone(), &hash).await;
    let _peer = insert_claim_with_props_and_hash(&pool, a2, props.clone(), &hash).await;

    let blockers: Vec<Box<dyn Blocker>> = vec![
        Box::new(ContentHashBlocker),
        Box::new(EmbeddingAnnBlocker::new(10)),
    ];
    let pairs = union_block(
        &pool,
        &blockers,
        &[_seed],
        SourceFilterConfig::default(),
        &EligibilityConfig::default(),
    )
    .await
    .expect("union_block");

    assert!(
        pairs.is_empty(),
        "same-paper pair should be filtered out, got {:?}",
        pairs
    );
}

async fn insert_claim_labeled(
    pool: &PgPool,
    agent: Uuid,
    props: serde_json::Value,
    hash: &[u8; 32],
    labels: &[&str],
) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    let labels: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, properties, labels)
         VALUES ($1, $2, $3, 0.5, $4, $5, $6)",
    )
    .bind(id)
    .bind(&content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(props)
    .bind(&labels)
    .execute(pool)
    .await
    .expect("claim");
    id
}

/// Candidate hygiene: a cross-source pair touching a `workflow_step` claim
/// (e.g. content "Body") must be dropped before scoring, while a substantive
/// cross-source pair survives. Both halves are load-bearing — the positive
/// control proves the filter discriminates rather than dropping everything.
#[sqlx::test(migrations = "../../migrations")]
async fn workflow_step_claims_are_excluded_by_hygiene(pool: PgPool) {
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    // Different paper_doi → the source-key filter does NOT drop these, so the
    // hygiene filter is the only thing that can.
    let props_a = serde_json::json!({"paper_doi": "10.1/HYGI-A"});
    let props_b = serde_json::json!({"paper_doi": "10.1/HYGI-B"});
    let blockers: Vec<Box<dyn Blocker>> = vec![Box::new(ContentHashBlocker)];
    let elig = EligibilityConfig::default(); // exclude_labels = [workflow_step, telemetry]

    // Positive control: substantive cross-source pair (no excluded labels),
    // sharing a content_hash so ContentHashBlocker pairs them → survives.
    let sub_hash = [11u8; 32];
    let sub_seed = insert_claim_labeled(&pool, a1, props_a.clone(), &sub_hash, &[]).await;
    let _sub_peer = insert_claim_labeled(&pool, a2, props_b.clone(), &sub_hash, &[]).await;
    let pairs = union_block(
        &pool,
        &blockers,
        &[sub_seed],
        SourceFilterConfig::default(),
        &elig,
    )
    .await
    .expect("union_block");
    assert_eq!(
        pairs.len(),
        1,
        "substantive cross-source pair must survive hygiene, got {:?}",
        pairs
    );

    // The bug class: a `workflow_step` pair would also be generated, but must
    // be EXCLUDED by candidate hygiene.
    let ws_hash = [12u8; 32];
    let ws_seed = insert_claim_labeled(&pool, a1, props_a, &ws_hash, &["workflow_step"]).await;
    let _ws_peer = insert_claim_labeled(&pool, a2, props_b, &ws_hash, &["workflow_step"]).await;
    let ws_pairs = union_block(
        &pool,
        &blockers,
        &[ws_seed],
        SourceFilterConfig::default(),
        &elig,
    )
    .await
    .expect("union_block");
    assert!(
        ws_pairs.is_empty(),
        "workflow_step pair must be excluded by candidate hygiene, got {:?}",
        ws_pairs
    );
}
