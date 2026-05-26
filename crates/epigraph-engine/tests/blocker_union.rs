//! Integration test for union_block with source-filter.

use epigraph_engine::matching::blocker::{
    content_hash_prefix::ContentHashBlocker, embedding_ann::EmbeddingAnnBlocker, union_block,
    Blocker,
};
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
    let pairs = union_block(&pool, &blockers, &[_seed], SourceFilterConfig::default())
        .await
        .expect("union_block");

    assert!(
        pairs.is_empty(),
        "same-paper pair should be filtered out, got {:?}",
        pairs
    );
}
