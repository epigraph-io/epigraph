//! Integration test for EmbeddingAnnBlocker.

use epigraph_engine::matching::blocker::{embedding_ann::EmbeddingAnnBlocker, Blocker};
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
                eprintln!("Skipping DB test: DATABASE_URL not set");
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

async fn insert_claim_with_embedding(pool: &PgPool, agent: Uuid, embedding: &[f32]) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    // pgvector accepts embeddings via SQL literal "[v1,v2,...]::vector" —
    // the same pattern used in epigraph-db/src/repos/entity.rs.
    let lit = format!(
        "[{}]",
        embedding
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    sqlx::query(&format!(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, embedding)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, '{}'::vector)",
        lit
    ))
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_topk_canonical_pairs_excluding_self(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let seed_vec = vec![1.0_f32; 1536];
    let seed = insert_claim_with_embedding(&pool, agent, &seed_vec).await;
    for _ in 0..5 {
        let v = vec![0.9_f32; 1536];
        insert_claim_with_embedding(&pool, agent, &v).await;
    }
    let b = EmbeddingAnnBlocker::new(3);
    let pairs = b.candidates(&pool, &[seed]).await.expect("candidates");
    assert!(pairs.len() <= 3, "got {} pairs, expected ≤ 3", pairs.len());
    for (a, b) in &pairs {
        assert!(a < b, "pair not canonical: ({a}, {b})");
        assert_ne!(a, b, "self-pair found");
    }
}
