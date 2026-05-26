//! Integration test for SharedTripleBlocker.

use epigraph_engine::matching::blocker::{shared_triple::SharedTripleBlocker, Blocker};
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

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

async fn insert_entity(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, canonical_name, type_top)
         VALUES ($1, $2, 'Concept')",
    )
    .bind(id)
    .bind(format!("entity-{}", id))
    .execute(pool)
    .await
    .expect("entity");
    id
}

async fn insert_triple(pool: &PgPool, claim_id: Uuid, subject_id: Uuid, predicate: &str) {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO triples (id, claim_id, subject_id, predicate, object_literal, confidence, extractor)
         VALUES ($1, $2, $3, $4, 'lit', 0.9, 'test')",
    )
    .bind(id)
    .bind(claim_id)
    .bind(subject_id)
    .bind(predicate)
    .execute(pool)
    .await
    .expect("triple");
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_shared_triple_candidates(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let seed = insert_claim(&pool, agent).await;
    let other = insert_claim(&pool, agent).await;

    let subject = insert_entity(&pool).await;
    let predicate = "has_property";
    insert_triple(&pool, seed, subject, predicate).await;
    insert_triple(&pool, other, subject, predicate).await;

    let b = SharedTripleBlocker::new(50);
    let pairs = b.candidates(&pool, &[seed]).await.expect("candidates");

    let expected = if seed < other {
        (seed, other)
    } else {
        (other, seed)
    };
    assert!(
        pairs.contains(&expected),
        "expected pair {:?} in {:?}",
        expected,
        pairs
    );
    for (a, b) in &pairs {
        assert!(a < b, "pair not canonical: ({a}, {b})");
        assert_ne!(a, b, "self-pair found");
    }
}
