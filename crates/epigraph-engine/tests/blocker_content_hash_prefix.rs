//! Integration test for ContentHashBlocker.

use epigraph_engine::matching::blocker::{content_hash_prefix::ContentHashBlocker, Blocker};
use sqlx::PgPool;
use uuid::Uuid;

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

/// Insert a claim with an explicit 32-byte content_hash (passed as a hex literal).
async fn insert_claim_with_hash(pool: &PgPool, agent: Uuid, hash_hex: &str) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(&format!(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, '\\x{}'::bytea, 0.5, $3)",
        hash_hex
    ))
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim with explicit hash");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_same_hash_cross_agent_pair(pool: PgPool) {
    // Two distinct agents so the UNIQUE(content_hash, agent_id) constraint is satisfied.
    let agent_a = insert_agent(&pool).await;
    let agent_b = insert_agent(&pool).await;

    // Exactly 32 bytes (64 hex chars).
    let hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let seed = insert_claim_with_hash(&pool, agent_a, hash).await;
    let other = insert_claim_with_hash(&pool, agent_b, hash).await;

    let b = ContentHashBlocker;
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
