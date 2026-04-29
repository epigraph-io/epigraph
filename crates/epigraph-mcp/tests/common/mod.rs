//! Shared test helpers for epigraph-mcp integration tests. Mirrors
//! crates/epigraph-db/tests/claim_repo_helpers.rs — same try_test_pool,
//! pre-107/post-107 fixture toggling, agent insert, claim builder.

#![allow(dead_code)]

use epigraph_core::{AgentId, Claim, TruthValue};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
    Some(pool)
}

#[macro_export]
macro_rules! test_pool_or_skip {
    () => {{
        match $crate::common::try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                return;
            }
        }
    }};
}

/// Drop the (content_hash, agent_id) UNIQUE constraint to exercise the
/// pre-107 fixture path.
pub async fn drop_unique_constraint(pool: &PgPool) {
    sqlx::query("ALTER TABLE claims DROP CONSTRAINT IF EXISTS uq_claims_content_hash_agent")
        .execute(pool)
        .await
        .expect("drop constraint");
}

/// Add the (content_hash, agent_id) UNIQUE constraint, deduping any
/// existing duplicate rows first. Postgres has no `ADD CONSTRAINT IF NOT
/// EXISTS`, so the DO block swallows duplicate_object.
pub async fn add_unique_constraint(pool: &PgPool) {
    sqlx::query(
        "DELETE FROM claims a USING claims b
         WHERE a.ctid > b.ctid
           AND a.content_hash = b.content_hash
           AND a.agent_id = b.agent_id",
    )
    .execute(pool)
    .await
    .expect("dedup before constraint");

    sqlx::query(
        r#"DO $$ BEGIN
              ALTER TABLE claims ADD CONSTRAINT uq_claims_content_hash_agent
                  UNIQUE (content_hash, agent_id);
           EXCEPTION WHEN duplicate_object THEN NULL;
           END $$"#,
    )
    .execute(pool)
    .await
    .expect("add constraint");
}

pub async fn insert_test_agent(pool: &PgPool, agent_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO agents (id, public_key, created_at, updated_at)
           VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("upsert agent");
}

pub fn make_claim(content: &str, agent_id: Uuid) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    )
}
