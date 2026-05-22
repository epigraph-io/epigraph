//! Integration tests for `derive_source_key`.
//!
//! Requires a live PostgreSQL database reachable via `DATABASE_URL`.
//! Tests skip automatically when the database is unavailable.

use epigraph_engine::matching::source_key::derive_source_key;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

// --- pool helpers (project pattern) ---

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
    () => {{
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                return;
            }
        }
    }};
}

// --- seed helpers ---

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("insert agent");
    id
}

async fn insert_claim_with_properties(
    pool: &PgPool,
    agent_id: Uuid,
    properties: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, properties)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent_id)
    .bind(properties)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

async fn insert_claim(pool: &PgPool, agent_id: Uuid) -> Uuid {
    insert_claim_with_properties(pool, agent_id, serde_json::json!({})).await
}

async fn insert_derived_from(pool: &PgPool, child: Uuid, parent: Uuid) {
    // source_type and target_type are NOT NULL; both are 'claim' here.
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', 'derived_from')",
    )
    .bind(child)
    .bind(parent)
    .execute(pool)
    .await
    .expect("insert derived_from edge");
}

// --- tests ---

#[sqlx::test(migrations = "../../migrations")]
async fn derive_extracts_paper_doi_from_properties(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let claim_id = insert_claim_with_properties(
        &pool,
        agent_id,
        serde_json::json!({"paper_doi": "10.1/abc"}),
    )
    .await;
    let key = derive_source_key(&pool, claim_id).await.expect("derive");
    assert_eq!(key.paper_doi.as_deref(), Some("10.1/abc"));
    assert_eq!(key.agent_id, agent_id);
    assert_eq!(key.ingestion_run_id, None);
    assert_eq!(key.derivation_root, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn derive_chases_derivation_root(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let root = insert_claim(&pool, agent_id).await;
    let mid = insert_claim(&pool, agent_id).await;
    let leaf = insert_claim(&pool, agent_id).await;
    insert_derived_from(&pool, mid, root).await;
    insert_derived_from(&pool, leaf, mid).await;
    let key = derive_source_key(&pool, leaf).await.expect("derive");
    assert_eq!(key.derivation_root, Some(root));
}
