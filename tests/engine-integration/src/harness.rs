//! Shared test harness for engine integration tests.
//! Provides TestDb, helper functions for creating test entities in PostgreSQL.

use sqlx::PgPool;
use uuid::Uuid;

/// Wrapper around PgPool for integration tests.
/// Connects via DATABASE_URL environment variable.
pub struct TestDb {
    pub pool: PgPool,
}

impl TestDb {
    /// Connect to the test database. Panics if DATABASE_URL is not set.
    pub async fn setup() -> Self {
        let url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");
        let pool = PgPool::connect(&url)
            .await
            .expect("Failed to connect to test database");
        Self { pool }
    }
}

/// Create a test agent in the database. Returns agent UUID.
pub async fn create_test_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    let mut public_key = [0u8; 32];
    public_key[..16].copy_from_slice(agent_id.as_bytes());

    sqlx::query(
        r#"INSERT INTO agents (id, public_key, display_name)
           VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(agent_id)
    .bind(&public_key[..])
    .bind(format!("Test Agent {}", &agent_id.to_string()[..8]))
    .execute(pool)
    .await
    .expect("Failed to create test agent");

    agent_id
}

/// Insert a claim into the database. Returns claim UUID.
pub async fn create_test_claim(
    pool: &PgPool,
    agent_id: Uuid,
    content: &str,
    truth_value: f64,
) -> Uuid {
    let claim_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current)
           VALUES ($1, $2, sha256($2::bytea), $3, $4, true)"#,
    )
    .bind(claim_id)
    .bind(content)
    .bind(agent_id)
    .bind(truth_value)
    .execute(pool)
    .await
    .expect("Failed to create test claim");

    claim_id
}

/// Insert an edge between two claims. Returns edge UUID.
pub async fn create_test_edge(
    pool: &PgPool,
    source_id: Uuid,
    target_id: Uuid,
    relationship: &str,
) -> Uuid {
    let edge_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship)
           VALUES ($1, $2, 'claim', $3, 'claim', $4)"#,
    )
    .bind(edge_id)
    .bind(source_id)
    .bind(target_id)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("Failed to create test edge");

    edge_id
}

/// Insert a factor manually (for tests that don't rely on auto-trigger).
pub async fn create_test_factor(
    pool: &PgPool,
    factor_type: &str,
    variable_ids: &[Uuid],
    potential: serde_json::Value,
) -> Uuid {
    let factor_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO factors (id, factor_type, variable_ids, potential)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(factor_id)
    .bind(factor_type)
    .bind(variable_ids)
    .bind(potential)
    .execute(pool)
    .await
    .expect("Failed to create test factor");

    factor_id
}

/// Clean up test data by prefix. Deletes claims whose content starts with the given prefix
/// and all edges/factors referencing them.
pub async fn cleanup_test_data(pool: &PgPool, content_prefix: &str) {
    // Get claim IDs first
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM claims WHERE content LIKE $1")
        .bind(format!("{content_prefix}%"))
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    if ids.is_empty() {
        return;
    }

    // Delete factors referencing these claims
    for id in &ids {
        let _ = sqlx::query("DELETE FROM factors WHERE $1 = ANY(variable_ids)")
            .bind(id)
            .execute(pool)
            .await;
    }

    // Delete edges referencing these claims
    let _ = sqlx::query("DELETE FROM edges WHERE source_id = ANY($1) OR target_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await;

    // Delete claims
    let _ = sqlx::query("DELETE FROM claims WHERE id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await;
}
