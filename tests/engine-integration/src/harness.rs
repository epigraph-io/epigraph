//! Shared test harness for engine integration tests.
//! Provides TestDb, helper functions for creating test entities in PostgreSQL.

use sqlx::{PgPool, Row};
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

/// RAII guard that cleans up test data on drop, even if the test panics.
///
/// Stores the content prefix; on `Drop`, opens a fresh DB connection (via
/// `DATABASE_URL`) on a new OS thread with its own tokio runtime and deletes
/// all claims/edges/factors whose content starts with the prefix. This avoids
/// the cross-runtime I/O-driver issue that arises when reusing a pool that was
/// created on a different runtime.
///
/// Tests should construct one at the top of the test body:
/// `let _guard = PrefixGuard::new(&db.pool, "[test-foo]");`
pub struct PrefixGuard {
    // The pool passed to `new` is kept alive for the test's duration but Drop
    // opens a fresh connection on its own runtime to avoid cross-runtime I/O
    // driver issues. Field name prefix _ suppresses the dead_code lint.
    _pool: PgPool,
    prefix: String,
}

impl PrefixGuard {
    #[must_use]
    pub fn new(pool: &PgPool, prefix: &str) -> Self {
        Self {
            _pool: pool.clone(),
            prefix: prefix.to_string(),
        }
    }
}

impl Drop for PrefixGuard {
    fn drop(&mut self) {
        // We cannot reuse the existing PgPool here: its connections are
        // registered with the tokio I/O driver of whichever runtime created
        // the pool, and that runtime may be partially unwound or blocked when
        // Drop runs. Instead we spawn a fresh OS thread with its own runtime
        // and a brand-new pool so cleanup always succeeds.
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set (PrefixGuard::drop)");
        let prefix = self.prefix.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("PrefixGuard::drop tokio runtime");
            rt.block_on(async move {
                let pool = sqlx::PgPool::connect(&database_url)
                    .await
                    .expect("PrefixGuard::drop db connect");
                cleanup_test_data(&pool, &prefix).await;
            });
        })
        .join()
        .expect("PrefixGuard::drop thread");
    }
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

/// Load all claims and edges matching `prefix` into a fresh
/// `PropagationOrchestrator`.
///
/// - Reads `claims` rows with `content LIKE prefix%` and registers each as a
///   `Claim` (with the DB-assigned id and truth_value).
/// - Reads `edges` joining those claims and converts:
///     `relationship = 'supports'`   → `is_supporting = true`,  EvidenceType::Empirical
///     `relationship = 'contradicts'`→ `is_supporting = false`, EvidenceType::Empirical
///   All edges use `strength = 0.8`, `age_days = 0.0` (test defaults).
///
/// Anything more elaborate (loading strength from edges.properties,
/// mapping evidence_type from a column, etc.) belongs in a production loader
/// — this is a test helper that exists to make the regression test exercise
/// real DB→engine flow rather than reconstructing state by hand.
pub async fn load_orchestrator_from_db(
    pool: &PgPool,
    prefix: &str,
) -> epigraph_engine::PropagationOrchestrator {
    use epigraph_core::{AgentId, Claim, ClaimId, TruthValue};
    use epigraph_engine::{EvidenceType, PropagationOrchestrator};

    let mut orch = PropagationOrchestrator::new();

    let claim_rows = sqlx::query(
        "SELECT id, content, agent_id, truth_value FROM claims WHERE content LIKE $1",
    )
    .bind(format!("{prefix}%"))
    .fetch_all(pool)
    .await
    .expect("load claims");

    for row in &claim_rows {
        let id: Uuid = row.get("id");
        let agent_id: Uuid = row.get("agent_id");
        let content: String = row.get("content");
        let truth: f64 = row.get("truth_value");

        // Reconstruct a Claim with the DB-assigned id. Public key is
        // synthetic — we never sign anything; the orchestrator doesn't verify.
        let mut public_key = [0u8; 32];
        public_key[..16].copy_from_slice(agent_id.as_bytes());
        let claim_proto = Claim::new(
            content,
            AgentId::from_uuid(agent_id),
            public_key,
            TruthValue::new(truth).unwrap(),
        );
        let claim = Claim::with_id(
            ClaimId::from_uuid(id),
            claim_proto.content,
            claim_proto.agent_id,
            claim_proto.public_key,
            claim_proto.content_hash,
            claim_proto.trace_id,
            claim_proto.signature,
            claim_proto.truth_value,
            claim_proto.created_at,
            claim_proto.updated_at,
        );
        orch.register_claim(claim).expect("register");
    }

    let edge_rows = sqlx::query(
        "SELECT e.source_id, e.target_id, e.relationship \
         FROM edges e \
         JOIN claims cs ON cs.id = e.source_id \
         WHERE cs.content LIKE $1",
    )
    .bind(format!("{prefix}%"))
    .fetch_all(pool)
    .await
    .expect("load edges");

    for row in &edge_rows {
        let src: Uuid = row.get("source_id");
        let tgt: Uuid = row.get("target_id");
        let rel: String = row.get("relationship");
        let is_supporting = !matches!(rel.to_lowercase().as_str(), "contradicts" | "refutes");
        orch.add_dependency(
            ClaimId::from_uuid(src),
            ClaimId::from_uuid(tgt),
            is_supporting,
            0.8,
            EvidenceType::Empirical,
            0.0,
        )
        .expect("add_dependency");
    }

    orch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires DATABASE_URL
    async fn prefix_guard_cleans_up_after_panic() {
        const PREFIX: &str = "[test-prefix-guard]";
        let db = TestDb::setup().await;
        let agent = create_test_agent(&db.pool).await;

        // Spawn a task that inserts a marker row then panics.
        // tokio::spawn catches the panic, unwinds the task (running Drop on
        // PrefixGuard), then resolves the JoinHandle to Err(JoinError).
        let pool = db.pool.clone();
        let handle = tokio::spawn(async move {
            let _guard = PrefixGuard::new(&pool, PREFIX);
            create_test_claim(&pool, agent, &format!("{PREFIX} marker"), 0.5).await;
            panic!("simulated test failure");
        });
        let join_result = handle.await;
        assert!(join_result.is_err(), "task should have panicked");

        // PrefixGuard::drop blocks until cleanup_test_data completes, so by
        // the time we reach here the rows are gone.
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM claims WHERE content LIKE $1",
        )
        .bind(format!("{PREFIX}%"))
        .fetch_one(&db.pool)
        .await
        .unwrap();

        assert_eq!(
            count, 0,
            "PrefixGuard::drop should have cleaned up rows even after panic"
        );
    }
}
