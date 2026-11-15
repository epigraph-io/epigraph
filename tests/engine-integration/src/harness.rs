//! Shared test harness for engine integration tests.
//! Provides TestDb, helper functions for creating test entities in PostgreSQL.

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Wrapper around the PgPool a `#[sqlx::test]` hands each test: its own
/// database, migrated from empty, dropped when the test ends. Nothing a test
/// writes needs cleaning up, and no test shares rows with another.
pub struct TestDb {
    pub pool: PgPool,
}

impl TestDb {
    /// Wrap the test's own pool.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
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

/// Load all claims and edges matching `prefix` into a fresh
/// `PropagationOrchestrator`.
///
/// - Reads `claims` rows with `content LIKE prefix%` and registers each as a
///   `Claim` (with the DB-assigned id and truth_value).
/// - Reads `edges` joining those claims and converts:
///   `relationship = 'supports'` → `is_supporting = true`,
///   `relationship = 'contradicts' | 'refutes'` → `is_supporting = false`,
///   everything else maps to `is_supporting = true`. Evidence type is
///   `EvidenceType::Empirical`; `strength = 0.8`; `age_days = 0.0`.
///
/// Anything more elaborate (loading strength from edges.properties,
/// mapping evidence_type from a column, etc.) belongs in a production loader
/// — this is a test helper that exists to make the regression test exercise
/// real DB→engine flow rather than reconstructing state by hand.
///
/// Limitation: the edge SELECT filters on `cs.content LIKE prefix%` for the
/// source side only. Tests must use the same prefix for both endpoints of
/// every edge — an edge to an out-of-prefix target is still added to the
/// DAG via `add_dependency`, but the target claim is never `register_claim`'d,
/// and `update_and_propagate` silently skips propagation through it.
pub async fn load_orchestrator_from_db(
    pool: &PgPool,
    prefix: &str,
) -> epigraph_engine::PropagationOrchestrator {
    use epigraph_core::{AgentId, Claim, ClaimId, TruthValue};
    use epigraph_engine::{EvidenceType, PropagationOrchestrator};

    let mut orch = PropagationOrchestrator::new();

    let claim_rows =
        sqlx::query("SELECT id, content, agent_id, truth_value FROM claims WHERE content LIKE $1")
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
