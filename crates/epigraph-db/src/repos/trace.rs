//! Reasoning trace repository for database operations

use crate::errors::DbError;
use epigraph_core::{AgentId, ClaimId, Methodology, ReasoningTrace, TraceId, TraceInput};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Repository for ReasoningTrace operations
pub struct ReasoningTraceRepository;

/// Row struct for trace queries that JOIN with claims to get agent_id.
///
/// This struct is used with `sqlx::query_as` to avoid requiring database
/// access at compile time while still preserving type safety at runtime.
#[derive(sqlx::FromRow)]
struct TraceWithAgentRow {
    id: Uuid,
    #[allow(dead_code)]
    claim_id: Uuid,
    reasoning_type: String,
    confidence: f64,
    explanation: String,
    properties: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    agent_id: Uuid,
}

/// Build ReasoningTrace from database row data.
///
/// This helper function handles the crypto fields that may not exist in
/// the database yet (public_key, content_hash). It uses placeholder values
/// until the database schema is migrated.
#[allow(clippy::too_many_arguments)]
fn trace_from_row(
    id: Uuid,
    agent_id: AgentId,
    methodology: Methodology,
    inputs: Vec<TraceInput>,
    confidence: f64,
    explanation: String,
    signature: Option<[u8; 64]>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> ReasoningTrace {
    // Placeholder crypto fields - will be populated when DB schema includes them
    let public_key = [0u8; 32];
    let content_hash = [0u8; 32];

    ReasoningTrace::with_id(
        TraceId::from_uuid(id),
        agent_id,
        public_key,
        content_hash,
        methodology,
        inputs,
        confidence,
        explanation,
        signature,
        created_at,
    )
}

impl ReasoningTraceRepository {
    /// Create a new reasoning trace in the database
    ///
    /// Note: This stores the trace metadata but does NOT store the inputs
    /// in trace_parents. Use `add_parent` to link traces together.
    ///
    /// # Arguments
    /// * `pool` - The database connection pool
    /// * `trace` - The reasoning trace to create
    /// * `claim_id` - The ID of the claim this trace is associated with
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, trace))]
    pub async fn create(
        pool: &PgPool,
        trace: &ReasoningTrace,
        claim_id: ClaimId,
    ) -> Result<ReasoningTrace, DbError> {
        let id: Uuid = trace.id.into();
        let agent_id: Uuid = trace.agent_id.into();
        let claim_uuid: Uuid = claim_id.into();

        let properties_json = serde_json::json!({
            "inputs": trace.inputs,
        });

        let methodology_str = Self::methodology_to_db_string(trace.methodology);
        let confidence = trace.confidence;
        let explanation = &trace.explanation;
        let created_at = trace.created_at;

        let row = sqlx::query!(
            r#"
            INSERT INTO reasoning_traces (
                id, claim_id, reasoning_type, confidence, explanation, properties, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, claim_id, reasoning_type, confidence, explanation, properties, created_at
            "#,
            id,
            claim_uuid,
            methodology_str,
            confidence,
            explanation,
            properties_json,
            created_at
        )
        .fetch_one(pool)
        .await?;

        let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

        // Extract inputs from properties (properties is NOT NULL DEFAULT '{}')
        let inputs: Vec<TraceInput> = serde_json::from_value(
            row.properties
                .get("inputs")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;

        Ok(trace_from_row(
            row.id,
            AgentId::from_uuid(agent_id),
            methodology,
            inputs,
            row.confidence,
            row.explanation,
            None, // signature not stored yet
            row.created_at,
        ))
    }

    /// Get a reasoning trace by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: TraceId) -> Result<Option<ReasoningTrace>, DbError> {
        let uuid: Uuid = id.into();

        // JOIN with claims table to get the correct agent_id
        // This preserves provenance tracking - the agent who made the claim
        // is the agent associated with the reasoning trace
        let row: Option<TraceWithAgentRow> = sqlx::query_as(
            r#"
            SELECT rt.id, rt.claim_id, rt.reasoning_type, rt.confidence,
                   rt.explanation, rt.properties, rt.created_at,
                   c.agent_id
            FROM reasoning_traces rt
            INNER JOIN claims c ON rt.claim_id = c.id
            WHERE rt.id = $1
            "#,
        )
        .bind(uuid)
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

                // Extract inputs from properties (properties is NOT NULL DEFAULT '{}')
                let inputs: Vec<TraceInput> = serde_json::from_value(
                    row.properties
                        .get("inputs")
                        .cloned()
                        .unwrap_or(serde_json::json!([])),
                )?;

                // Get agent_id from the joined claims table - preserves provenance
                let agent_id = AgentId::from_uuid(row.agent_id);

                Ok(Some(trace_from_row(
                    row.id,
                    agent_id,
                    methodology,
                    inputs,
                    row.confidence,
                    row.explanation,
                    None,
                    row.created_at,
                )))
            }
            None => Ok(None),
        }
    }

    /// Get all reasoning traces for a claim
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_claim(
        pool: &PgPool,
        claim_id: ClaimId,
    ) -> Result<Vec<ReasoningTrace>, DbError> {
        let uuid: Uuid = claim_id.into();

        // JOIN with claims table to get the correct agent_id
        let rows: Vec<TraceWithAgentRow> = sqlx::query_as(
            r#"
            SELECT rt.id, rt.claim_id, rt.reasoning_type, rt.confidence,
                   rt.explanation, rt.properties, rt.created_at,
                   c.agent_id
            FROM reasoning_traces rt
            INNER JOIN claims c ON rt.claim_id = c.id
            WHERE rt.claim_id = $1
            ORDER BY rt.created_at DESC
            "#,
        )
        .bind(uuid)
        .fetch_all(pool)
        .await?;

        let mut traces = Vec::with_capacity(rows.len());

        for row in rows {
            let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

            let inputs: Vec<TraceInput> = serde_json::from_value(
                row.properties
                    .get("inputs")
                    .cloned()
                    .unwrap_or(serde_json::json!([])),
            )?;

            // Get agent_id from the joined claims table - preserves provenance
            let agent_id = AgentId::from_uuid(row.agent_id);

            traces.push(trace_from_row(
                row.id,
                agent_id,
                methodology,
                inputs,
                row.confidence,
                row.explanation,
                None,
                row.created_at,
            ));
        }

        Ok(traces)
    }

    /// Add a parent trace relationship
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn add_parent(
        pool: &PgPool,
        trace_id: TraceId,
        parent_id: TraceId,
    ) -> Result<(), DbError> {
        let trace_uuid: Uuid = trace_id.into();
        let parent_uuid: Uuid = parent_id.into();

        sqlx::query!(
            r#"
            INSERT INTO trace_parents (trace_id, parent_id)
            VALUES ($1, $2)
            ON CONFLICT (trace_id, parent_id) DO NOTHING
            "#,
            trace_uuid,
            parent_uuid
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get parent traces
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_parents(
        pool: &PgPool,
        trace_id: TraceId,
    ) -> Result<Vec<ReasoningTrace>, DbError> {
        let uuid: Uuid = trace_id.into();

        // JOIN with claims table to get the correct agent_id for each parent trace
        let rows: Vec<TraceWithAgentRow> = sqlx::query_as(
            r#"
            SELECT rt.id, rt.claim_id, rt.reasoning_type, rt.confidence,
                   rt.explanation, rt.properties, rt.created_at,
                   c.agent_id
            FROM reasoning_traces rt
            INNER JOIN trace_parents tp ON rt.id = tp.parent_id
            INNER JOIN claims c ON rt.claim_id = c.id
            WHERE tp.trace_id = $1
            "#,
        )
        .bind(uuid)
        .fetch_all(pool)
        .await?;

        let mut traces = Vec::with_capacity(rows.len());

        for row in rows {
            let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

            let inputs: Vec<TraceInput> = serde_json::from_value(
                row.properties
                    .get("inputs")
                    .cloned()
                    .unwrap_or(serde_json::json!([])),
            )?;

            // Get agent_id from the joined claims table - preserves provenance
            let agent_id = AgentId::from_uuid(row.agent_id);

            traces.push(trace_from_row(
                row.id,
                agent_id,
                methodology,
                inputs,
                row.confidence,
                row.explanation,
                None,
                row.created_at,
            ));
        }

        Ok(traces)
    }

    /// Get child traces
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_children(
        pool: &PgPool,
        trace_id: TraceId,
    ) -> Result<Vec<ReasoningTrace>, DbError> {
        let uuid: Uuid = trace_id.into();

        // JOIN with claims table to get the correct agent_id for each child trace
        let rows: Vec<TraceWithAgentRow> = sqlx::query_as(
            r#"
            SELECT rt.id, rt.claim_id, rt.reasoning_type, rt.confidence,
                   rt.explanation, rt.properties, rt.created_at,
                   c.agent_id
            FROM reasoning_traces rt
            INNER JOIN trace_parents tp ON rt.id = tp.trace_id
            INNER JOIN claims c ON rt.claim_id = c.id
            WHERE tp.parent_id = $1
            "#,
        )
        .bind(uuid)
        .fetch_all(pool)
        .await?;

        let mut traces = Vec::with_capacity(rows.len());

        for row in rows {
            let methodology = Self::db_string_to_methodology(&row.reasoning_type)?;

            let inputs: Vec<TraceInput> = serde_json::from_value(
                row.properties
                    .get("inputs")
                    .cloned()
                    .unwrap_or(serde_json::json!([])),
            )?;

            // Get agent_id from the joined claims table - preserves provenance
            let agent_id = AgentId::from_uuid(row.agent_id);

            traces.push(trace_from_row(
                row.id,
                agent_id,
                methodology,
                inputs,
                row.confidence,
                row.explanation,
                None,
                row.created_at,
            ));
        }

        Ok(traces)
    }

    /// Convert Methodology enum to database string
    fn methodology_to_db_string(methodology: Methodology) -> &'static str {
        match methodology {
            Methodology::Deductive => "deductive",
            Methodology::Inductive => "inductive",
            Methodology::Abductive => "abductive",
            Methodology::Instrumental => "statistical",
            Methodology::Extraction => "statistical",
            Methodology::BayesianInference => "statistical",
            Methodology::VisualInspection => "statistical",
            Methodology::FormalProof => "deductive",
            Methodology::Heuristic => "abductive",
        }
    }

    /// Convert database string to Methodology enum
    fn db_string_to_methodology(s: &str) -> Result<Methodology, DbError> {
        match s {
            "deductive" => Ok(Methodology::Deductive),
            "inductive" => Ok(Methodology::Inductive),
            "abductive" => Ok(Methodology::Abductive),
            "analogical" => Ok(Methodology::Abductive), // Map to closest
            "statistical" => Ok(Methodology::BayesianInference),
            _ => Err(DbError::InvalidData {
                reason: format!("Unknown reasoning type: {}", s),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_trace_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/trace_tests.rs
    }

    /// Test: Verify that traces return correct agent_id from claims table
    ///
    /// **Evidence**: Security vulnerability - placeholder AgentId::new() breaks provenance
    /// **Reasoning**: Agent ID must be fetched via JOIN with claims table
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_trace_returns_correct_agent_id_not_placeholder(pool: sqlx::PgPool) {
        // Create a specific agent with unique public key derived from agent ID
        let known_agent_id = Uuid::new_v4();
        let mut public_key = [0u8; 32];
        public_key[..16].copy_from_slice(&known_agent_id.as_bytes()[..16]);
        public_key[16..].copy_from_slice(&known_agent_id.as_bytes()[..16]);
        sqlx::query(
            r#"
            INSERT INTO agents (id, public_key, display_name)
            VALUES ($1, $2, $3)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(known_agent_id)
        .bind(&public_key[..])
        .bind("Test Agent for Trace Provenance")
        .execute(&pool)
        .await
        .expect("Failed to create test agent");

        // Create a claim with that agent
        let claim_id = Uuid::new_v4();
        let content = "Test claim for trace provenance";
        let content_hash = blake3::hash(content.as_bytes());
        sqlx::query(
            r#"
            INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(claim_id)
        .bind(content)
        .bind(content_hash.as_bytes().as_slice())
        .bind(0.75f64)
        .bind(known_agent_id)
        .execute(&pool)
        .await
        .expect("Failed to create test claim");

        // Create a trace for that claim using the repository
        let trace = ReasoningTrace::new(
            AgentId::from_uuid(known_agent_id),
            public_key,
            Methodology::Deductive,
            vec![],
            0.9,
            "Test trace for provenance verification".to_string(),
        );

        let created_trace =
            ReasoningTraceRepository::create(&pool, &trace, ClaimId::from_uuid(claim_id))
                .await
                .expect("Failed to create trace");

        // CRITICAL: Verify the created trace has the correct agent_id
        let created_agent_uuid: Uuid = created_trace.agent_id.into();
        assert_eq!(
            created_agent_uuid, known_agent_id,
            "Created trace must have the original agent ID, not a placeholder"
        );

        // Now fetch the trace by ID and verify agent_id is correct
        let fetched_trace = ReasoningTraceRepository::get_by_id(&pool, created_trace.id)
            .await
            .expect("Failed to fetch trace")
            .expect("Trace should exist");

        let fetched_agent_uuid: Uuid = fetched_trace.agent_id.into();
        assert_eq!(
            fetched_agent_uuid, known_agent_id,
            "Fetched trace must have the correct agent ID from claims table, not a random placeholder"
        );

        // Verify by fetching via get_by_claim
        let traces_for_claim =
            ReasoningTraceRepository::get_by_claim(&pool, ClaimId::from_uuid(claim_id))
                .await
                .expect("Failed to fetch traces by claim");

        assert_eq!(traces_for_claim.len(), 1);
        let trace_from_claim: Uuid = traces_for_claim[0].agent_id.into();
        assert_eq!(
            trace_from_claim, known_agent_id,
            "Trace fetched by claim must have correct agent ID"
        );
    }

    /// Test: Verify that get_parents and get_children return correct agent IDs
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_trace_parents_children_have_correct_agent_ids(pool: sqlx::PgPool) {
        // Create two agents with unique public keys
        let agent1_id = Uuid::new_v4();
        let agent2_id = Uuid::new_v4();
        let mut public_key1 = [0u8; 32];
        let mut public_key2 = [0u8; 32];
        // Use agent IDs to create unique public keys
        public_key1[..16].copy_from_slice(&agent1_id.as_bytes()[..16]);
        public_key2[..16].copy_from_slice(&agent2_id.as_bytes()[..16]);

        for (agent_id, public_key, name) in [
            (agent1_id, &public_key1[..], "Agent 1"),
            (agent2_id, &public_key2[..], "Agent 2"),
        ] {
            sqlx::query(
                r#"
                INSERT INTO agents (id, public_key, display_name)
                VALUES ($1, $2, $3)
                ON CONFLICT (id) DO NOTHING
                "#,
            )
            .bind(agent_id)
            .bind(public_key)
            .bind(name)
            .execute(&pool)
            .await
            .expect("Failed to create agent");
        }

        // Create two claims with different agents
        let claim1_id = Uuid::new_v4();
        let claim2_id = Uuid::new_v4();
        let content_hash = blake3::hash(b"test");

        for (claim_id, agent_id, content) in [
            (claim1_id, agent1_id, "Claim by agent 1"),
            (claim2_id, agent2_id, "Claim by agent 2"),
        ] {
            sqlx::query(
                r#"
                INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
                VALUES ($1, $2, $3, $4, $5)
                "#,
            )
            .bind(claim_id)
            .bind(content)
            .bind(content_hash.as_bytes().as_slice())
            .bind(0.5f64)
            .bind(agent_id)
            .execute(&pool)
            .await
            .expect("Failed to create claim");
        }

        // Create parent trace (for claim1 by agent1)
        let parent_trace = ReasoningTrace::new(
            AgentId::from_uuid(agent1_id),
            public_key1,
            Methodology::Deductive,
            vec![],
            0.8,
            "Parent trace".to_string(),
        );
        let parent =
            ReasoningTraceRepository::create(&pool, &parent_trace, ClaimId::from_uuid(claim1_id))
                .await
                .expect("Failed to create parent trace");

        // Create child trace (for claim2 by agent2)
        let child_trace = ReasoningTrace::new(
            AgentId::from_uuid(agent2_id),
            public_key2,
            Methodology::Inductive,
            vec![],
            0.7,
            "Child trace".to_string(),
        );
        let child =
            ReasoningTraceRepository::create(&pool, &child_trace, ClaimId::from_uuid(claim2_id))
                .await
                .expect("Failed to create child trace");

        // Link parent-child
        ReasoningTraceRepository::add_parent(&pool, child.id, parent.id)
            .await
            .expect("Failed to add parent");

        // Verify get_parents returns correct agent_id for parent
        let parents = ReasoningTraceRepository::get_parents(&pool, child.id)
            .await
            .expect("Failed to get parents");
        assert_eq!(parents.len(), 1);
        let parent_agent: Uuid = parents[0].agent_id.into();
        assert_eq!(
            parent_agent, agent1_id,
            "Parent trace must have agent1's ID, not a placeholder"
        );

        // Verify get_children returns correct agent_id for child
        let children = ReasoningTraceRepository::get_children(&pool, parent.id)
            .await
            .expect("Failed to get children");
        assert_eq!(children.len(), 1);
        let child_agent: Uuid = children[0].agent_id.into();
        assert_eq!(
            child_agent, agent2_id,
            "Child trace must have agent2's ID, not a placeholder"
        );
    }
}
