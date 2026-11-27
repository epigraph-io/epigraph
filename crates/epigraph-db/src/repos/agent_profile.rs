//! The reads behind `GET /api/v1/agents/:id/epistemic-profile`: the claims
//! attributed to an agent and the evidence-type distribution under them.
//!
//! Both are viewer-spliced (`{VISIBILITY}` / `{EDGE_VISIBILITY}`) and generic
//! over `PgExecutor`, so the handler (`routes/agents.rs::epistemic_profile`)
//! runs them on the one connection its `AppState::read_as` stamped from the
//! caller's viewer.

use crate::errors::DbError;
use tracing::instrument;
use uuid::Uuid;

/// Raw claim data for building an epistemic profile
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentClaimProfileRow {
    pub claim_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub properties: serde_json::Value,
    pub labels: Vec<String>,
}

/// Evidence type distribution row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EvidenceTypeCount {
    pub evidence_type: Option<String>,
    pub count: i64,
}

/// Repository for the agent epistemic-profile reads.
pub struct AgentProfileRepository;

impl AgentProfileRepository {
    /// Get all claims attributed to an agent for profile building.
    /// Traverses both ATTRIBUTED_TO and ORIGINATED_BY edges.
    #[instrument(skip(executor, viewer))]
    pub async fn get_agent_profile_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        agent_id: Uuid,
    ) -> Result<Vec<AgentClaimProfileRow>, DbError> {
        // The `edges` marker is in the LEFT JOIN's ON clause (a WHERE-clause
        // marker would null-filter it into an inner join), and the pre-existing
        // OR is parenthesised so the claim predicate ANDs with the whole
        // disjunction rather than only its right arm.
        let sql = viewer.splice(
            r#"
            SELECT DISTINCT c.id AS claim_id, c.content, c.truth_value,
                   c.created_at, c.properties, c.labels
            FROM claims c
            LEFT JOIN edges e ON e.source_id = c.id AND e.source_type = 'claim'
                              AND e.target_id = $1 AND e.target_type = 'agent'
                              AND e.relationship IN ('attributed_to', 'ATTRIBUTED_TO', 'ORIGINATED_BY')
                              /* {EDGE_VISIBILITY:e} */
            WHERE (c.agent_id = $1 OR e.id IS NOT NULL)
              /* {VISIBILITY:c} */
            ORDER BY c.created_at DESC
            "#,
            2,
        );
        let mut vq = sqlx::query_as::<_, AgentClaimProfileRow>(&sql).bind(agent_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Get evidence type distribution for an agent's claims
    #[instrument(skip(executor, viewer))]
    pub async fn get_agent_evidence_distribution<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        agent_id: Uuid,
    ) -> Result<Vec<EvidenceTypeCount>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT ev.evidence_type::TEXT AS evidence_type, COUNT(*) AS count
            FROM evidence ev
            JOIN edges e ON e.source_id = ev.id AND e.source_type = 'evidence'
                        AND e.target_type = 'claim'
                        AND e.relationship IN ('supports', 'SUPPORTS', 'uses_evidence')
            JOIN claims c ON e.target_id = c.id
            WHERE c.agent_id = $1
              /* {VISIBILITY:ev} */ /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:c} */
            GROUP BY ev.evidence_type
            ORDER BY count DESC
            "#,
            2,
        );
        let mut vq = sqlx::query_as::<_, EvidenceTypeCount>(&sql).bind(agent_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(executor).await?;

        Ok(rows)
    }
}
