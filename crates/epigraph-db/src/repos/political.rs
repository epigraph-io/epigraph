//! Political network monitoring repository
//!
//! Provides database queries for narrative propagation analysis:
//! - Epistemic profiles (Item 4)
//! - Position timelines (Item 5)
//! - Talking point genealogy (Item 8)
//! - Inflation index (Item 9)
//! - Coalition queries (Item 7)
//! - Propaganda technique CRUD

use crate::errors::DbError;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

// ============================================================================
// Propaganda Technique CRUD
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PropagandaTechniqueRow {
    pub id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub detection_guidance: Option<String>,
    pub properties: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CoalitionRow {
    pub id: Uuid,
    pub name: Option<String>,
    pub archetype: Option<String>,
    pub dominant_antagonist: Option<String>,
    pub cognitive_shape: Option<String>,
    pub member_count: i32,
    pub start_date: Option<chrono::DateTime<chrono::Utc>>,
    pub peak_date: Option<chrono::DateTime<chrono::Utc>>,
    pub end_date: Option<chrono::DateTime<chrono::Utc>>,
    pub reach_estimate: Option<i64>,
    pub is_active: bool,
    pub detection_method: String,
    pub properties: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Epistemic Profile (Item 4)
// ============================================================================

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

// ============================================================================
// Position Timeline (Item 5)
// ============================================================================

/// A claim with its date and supersession info for timeline construction
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TimelineClaimRow {
    pub claim_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub properties: serde_json::Value,
    pub supersedes_id: Option<Uuid>,
}

// ============================================================================
// Genealogy (Item 8)
// ============================================================================

/// A propagation step in a talking point's genealogy
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PropagationStepRow {
    pub edge_id: Uuid,
    pub agent_id: Uuid,
    pub agent_name: Option<String>,
    pub relationship: String,
    pub properties: serde_json::Value,
    pub edge_created_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Repository
// ============================================================================

pub struct PoliticalRepository;

impl PoliticalRepository {
    // ── Propaganda Techniques ────────────────────────────────────────────

    #[instrument(skip(pool))]
    pub async fn create_technique(
        pool: &PgPool,
        name: &str,
        category: Option<&str>,
        description: Option<&str>,
        detection_guidance: Option<&str>,
        properties: Option<serde_json::Value>,
    ) -> Result<PropagandaTechniqueRow, DbError> {
        let props = properties.unwrap_or(serde_json::json!({}));
        let row = sqlx::query_as::<_, PropagandaTechniqueRow>(
            r#"
            INSERT INTO propaganda_techniques (name, category, description, detection_guidance, properties)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, name, category, description, detection_guidance, properties, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(category)
        .bind(description)
        .bind(detection_guidance)
        .bind(props)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    #[instrument(skip(pool))]
    pub async fn get_technique(
        pool: &PgPool,
        id: Uuid,
    ) -> Result<Option<PropagandaTechniqueRow>, DbError> {
        let row = sqlx::query_as::<_, PropagandaTechniqueRow>(
            r#"
            SELECT id, name, category, description, detection_guidance, properties, created_at, updated_at
            FROM propaganda_techniques WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    #[instrument(skip(pool))]
    pub async fn list_techniques(
        pool: &PgPool,
        category: Option<&str>,
        limit: i64,
    ) -> Result<Vec<PropagandaTechniqueRow>, DbError> {
        let rows = if let Some(cat) = category {
            sqlx::query_as::<_, PropagandaTechniqueRow>(
                r#"
                SELECT id, name, category, description, detection_guidance, properties, created_at, updated_at
                FROM propaganda_techniques WHERE category = $1
                ORDER BY name LIMIT $2
                "#,
            )
            .bind(cat)
            .bind(limit)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as::<_, PropagandaTechniqueRow>(
                r#"
                SELECT id, name, category, description, detection_guidance, properties, created_at, updated_at
                FROM propaganda_techniques ORDER BY name LIMIT $1
                "#,
            )
            .bind(limit)
            .fetch_all(pool)
            .await?
        };

        Ok(rows)
    }

    // ── Coalitions ──────────────────────────────────────────────────────

    #[instrument(skip(pool))]
    pub async fn create_coalition(
        pool: &PgPool,
        name: Option<&str>,
        archetype: Option<&str>,
        dominant_antagonist: Option<&str>,
        cognitive_shape: Option<&str>,
        detection_method: &str,
        properties: Option<serde_json::Value>,
    ) -> Result<CoalitionRow, DbError> {
        let props = properties.unwrap_or(serde_json::json!({}));
        let row = sqlx::query_as::<_, CoalitionRow>(
            r#"
            INSERT INTO coalitions (name, archetype, dominant_antagonist, cognitive_shape, detection_method, properties)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, archetype, dominant_antagonist, cognitive_shape, member_count,
                      start_date, peak_date, end_date, reach_estimate, is_active, detection_method,
                      properties, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(archetype)
        .bind(dominant_antagonist)
        .bind(cognitive_shape)
        .bind(detection_method)
        .bind(props)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    #[instrument(skip(pool))]
    pub async fn list_coalitions(
        pool: &PgPool,
        active_only: bool,
        archetype: Option<&str>,
        min_members: i32,
        limit: i64,
    ) -> Result<Vec<CoalitionRow>, DbError> {
        let rows = sqlx::query_as::<_, CoalitionRow>(
            r#"
            SELECT id, name, archetype, dominant_antagonist, cognitive_shape, member_count,
                   start_date, peak_date, end_date, reach_estimate, is_active, detection_method,
                   properties, created_at, updated_at
            FROM coalitions
            WHERE ($1 = FALSE OR is_active = TRUE)
              AND ($2::VARCHAR IS NULL OR archetype = $2)
              AND member_count >= $3
            ORDER BY created_at DESC
            LIMIT $4
            "#,
        )
        .bind(active_only)
        .bind(archetype)
        .bind(min_members)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    // ── Epistemic Profile (Item 4) ──────────────────────────────────────

    /// Get all claims attributed to an agent for profile building.
    /// Traverses both ATTRIBUTED_TO and ORIGINATED_BY edges.
    #[instrument(skip(pool))]
    pub async fn get_agent_profile_claims(
        pool: &PgPool,
        agent_id: Uuid,
    ) -> Result<Vec<AgentClaimProfileRow>, DbError> {
        let rows = sqlx::query_as::<_, AgentClaimProfileRow>(
            r#"
            SELECT DISTINCT c.id AS claim_id, c.content, c.truth_value,
                   c.created_at, c.properties, c.labels
            FROM claims c
            LEFT JOIN edges e ON e.source_id = c.id AND e.source_type = 'claim'
                              AND e.target_id = $1 AND e.target_type = 'agent'
                              AND e.relationship IN ('attributed_to', 'ATTRIBUTED_TO', 'ORIGINATED_BY')
            WHERE c.agent_id = $1 OR e.id IS NOT NULL
            ORDER BY c.created_at DESC
            "#,
        )
        .bind(agent_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get evidence type distribution for an agent's claims
    #[instrument(skip(pool))]
    pub async fn get_agent_evidence_distribution(
        pool: &PgPool,
        agent_id: Uuid,
    ) -> Result<Vec<EvidenceTypeCount>, DbError> {
        let rows = sqlx::query_as::<_, EvidenceTypeCount>(
            r#"
            SELECT ev.evidence_type::TEXT AS evidence_type, COUNT(*) AS count
            FROM evidence ev
            JOIN edges e ON e.source_id = ev.id AND e.source_type = 'evidence'
                        AND e.target_type = 'claim'
                        AND e.relationship IN ('supports', 'SUPPORTS', 'uses_evidence')
            JOIN claims c ON e.target_id = c.id
            WHERE c.agent_id = $1
            GROUP BY ev.evidence_type
            ORDER BY count DESC
            "#,
        )
        .bind(agent_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    // ── Position Timeline (Item 5) ──────────────────────────────────────

    /// Get claims for an agent on a given topic, ordered by date.
    /// Uses semantic similarity if an embedding is provided.
    #[instrument(skip(pool))]
    pub async fn get_agent_position_timeline(
        pool: &PgPool,
        agent_id: Uuid,
        since: Option<chrono::DateTime<chrono::Utc>>,
        until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<TimelineClaimRow>, DbError> {
        let since_date = since.unwrap_or(chrono::DateTime::UNIX_EPOCH);
        let until_date = until.unwrap_or_else(chrono::Utc::now);

        let rows = sqlx::query_as::<_, TimelineClaimRow>(
            r#"
            SELECT c.id AS claim_id, c.content, c.truth_value,
                   c.created_at, c.properties,
                   sup_edge.target_id AS supersedes_id
            FROM claims c
            LEFT JOIN edges sup_edge ON sup_edge.source_id = c.id
                AND sup_edge.source_type = 'claim'
                AND sup_edge.target_type = 'claim'
                AND sup_edge.relationship IN ('supersedes', 'SUPERSEDES')
            WHERE c.agent_id = $1
              AND c.created_at >= $2
              AND c.created_at <= $3
            ORDER BY c.created_at ASC
            "#,
        )
        .bind(agent_id)
        .bind(since_date)
        .bind(until_date)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    // ── Talking Point Genealogy (Item 8) ─────────────────────────────────

    /// Get the propagation tree for a claim — walk ORIGINATED_BY and AMPLIFIED_BY edges.
    #[instrument(skip(pool))]
    pub async fn get_claim_genealogy(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<PropagationStepRow>, DbError> {
        let rows = sqlx::query_as::<_, PropagationStepRow>(
            r#"
            SELECT e.id AS edge_id, e.target_id AS agent_id,
                   a.display_name AS agent_name,
                   e.relationship, e.properties,
                   e.created_at AS edge_created_at
            FROM edges e
            JOIN agents a ON a.id = e.target_id
            WHERE e.source_id = $1
              AND e.source_type = 'claim'
              AND e.target_type = 'agent'
              AND e.relationship IN ('ORIGINATED_BY', 'AMPLIFIED_BY')
            ORDER BY e.properties->>'date_asserted' ASC NULLS LAST,
                     e.properties->>'date_amplified' ASC NULLS LAST,
                     e.created_at ASC
            "#,
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get claims originated by an agent that were amplified by N+ others.
    #[instrument(skip(pool))]
    pub async fn get_originated_claims_with_amplification(
        pool: &PgPool,
        agent_id: Uuid,
        min_amplifiers: i64,
        limit: i64,
    ) -> Result<Vec<(Uuid, String, i64)>, DbError> {
        let rows: Vec<(Uuid, String, i64)> = sqlx::query_as(
            r#"
            SELECT c.id, c.content, COUNT(amp.id) AS amplifier_count
            FROM claims c
            JOIN edges orig ON orig.source_id = c.id
                AND orig.source_type = 'claim'
                AND orig.target_id = $1 AND orig.target_type = 'agent'
                AND orig.relationship = 'ORIGINATED_BY'
            LEFT JOIN edges amp ON amp.source_id = c.id
                AND amp.source_type = 'claim'
                AND amp.target_type = 'agent'
                AND amp.relationship = 'AMPLIFIED_BY'
            GROUP BY c.id, c.content
            HAVING COUNT(amp.id) >= $2
            ORDER BY amplifier_count DESC
            LIMIT $3
            "#,
        )
        .bind(agent_id)
        .bind(min_amplifiers)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    // ── Inflation Index (Item 9) ─────────────────────────────────────────

    /// Get claims with quantitative assertions and their counter-evidence.
    /// Looks for claims with inflation_factor in properties.
    #[instrument(skip(pool))]
    pub async fn get_agent_inflation_claims(
        pool: &PgPool,
        agent_id: Uuid,
    ) -> Result<Vec<(Uuid, String, f64, serde_json::Value)>, DbError> {
        let rows: Vec<(Uuid, String, f64, serde_json::Value)> = sqlx::query_as(
            r#"
            SELECT c.id, c.content, c.truth_value, c.properties
            FROM claims c
            WHERE c.agent_id = $1
              AND c.properties ? 'inflation_factor'
            ORDER BY (c.properties->>'inflation_factor')::FLOAT DESC NULLS LAST
            "#,
        )
        .bind(agent_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    // ── Techniques on a claim ────────────────────────────────────────────

    /// Get propaganda techniques used by a claim via USES_TECHNIQUE edges.
    #[instrument(skip(pool))]
    #[allow(clippy::type_complexity)]
    pub async fn get_claim_techniques(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<(PropagandaTechniqueRow, serde_json::Value)>, DbError> {
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            Uuid,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            serde_json::Value,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
            serde_json::Value,
        )> = sqlx::query_as(
            r#"
            SELECT pt.id, pt.name, pt.category, pt.description, pt.detection_guidance,
                   pt.properties, pt.created_at, pt.updated_at,
                   e.properties AS edge_properties
            FROM edges e
            JOIN propaganda_techniques pt ON pt.id = e.target_id
            WHERE e.source_id = $1
              AND e.source_type = 'claim'
              AND e.target_type = 'propaganda_technique'
              AND e.relationship = 'USES_TECHNIQUE'
            ORDER BY (e.properties->>'confidence')::FLOAT DESC NULLS LAST
            "#,
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    category,
                    description,
                    detection_guidance,
                    properties,
                    created_at,
                    updated_at,
                    edge_props,
                )| {
                    (
                        PropagandaTechniqueRow {
                            id,
                            name,
                            category,
                            description,
                            detection_guidance,
                            properties,
                            created_at,
                            updated_at,
                        },
                        edge_props,
                    )
                },
            )
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propaganda_technique_row_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PropagandaTechniqueRow>();
    }

    #[test]
    fn coalition_row_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CoalitionRow>();
    }

    #[test]
    fn propagation_step_row_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PropagationStepRow>();
    }
}
