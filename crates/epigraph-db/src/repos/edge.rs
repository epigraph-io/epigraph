//! Edge repository for LPG-style relationships

use crate::errors::DbError;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A row from the edges table
#[derive(Debug, Clone)]
pub struct EdgeRow {
    pub id: Uuid,
    pub source_id: Uuid,
    pub source_type: String,
    pub target_id: Uuid,
    pub target_type: String,
    pub relationship: String,
    pub properties: serde_json::Value,
    pub valid_from: Option<chrono::DateTime<chrono::Utc>>,
    pub valid_to: Option<chrono::DateTime<chrono::Utc>>,
}

/// Repository for Edge operations
pub struct EdgeRepository;

impl EdgeRepository {
    /// Create a new edge relationship
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `source_id` - Source entity UUID
    /// * `source_type` - Source entity type (e.g., "claim", "agent")
    /// * `target_id` - Target entity UUID
    /// * `target_type` - Target entity type
    /// * `relationship` - Relationship label (e.g., "supports", "refutes")
    /// * `properties` - Optional JSONB properties for the edge
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, properties))]
    pub async fn create(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
        relationship: &str,
        properties: Option<serde_json::Value>,
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        valid_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Uuid, DbError> {
        let properties = properties.unwrap_or(serde_json::json!({}));

        let row = sqlx::query!(
            r#"
            INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            "#,
            source_id,
            source_type,
            target_id,
            target_type,
            relationship,
            properties,
            valid_from,
            valid_to
        )
        .fetch_one(pool)
        .await?;

        Ok(row.id)
    }

    /// Like [`create`], but if an edge with the same
    /// `(source_id, target_id, relationship)` triple already exists, returns
    /// that edge's id without inserting a duplicate. Idempotent.
    ///
    /// Uses check-then-insert in a transaction. The `edges` table has no
    /// unique index on this triple (multiple parallel edges with different
    /// `properties` are valid in the general case), so we cannot rely on
    /// `ON CONFLICT`. Two round-trips are acceptable for the ingestion
    /// path; the race window is small and edges are idempotent in practice.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, properties))]
    pub async fn create_if_not_exists(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
        relationship: &str,
        properties: Option<serde_json::Value>,
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        valid_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Uuid, DbError> {
        let mut tx = pool.begin().await?;

        let existing = sqlx::query!(
            r#"
            SELECT id FROM edges
            WHERE source_id = $1 AND target_id = $2 AND relationship = $3
            LIMIT 1
            "#,
            source_id,
            target_id,
            relationship,
        )
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = existing {
            tx.commit().await?;
            return Ok(row.id);
        }

        let properties = properties.unwrap_or(serde_json::json!({}));
        let row = sqlx::query!(
            r#"
            INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            "#,
            source_id,
            source_type,
            target_id,
            target_type,
            relationship,
            properties,
            valid_from,
            valid_to,
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.id)
    }

    /// Get edges by source entity
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_source(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE source_id = $1 AND source_type = $2
            ORDER BY created_at DESC
            "#,
            source_id,
            source_type
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// Get edges by target entity
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_target(
        pool: &PgPool,
        target_id: Uuid,
        target_type: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE target_id = $1 AND target_type = $2
            ORDER BY created_at DESC
            "#,
            target_id,
            target_type
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// Get edges by relationship type
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_relationship(
        pool: &PgPool,
        relationship: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE relationship = $1
            ORDER BY created_at DESC
            "#,
            relationship
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// Get edges between two specific entities
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_between(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE source_id = $1 AND source_type = $2
              AND target_id = $3 AND target_type = $4
            ORDER BY created_at DESC
            "#,
            source_id,
            source_type,
            target_id,
            target_type
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// List all edges, optionally filtered by source_type and target_type
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_all(pool: &PgPool, limit: i64) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            ORDER BY created_at DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// Get currently-valid edges for an entity with a specific relationship.
    /// Returns edges where valid_to IS NULL (ongoing or atemporal).
    #[instrument(skip(pool))]
    pub async fn get_current_edges(
        pool: &PgPool,
        entity_id: Uuid,
        relationship: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE (source_id = $1 OR target_id = $1)
              AND relationship = $2
              AND valid_to IS NULL
            ORDER BY valid_from DESC NULLS LAST
            "#,
            entity_id,
            relationship
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// Delete an edge by ID
    ///
    /// # Returns
    /// Returns `true` if the edge was deleted, `false` if it didn't exist.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM edges
            WHERE id = $1
            "#,
            id
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all edges between two entities
    ///
    /// # Returns
    /// Returns the number of edges deleted.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete_between(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM edges
            WHERE source_id = $1 AND source_type = $2
              AND target_id = $3 AND target_type = $4
            "#,
            source_id,
            source_type,
            target_id,
            target_type
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count edges for an entity (as either source or target)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count_for_entity(
        pool: &PgPool,
        entity_id: Uuid,
        entity_type: &str,
    ) -> Result<i64, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM edges
            WHERE (source_id = $1 AND source_type = $2)
               OR (target_id = $1 AND target_type = $2)
            "#,
            entity_id,
            entity_type
        )
        .fetch_one(pool)
        .await?;

        Ok(row.count.unwrap_or(0))
    }

    /// Get claims attributed to an agent via ATTRIBUTED_TO edges.
    ///
    /// Traverses `ATTRIBUTED_TO` edges (claim → agent) to find all claims
    /// attributed to the given agent. Supports pagination and minimum truth
    /// value filtering.
    ///
    /// This implements `prov:wasAttributedTo` traversal for W3C PROV-O compliance.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `agent_id` - The agent UUID to find attributed claims for
    /// * `min_truth` - Minimum truth value filter (inclusive)
    /// * `limit` - Maximum number of results
    /// * `offset` - Number of results to skip
    ///
    /// # Returns
    /// Tuples of (claim fields, edge properties) for each attributed claim.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_claims_attributed_to(
        pool: &PgPool,
        agent_id: Uuid,
        min_truth: f64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AttributedClaimRow>, DbError> {
        let rows = sqlx::query_as::<_, AttributedClaimRow>(
            r#"
            SELECT c.id, c.content, c.truth_value, c.agent_id,
                   c.trace_id, c.created_at, c.updated_at,
                   e.properties AS edge_properties
            FROM edges e
            JOIN claims c ON e.source_id = c.id
            WHERE e.target_id = $1
              AND e.target_type = 'agent'
              AND e.source_type = 'claim'
              AND e.relationship IN ('attributed_to', 'ATTRIBUTED_TO')
              AND c.truth_value >= $2
            ORDER BY c.created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(agent_id)
        .bind(min_truth)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Count claims attributed to an agent via ATTRIBUTED_TO edges.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count_claims_attributed_to(
        pool: &PgPool,
        agent_id: Uuid,
        min_truth: f64,
    ) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM edges e
            JOIN claims c ON e.source_id = c.id
            WHERE e.target_id = $1
              AND e.target_type = 'agent'
              AND e.source_type = 'claim'
              AND e.relationship IN ('attributed_to', 'ATTRIBUTED_TO')
              AND c.truth_value >= $2
            "#,
        )
        .bind(agent_id)
        .bind(min_truth)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }
}

/// Row type for claims attributed to an agent via ATTRIBUTED_TO edges
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AttributedClaimRow {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub agent_id: Uuid,
    pub trace_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub edge_properties: serde_json::Value,
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_edge_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/edge_tests.rs
    }
}
