//! Perspective repository
//!
//! CRUD operations for agent perspectives (viewpoints that contextualize evidence).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the perspectives table
#[derive(Debug, Clone, FromRow)]
pub struct PerspectiveRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub owner_agent_id: Option<Uuid>,
    pub perspective_type: Option<String>,
    pub frame_ids: Option<Vec<Uuid>>,
    pub extraction_method: Option<String>,
    pub confidence_calibration: Option<f64>,
    pub created_at: DateTime<Utc>,
}

/// Repository for Perspective operations
pub struct PerspectiveRepository;

impl PerspectiveRepository {
    /// Create a new perspective
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool))]
    pub async fn create(
        pool: &PgPool,
        name: &str,
        description: Option<&str>,
        owner_agent_id: Option<Uuid>,
        perspective_type: Option<&str>,
        frame_ids: &[Uuid],
        extraction_method: Option<&str>,
        confidence_calibration: Option<f64>,
    ) -> Result<PerspectiveRow, DbError> {
        let row: PerspectiveRow = sqlx::query_as(
            r#"
            INSERT INTO perspectives
                (name, description, owner_agent_id, perspective_type, frame_ids,
                 extraction_method, confidence_calibration)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, name, description, owner_agent_id, perspective_type,
                      frame_ids, extraction_method, confidence_calibration, created_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(owner_agent_id)
        .bind(perspective_type)
        .bind(frame_ids)
        .bind(extraction_method)
        .bind(confidence_calibration)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// Ensure a synthetic "evidence_grounded" perspective row exists with the
    /// given id. Used by `auto_wire_ds_update` to satisfy the
    /// `mass_functions.perspective_id` FK while keeping each evidence submission
    /// distinguishable on the unique index `(claim, frame, agent, perspective)`.
    ///
    /// Idempotent — `ON CONFLICT DO NOTHING` so concurrent inserts are safe.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn ensure_evidence_perspective(
        pool: &PgPool,
        id: Uuid,
        owner_agent_id: Option<Uuid>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO perspectives (id, name, owner_agent_id, perspective_type)
            VALUES ($1, 'evidence_grounded', $2, 'evidence')
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(id)
        .bind(owner_agent_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Ensure a synthetic "edge_factor" perspective row exists with the given
    /// id (= edge UUID). Used by `auto_wire_ds_for_edge` to satisfy the
    /// `mass_functions.perspective_id` FK so each epistemic edge produces its
    /// own BBA row keyed by `(claim, frame, agent, edge_id)`.
    ///
    /// Idempotent — `ON CONFLICT DO NOTHING`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn ensure_edge_perspective(
        pool: &PgPool,
        id: Uuid,
        owner_agent_id: Option<Uuid>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO perspectives (id, name, owner_agent_id, perspective_type)
            VALUES ($1, 'edge_factor', $2, 'edge')
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(id)
        .bind(owner_agent_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Get a perspective by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<PerspectiveRow>, DbError> {
        let row: Option<PerspectiveRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, owner_agent_id, perspective_type,
                   frame_ids, extraction_method, confidence_calibration, created_at
            FROM perspectives
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List perspectives by agent
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_by_agent(
        pool: &PgPool,
        agent_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PerspectiveRow>, DbError> {
        let rows: Vec<PerspectiveRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, owner_agent_id, perspective_type,
                   frame_ids, extraction_method, confidence_calibration, created_at
            FROM perspectives
            WHERE owner_agent_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(agent_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// List all perspectives with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PerspectiveRow>, DbError> {
        let rows: Vec<PerspectiveRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, owner_agent_id, perspective_type,
                   frame_ids, extraction_method, confidence_calibration, created_at
            FROM perspectives
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perspective_row_has_expected_fields() {
        let _row = PerspectiveRow {
            id: Uuid::new_v4(),
            name: "skeptical_analysis".to_string(),
            description: Some("Critical evaluation perspective".to_string()),
            owner_agent_id: Some(Uuid::new_v4()),
            perspective_type: Some("analytical".to_string()),
            frame_ids: Some(vec![Uuid::new_v4()]),
            extraction_method: Some("ai_generated".to_string()),
            confidence_calibration: Some(0.8),
            created_at: Utc::now(),
        };
    }

    #[test]
    fn perspective_row_allows_none_optionals() {
        let _row = PerspectiveRow {
            id: Uuid::new_v4(),
            name: "minimal".to_string(),
            description: None,
            owner_agent_id: None,
            perspective_type: None,
            frame_ids: None,
            extraction_method: None,
            confidence_calibration: None,
            created_at: Utc::now(),
        };
    }
}
