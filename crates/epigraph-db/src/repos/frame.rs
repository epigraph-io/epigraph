//! Frame of discernment repository
//!
//! CRUD operations for DS frames and claim-frame assignments.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the frames table
#[derive(Debug, Clone, FromRow)]
pub struct FrameRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub hypotheses: Vec<String>,
    pub parent_frame_id: Option<Uuid>,
    pub is_refinable: bool,
    pub version: i32,
    pub created_at: DateTime<Utc>,
}

/// A row from the claim_frames junction table
#[derive(Debug, Clone, FromRow)]
pub struct ClaimFrameRow {
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub hypothesis_index: Option<i32>,
}

/// Repository for Frame operations
pub struct FrameRepository;

impl FrameRepository {
    /// Create a new frame of discernment
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` if a frame with the same name exists.
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, hypotheses))]
    pub async fn create(
        pool: &PgPool,
        name: &str,
        description: Option<&str>,
        hypotheses: &[String],
    ) -> Result<FrameRow, DbError> {
        let row: FrameRow = sqlx::query_as(
            r#"
            INSERT INTO frames (name, description, hypotheses)
            VALUES ($1, $2, $3)
            RETURNING id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(hypotheses)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// Get a frame by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<FrameRow>, DbError> {
        let row: Option<FrameRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at
            FROM frames
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Get a frame by name
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_name(pool: &PgPool, name: &str) -> Result<Option<FrameRow>, DbError> {
        let row: Option<FrameRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at
            FROM frames
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List frames with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<FrameRow>, DbError> {
        let rows: Vec<FrameRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at
            FROM frames
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

    /// Get all claims assigned to a frame
    ///
    /// Returns claim IDs and their optional hypothesis index within the frame.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_claims_in_frame(
        pool: &PgPool,
        frame_id: Uuid,
    ) -> Result<Vec<ClaimFrameRow>, DbError> {
        let rows: Vec<ClaimFrameRow> = sqlx::query_as(
            r#"
            SELECT claim_id, frame_id, hypothesis_index
            FROM claim_frames
            WHERE frame_id = $1
            "#,
        )
        .bind(frame_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Assign a claim to a frame with an optional hypothesis index
    ///
    /// Uses ON CONFLICT to update the hypothesis_index if the assignment exists.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn assign_claim(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
        hypothesis_index: Option<i32>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index)
            VALUES ($1, $2, $3)
            ON CONFLICT (claim_id, frame_id) DO UPDATE
            SET hypothesis_index = EXCLUDED.hypothesis_index
            "#,
        )
        .bind(claim_id)
        .bind(frame_id)
        .bind(hypothesis_index)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Create a refinement of an existing frame
    ///
    /// The parent frame must have `is_refinable = true`. The new frame's
    /// `parent_frame_id` points back to the parent.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, hypotheses))]
    pub async fn create_refinement(
        pool: &PgPool,
        parent_frame_id: Uuid,
        name: &str,
        description: Option<&str>,
        hypotheses: &[String],
    ) -> Result<FrameRow, DbError> {
        let row: FrameRow = sqlx::query_as(
            r#"
            INSERT INTO frames (name, description, hypotheses, parent_frame_id)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(hypotheses)
        .bind(parent_frame_id)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// List child frames (direct refinements) of a frame
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_children(pool: &PgPool, frame_id: Uuid) -> Result<Vec<FrameRow>, DbError> {
        let rows: Vec<FrameRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at
            FROM frames
            WHERE parent_frame_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(frame_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Walk up the parent chain from a frame to the root
    ///
    /// Returns frames from the given frame up to (and including) the root.
    /// Uses a recursive CTE to traverse the hierarchy.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_ancestry(pool: &PgPool, frame_id: Uuid) -> Result<Vec<FrameRow>, DbError> {
        let rows: Vec<FrameRow> = sqlx::query_as(
            r#"
            WITH RECURSIVE ancestry AS (
                SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at
                FROM frames
                WHERE id = $1
                UNION ALL
                SELECT f.id, f.name, f.description, f.hypotheses, f.parent_frame_id, f.is_refinable, f.version, f.created_at
                FROM frames f
                JOIN ancestry a ON f.id = a.parent_frame_id
            )
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at
            FROM ancestry
            "#,
        )
        .bind(frame_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get the hypothesis_index for a claim within a frame
    ///
    /// Returns the claim-frame assignment row if the claim is assigned to the frame.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_claim_assignment(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
    ) -> Result<Option<ClaimFrameRow>, DbError> {
        let row: Option<ClaimFrameRow> = sqlx::query_as(
            r#"
            SELECT claim_id, frame_id, hypothesis_index
            FROM claim_frames
            WHERE claim_id = $1 AND frame_id = $2
            "#,
        )
        .bind(claim_id)
        .bind(frame_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Count total frames
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count(pool: &PgPool) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM frames")
            .fetch_one(pool)
            .await?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_row_has_expected_fields() {
        let _row = FrameRow {
            id: Uuid::new_v4(),
            name: "test_frame".to_string(),
            description: Some("A test frame".to_string()),
            hypotheses: vec!["h1".to_string(), "h2".to_string()],
            parent_frame_id: None,
            is_refinable: true,
            version: 1,
            created_at: Utc::now(),
        };
    }

    #[test]
    fn claim_frame_row_has_expected_fields() {
        let _row = ClaimFrameRow {
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            hypothesis_index: Some(0),
        };
    }
}
