//! Repository for the `group_key_epochs` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `group_key_epochs` table
#[derive(Debug, Clone, FromRow)]
pub struct KeyEpochRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub epoch: i32,
    pub wrapped_key: Option<Vec<u8>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

/// Repository for GroupKeyEpoch operations
pub struct GroupKeyEpochRepository;

impl GroupKeyEpochRepository {
    /// Create a new key epoch for a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, wrapped_key))]
    pub async fn create_epoch(
        pool: &PgPool,
        group_id: Uuid,
        epoch: i32,
        wrapped_key: Option<&[u8]>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO group_key_epochs (group_id, epoch, wrapped_key)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
        )
        .bind(group_id)
        .bind(epoch)
        .bind(wrapped_key)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get the active epoch for a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_active_epoch(
        pool: &PgPool,
        group_id: Uuid,
    ) -> Result<Option<KeyEpochRow>, DbError> {
        let row: Option<KeyEpochRow> = sqlx::query_as(
            r#"
            SELECT id, group_id, epoch, wrapped_key, status, created_at, retired_at
            FROM group_key_epochs
            WHERE group_id = $1 AND status = 'active'
            ORDER BY epoch DESC
            LIMIT 1
            "#,
        )
        .bind(group_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Retire a specific epoch for a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn retire_epoch(pool: &PgPool, group_id: Uuid, epoch: i32) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE group_key_epochs
            SET status = 'retired', retired_at = now()
            WHERE group_id = $1 AND epoch = $2
            "#,
        )
        .bind(group_id)
        .bind(epoch)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get a specific epoch by group and epoch number
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_group_and_epoch(
        pool: &PgPool,
        group_id: Uuid,
        epoch: i32,
    ) -> Result<Option<KeyEpochRow>, DbError> {
        let row: Option<KeyEpochRow> = sqlx::query_as(
            r#"
            SELECT id, group_id, epoch, wrapped_key, status, created_at, retired_at
            FROM group_key_epochs
            WHERE group_id = $1 AND epoch = $2
            "#,
        )
        .bind(group_id)
        .bind(epoch)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }
}
