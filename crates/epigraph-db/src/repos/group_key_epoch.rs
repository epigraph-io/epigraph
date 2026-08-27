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
    /// Create a new key epoch for a group.
    ///
    /// Thin wrapper over [`Self::create_epoch_conn`] for callers that are not
    /// already inside a transaction.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, wrapped_key))]
    pub async fn create_epoch(
        pool: &PgPool,
        group_id: Uuid,
        epoch: i32,
        wrapped_key: Option<&[u8]>,
        status: &str,
    ) -> Result<Uuid, DbError> {
        let mut conn = pool.acquire().await?;
        Self::create_epoch_conn(&mut conn, group_id, epoch, wrapped_key, status).await
    }

    /// `create_epoch` over a borrowed connection, for callers already inside a
    /// transaction.
    ///
    /// `GroupRepository::create_with_admin` inlined an equivalent INSERT that
    /// additionally pinned `status = 'active'`, which left this function with
    /// zero callers workspace-wide and two statements free to drift apart —
    /// exactly the pair migration 060's ROTATION CONTRACT comment addresses by
    /// name. `status` is therefore an explicit parameter rather than relying on
    /// the column DEFAULT: an epoch row's status is the rotation state machine,
    /// and a caller must say which state it is writing.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn, wrapped_key))]
    pub async fn create_epoch_conn(
        conn: &mut sqlx::PgConnection,
        group_id: Uuid,
        epoch: i32,
        wrapped_key: Option<&[u8]>,
        status: &str,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO group_key_epochs (group_id, epoch, wrapped_key, status)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(group_id)
        .bind(epoch)
        .bind(wrapped_key)
        .bind(status)
        .fetch_one(&mut *conn)
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
