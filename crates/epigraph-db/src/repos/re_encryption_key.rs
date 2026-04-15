//! Repository for the `re_encryption_keys` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `re_encryption_keys` table
#[derive(Debug, Clone, FromRow)]
pub struct ReEncryptionKeyRow {
    pub id: Uuid,
    pub source_group_id: Uuid,
    pub target_group_id: Uuid,
    pub re_key: Vec<u8>,
    pub source_epoch: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Repository for ReEncryptionKey operations
pub struct ReEncryptionKeyRepository;

impl ReEncryptionKeyRepository {
    /// Insert a proxy re-encryption key
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, re_key))]
    pub async fn insert(
        pool: &PgPool,
        source_group_id: Uuid,
        target_group_id: Uuid,
        re_key: &[u8],
        source_epoch: i32,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO re_encryption_keys
                (source_group_id, target_group_id, re_key, source_epoch, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(source_group_id)
        .bind(target_group_id)
        .bind(re_key)
        .bind(source_epoch)
        .bind(expires_at)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get re-encryption key by source and target group
    ///
    /// Returns the most recently created non-expired key for the given group pair.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_groups(
        pool: &PgPool,
        source_group_id: Uuid,
        target_group_id: Uuid,
    ) -> Result<Option<ReEncryptionKeyRow>, DbError> {
        let row: Option<ReEncryptionKeyRow> = sqlx::query_as(
            r#"
            SELECT id, source_group_id, target_group_id, re_key, source_epoch, created_at, expires_at
            FROM re_encryption_keys
            WHERE source_group_id = $1
              AND target_group_id = $2
              AND (expires_at IS NULL OR expires_at > now())
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(source_group_id)
        .bind(target_group_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Delete all expired re-encryption keys, returning the number of rows deleted
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete_expired(pool: &PgPool) -> Result<u64, DbError> {
        let result = sqlx::query(
            r#"
            DELETE FROM re_encryption_keys
            WHERE expires_at IS NOT NULL AND expires_at <= now()
            "#,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}
