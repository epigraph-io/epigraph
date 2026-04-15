//! Repository for the `edge_encryption` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `edge_encryption` table
#[derive(Debug, Clone, FromRow)]
pub struct EdgeEncryptionRow {
    pub edge_id: Uuid,
    pub group_id: Uuid,
    pub epoch: i32,
    pub privacy_tier: String,
    pub encrypted_labels: Option<Vec<u8>>,
    pub encrypted_properties: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Repository for EdgeEncryption operations
pub struct EdgeEncryptionRepository;

impl EdgeEncryptionRepository {
    /// Insert encryption metadata for an edge
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, encrypted_labels, encrypted_properties))]
    pub async fn insert(
        pool: &PgPool,
        edge_id: Uuid,
        group_id: Uuid,
        epoch: i32,
        privacy_tier: &str,
        encrypted_labels: Option<&[u8]>,
        encrypted_properties: Option<&[u8]>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO edge_encryption
                (edge_id, group_id, epoch, privacy_tier, encrypted_labels, encrypted_properties)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(edge_id)
        .bind(group_id)
        .bind(epoch)
        .bind(privacy_tier)
        .bind(encrypted_labels)
        .bind(encrypted_properties)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get encryption metadata by edge ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_edge_id(
        pool: &PgPool,
        edge_id: Uuid,
    ) -> Result<Option<EdgeEncryptionRow>, DbError> {
        let row: Option<EdgeEncryptionRow> = sqlx::query_as(
            r#"
            SELECT edge_id, group_id, epoch, privacy_tier, encrypted_labels, encrypted_properties, created_at
            FROM edge_encryption
            WHERE edge_id = $1
            "#,
        )
        .bind(edge_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Get all encrypted edges for a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_group(
        pool: &PgPool,
        group_id: Uuid,
    ) -> Result<Vec<EdgeEncryptionRow>, DbError> {
        let rows: Vec<EdgeEncryptionRow> = sqlx::query_as(
            r#"
            SELECT edge_id, group_id, epoch, privacy_tier, encrypted_labels, encrypted_properties, created_at
            FROM edge_encryption
            WHERE group_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(group_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Delete encryption metadata for an edge
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete_by_edge_id(pool: &PgPool, edge_id: Uuid) -> Result<(), DbError> {
        sqlx::query(
            r#"
            DELETE FROM edge_encryption WHERE edge_id = $1
            "#,
        )
        .bind(edge_id)
        .execute(pool)
        .await?;

        Ok(())
    }
}
