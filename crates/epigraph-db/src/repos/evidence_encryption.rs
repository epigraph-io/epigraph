//! Repository for the `evidence_encryption` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `evidence_encryption` table
#[derive(Debug, Clone, FromRow)]
pub struct EvidenceEncryptionRow {
    pub evidence_id: Uuid,
    pub group_id: Uuid,
    pub epoch: i32,
    pub privacy_tier: String,
    pub encrypted_content: Vec<u8>,
    pub encrypted_labels: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Repository for EvidenceEncryption operations
pub struct EvidenceEncryptionRepository;

impl EvidenceEncryptionRepository {
    /// Insert encryption metadata for an evidence record
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, encrypted_content, encrypted_labels))]
    pub async fn insert(
        pool: &PgPool,
        evidence_id: Uuid,
        group_id: Uuid,
        epoch: i32,
        privacy_tier: &str,
        encrypted_content: &[u8],
        encrypted_labels: Option<&[u8]>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO evidence_encryption
                (evidence_id, group_id, epoch, privacy_tier, encrypted_content, encrypted_labels)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(evidence_id)
        .bind(group_id)
        .bind(epoch)
        .bind(privacy_tier)
        .bind(encrypted_content)
        .bind(encrypted_labels)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get encryption metadata by evidence ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_evidence_id(
        pool: &PgPool,
        evidence_id: Uuid,
    ) -> Result<Option<EvidenceEncryptionRow>, DbError> {
        let row: Option<EvidenceEncryptionRow> = sqlx::query_as(
            r#"
            SELECT evidence_id, group_id, epoch, privacy_tier, encrypted_content, encrypted_labels, created_at
            FROM evidence_encryption
            WHERE evidence_id = $1
            "#,
        )
        .bind(evidence_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Get all encrypted evidence records for a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_group(
        pool: &PgPool,
        group_id: Uuid,
    ) -> Result<Vec<EvidenceEncryptionRow>, DbError> {
        let rows: Vec<EvidenceEncryptionRow> = sqlx::query_as(
            r#"
            SELECT evidence_id, group_id, epoch, privacy_tier, encrypted_content, encrypted_labels, created_at
            FROM evidence_encryption
            WHERE group_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(group_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Delete encryption metadata for an evidence record
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete_by_evidence_id(pool: &PgPool, evidence_id: Uuid) -> Result<(), DbError> {
        sqlx::query(
            r#"
            DELETE FROM evidence_encryption WHERE evidence_id = $1
            "#,
        )
        .bind(evidence_id)
        .execute(pool)
        .await?;

        Ok(())
    }
}
