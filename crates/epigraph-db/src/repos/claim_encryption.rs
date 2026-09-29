//! Repository for the `claim_encryption` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `claim_encryption` table
#[derive(Debug, Clone, FromRow)]
pub struct ClaimEncryptionRow {
    pub claim_id: Uuid,
    pub group_id: Uuid,
    pub epoch: i32,
    pub privacy_tier: String,
    pub encrypted_content: Vec<u8>,
    pub encrypted_labels: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Repository for ClaimEncryption operations
pub struct ClaimEncryptionRepository;

impl ClaimEncryptionRepository {
    /// Insert encryption metadata for a claim
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, encrypted_content, encrypted_labels))]
    pub async fn insert(
        pool: &PgPool,
        claim_id: Uuid,
        group_id: Uuid,
        epoch: i32,
        privacy_tier: &str,
        encrypted_content: &[u8],
        encrypted_labels: Option<&[u8]>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO claim_encryption
                (claim_id, group_id, epoch, privacy_tier, encrypted_content, encrypted_labels)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(claim_id)
        .bind(group_id)
        .bind(epoch)
        .bind(privacy_tier)
        .bind(encrypted_content)
        .bind(encrypted_labels)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Insert encryption metadata within an existing transaction.
    ///
    /// Same as `insert()` but accepts a `&mut PgConnection` for transactional use.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn insert_conn(
        conn: &mut sqlx::PgConnection,
        claim_id: Uuid,
        group_id: Uuid,
        epoch: i32,
        privacy_tier: &str,
        encrypted_content: &[u8],
        encrypted_labels: Option<&[u8]>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO claim_encryption
                (claim_id, group_id, epoch, privacy_tier, encrypted_content, encrypted_labels)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(claim_id)
        .bind(group_id)
        .bind(epoch)
        .bind(privacy_tier)
        .bind(encrypted_content)
        .bind(encrypted_labels)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Get encryption metadata by claim ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_claim_id(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Option<ClaimEncryptionRow>, DbError> {
        let row: Option<ClaimEncryptionRow> = sqlx::query_as(
            r#"
            SELECT claim_id, group_id, epoch, privacy_tier, encrypted_content, encrypted_labels, created_at
            FROM claim_encryption
            WHERE claim_id = $1
            "#,
        )
        .bind(claim_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Get encryption metadata by claim ID within an existing transaction.
    pub async fn get_by_claim_id_conn(
        conn: &mut sqlx::PgConnection,
        claim_id: Uuid,
    ) -> Result<Option<ClaimEncryptionRow>, DbError> {
        let row: Option<ClaimEncryptionRow> = sqlx::query_as(
            r#"SELECT claim_id, group_id, epoch, privacy_tier, encrypted_content, encrypted_labels, created_at
            FROM claim_encryption WHERE claim_id = $1"#,
        )
        .bind(claim_id)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row)
    }

    /// Get all encrypted claims for a group
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_group(
        pool: &PgPool,
        group_id: Uuid,
    ) -> Result<Vec<ClaimEncryptionRow>, DbError> {
        let rows: Vec<ClaimEncryptionRow> = sqlx::query_as(
            r#"
            SELECT claim_id, group_id, epoch, privacy_tier, encrypted_content, encrypted_labels, created_at
            FROM claim_encryption
            WHERE group_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(group_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Delete encryption metadata for a claim
    ///
    /// # Errors
    /// `DbError::WriteRefused` when a row this session can read was not
    /// deleted (row security refused it); `DbError::QueryFailed` if the
    /// database query fails.
    #[instrument(skip(pool))]
    pub async fn delete_by_claim_id(pool: &PgPool, claim_id: Uuid) -> Result<(), DbError> {
        // Checked: 115's owner-scoped DELETE matches no row it refuses, and
        // reports success; a sealed row this session can read but not delete
        // is a refusal, not a deleted row (`require_all_changed`). In a
        // transaction, so a refusal also undoes the rows it could delete.
        let mut tx = pool.begin().await?;
        let counts: (i64, i64) = sqlx::query_as(
            r#"
            WITH seen AS (SELECT 1 FROM claim_encryption WHERE claim_id = $1),
                 done AS (DELETE FROM claim_encryption WHERE claim_id = $1 RETURNING 1)
            SELECT (SELECT count(*) FROM seen), (SELECT count(*) FROM done)
            "#,
        )
        .bind(claim_id)
        .fetch_one(&mut *tx)
        .await?;
        super::require_all_changed("claim_encryption of claim", claim_id, "delete", counts)?;
        tx.commit().await?;

        Ok(())
    }
}
