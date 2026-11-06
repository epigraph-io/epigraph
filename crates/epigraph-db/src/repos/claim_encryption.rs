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

    /// Seal records for many claims, viewer-filtered through the parent claim.
    ///
    /// Unlike [`Self::get_by_claim_id_conn`] this takes a Viewer: that
    /// function's exemption in `visibility_lint.rs` (`CONN_WITHOUT_VIEWER`)
    /// holds only for callers that ran a gated fetch first, and says a new
    /// caller must give it a Viewer instead of inheriting the entry. The join
    /// to `claims` under the marker is that viewer, so a seal record (and its
    /// `group_id`) is never returned for a claim the viewer cannot read.
    ///
    /// `claim_encryption` is keyed by `claim_id` (migration 060), so the map is
    /// one-to-one. Empty input returns an empty map without a query.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn, viewer, claim_ids), fields(n = claim_ids.len()))]
    pub async fn get_by_claim_ids_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        claim_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, ClaimEncryptionRow>, DbError> {
        if claim_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let sql = viewer.splice(
            r#"
            SELECT ce.claim_id, ce.group_id, ce.epoch, ce.privacy_tier,
                   ce.encrypted_content, ce.encrypted_labels, ce.created_at
            FROM claim_encryption ce
            JOIN claims c ON c.id = ce.claim_id
            WHERE ce.claim_id = ANY($1)
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, ClaimEncryptionRow>(&sql).bind(claim_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(&mut *conn).await?;
        Ok(rows.into_iter().map(|r| (r.claim_id, r)).collect())
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
