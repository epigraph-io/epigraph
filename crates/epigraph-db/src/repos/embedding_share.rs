//! Repository for the `embedding_shares` table

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the `embedding_shares` table
#[derive(Debug, Clone, FromRow)]
pub struct EmbeddingShareRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub group_id: Uuid,
    pub party_index: i16,
    pub share_data: Vec<u8>,
    pub epoch: i32,
    pub created_at: DateTime<Utc>,
}

/// Repository for EmbeddingShare operations
pub struct EmbeddingShareRepository;

impl EmbeddingShareRepository {
    /// Insert multiple embedding shares in a single transaction
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, shares))]
    pub async fn insert_shares(
        pool: &PgPool,
        shares: Vec<(Uuid, Uuid, i16, Vec<u8>, i32)>,
    ) -> Result<(), DbError> {
        for (claim_id, group_id, party_index, share_data, epoch) in shares {
            sqlx::query(
                r#"
                INSERT INTO embedding_shares (claim_id, group_id, party_index, share_data, epoch)
                VALUES ($1, $2, $3, $4, $5)
                "#,
            )
            .bind(claim_id)
            .bind(group_id)
            .bind(party_index)
            .bind(&share_data)
            .bind(epoch)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Get all shares for a specific claim
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_shares_for_claim(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<EmbeddingShareRow>, DbError> {
        let rows: Vec<EmbeddingShareRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, group_id, party_index, share_data, epoch, created_at
            FROM embedding_shares
            WHERE claim_id = $1
            ORDER BY party_index ASC
            "#,
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Delete all shares for a specific claim
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete_by_claim(pool: &PgPool, claim_id: Uuid) -> Result<(), DbError> {
        sqlx::query(
            r#"
            DELETE FROM embedding_shares WHERE claim_id = $1
            "#,
        )
        .bind(claim_id)
        .execute(pool)
        .await?;

        Ok(())
    }
}
