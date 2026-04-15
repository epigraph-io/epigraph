//! Repository for claim version history.
//!
//! Tracks the full edit history of a claim's content and truth value.
//! Each mutation to a claim should append a new version row, preserving
//! the prior state for audit and rollback purposes.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// A single version snapshot of a claim.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimVersionRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub version_number: i32,
    pub content: String,
    pub truth_value: f64,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

pub struct ClaimVersionRepository;

impl ClaimVersionRepository {
    /// Insert a new version snapshot for a claim.
    pub async fn create(pool: &PgPool, row: &ClaimVersionRow) -> Result<ClaimVersionRow, DbError> {
        let result = sqlx::query_as::<_, ClaimVersionRow>(
            "INSERT INTO claim_versions (id, claim_id, version_number, content, truth_value, created_by, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id, claim_id, version_number, content, truth_value, created_by, created_at",
        )
        .bind(row.id)
        .bind(row.claim_id)
        .bind(row.version_number)
        .bind(&row.content)
        .bind(row.truth_value)
        .bind(row.created_by)
        .bind(row.created_at)
        .fetch_one(pool)
        .await?;
        Ok(result)
    }

    /// List all versions for a claim, most recent first.
    pub async fn list_by_claim(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<ClaimVersionRow>, DbError> {
        let rows = sqlx::query_as::<_, ClaimVersionRow>(
            "SELECT id, claim_id, version_number, content, truth_value, created_by, created_at \
             FROM claim_versions \
             WHERE claim_id = $1 \
             ORDER BY version_number DESC",
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Return the highest version number recorded for a claim, or 0 if none.
    pub async fn latest_version_number(pool: &PgPool, claim_id: Uuid) -> Result<i32, DbError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COALESCE(MAX(version_number), 0) FROM claim_versions WHERE claim_id = $1",
        )
        .bind(claim_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0 as i32)
    }
}
