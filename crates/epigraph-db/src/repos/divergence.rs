//! DS vs Bayesian divergence repository
//!
//! Stores and queries pignistic-vs-posterior divergence records
//! to track when Dempster-Shafer and Bayesian reasoning disagree.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the ds_bayesian_divergence table
#[derive(Debug, Clone, FromRow)]
pub struct DivergenceRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub pignistic_prob: f64,
    pub bayesian_posterior: f64,
    pub kl_divergence: f64,
    pub frame_version: Option<i32>,
    pub computed_at: DateTime<Utc>,
}

/// Repository for DS-Bayesian divergence tracking
pub struct DivergenceRepository;

impl DivergenceRepository {
    /// Store a divergence measurement
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn store(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
        pignistic_prob: f64,
        bayesian_posterior: f64,
        kl_divergence: f64,
        frame_version: Option<i32>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO ds_bayesian_divergence
                (claim_id, frame_id, pignistic_prob, bayesian_posterior, kl_divergence, frame_version)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(claim_id)
        .bind(frame_id)
        .bind(pignistic_prob)
        .bind(bayesian_posterior)
        .bind(kl_divergence)
        .bind(frame_version)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get the most recent divergence record for a claim (across all frames)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_latest(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Option<DivergenceRow>, DbError> {
        let row: Option<DivergenceRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, frame_id, pignistic_prob, bayesian_posterior,
                   kl_divergence, frame_version, computed_at
            FROM ds_bayesian_divergence
            WHERE claim_id = $1
            ORDER BY computed_at DESC
            LIMIT 1
            "#,
        )
        .bind(claim_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Get claims with the highest KL divergence
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn top_divergent(pool: &PgPool, limit: i64) -> Result<Vec<DivergenceRow>, DbError> {
        let rows: Vec<DivergenceRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (claim_id)
                   id, claim_id, frame_id, pignistic_prob, bayesian_posterior,
                   kl_divergence, frame_version, computed_at
            FROM ds_bayesian_divergence
            ORDER BY claim_id, computed_at DESC
            "#,
        )
        .fetch_all(pool)
        .await?;

        // Sort by KL divergence descending and take the top N.
        // We do this in Rust because DISTINCT ON + ORDER BY kl_divergence
        // requires a subquery that complicates the SQL unnecessarily.
        let mut sorted = rows;
        sorted.sort_by(|a, b| {
            b.kl_divergence
                .partial_cmp(&a.kl_divergence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.truncate(limit as usize);

        Ok(sorted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divergence_row_has_expected_fields() {
        let _row = DivergenceRow {
            id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            pignistic_prob: 0.85,
            bayesian_posterior: 0.70,
            kl_divergence: 0.12,
            frame_version: Some(1),
            computed_at: Utc::now(),
        };
    }
}
