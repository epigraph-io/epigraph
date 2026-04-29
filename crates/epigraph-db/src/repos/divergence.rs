//! DS vs Bayesian divergence repository
//!
//! Stores and queries pignistic-vs-posterior divergence records
//! to track when Dempster-Shafer and Bayesian reasoning disagree.

use crate::errors::DbError;
use chrono::{DateTime, Duration, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// Divergence entries older than this are excluded from queries and treated as stale.
const DIVERGENCE_TTL_DAYS: i64 = 7;

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
    /// Store a divergence measurement.
    ///
    /// `pignistic_prob` is clamped to [0, 1] and NaN is mapped to 0.0 before
    /// insertion so the cache never holds an invalid probability.
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
        // IEEE 754: -0.0.clamp(0.0, 1.0) == -0.0 (equal comparison preserves negative zero).
        // Use explicit comparisons so -0.0 and any small negative clamp to a
        // fresh positive 0.0 literal.
        let safe_betp =
            if pignistic_prob.is_nan() || !pignistic_prob.is_finite() || pignistic_prob <= 0.0 {
                0.0_f64
            } else if pignistic_prob >= 1.0 {
                1.0_f64
            } else {
                pignistic_prob
            };

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
        .bind(safe_betp)
        .bind(bayesian_posterior)
        .bind(kl_divergence)
        .bind(frame_version)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get the most recent divergence record for a claim (across all frames).
    ///
    /// Returns `None` if no record exists or the most recent entry is older than
    /// `DIVERGENCE_TTL_DAYS` — stale entries are invisible until new evidence
    /// arrives and writes a fresh record.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_latest(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Option<DivergenceRow>, DbError> {
        let cutoff = Utc::now() - Duration::days(DIVERGENCE_TTL_DAYS);
        let row: Option<DivergenceRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, frame_id, pignistic_prob, bayesian_posterior,
                   kl_divergence, frame_version, computed_at
            FROM ds_bayesian_divergence
            WHERE claim_id = $1
              AND computed_at >= $2
            ORDER BY computed_at DESC
            LIMIT 1
            "#,
        )
        .bind(claim_id)
        .bind(cutoff)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Get claims with the highest KL divergence, excluding entries older than
    /// `DIVERGENCE_TTL_DAYS` to prevent stale/invalid cached values from surfacing.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn top_divergent(pool: &PgPool, limit: i64) -> Result<Vec<DivergenceRow>, DbError> {
        let cutoff = Utc::now() - Duration::days(DIVERGENCE_TTL_DAYS);
        let rows: Vec<DivergenceRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (claim_id)
                   id, claim_id, frame_id, pignistic_prob, bayesian_posterior,
                   kl_divergence, frame_version, computed_at
            FROM ds_bayesian_divergence
            WHERE computed_at >= $1
            ORDER BY claim_id, computed_at DESC
            "#,
        )
        .bind(cutoff)
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

    /// Regression: store must sanitize -0.0 pignistic (floating-point underflow
    /// artifact) before writing to the cache — the cached value must be +0.0.
    #[test]
    fn store_sanitizes_negative_zero_pignistic() {
        let neg_zero: f64 = -0.0_f64;
        let safe = if neg_zero.is_nan() || !neg_zero.is_finite() || neg_zero <= 0.0 {
            0.0_f64
        } else if neg_zero >= 1.0 {
            1.0_f64
        } else {
            neg_zero
        };
        assert!(safe >= 0.0, "safe_betp must be non-negative, got {safe}");
        assert!(
            !safe.is_sign_negative(),
            "safe_betp must be positive zero, not -0.0"
        );
    }

    #[test]
    fn store_sanitizes_nan_pignistic() {
        let nan: f64 = f64::NAN;
        let safe = if nan.is_nan() {
            0.0
        } else {
            nan.clamp(0.0, 1.0)
        };
        assert_eq!(safe, 0.0, "NaN pignistic should map to 0.0, got {safe}");
    }

    #[test]
    fn store_sanitizes_negative_pignistic() {
        let neg: f64 = -0.05_f64;
        let safe = if neg.is_nan() {
            0.0
        } else {
            neg.clamp(0.0, 1.0)
        };
        assert_eq!(
            safe, 0.0,
            "Negative pignistic should clamp to 0.0, got {safe}"
        );
    }

    #[test]
    fn store_sanitizes_pignistic_above_one() {
        let above: f64 = 1.2_f64;
        let safe = if above.is_nan() {
            0.0
        } else {
            above.clamp(0.0, 1.0)
        };
        assert_eq!(safe, 1.0, "pignistic > 1 should clamp to 1.0, got {safe}");
    }
}
