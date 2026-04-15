//! Scoped combined beliefs repository
//!
//! Operations on the `ds_combined_beliefs` table which caches combined
//! belief intervals per (claim, frame, scope).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the ds_combined_beliefs table
#[derive(Debug, Clone, FromRow)]
pub struct ScopedBeliefRow {
    pub id: Uuid,
    pub frame_id: Uuid,
    pub claim_id: Uuid,
    pub scope_type: String,
    pub scope_id: Option<Uuid>,
    pub belief: f64,
    pub plausibility: f64,
    pub mass_on_empty: f64,
    pub mass_on_missing: f64,
    pub conflict_k: Option<f64>,
    pub strategy_used: Option<String>,
    pub pignistic_prob: Option<f64>,
    pub computed_at: DateTime<Utc>,
}

/// Repository for scoped combined belief operations
pub struct ScopedBeliefRepository;

impl ScopedBeliefRepository {
    /// Upsert a scoped combined belief
    ///
    /// Uses ON CONFLICT on (frame_id, claim_id, scope_type, scope_id) to update.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool))]
    pub async fn upsert(
        pool: &PgPool,
        frame_id: Uuid,
        claim_id: Uuid,
        scope_type: &str,
        scope_id: Option<Uuid>,
        belief: f64,
        plausibility: f64,
        mass_on_empty: f64,
        mass_on_missing: f64,
        conflict_k: Option<f64>,
        strategy_used: Option<&str>,
        pignistic_prob: Option<f64>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO ds_combined_beliefs
                (frame_id, claim_id, scope_type, scope_id, belief, plausibility,
                 mass_on_empty, mass_on_missing, conflict_k, strategy_used, pignistic_prob)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (frame_id, claim_id, scope_type, scope_id) DO UPDATE
            SET belief = EXCLUDED.belief,
                plausibility = EXCLUDED.plausibility,
                mass_on_empty = EXCLUDED.mass_on_empty,
                mass_on_missing = EXCLUDED.mass_on_missing,
                conflict_k = EXCLUDED.conflict_k,
                strategy_used = EXCLUDED.strategy_used,
                pignistic_prob = EXCLUDED.pignistic_prob,
                computed_at = NOW()
            RETURNING id
            "#,
        )
        .bind(frame_id)
        .bind(claim_id)
        .bind(scope_type)
        .bind(scope_id)
        .bind(belief)
        .bind(plausibility)
        .bind(mass_on_empty)
        .bind(mass_on_missing)
        .bind(conflict_k)
        .bind(strategy_used)
        .bind(pignistic_prob)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get a scoped belief for a specific claim and scope
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get(
        pool: &PgPool,
        claim_id: Uuid,
        scope_type: &str,
        scope_id: Option<Uuid>,
    ) -> Result<Option<ScopedBeliefRow>, DbError> {
        let row: Option<ScopedBeliefRow> = sqlx::query_as(
            r#"
            SELECT id, frame_id, claim_id, scope_type, scope_id,
                   belief, plausibility, mass_on_empty, mass_on_missing,
                   conflict_k, strategy_used, pignistic_prob, computed_at
            FROM ds_combined_beliefs
            WHERE claim_id = $1 AND scope_type = $2
              AND (($3::uuid IS NULL AND scope_id IS NULL) OR scope_id = $3)
            ORDER BY computed_at DESC
            LIMIT 1
            "#,
        )
        .bind(claim_id)
        .bind(scope_type)
        .bind(scope_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List all scoped beliefs for a claim (global + all perspective/community scopes)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_for_claim(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<ScopedBeliefRow>, DbError> {
        let rows: Vec<ScopedBeliefRow> = sqlx::query_as(
            r#"
            SELECT id, frame_id, claim_id, scope_type, scope_id,
                   belief, plausibility, mass_on_empty, mass_on_missing,
                   conflict_k, strategy_used, pignistic_prob, computed_at
            FROM ds_combined_beliefs
            WHERE claim_id = $1
            ORDER BY scope_type, computed_at DESC
            "#,
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// List claims within a specific scope
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_for_scope(
        pool: &PgPool,
        scope_type: &str,
        scope_id: Option<Uuid>,
        frame_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ScopedBeliefRow>, DbError> {
        let rows: Vec<ScopedBeliefRow> = sqlx::query_as(
            r#"
            SELECT id, frame_id, claim_id, scope_type, scope_id,
                   belief, plausibility, mass_on_empty, mass_on_missing,
                   conflict_k, strategy_used, pignistic_prob, computed_at
            FROM ds_combined_beliefs
            WHERE scope_type = $1
              AND (($2::uuid IS NULL AND scope_id IS NULL) OR scope_id = $2)
              AND ($3::uuid IS NULL OR frame_id = $3)
            ORDER BY belief DESC
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(scope_type)
        .bind(scope_id)
        .bind(frame_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_belief_row_has_expected_fields() {
        let _row = ScopedBeliefRow {
            id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            scope_type: "perspective".to_string(),
            scope_id: Some(Uuid::new_v4()),
            belief: 0.7,
            plausibility: 0.9,
            mass_on_empty: 0.01,
            mass_on_missing: 0.02,
            conflict_k: Some(0.15),
            strategy_used: Some("dempster".to_string()),
            pignistic_prob: Some(0.85),
            computed_at: Utc::now(),
        };
    }

    #[test]
    fn scoped_belief_row_global_scope_has_no_scope_id() {
        let _row = ScopedBeliefRow {
            id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            scope_type: "global".to_string(),
            scope_id: None,
            belief: 0.5,
            plausibility: 0.8,
            mass_on_empty: 0.0,
            mass_on_missing: 0.0,
            conflict_k: None,
            strategy_used: None,
            pignistic_prob: None,
            computed_at: Utc::now(),
        };
    }
}
