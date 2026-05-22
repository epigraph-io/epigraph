//! Repository for `match_candidates` (cross-source matcher review queue).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct MatchCandidateRow {
    pub id: Uuid,
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub score: f32,
    pub features: serde_json::Value,
    pub verifier_verdict: Option<String>,
    pub verifier_rationale: Option<String>,
    pub status: String,
    pub matcher_run_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<Uuid>,
}

#[derive(Clone)]
pub struct MatchCandidateRepo {
    pool: PgPool,
}

impl MatchCandidateRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert or update a candidate. Caller MUST pass `claim_a < claim_b`.
    pub async fn upsert(
        &self,
        claim_a: Uuid,
        claim_b: Uuid,
        score: f32,
        features: serde_json::Value,
        status: &str,
        run_id: Option<Uuid>,
    ) -> sqlx::Result<Uuid> {
        debug_assert!(claim_a < claim_b, "callers must pass canonical order");
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO match_candidates
                (claim_a, claim_b, score, features, status, matcher_run_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (claim_a, claim_b) DO UPDATE SET
                score = EXCLUDED.score,
                features = EXCLUDED.features,
                status = EXCLUDED.status,
                matcher_run_id = EXCLUDED.matcher_run_id
             RETURNING id",
        )
        .bind(claim_a)
        .bind(claim_b)
        .bind(score)
        .bind(Json(features))
        .bind(status)
        .bind(run_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn get(&self, id: Uuid) -> sqlx::Result<MatchCandidateRow> {
        sqlx::query_as("SELECT * FROM match_candidates WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn set_status(&self, id: Uuid, status: &str, by: Option<Uuid>) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE match_candidates
             SET status = $2, decided_at = now(), decided_by = $3
             WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_pending(&self, limit: i64) -> sqlx::Result<Vec<MatchCandidateRow>> {
        sqlx::query_as(
            "SELECT * FROM match_candidates
             WHERE status = 'pending'
             ORDER BY score DESC
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Rows in any status, sorted by score desc, optionally filtered by status.
    pub async fn list(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> sqlx::Result<Vec<MatchCandidateRow>> {
        match status {
            Some(s) => {
                sqlx::query_as(
                    "SELECT * FROM match_candidates
                 WHERE status = $1
                 ORDER BY score DESC
                 LIMIT $2",
                )
                .bind(s)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as(
                    "SELECT * FROM match_candidates
                 ORDER BY score DESC
                 LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
        }
    }

    /// All rows where `claim_id` is either side of the pair. Used by the
    /// per-claim "find cross-source matches" API/MCP read paths.
    pub async fn list_for_claim(&self, claim_id: Uuid) -> sqlx::Result<Vec<MatchCandidateRow>> {
        sqlx::query_as(
            "SELECT * FROM match_candidates
             WHERE claim_a = $1 OR claim_b = $1
             ORDER BY score DESC",
        )
        .bind(claim_id)
        .fetch_all(&self.pool)
        .await
    }
}
