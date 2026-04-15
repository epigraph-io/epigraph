//! Repository for learning event operations.
//!
//! Learning events record lessons from conflict resolution,
//! including extraction adjustments for pipeline improvement.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Learning event row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct LearningEventRow {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub conflict_claim_a: Option<Uuid>,
    pub conflict_claim_b: Option<Uuid>,
    pub resolution: String,
    pub lesson: String,
    pub extraction_adjustments: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

pub struct LearningEventRepository;

impl LearningEventRepository {
    /// Insert a learning event from conflict resolution.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        pool: &PgPool,
        challenge_id: Uuid,
        claim_a_id: Option<Uuid>,
        claim_b_id: Option<Uuid>,
        resolution: &str,
        lesson: &str,
        extraction_adjustments: Option<&serde_json::Value>,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO learning_events \
             (id, challenge_id, conflict_claim_a, conflict_claim_b, resolution, lesson, extraction_adjustments) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(challenge_id)
        .bind(claim_a_id)
        .bind(claim_b_id)
        .bind(resolution)
        .bind(lesson)
        .bind(extraction_adjustments)
        .execute(pool)
        .await?;
        Ok(id)
    }

    /// Query learning events by challenge, claim, or text search.
    pub async fn list(
        pool: &PgPool,
        challenge_id: Option<Uuid>,
        claim_id: Option<Uuid>,
        search_text: Option<&str>,
        limit: i64,
    ) -> Result<Vec<LearningEventRow>, sqlx::Error> {
        if let Some(cid) = challenge_id {
            sqlx::query_as::<_, LearningEventRow>(
                "SELECT id, challenge_id, conflict_claim_a, conflict_claim_b, resolution, lesson, \
                        extraction_adjustments, created_at \
                 FROM learning_events WHERE challenge_id = $1 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(cid)
            .bind(limit)
            .fetch_all(pool)
            .await
        } else if let Some(cid) = claim_id {
            sqlx::query_as::<_, LearningEventRow>(
                "SELECT id, challenge_id, conflict_claim_a, conflict_claim_b, resolution, lesson, \
                        extraction_adjustments, created_at \
                 FROM learning_events \
                 WHERE conflict_claim_a = $1 OR conflict_claim_b = $1 \
                 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(cid)
            .bind(limit)
            .fetch_all(pool)
            .await
        } else if let Some(text) = search_text {
            let pattern = format!("%{text}%");
            sqlx::query_as::<_, LearningEventRow>(
                "SELECT id, challenge_id, conflict_claim_a, conflict_claim_b, resolution, lesson, \
                        extraction_adjustments, created_at \
                 FROM learning_events \
                 WHERE lesson ILIKE $1 OR resolution ILIKE $1 \
                 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(pattern)
            .bind(limit)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as::<_, LearningEventRow>(
                "SELECT id, challenge_id, conflict_claim_a, conflict_claim_b, resolution, lesson, \
                        extraction_adjustments, created_at \
                 FROM learning_events ORDER BY created_at DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(pool)
            .await
        }
    }
}
