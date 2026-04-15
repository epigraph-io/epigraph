//! Repository for challenge operations (anti-sycophancy system).
//!
//! Challenges are typed objections to claims that must be resolved.
//! Five challenge types: insufficient_evidence, outdated_evidence,
//! flawed_methodology, contradicting_evidence, factual_error.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Row type for challenge queries.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ChallengeRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub challenger_id: Option<Uuid>,
    pub challenge_type: String,
    pub explanation: String,
    pub state: String,
    pub resolved_by: Option<Uuid>,
    pub resolution_details: Option<serde_json::Value>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Gap-originated challenge row (subset of fields).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct GapChallengeRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub challenge_type: String,
    pub explanation: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

pub struct ChallengeRepository;

impl ChallengeRepository {
    /// Insert a new challenge against a claim.
    pub async fn create(
        pool: &PgPool,
        claim_id: Uuid,
        challenger_id: Option<Uuid>,
        challenge_type: &str,
        explanation: &str,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO challenges (id, claim_id, challenger_id, challenge_type, explanation, state) \
             VALUES ($1, $2, $3, $4, $5, 'pending')",
        )
        .bind(id)
        .bind(claim_id)
        .bind(challenger_id)
        .bind(challenge_type)
        .bind(explanation)
        .execute(pool)
        .await?;
        Ok(id)
    }

    /// Get a single challenge by ID.
    pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<ChallengeRow>, sqlx::Error> {
        sqlx::query_as::<_, ChallengeRow>(
            "SELECT id, claim_id, challenger_id, challenge_type, explanation, state, \
                    resolved_by, resolution_details, resolved_at, created_at \
             FROM challenges WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List all challenges for a given claim.
    pub async fn list_for_claim(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<ChallengeRow>, sqlx::Error> {
        sqlx::query_as::<_, ChallengeRow>(
            "SELECT id, claim_id, challenger_id, challenge_type, explanation, state, \
                    resolved_by, resolution_details, resolved_at, created_at \
             FROM challenges WHERE claim_id = $1 \
             ORDER BY created_at DESC",
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await
    }

    /// Update challenge state (e.g. pending -> accepted/rejected).
    pub async fn update_state(
        pool: &PgPool,
        challenge_id: Uuid,
        state: &str,
        resolved_by: Option<Uuid>,
        resolution_details: Option<&serde_json::Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE challenges SET state = $1, resolved_by = $2, resolution_details = $3, \
             resolved_at = CASE WHEN $1 IN ('accepted', 'rejected') THEN NOW() ELSE resolved_at END \
             WHERE id = $4",
        )
        .bind(state)
        .bind(resolved_by)
        .bind(resolution_details)
        .bind(challenge_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Insert a gap-originated challenge with event emission.
    pub async fn insert_gap_challenge(
        pool: &PgPool,
        claim_id: Uuid,
        gap_type: &str,
        severity: f64,
        unconstrained_claim: &str,
        nearest_graph_claim: Option<&str>,
        agent_id: Option<Uuid>,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        let challenge_type = format!("epistemic_gap_{gap_type}");
        let explanation = format!(
            "Epistemic gap detected (severity: {severity:.2}). Unconstrained claim: \"{unconstrained_claim}\". \
             Nearest graph claim: {}",
            nearest_graph_claim.unwrap_or("(none)")
        );

        sqlx::query(
            "INSERT INTO challenges (id, claim_id, challenger_id, challenge_type, explanation, state) \
             VALUES ($1, $2, $3, $4, $5, 'pending')",
        )
        .bind(id)
        .bind(claim_id)
        .bind(agent_id)
        .bind(&challenge_type)
        .bind(&explanation)
        .execute(pool)
        .await?;

        Ok(id)
    }

    /// Query gap-originated challenges with optional filters.
    pub async fn get_gap_challenges(
        pool: &PgPool,
        gap_type: Option<&str>,
        state: Option<&str>,
        limit: i64,
    ) -> Result<Vec<GapChallengeRow>, sqlx::Error> {
        let type_filter = gap_type
            .map(|t| format!("epistemic_gap_{t}"))
            .unwrap_or_else(|| "epistemic_gap_%".into());
        let state_filter = state.unwrap_or("%");

        sqlx::query_as::<_, GapChallengeRow>(
            "SELECT id, claim_id, challenge_type, explanation, state, created_at \
             FROM challenges \
             WHERE challenge_type LIKE $1 AND state LIKE $2 \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(&type_filter)
        .bind(state_filter)
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}
