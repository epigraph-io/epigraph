//! Repository for counterfactual scenario storage and retrieval.
//!
//! Counterfactuals are "what-if" scenarios generated during conflict
//! resolution to identify discriminating tests between competing claims.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Counterfactual scenario row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct CounterfactualRow {
    pub id: Uuid,
    pub conflict_event_id: Option<Uuid>,
    pub claim_a_id: Uuid,
    pub claim_b_id: Uuid,
    pub scenario_a: serde_json::Value,
    pub scenario_b: serde_json::Value,
    pub discriminating_tests: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

pub struct CounterfactualRepository;

impl CounterfactualRepository {
    /// Store a counterfactual scenario for a pair of conflicting claims.
    #[allow(clippy::too_many_arguments)]
    pub async fn store(
        pool: &PgPool,
        conflict_event_id: Option<Uuid>,
        claim_a_id: Uuid,
        claim_b_id: Uuid,
        scenario_a: &serde_json::Value,
        scenario_b: &serde_json::Value,
        discriminating_tests: Option<&serde_json::Value>,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO counterfactual_scenarios \
             (id, conflict_event_id, claim_a_id, claim_b_id, scenario_a, scenario_b, discriminating_tests) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(conflict_event_id)
        .bind(claim_a_id)
        .bind(claim_b_id)
        .bind(scenario_a)
        .bind(scenario_b)
        .bind(discriminating_tests)
        .execute(pool)
        .await?;
        Ok(id)
    }

    /// Get counterfactual scenarios for a claim pair (order-independent).
    #[allow(clippy::similar_names)]
    pub async fn get_for_claims(
        pool: &PgPool,
        claim_a_id: Uuid,
        claim_b_id: Uuid,
    ) -> Result<Vec<CounterfactualRow>, sqlx::Error> {
        sqlx::query_as::<_, CounterfactualRow>(
            "SELECT id, conflict_event_id, claim_a_id, claim_b_id, scenario_a, scenario_b, \
                    discriminating_tests, created_at \
             FROM counterfactual_scenarios \
             WHERE (claim_a_id = $1 AND claim_b_id = $2) OR (claim_a_id = $2 AND claim_b_id = $1) \
             ORDER BY created_at DESC",
        )
        .bind(claim_a_id)
        .bind(claim_b_id)
        .fetch_all(pool)
        .await
    }
}
