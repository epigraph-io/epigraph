//! Database-backed reputation service for background job processing.
//!
//! Implements the [`ReputationJobService`] trait using `PostgreSQL` for:
//! - Fetching claim outcomes (via [`epigraph_db::ClaimRepository`])
//! - Storing computed reputation scores in agent metadata (via raw SQL)
//!
//! # Design
//!
//! This service bridges the gap between the abstract `ReputationJobService` trait
//! (which enables testing with mocks) and the real database layer. It converts
//! between the `epigraph_core::Claim` model and the `ClaimOutcomeData` struct
//! expected by the reputation calculation pipeline.
//!
//! # Reputation Storage
//!
//! Reputation scores are stored in the agent's `metadata` JSONB column:
//! - Overall reputation: `metadata.reputation`
//! - Domain-specific: `metadata.domain_reputations.<domain>`
//!
//! This avoids schema migrations while the reputation system stabilizes.

use crate::{ClaimOutcomeData, ReputationJobError, ReputationJobService};
use async_trait::async_trait;
use epigraph_core::AgentId;
use epigraph_db::{ClaimRepository, PgPool};
use uuid::Uuid;

/// Truth value below which a claim is considered refuted by strong counter-evidence.
const REFUTATION_THRESHOLD: f64 = 0.2;

/// PostgreSQL-backed reputation service.
///
/// Uses [`ClaimRepository`] to fetch claim outcomes and raw SQL to store
/// reputation scores in the agent metadata JSONB column.
///
/// # Example
///
/// ```ignore
/// use epigraph_jobs::{DbReputationService, ConfigurableReputationHandler};
/// use std::sync::Arc;
///
/// let pool = epigraph_db::create_pool("postgres://...").await?;
/// let service = Arc::new(DbReputationService::new(pool));
/// let handler = ConfigurableReputationHandler::new(service);
/// ```
pub struct DbReputationService {
    pool: PgPool,
}

impl DbReputationService {
    /// Create a new `DbReputationService` with the given connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ReputationJobService for DbReputationService {
    async fn get_claim_outcomes(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<ClaimOutcomeData>, ReputationJobError> {
        let agent = AgentId::from(agent_id);

        let claims = ClaimRepository::get_by_agent(&self.pool, agent)
            .await
            .map_err(|e| ReputationJobError::StorageError {
                message: format!("Failed to fetch claims for agent {agent_id}: {e}"),
            })?;

        let now = chrono::Utc::now();

        let outcomes = claims
            .iter()
            .map(|claim| {
                let age = now.signed_duration_since(claim.created_at);
                // Convert to fractional days; use hours for sub-day precision.
                // Precision loss is acceptable: age in hours fits well within f64 mantissa
                // for any reasonable claim lifetime.
                #[allow(clippy::cast_precision_loss)]
                let age_days = age.num_hours() as f64 / 24.0;
                let truth = claim.truth_value.value();

                ClaimOutcomeData {
                    truth_value: truth,
                    age_days,
                    was_refuted: truth < REFUTATION_THRESHOLD,
                    // Claims don't currently carry domain metadata
                    domain: None,
                }
            })
            .collect();

        Ok(outcomes)
    }

    async fn store_reputation(
        &self,
        agent_id: Uuid,
        reputation: f64,
    ) -> Result<(), ReputationJobError> {
        // Store overall reputation in the agent's metadata JSONB column.
        // Uses jsonb_set to merge without overwriting other metadata fields.
        // The '{}' in SQL is a JSON empty object literal, not a Rust format placeholder.
        #[allow(clippy::literal_string_with_formatting_args)]
        let query = "UPDATE agents \
             SET metadata = jsonb_set(\
                 COALESCE(metadata, '{}'), \
                 '{reputation}', \
                 $1::text::jsonb\
             ) \
             WHERE id = $2";

        sqlx::query(query)
            .bind(serde_json::json!(reputation).to_string())
            .bind(agent_id)
            .execute(&self.pool)
            .await
            .map_err(|e| ReputationJobError::StorageError {
                message: format!("Failed to store reputation for agent {agent_id}: {e}"),
            })?;

        Ok(())
    }

    async fn store_domain_reputation(
        &self,
        agent_id: Uuid,
        domain: &str,
        reputation: f64,
    ) -> Result<(), ReputationJobError> {
        // Validate domain to prevent JSONB path injection.
        // Only allow alphanumeric, hyphens, and underscores.
        if domain.is_empty()
            || !domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ReputationJobError::StorageError {
                message: format!(
                    "Invalid domain name '{domain}': must be non-empty and contain only alphanumeric characters, hyphens, or underscores"
                ),
            });
        }

        // Ensure the domain_reputations object exists, then set the specific domain key.
        // Two-step jsonb_set: first ensure parent object, then set nested key.
        let path = format!("{{domain_reputations,{domain}}}");

        // The '{}' in SQL is a JSON empty object literal, not a Rust format placeholder.
        #[allow(clippy::literal_string_with_formatting_args)]
        let query = "UPDATE agents \
             SET metadata = jsonb_set(\
                 jsonb_set(\
                     COALESCE(metadata, '{}'), \
                     '{domain_reputations}', \
                     COALESCE(metadata->'domain_reputations', '{}')\
                 ), \
                 $1::text[], \
                 $2::text::jsonb\
             ) \
             WHERE id = $3";

        sqlx::query(query)
            .bind([path.as_str()])
            .bind(serde_json::json!(reputation).to_string())
            .bind(agent_id)
            .execute(&self.pool)
            .await
            .map_err(|e| ReputationJobError::StorageError {
                message: format!(
                "Failed to store domain reputation for agent {agent_id}, domain '{domain}': {e}"
            ),
            })?;

        Ok(())
    }
}
