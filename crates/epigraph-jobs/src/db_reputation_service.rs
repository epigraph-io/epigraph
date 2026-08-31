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
    /// The tenancy-aware pool, when the process built one.
    ///
    /// `ReputationJobService` is a trait in `epigraph-jobs` whose signature
    /// cannot carry a `Viewer` (the trait is transport- and tenancy-agnostic by
    /// design, and widening it would push a `Viewer` into every mock in the
    /// test suite). But `ClaimRepository::get_by_agent` now requires one, and
    /// reputation is a **corpus-wide aggregate over an agent's whole output** —
    /// a scoped view of it would compute a different reputation per reader,
    /// which is not what a reputation is.
    ///
    /// So this reads under a bypass, and the bypass needs a
    /// `MaintenanceLease`, which only a `ScopedPool` can mint. Without one the
    /// service fails closed rather than reading unfiltered.
    scoped: Option<epigraph_db::ScopedPool>,
}

impl DbReputationService {
    /// Create a new `DbReputationService` with the given connection pool.
    ///
    /// The resulting service cannot compute outcomes until
    /// [`Self::with_scoped_pool`] supplies a `ScopedPool` — see [`Self::scoped`].
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool, scoped: None }
    }

    /// Attach the pool that can mint a maintenance lease.
    #[must_use]
    pub fn with_scoped_pool(mut self, scoped: epigraph_db::ScopedPool) -> Self {
        self.scoped = Some(scoped);
        self
    }
}

#[async_trait]
impl ReputationJobService for DbReputationService {
    async fn get_claim_outcomes(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<ClaimOutcomeData>, ReputationJobError> {
        let agent = AgentId::from(agent_id);

        // Corpus-wide aggregate; see the `scoped` field docs for why this is a
        // bypass and why it fails closed without a `ScopedPool`.
        // `BeliefRecomputation` is the enumerated reason: reputation is a
        // derived belief statistic recomputed over the whole corpus, and adding
        // a variant here would break `viewer_ratchet.rs`'s monotone-decreasing
        // property for a job that is already covered by an existing reason.
        let scoped = self
            .scoped
            .as_ref()
            .ok_or_else(|| ReputationJobError::StorageError {
                message: "DbReputationService has no ScopedPool, so it cannot mint the \
                      maintenance lease a corpus-wide reputation read requires; \
                      construct it with DbReputationService::with_scoped_pool"
                    .to_string(),
            })?;
        let (_maint_conn, lease) = scoped
            .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .map_err(|e| ReputationJobError::StorageError {
                message: format!("maintenance acquire failed: {e}"),
            })?;
        let viewer = epigraph_db::visibility::Viewer::system(
            &lease,
            epigraph_db::visibility::SystemReason::BeliefRecomputation,
        );

        let claims = ClaimRepository::get_by_agent(&self.pool, &viewer, agent)
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
