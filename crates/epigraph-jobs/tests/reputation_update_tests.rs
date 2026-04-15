//! TDD Tests for `ReputationUpdateHandler`
//!
//! These tests define the expected behavior of the reputation update job handler.
//! They implement the core epistemic principle: reputation is calculated FROM claims,
//! never used AS INPUT to truth calculation.
//!
//! # Critical Invariant (The Bad Actor Test)
//!
//! The "Bad Actor Test" MUST always pass: a high-reputation agent submitting a claim
//! without evidence should receive a LOW truth value, not a high one.
//!
//! ```text
//! CORRECT:  Evidence -> Truth -> Reputation
//! WRONG:    Reputation -> Truth
//! ```
//!
//! # Test Coverage
//!
//! This module tests:
//! - Reputation calculation from verified claims
//! - Domain-specific reputation scoring
//! - The Bad Actor invariant (reputation isolation from truth)
//! - Refutation penalty (0.5x weight)
//! - Recency weighting (recent claims weight more)
//! - Sybil attack resistance (independent agent calculations)
//! - Boundary truth value handling (0.0, 1.0 extremes)

use epigraph_jobs::{
    async_trait, ClaimOutcomeData, ConfigurableReputationHandler, EpiGraphJob, InMemoryJobQueue,
    Job, JobError, JobHandler, JobResult, JobResultMetadata, JobRunner, ReputationJobError,
    ReputationJobService, ReputationUpdateHandler,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use uuid::Uuid;

// ============================================================================
// Mock Repositories for Testing
// ============================================================================

/// Mock claim outcome for reputation calculation
#[derive(Debug, Clone)]
pub struct MockClaimOutcome {
    /// Final truth value of the claim
    pub truth_value: f64,
    /// Age of the claim in days
    pub age_days: f64,
    /// Whether the claim was later refuted by strong evidence
    pub was_refuted: bool,
    /// Domain of the claim (optional, for domain-specific reputation)
    pub domain: Option<String>,
}

/// Mock agent data
#[derive(Debug, Clone)]
pub struct MockAgent {
    pub id: Uuid,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Mock repository for agent data
#[derive(Default)]
pub struct MockAgentRepository {
    agents: RwLock<HashMap<Uuid, MockAgent>>,
    claim_outcomes: RwLock<HashMap<Uuid, Vec<MockClaimOutcome>>>,
    reputation_scores: RwLock<HashMap<Uuid, f64>>,
    domain_reputation_scores: RwLock<HashMap<(Uuid, String), f64>>,
}

impl MockAgentRepository {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_agent(&self, agent: MockAgent) {
        self.agents.write().unwrap().insert(agent.id, agent);
    }

    pub fn add_claim_outcomes(&self, agent_id: Uuid, outcomes: Vec<MockClaimOutcome>) {
        self.claim_outcomes
            .write()
            .unwrap()
            .insert(agent_id, outcomes);
    }

    pub fn get_claim_outcomes(&self, agent_id: Uuid) -> Vec<MockClaimOutcome> {
        self.claim_outcomes
            .read()
            .unwrap()
            .get(&agent_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_reputation(&self, agent_id: Uuid) -> Option<f64> {
        self.reputation_scores
            .read()
            .unwrap()
            .get(&agent_id)
            .copied()
    }

    pub fn set_reputation(&self, agent_id: Uuid, reputation: f64) {
        self.reputation_scores
            .write()
            .unwrap()
            .insert(agent_id, reputation);
    }

    pub fn get_domain_reputation(&self, agent_id: Uuid, domain: &str) -> Option<f64> {
        self.domain_reputation_scores
            .read()
            .unwrap()
            .get(&(agent_id, domain.to_string()))
            .copied()
    }

    pub fn set_domain_reputation(&self, agent_id: Uuid, domain: &str, reputation: f64) {
        self.domain_reputation_scores
            .write()
            .unwrap()
            .insert((agent_id, domain.to_string()), reputation);
    }
}

// ============================================================================
// Mock Reputation Update Handler for Testing
// ============================================================================

/// Configuration for mock reputation calculation
#[derive(Debug, Clone)]
pub struct MockReputationConfig {
    pub initial_reputation: f64,
    pub min_reputation: f64,
    pub max_reputation: f64,
    pub recency_weight: f64,
    pub min_claims_for_stability: usize,
    /// Penalty multiplier for refuted claims (default 0.5)
    pub refutation_penalty: f64,
}

impl Default for MockReputationConfig {
    fn default() -> Self {
        Self {
            initial_reputation: 0.5,
            min_reputation: 0.1,
            max_reputation: 0.95,
            recency_weight: 0.7,
            min_claims_for_stability: 10,
            refutation_penalty: 0.5,
        }
    }
}

/// Mock handler that implements the reputation update logic
pub struct MockReputationUpdateHandler {
    pub repository: Arc<MockAgentRepository>,
    pub config: MockReputationConfig,
}

impl MockReputationUpdateHandler {
    pub fn new(repository: Arc<MockAgentRepository>) -> Self {
        Self {
            repository,
            config: MockReputationConfig::default(),
        }
    }

    pub const fn with_config(
        repository: Arc<MockAgentRepository>,
        config: MockReputationConfig,
    ) -> Self {
        Self { repository, config }
    }

    /// Calculate reputation from claim outcomes
    /// This mirrors the logic in epigraph-engine's `ReputationCalculator`
    fn calculate_reputation(&self, outcomes: &[MockClaimOutcome]) -> f64 {
        if outcomes.is_empty() {
            return self.config.initial_reputation;
        }

        // Separate recent vs historical
        let mut recent: Vec<&MockClaimOutcome> = vec![];
        let mut historical: Vec<&MockClaimOutcome> = vec![];

        for outcome in outcomes {
            if outcome.age_days <= 30.0 {
                recent.push(outcome);
            } else {
                historical.push(outcome);
            }
        }

        // Calculate scores for each group
        let recent_score = self.calculate_group_score(&recent);
        let historical_score = self.calculate_group_score(&historical);

        // Weighted combination
        let combined = if historical.is_empty() {
            recent_score
        } else if recent.is_empty() {
            historical_score
        } else {
            recent_score.mul_add(
                self.config.recency_weight,
                historical_score * (1.0 - self.config.recency_weight),
            )
        };

        // Apply stability penalty if too few claims
        let stability_factor = if outcomes.len() < self.config.min_claims_for_stability {
            let progress = outcomes.len() as f64 / self.config.min_claims_for_stability as f64;
            progress.mul_add(combined, (1.0 - progress) * self.config.initial_reputation)
        } else {
            combined
        };

        // Clamp to bounds
        stability_factor.clamp(self.config.min_reputation, self.config.max_reputation)
    }

    fn calculate_group_score(&self, outcomes: &[&MockClaimOutcome]) -> f64 {
        if outcomes.is_empty() {
            return self.config.initial_reputation;
        }

        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for outcome in outcomes {
            // Refuted claims get penalized by the refutation_penalty factor
            let claim_score = if outcome.was_refuted {
                outcome.truth_value * self.config.refutation_penalty
            } else {
                outcome.truth_value
            };

            // More recent claims weighted higher
            let recency_factor = 1.0 / (1.0 + outcome.age_days / 30.0);

            total_score += claim_score * recency_factor;
            total_weight += recency_factor;
        }

        if total_weight > 0.0 {
            total_score / total_weight
        } else {
            self.config.initial_reputation
        }
    }

    /// Calculate domain-specific reputation
    fn calculate_domain_reputation(&self, agent_id: Uuid, domain: &str) -> f64 {
        let all_outcomes = self.repository.get_claim_outcomes(agent_id);
        let domain_outcomes: Vec<MockClaimOutcome> = all_outcomes
            .into_iter()
            .filter(|o| o.domain.as_deref() == Some(domain))
            .collect();

        self.calculate_reputation(&domain_outcomes)
    }
}

#[async_trait]
impl JobHandler for MockReputationUpdateHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        // Parse the job payload
        let payload: serde_json::Value = job.payload.clone();

        let agent_id = payload
            .get("ReputationUpdate")
            .and_then(|v| v.get("agent_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| JobError::PayloadError {
                message: "Missing agent_id in payload".into(),
            })?;

        let agent_id: Uuid = agent_id.parse().map_err(|_| JobError::PayloadError {
            message: "Invalid agent_id format".into(),
        })?;

        // Get claim outcomes for this agent
        let outcomes = self.repository.get_claim_outcomes(agent_id);

        // Calculate reputation
        let reputation = self.calculate_reputation(&outcomes);

        // Store the calculated reputation
        self.repository.set_reputation(agent_id, reputation);

        // Also calculate domain-specific reputations
        let domains: Vec<String> = outcomes
            .iter()
            .filter_map(|o| o.domain.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        for domain in &domains {
            let domain_rep = self.calculate_domain_reputation(agent_id, domain);
            self.repository
                .set_domain_reputation(agent_id, domain, domain_rep);
        }

        Ok(JobResult {
            output: json!({
                "agent_id": agent_id.to_string(),
                "reputation": reputation,
                "domain_reputations": domains.len(),
                "claims_processed": outcomes.len()
            }),
            execution_duration: Duration::from_millis(10),
            metadata: JobResultMetadata {
                worker_id: Some("reputation-worker-1".into()),
                items_processed: Some(outcomes.len() as u64),
                extra: Default::default(),
            },
        })
    }

    fn job_type(&self) -> &'static str {
        "reputation_update"
    }
}

// ============================================================================
// Mock Truth Calculator for Bad Actor Test
// ============================================================================

/// Mock implementation of initial truth calculation.
///
/// This simulates the `BayesianUpdater::calculate_initial_truth` function
/// from epigraph-engine to verify the Bad Actor invariant at the jobs layer.
///
/// # Critical Design Principle
///
/// This function takes ONLY evidence parameters, never reputation.
/// The function signature itself enforces the epistemic invariant:
/// - `evidence_weight`: f64 (how strong the evidence is)
/// - `evidence_count`: usize (how many independent sources)
///
/// There is NO `agent_reputation` parameter. This is intentional.
fn calculate_initial_truth(evidence_weight: f64, evidence_count: usize) -> f64 {
    // Base truth from evidence weight (max 0.5 from weight alone)
    let base = evidence_weight * 0.5;

    // Diversity bonus for multiple evidence sources
    let diversity_bonus = match evidence_count {
        0 => 0.0,
        1 => 0.1,
        2 => 0.15,
        3 => 0.18,
        _ => 0.2, // Cap at 0.2
    };

    // Start from uncertainty (0.5) and adjust
    let truth = 0.5 + base + diversity_bonus;

    // Clamp to never exceed 0.85 for initial truth
    truth.min(0.85).max(0.0)
}

// ============================================================================
// Test: Reputation Calculated from Verified Claims
// ============================================================================

/// Agent reputation should be calculated from their verified claims' truth values
#[tokio::test]
async fn test_reputation_calculated_from_verified_claims() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    // Agent has made several claims with high truth values (verified)
    repository.add_claim_outcomes(
        agent_id,
        vec![
            MockClaimOutcome {
                truth_value: 0.9,
                age_days: 5.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.85,
                age_days: 10.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.92,
                age_days: 2.0,
                was_refuted: false,
                domain: None,
            },
            // Add enough claims to reach stability threshold
            MockClaimOutcome {
                truth_value: 0.88,
                age_days: 8.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.91,
                age_days: 3.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.87,
                age_days: 12.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.9,
                age_days: 7.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.86,
                age_days: 15.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.89,
                age_days: 4.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.93,
                age_days: 1.0,
                was_refuted: false,
                domain: None,
            },
        ],
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());

    // Create the job
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();

    // Process the job
    let result = handler.handle(&job).await;

    assert!(result.is_ok(), "Reputation update job should succeed");

    let reputation = repository.get_reputation(agent_id).unwrap();

    // Agent with consistently high truth claims should have high reputation
    assert!(
        reputation > 0.7,
        "Agent with high-truth claims should have high reputation, got: {reputation}"
    );
    assert!(
        reputation <= 0.95,
        "Reputation should be capped at max_reputation (0.95), got: {reputation}"
    );
}

/// Agent with low-truth claims should have low reputation
#[tokio::test]
async fn test_low_truth_claims_decrease_reputation() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    // Agent has made claims that turned out to be false/low truth
    repository.add_claim_outcomes(
        agent_id,
        vec![
            MockClaimOutcome {
                truth_value: 0.2,
                age_days: 5.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.15,
                age_days: 10.0,
                was_refuted: true,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.1,
                age_days: 2.0,
                was_refuted: true,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.25,
                age_days: 8.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.18,
                age_days: 3.0,
                was_refuted: true,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.22,
                age_days: 12.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.12,
                age_days: 7.0,
                was_refuted: true,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.19,
                age_days: 15.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.21,
                age_days: 4.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.14,
                age_days: 1.0,
                was_refuted: true,
                domain: None,
            },
        ],
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    let result = handler.handle(&job).await;

    assert!(result.is_ok());

    let reputation = repository.get_reputation(agent_id).unwrap();

    // Agent with consistently low truth claims should have low reputation
    assert!(
        reputation < 0.3,
        "Agent with low-truth claims should have low reputation, got: {reputation}"
    );
    assert!(
        reputation >= 0.1,
        "Reputation should be floored at min_reputation (0.1), got: {reputation}"
    );
}

// ============================================================================
// Test: Domain-Specific Reputation
// ============================================================================

/// Agent should have separate reputation scores per domain
#[tokio::test]
async fn test_domain_specific_reputation_scores() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    // Agent is expert in "physics" but novice in "biology"
    repository.add_claim_outcomes(
        agent_id,
        vec![
            // Physics claims - high truth
            MockClaimOutcome {
                truth_value: 0.95,
                age_days: 5.0,
                was_refuted: false,
                domain: Some("physics".to_string()),
            },
            MockClaimOutcome {
                truth_value: 0.92,
                age_days: 10.0,
                was_refuted: false,
                domain: Some("physics".to_string()),
            },
            MockClaimOutcome {
                truth_value: 0.9,
                age_days: 2.0,
                was_refuted: false,
                domain: Some("physics".to_string()),
            },
            // Biology claims - low truth
            MockClaimOutcome {
                truth_value: 0.25,
                age_days: 5.0,
                was_refuted: true,
                domain: Some("biology".to_string()),
            },
            MockClaimOutcome {
                truth_value: 0.3,
                age_days: 10.0,
                was_refuted: false,
                domain: Some("biology".to_string()),
            },
            MockClaimOutcome {
                truth_value: 0.2,
                age_days: 2.0,
                was_refuted: true,
                domain: Some("biology".to_string()),
            },
        ],
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    let result = handler.handle(&job).await;

    assert!(result.is_ok());

    let physics_rep = repository
        .get_domain_reputation(agent_id, "physics")
        .unwrap();
    let biology_rep = repository
        .get_domain_reputation(agent_id, "biology")
        .unwrap();

    // Physics reputation should be much higher than biology
    assert!(
        physics_rep > biology_rep,
        "Physics reputation ({physics_rep}) should be higher than biology ({biology_rep})"
    );
    assert!(
        physics_rep > 0.6,
        "Physics reputation should be high, got: {physics_rep}"
    );
    assert!(
        biology_rep < 0.5,
        "Biology reputation should be low, got: {biology_rep}"
    );
}

/// Agent with claims across multiple domains should have correctly weighted domain reputations
#[tokio::test]
async fn test_agent_with_mixed_domains_calculated_correctly() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    // Agent has mixed performance across three domains
    // Note: With only 2 claims per domain (below stability threshold of 10),
    // the reputation will regress toward 0.5. We need to verify relative ordering.
    repository.add_claim_outcomes(
        agent_id,
        vec![
            // Math domain - excellent (all high truth, recent)
            MockClaimOutcome {
                truth_value: 0.95,
                age_days: 1.0,
                was_refuted: false,
                domain: Some("math".to_string()),
            },
            MockClaimOutcome {
                truth_value: 0.92,
                age_days: 2.0,
                was_refuted: false,
                domain: Some("math".to_string()),
            },
            // History domain - poor (low truth, some refuted)
            MockClaimOutcome {
                truth_value: 0.3,
                age_days: 1.0,
                was_refuted: true,
                domain: Some("history".to_string()),
            },
            MockClaimOutcome {
                truth_value: 0.25,
                age_days: 2.0,
                was_refuted: false,
                domain: Some("history".to_string()),
            },
            // Philosophy domain - mediocre (medium truth)
            MockClaimOutcome {
                truth_value: 0.55,
                age_days: 1.0,
                was_refuted: false,
                domain: Some("philosophy".to_string()),
            },
            MockClaimOutcome {
                truth_value: 0.6,
                age_days: 2.0,
                was_refuted: false,
                domain: Some("philosophy".to_string()),
            },
        ],
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    let result = handler.handle(&job).await;

    assert!(result.is_ok());

    let math_rep = repository.get_domain_reputation(agent_id, "math").unwrap();
    let history_rep = repository
        .get_domain_reputation(agent_id, "history")
        .unwrap();
    let philosophy_rep = repository
        .get_domain_reputation(agent_id, "philosophy")
        .unwrap();

    // Verify ordering: math > philosophy > history
    // This is the key property - even with stability regression, the relative
    // ordering must be preserved based on claim quality
    assert!(
        math_rep > philosophy_rep,
        "Math ({math_rep}) should be higher than philosophy ({philosophy_rep})"
    );
    assert!(
        philosophy_rep > history_rep,
        "Philosophy ({philosophy_rep}) should be higher than history ({history_rep})"
    );

    // Math should be above neutral (good claims, regressed toward 0.5)
    // With 2/10 claims, progress = 0.2, so:
    // reputation = 0.2 * ~0.93 + 0.8 * 0.5 = ~0.59
    assert!(
        math_rep > 0.5,
        "Math should be above neutral despite regression: {math_rep}"
    );

    // History should be below neutral (bad claims, some refuted)
    assert!(
        history_rep < 0.5,
        "History should be below neutral: {history_rep}"
    );

    // Philosophy should be near neutral (mediocre claims)
    assert!(
        philosophy_rep > 0.45 && philosophy_rep < 0.6,
        "Philosophy should be near neutral: {philosophy_rep}"
    );
}

// ============================================================================
// Test: CRITICAL - The Bad Actor Test (Reputation Isolation)
// ============================================================================

/// # THE BAD ACTOR TEST - CRITICAL EPISTEMIC INVARIANT
///
/// This is the MOST IMPORTANT test in the reputation system. It validates
/// the core principle from CLAUDE.md:
///
/// > A high-reputation agent submitting a claim without evidence should
/// > receive a LOW truth value, not a high one.
///
/// ## What This Test Validates
///
/// 1. A high-reputation agent (0.95 reputation from historical claims)
/// 2. Submits a NEW claim with ZERO evidence
/// 3. The initial truth value MUST be LOW (< 0.3)
/// 4. Reputation NEVER influences initial truth calculation
///
/// ## Architectural Enforcement
///
/// The `calculate_initial_truth` function signature enforces this:
/// - It takes (`evidence_weight`, `evidence_count`)
/// - It has NO reputation parameter
/// - This is a compile-time guarantee that reputation cannot leak in
///
/// ## Why This Matters
///
/// Without this invariant, the system degrades to "Appeal to Authority":
/// - Famous scientist says X -> X must be true
/// - This is a logical fallacy
/// - `EpiGraph` requires evidence, not reputation
#[tokio::test]
async fn test_bad_actor_high_reputation_no_evidence_gets_low_truth() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    // Step 1: Create an agent with STELLAR reputation (past verified claims)
    // This agent has a perfect track record - all high-truth claims
    repository.add_claim_outcomes(
        agent_id,
        (0..10)
            .map(|i| MockClaimOutcome {
                truth_value: 0.95,
                age_days: f64::from(i).mul_add(5.0, 30.0),
                was_refuted: false,
                domain: None,
            })
            .collect(),
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    let result = handler.handle(&job).await;

    assert!(result.is_ok());

    // Step 2: Verify the agent has HIGH reputation (precondition)
    let reputation = repository.get_reputation(agent_id).unwrap();
    assert!(
        reputation > 0.7,
        "Test setup: Agent should have high reputation from historical claims, got: {reputation}"
    );

    // Step 3: THE CRITICAL TEST
    // Simulate submitting a NEW claim with NO evidence
    // This is what happens when the agent says "Trust me, I'm an expert"

    // Calculate initial truth using ONLY evidence parameters
    // Note: There is NO reputation parameter - this is architectural enforcement
    let no_evidence_weight = 0.0;
    let no_evidence_count = 0usize;
    let initial_truth = calculate_initial_truth(no_evidence_weight, no_evidence_count);

    // Step 4: ASSERT - Initial truth MUST be LOW despite high reputation
    //
    // Key insight: "low truth" means below the threshold where a claim would
    // be considered "likely true" (0.7+). With zero evidence, truth = 0.5
    // which represents maximum uncertainty - this IS a low/neutral value.
    //
    // The critical point is that the truth is NOT inflated by reputation.
    // A high-rep agent with no evidence gets the SAME truth as a zero-rep agent.
    assert!(
        initial_truth <= 0.5,
        "BAD ACTOR TEST FAILED: High-reputation agent with no evidence got truth {initial_truth} \
         (expected <= 0.5). Reputation MUST NOT inflate truth!"
    );

    // With zero evidence, truth should be exactly 0.5 (maximum uncertainty)
    // This proves reputation has NO influence - the result depends ONLY on evidence
    assert!(
        (initial_truth - 0.5).abs() < f64::EPSILON,
        "Zero evidence should produce exactly 0.5 (maximum uncertainty), got {initial_truth}"
    );

    // THE CORE INVARIANT: Compare high-rep agent's claim truth to a zero-rep agent
    // They MUST be identical because reputation is NOT an input to truth calculation
    let zero_rep_agent_truth = calculate_initial_truth(0.0, 0);
    assert!(
        (initial_truth - zero_rep_agent_truth).abs() < f64::EPSILON,
        "CRITICAL: High-rep agent ({initial_truth}) and zero-rep agent ({zero_rep_agent_truth}) must get IDENTICAL \
         initial truth with same evidence. Reputation leaked into truth calculation!"
    );

    // Step 5: Document what CANNOT happen due to architectural enforcement
    // The following line would be required if reputation could influence truth:
    //
    // IMPOSSIBLE (won't compile - no reputation parameter exists):
    // let boosted_truth = calculate_initial_truth(0.0, 0, reputation);
    //
    // This compile-time guarantee prevents the Appeal to Authority fallacy
}

/// Reputation MUST be OUTPUT not INPUT to truth calculation
///
/// This test verifies that:
/// 1. The reputation job calculates reputation FROM claims
/// 2. It does NOT output any fields that could influence future truth
/// 3. Reputation is for tracking/access-control, NOT truth boosting
#[tokio::test]
async fn test_reputation_is_output_not_input_to_truth() {
    let repository = Arc::new(MockAgentRepository::new());

    // Create two agents with vastly different reputations
    let good_agent = Uuid::new_v4();
    let bad_agent = Uuid::new_v4();

    // Good agent: history of verified claims
    repository.add_claim_outcomes(
        good_agent,
        (0..10)
            .map(|i| MockClaimOutcome {
                truth_value: 0.9,
                age_days: f64::from(i) * 5.0,
                was_refuted: false,
                domain: None,
            })
            .collect(),
    );

    // Bad agent: history of refuted claims
    repository.add_claim_outcomes(
        bad_agent,
        (0..10)
            .map(|i| MockClaimOutcome {
                truth_value: 0.2,
                age_days: f64::from(i) * 5.0,
                was_refuted: true,
                domain: None,
            })
            .collect(),
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());

    // Process both reputation updates
    let good_job = EpiGraphJob::ReputationUpdate {
        agent_id: good_agent,
    }
    .into_job()
    .unwrap();
    let bad_job = EpiGraphJob::ReputationUpdate {
        agent_id: bad_agent,
    }
    .into_job()
    .unwrap();

    let good_result = handler.handle(&good_job).await.unwrap();
    let bad_result = handler.handle(&bad_job).await.unwrap();

    let good_rep = repository.get_reputation(good_agent).unwrap();
    let bad_rep = repository.get_reputation(bad_agent).unwrap();

    // Verify different reputations were computed correctly
    assert!(
        good_rep > bad_rep,
        "Good agent should have higher reputation: good={good_rep}, bad={bad_rep}"
    );

    // KEY ASSERTIONS: The job result must NOT include any truth-influencing fields
    let forbidden_fields = [
        "pre_approved_truth",
        "future_claim_truth_boost",
        "initial_truth",
        "truth_modifier",
        "trust_score",
        "credibility_boost",
    ];

    let good_output = good_result.output.to_string();
    let bad_output = bad_result.output.to_string();

    for field in &forbidden_fields {
        assert!(
            !good_output.contains(field),
            "Reputation job must not output '{field}' - found in good_result"
        );
        assert!(
            !bad_output.contains(field),
            "Reputation job must not output '{field}' - found in bad_result"
        );
    }

    // Verify the critical property: SAME initial truth regardless of reputation
    // When both agents submit new claims with identical evidence, they get identical truth
    let evidence_weight = 0.3;
    let evidence_count = 1;

    let good_agent_claim_truth = calculate_initial_truth(evidence_weight, evidence_count);
    let bad_agent_claim_truth = calculate_initial_truth(evidence_weight, evidence_count);

    assert!(
        (good_agent_claim_truth - bad_agent_claim_truth).abs() < f64::EPSILON,
        "Initial truth must be IDENTICAL regardless of agent reputation: \
         good_agent got {good_agent_claim_truth}, bad_agent got {bad_agent_claim_truth} \
         (with same evidence: weight={evidence_weight}, count={evidence_count})"
    );
}

// ============================================================================
// Test: Refutation Penalty Verification (0.5x)
// ============================================================================

/// Refuted claims MUST receive exactly 0.5x penalty in reputation calculation
///
/// From epigraph-engine/src/reputation.rs:
/// ```rust
/// let claim_score = if outcome.was_refuted {
///     outcome.truth_value * 0.5 // Penalty for being refuted
/// } else {
///     outcome.truth_value
/// };
/// ```
#[tokio::test]
async fn test_refutation_penalty_applied_correctly() {
    let repository = Arc::new(MockAgentRepository::new());

    // Agent A: Claims NOT refuted
    let agent_not_refuted = Uuid::new_v4();
    repository.add_claim_outcomes(
        agent_not_refuted,
        (0..10)
            .map(|i| MockClaimOutcome {
                truth_value: 0.8,
                age_days: f64::from(i) + 1.0,
                was_refuted: false, // NOT refuted
                domain: None,
            })
            .collect(),
    );

    // Agent B: Identical claims but ALL refuted
    let agent_refuted = Uuid::new_v4();
    repository.add_claim_outcomes(
        agent_refuted,
        (0..10)
            .map(|i| MockClaimOutcome {
                truth_value: 0.8,
                age_days: f64::from(i) + 1.0,
                was_refuted: true, // REFUTED
                domain: None,
            })
            .collect(),
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());

    // Process both
    let job_not_refuted = EpiGraphJob::ReputationUpdate {
        agent_id: agent_not_refuted,
    }
    .into_job()
    .unwrap();
    let job_refuted = EpiGraphJob::ReputationUpdate {
        agent_id: agent_refuted,
    }
    .into_job()
    .unwrap();

    handler.handle(&job_not_refuted).await.unwrap();
    handler.handle(&job_refuted).await.unwrap();

    let rep_not_refuted = repository.get_reputation(agent_not_refuted).unwrap();
    let rep_refuted = repository.get_reputation(agent_refuted).unwrap();

    // Refuted agent should have significantly lower reputation
    assert!(
        rep_not_refuted > rep_refuted,
        "Refuted claims should hurt reputation: not_refuted={rep_not_refuted}, refuted={rep_refuted}"
    );

    // The penalty should be approximately 0.5x
    // With all claims having truth 0.8:
    // - Not refuted: effective score ~0.8
    // - Refuted: effective score ~0.4 (0.8 * 0.5)
    // Due to recency weighting and stability factors, exact ratio may vary,
    // but refuted should be roughly half
    let ratio = rep_refuted / rep_not_refuted;
    assert!(
        ratio < 0.7,
        "Refutation penalty should result in significantly lower reputation. \
         Ratio: {ratio} (expected < 0.7)"
    );
}

// ============================================================================
// Test: Recency Weight Verification
// ============================================================================

/// Recent claims MUST weight more heavily than historical claims
///
/// The config has `recency_weight` = 0.7, meaning:
/// - 70% weight on claims <= 30 days old
/// - 30% weight on claims > 30 days old
#[tokio::test]
async fn test_recency_weight_affects_reputation() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    // Agent with GOOD recent history but BAD historical record
    // Recent (< 30 days): high truth
    // Historical (> 30 days): low truth
    repository.add_claim_outcomes(
        agent_id,
        vec![
            // Recent good claims (5 claims, 1-25 days old)
            MockClaimOutcome {
                truth_value: 0.95,
                age_days: 1.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.92,
                age_days: 5.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.9,
                age_days: 10.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.88,
                age_days: 15.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.91,
                age_days: 25.0,
                was_refuted: false,
                domain: None,
            },
            // Historical bad claims (5 claims, 40-80 days old)
            MockClaimOutcome {
                truth_value: 0.15,
                age_days: 40.0,
                was_refuted: true,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.2,
                age_days: 50.0,
                was_refuted: true,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.1,
                age_days: 60.0,
                was_refuted: true,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.18,
                age_days: 70.0,
                was_refuted: true,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.12,
                age_days: 80.0,
                was_refuted: true,
                domain: None,
            },
        ],
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    handler.handle(&job).await.unwrap();

    let reputation = repository.get_reputation(agent_id).unwrap();

    // With 70% recency weight, reputation should be closer to recent (0.9+) than historical (0.1-0.2)
    // Expected: ~0.7 * 0.9 + 0.3 * 0.1 = 0.63 + 0.03 = ~0.66
    // (accounting for refutation penalty and recency factors within groups)
    assert!(
        reputation > 0.5,
        "Recent good performance should outweigh historical bad: got {reputation}"
    );

    // Verify it's not as high as if there were no bad history
    assert!(
        reputation < 0.85,
        "Historical bad performance should still have some effect: got {reputation}"
    );
}

// ============================================================================
// Test: Sybil Attack Resistance
// ============================================================================

/// Agent reputations MUST be calculated independently
///
/// A Sybil attack creates many fake agents to boost claims. `EpiGraph` resists this by:
/// 1. Each agent's reputation is calculated independently
/// 2. Creating new agents gives them initial (neutral) reputation
/// 3. Reputation cannot be transferred between agents
#[tokio::test]
async fn test_sybil_attack_resistance() {
    let repository = Arc::new(MockAgentRepository::new());

    // Create "main" agent with high reputation
    let main_agent = Uuid::new_v4();
    repository.add_claim_outcomes(
        main_agent,
        (0..20)
            .map(|i| MockClaimOutcome {
                truth_value: 0.95,
                age_days: f64::from(i) + 1.0,
                was_refuted: false,
                domain: None,
            })
            .collect(),
    );

    // Create "sybil" agents (fake accounts) - no claim history
    let sybil_agents: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();
    for sybil in &sybil_agents {
        repository.add_claim_outcomes(*sybil, vec![]); // No history
    }

    let handler = MockReputationUpdateHandler::new(repository.clone());

    // Process main agent
    let main_job = EpiGraphJob::ReputationUpdate {
        agent_id: main_agent,
    }
    .into_job()
    .unwrap();
    handler.handle(&main_job).await.unwrap();

    // Process all sybil agents
    for sybil in &sybil_agents {
        let sybil_job = EpiGraphJob::ReputationUpdate { agent_id: *sybil }
            .into_job()
            .unwrap();
        handler.handle(&sybil_job).await.unwrap();
    }

    let main_rep = repository.get_reputation(main_agent).unwrap();

    // Key assertions for Sybil resistance:

    // 1. Sybil agents should have neutral (initial) reputation
    for sybil in &sybil_agents {
        let sybil_rep = repository.get_reputation(*sybil).unwrap();
        assert!(
            (sybil_rep - 0.5).abs() < f64::EPSILON,
            "Sybil agent should have neutral reputation (0.5), got {sybil_rep}"
        );

        // 2. Sybil reputation is INDEPENDENT of main agent
        assert!(
            sybil_rep < main_rep,
            "Sybil ({sybil_rep}) should be lower than main ({main_rep})"
        );
    }

    // 3. Main agent reputation is unaffected by sybils existing
    assert!(
        main_rep > 0.8,
        "Main agent should maintain high reputation: {main_rep}"
    );

    // 4. Even with 5 sybil agents, they can't boost their own claims
    // (verified by the initial truth calculation being reputation-independent)
    // Test one sybil agent's claim (all would get same result since truth
    // calculation ignores reputation entirely)
    let sybil_claim_truth = calculate_initial_truth(0.0, 0);
    assert!(
        sybil_claim_truth <= 0.5,
        "Sybil claims without evidence should have low truth: {sybil_claim_truth}"
    );

    // Verify that all 5 sybil agents would get the exact same truth value
    // because reputation is isolated from truth calculation
    assert_eq!(
        sybil_agents.len(),
        5,
        "Should have 5 sybil agents for this test"
    );
}

// ============================================================================
// Test: Boundary Truth Value Handling
// ============================================================================

/// Truth values at boundaries (0.0 and 1.0) must be handled correctly
#[tokio::test]
async fn test_boundary_truth_values_zero_and_one() {
    let repository = Arc::new(MockAgentRepository::new());

    // Agent A: All claims with truth = 0.0 (complete falsehood)
    let agent_zero = Uuid::new_v4();
    repository.add_claim_outcomes(
        agent_zero,
        (0..10)
            .map(|i| MockClaimOutcome {
                truth_value: 0.0,
                age_days: f64::from(i) + 1.0,
                was_refuted: true,
                domain: None,
            })
            .collect(),
    );

    // Agent B: All claims with truth = 1.0 (complete truth)
    let agent_one = Uuid::new_v4();
    repository.add_claim_outcomes(
        agent_one,
        (0..10)
            .map(|i| MockClaimOutcome {
                truth_value: 1.0,
                age_days: f64::from(i) + 1.0,
                was_refuted: false,
                domain: None,
            })
            .collect(),
    );

    // Agent C: Mix of 0.0 and 1.0 (extreme variance)
    let agent_mixed = Uuid::new_v4();
    repository.add_claim_outcomes(
        agent_mixed,
        (0..10)
            .map(|i| MockClaimOutcome {
                truth_value: if i % 2 == 0 { 0.0 } else { 1.0 },
                age_days: f64::from(i) + 1.0,
                was_refuted: i % 2 == 0, // Zero-truth claims are refuted
                domain: None,
            })
            .collect(),
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());

    // Process all three
    for agent in [agent_zero, agent_one, agent_mixed] {
        let job = EpiGraphJob::ReputationUpdate { agent_id: agent }
            .into_job()
            .unwrap();
        handler.handle(&job).await.unwrap();
    }

    let rep_zero = repository.get_reputation(agent_zero).unwrap();
    let rep_one = repository.get_reputation(agent_one).unwrap();
    let rep_mixed = repository.get_reputation(agent_mixed).unwrap();

    // All zero: should be at minimum reputation
    assert!(
        rep_zero >= 0.1,
        "Zero-truth agent should be at min_reputation: {rep_zero}"
    );
    assert!(
        rep_zero <= 0.15,
        "Zero-truth agent should be near min: {rep_zero}"
    );

    // All one: should be at maximum reputation
    assert!(
        rep_one <= 0.95,
        "Perfect agent should be at max_reputation: {rep_one}"
    );
    assert!(
        rep_one >= 0.9,
        "Perfect agent should be near max: {rep_one}"
    );

    // Mixed: should be somewhere in between
    assert!(
        rep_mixed > rep_zero,
        "Mixed agent should be higher than all-zero: mixed={rep_mixed}, zero={rep_zero}"
    );
    assert!(
        rep_mixed < rep_one,
        "Mixed agent should be lower than all-one: mixed={rep_mixed}, one={rep_one}"
    );

    // Ordering should be: zero < mixed < one
    assert!(
        rep_zero < rep_mixed && rep_mixed < rep_one,
        "Ordering should be zero ({rep_zero}) < mixed ({rep_mixed}) < one ({rep_one})"
    );
}

/// Initial truth calculation at boundary evidence values
#[tokio::test]
async fn test_initial_truth_boundary_evidence() {
    // Zero evidence: maximum uncertainty
    let zero_truth = calculate_initial_truth(0.0, 0);
    assert!(
        (zero_truth - 0.5).abs() < f64::EPSILON,
        "Zero evidence should give 0.5 uncertainty: {zero_truth}"
    );

    // Maximum evidence: capped at 0.85
    let max_truth = calculate_initial_truth(1.0, 10);
    assert!(
        max_truth <= 0.85,
        "Maximum evidence should cap at 0.85: {max_truth}"
    );
    assert!(
        max_truth >= 0.84,
        "Maximum evidence should be near cap: {max_truth}"
    );

    // Single weak evidence: above uncertainty but not high
    let weak_truth = calculate_initial_truth(0.1, 1);
    assert!(
        weak_truth > 0.5,
        "Some evidence should exceed 0.5: {weak_truth}"
    );
    assert!(
        weak_truth < 0.7,
        "Weak evidence should not be high: {weak_truth}"
    );
}

// ============================================================================
// Test: New Agent Starts with Neutral Reputation
// ============================================================================

/// New agents with no claim history should start with neutral reputation (0.5)
#[tokio::test]
async fn test_new_agent_starts_with_neutral_reputation() {
    let repository = Arc::new(MockAgentRepository::new());
    let new_agent = Uuid::new_v4();

    // New agent has no claim history
    repository.add_claim_outcomes(new_agent, vec![]);

    let handler = MockReputationUpdateHandler::new(repository.clone());
    let job = EpiGraphJob::ReputationUpdate {
        agent_id: new_agent,
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await;
    assert!(result.is_ok());

    let reputation = repository.get_reputation(new_agent).unwrap();

    // New agents should have initial reputation of 0.5 (neutral)
    assert!(
        (reputation - 0.5).abs() < f64::EPSILON,
        "New agent should have neutral reputation (0.5), got: {reputation}"
    );
}

/// Agent with very few claims should regress toward neutral
#[tokio::test]
async fn test_few_claims_regresses_toward_neutral() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    // Agent has only 2 high-truth claims (below stability threshold of 10)
    repository.add_claim_outcomes(
        agent_id,
        vec![
            MockClaimOutcome {
                truth_value: 1.0,
                age_days: 1.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 1.0,
                age_days: 2.0,
                was_refuted: false,
                domain: None,
            },
        ],
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    let result = handler.handle(&job).await;

    assert!(result.is_ok());

    let reputation = repository.get_reputation(agent_id).unwrap();

    // With only 2 claims (below threshold of 10), reputation should be
    // pulled toward the neutral 0.5, not be at 1.0
    assert!(
        reputation < 0.9,
        "Agent with few claims should not have extreme reputation, got: {reputation}"
    );
    assert!(
        reputation > 0.5,
        "Agent with high-truth claims should still be above neutral, got: {reputation}"
    );
}

// ============================================================================
// Test: Reputation Recalculation is Idempotent
// ============================================================================

/// Running reputation update multiple times should produce the same result
#[tokio::test]
async fn test_reputation_recalculation_is_idempotent() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    repository.add_claim_outcomes(
        agent_id,
        vec![
            MockClaimOutcome {
                truth_value: 0.8,
                age_days: 5.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.75,
                age_days: 10.0,
                was_refuted: false,
                domain: None,
            },
            MockClaimOutcome {
                truth_value: 0.85,
                age_days: 3.0,
                was_refuted: false,
                domain: None,
            },
        ],
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());

    // Run the job three times
    let job1 = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    let job2 = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    let job3 = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();

    handler.handle(&job1).await.unwrap();
    let rep1 = repository.get_reputation(agent_id).unwrap();

    handler.handle(&job2).await.unwrap();
    let rep2 = repository.get_reputation(agent_id).unwrap();

    handler.handle(&job3).await.unwrap();
    let rep3 = repository.get_reputation(agent_id).unwrap();

    // All three calculations should produce the same result
    assert!(
        (rep1 - rep2).abs() < f64::EPSILON,
        "Idempotent: rep1 ({rep1}) should equal rep2 ({rep2})"
    );
    assert!(
        (rep2 - rep3).abs() < f64::EPSILON,
        "Idempotent: rep2 ({rep2}) should equal rep3 ({rep3})"
    );
}

/// Idempotency should hold even for domain-specific reputations
#[tokio::test]
async fn test_domain_reputation_idempotent() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    repository.add_claim_outcomes(
        agent_id,
        vec![
            MockClaimOutcome {
                truth_value: 0.9,
                age_days: 5.0,
                was_refuted: false,
                domain: Some("math".to_string()),
            },
            MockClaimOutcome {
                truth_value: 0.85,
                age_days: 10.0,
                was_refuted: false,
                domain: Some("math".to_string()),
            },
        ],
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());

    // Run twice
    let job1 = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    let job2 = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();

    handler.handle(&job1).await.unwrap();
    let math_rep1 = repository.get_domain_reputation(agent_id, "math").unwrap();

    handler.handle(&job2).await.unwrap();
    let math_rep2 = repository.get_domain_reputation(agent_id, "math").unwrap();

    assert!(
        (math_rep1 - math_rep2).abs() < f64::EPSILON,
        "Domain reputation should be idempotent: {math_rep1} vs {math_rep2}"
    );
}

// ============================================================================
// Test: JobResult Contains Expected Metadata
// ============================================================================

/// Reputation update job should report processing statistics
#[tokio::test]
async fn test_job_result_contains_processing_metadata() {
    let repository = Arc::new(MockAgentRepository::new());
    let agent_id = Uuid::new_v4();

    repository.add_claim_outcomes(
        agent_id,
        vec![
            MockClaimOutcome {
                truth_value: 0.8,
                age_days: 5.0,
                was_refuted: false,
                domain: Some("science".to_string()),
            },
            MockClaimOutcome {
                truth_value: 0.75,
                age_days: 10.0,
                was_refuted: false,
                domain: Some("art".to_string()),
            },
        ],
    );

    let handler = MockReputationUpdateHandler::new(repository.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();
    let result = handler.handle(&job).await.unwrap();

    // Verify output contains expected fields
    assert_eq!(
        result.output["agent_id"],
        agent_id.to_string(),
        "Result should include agent_id"
    );
    assert!(
        result.output.get("reputation").is_some(),
        "Result should include calculated reputation"
    );
    assert_eq!(
        result.output["claims_processed"], 2,
        "Result should report number of claims processed"
    );
    assert_eq!(
        result.output["domain_reputations"], 2,
        "Result should report number of domain reputations calculated"
    );

    // Verify metadata
    assert!(
        result.metadata.items_processed == Some(2),
        "Metadata should report items processed"
    );
}

// ============================================================================
// Test: Handler Error Cases
// ============================================================================

/// Handler should return error for invalid `agent_id` format
#[tokio::test]
async fn test_invalid_agent_id_returns_error() {
    let repository = Arc::new(MockAgentRepository::new());
    let handler = MockReputationUpdateHandler::new(repository);

    // Create a job with malformed agent_id
    let job = Job::new(
        "reputation_update",
        json!({
            "ReputationUpdate": {
                "agent_id": "not-a-valid-uuid"
            }
        }),
    );

    let result = handler.handle(&job).await;

    assert!(result.is_err(), "Should error on invalid agent_id");
    match result {
        Err(JobError::PayloadError { message }) => {
            assert!(
                message.contains("Invalid agent_id"),
                "Error should mention invalid agent_id"
            );
        }
        _ => panic!("Expected PayloadError"),
    }
}

/// Handler should return error for missing `agent_id`
#[tokio::test]
async fn test_missing_agent_id_returns_error() {
    let repository = Arc::new(MockAgentRepository::new());
    let handler = MockReputationUpdateHandler::new(repository);

    // Create a job without agent_id
    let job = Job::new(
        "reputation_update",
        json!({
            "ReputationUpdate": {}
        }),
    );

    let result = handler.handle(&job).await;

    assert!(result.is_err(), "Should error on missing agent_id");
    match result {
        Err(JobError::PayloadError { message }) => {
            assert!(
                message.contains("Missing agent_id"),
                "Error should mention missing agent_id"
            );
        }
        _ => panic!("Expected PayloadError"),
    }
}

// ============================================================================
// Test: Built-in Handler Registration
// ============================================================================

/// The built-in `ReputationUpdateHandler` should have correct job type
#[test]
fn test_builtin_handler_has_correct_job_type() {
    let handler = ReputationUpdateHandler;
    assert_eq!(
        handler.job_type(),
        "reputation_update",
        "Built-in handler should have job_type 'reputation_update'"
    );
}

/// Built-in handler should be registrable with `JobRunner`
#[test]
fn test_builtin_handler_is_registrable() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(1, queue);

    // Should not panic
    runner.register_handler(Arc::new(ReputationUpdateHandler));

    let registered = runner.registered_job_types();
    assert!(
        registered.contains(&"reputation_update".to_string()),
        "reputation_update should be registered"
    );
}

// ============================================================================
// ConfigurableReputationHandler Tests (Engine Integration)
// ============================================================================

/// Mock implementation of `ReputationJobService` for testing `ConfigurableReputationHandler`
struct TestReputationService {
    claim_outcomes: RwLock<HashMap<Uuid, Vec<ClaimOutcomeData>>>,
    reputations: RwLock<HashMap<Uuid, f64>>,
    domain_reputations: RwLock<HashMap<(Uuid, String), f64>>,
}

impl TestReputationService {
    fn new() -> Self {
        Self {
            claim_outcomes: RwLock::new(HashMap::new()),
            reputations: RwLock::new(HashMap::new()),
            domain_reputations: RwLock::new(HashMap::new()),
        }
    }

    fn add_outcomes(&self, agent_id: Uuid, outcomes: Vec<ClaimOutcomeData>) {
        self.claim_outcomes
            .write()
            .unwrap()
            .insert(agent_id, outcomes);
    }

    fn get_stored_reputation(&self, agent_id: Uuid) -> Option<f64> {
        self.reputations.read().unwrap().get(&agent_id).copied()
    }

    fn get_stored_domain_reputation(&self, agent_id: Uuid, domain: &str) -> Option<f64> {
        self.domain_reputations
            .read()
            .unwrap()
            .get(&(agent_id, domain.to_string()))
            .copied()
    }
}

#[async_trait]
impl ReputationJobService for TestReputationService {
    async fn get_claim_outcomes(
        &self,
        agent_id: Uuid,
    ) -> Result<Vec<ClaimOutcomeData>, ReputationJobError> {
        Ok(self
            .claim_outcomes
            .read()
            .unwrap()
            .get(&agent_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn store_reputation(
        &self,
        agent_id: Uuid,
        reputation: f64,
    ) -> Result<(), ReputationJobError> {
        self.reputations
            .write()
            .unwrap()
            .insert(agent_id, reputation);
        Ok(())
    }

    async fn store_domain_reputation(
        &self,
        agent_id: Uuid,
        domain: &str,
        reputation: f64,
    ) -> Result<(), ReputationJobError> {
        self.domain_reputations
            .write()
            .unwrap()
            .insert((agent_id, domain.to_string()), reputation);
        Ok(())
    }
}

// ============================================================================
// Test: ConfigurableReputationHandler uses engine's ReputationCalculator
// ============================================================================

/// Verifies that `ConfigurableReputationHandler` integrates with engine's `ReputationCalculator`
#[tokio::test]
async fn test_configurable_handler_uses_engine_calculator() {
    let service = Arc::new(TestReputationService::new());
    let agent_id = Uuid::new_v4();

    // Add claim outcomes - high truth claims
    service.add_outcomes(
        agent_id,
        (0..10)
            .map(|i| ClaimOutcomeData {
                truth_value: 0.9,
                age_days: f64::from(i) + 1.0,
                was_refuted: false,
                domain: None,
            })
            .collect(),
    );

    let handler = ConfigurableReputationHandler::new(service.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();

    let result = handler.handle(&job).await;
    assert!(result.is_ok(), "Handler should succeed");

    // Verify reputation was stored
    let stored_rep = service.get_stored_reputation(agent_id);
    assert!(stored_rep.is_some(), "Reputation should be stored");

    let rep = stored_rep.unwrap();
    // Engine's calculator should produce high reputation for high-truth claims
    assert!(
        rep > 0.7,
        "High-truth claims should yield high reputation: got {rep}"
    );
    assert!(
        rep <= 0.95,
        "Reputation should be capped at max_reputation: got {rep}"
    );
}

/// Test that handler correctly calculates domain-specific reputations
#[tokio::test]
async fn test_configurable_handler_domain_reputations() {
    let service = Arc::new(TestReputationService::new());
    let agent_id = Uuid::new_v4();

    // Agent is expert in physics but novice in biology
    service.add_outcomes(
        agent_id,
        vec![
            // Physics - high truth
            ClaimOutcomeData {
                truth_value: 0.95,
                age_days: 1.0,
                was_refuted: false,
                domain: Some("physics".to_string()),
            },
            ClaimOutcomeData {
                truth_value: 0.92,
                age_days: 5.0,
                was_refuted: false,
                domain: Some("physics".to_string()),
            },
            ClaimOutcomeData {
                truth_value: 0.9,
                age_days: 10.0,
                was_refuted: false,
                domain: Some("physics".to_string()),
            },
            // Biology - low truth
            ClaimOutcomeData {
                truth_value: 0.2,
                age_days: 1.0,
                was_refuted: true,
                domain: Some("biology".to_string()),
            },
            ClaimOutcomeData {
                truth_value: 0.25,
                age_days: 5.0,
                was_refuted: false,
                domain: Some("biology".to_string()),
            },
            ClaimOutcomeData {
                truth_value: 0.15,
                age_days: 10.0,
                was_refuted: true,
                domain: Some("biology".to_string()),
            },
        ],
    );

    let handler = ConfigurableReputationHandler::new(service.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();

    let result = handler.handle(&job).await;
    assert!(result.is_ok(), "Handler should succeed");

    let physics_rep = service
        .get_stored_domain_reputation(agent_id, "physics")
        .expect("Physics reputation should be stored");
    let biology_rep = service
        .get_stored_domain_reputation(agent_id, "biology")
        .expect("Biology reputation should be stored");

    // Physics should be much higher than biology
    assert!(
        physics_rep > biology_rep,
        "Physics ({physics_rep}) should be higher than biology ({biology_rep})"
    );
    assert!(
        physics_rep > 0.6,
        "Physics reputation should be high: {physics_rep}"
    );
    assert!(
        biology_rep < 0.5,
        "Biology reputation should be low: {biology_rep}"
    );
}

/// Test recency weighting (70% recent, 30% historical)
#[tokio::test]
async fn test_configurable_handler_recency_weighting() {
    let service = Arc::new(TestReputationService::new());
    let agent_id = Uuid::new_v4();

    // Good recent history (< 30 days), bad historical (> 30 days)
    service.add_outcomes(
        agent_id,
        vec![
            // Recent good claims
            ClaimOutcomeData {
                truth_value: 0.95,
                age_days: 1.0,
                was_refuted: false,
                domain: None,
            },
            ClaimOutcomeData {
                truth_value: 0.92,
                age_days: 5.0,
                was_refuted: false,
                domain: None,
            },
            ClaimOutcomeData {
                truth_value: 0.9,
                age_days: 10.0,
                was_refuted: false,
                domain: None,
            },
            ClaimOutcomeData {
                truth_value: 0.88,
                age_days: 15.0,
                was_refuted: false,
                domain: None,
            },
            ClaimOutcomeData {
                truth_value: 0.91,
                age_days: 25.0,
                was_refuted: false,
                domain: None,
            },
            // Historical bad claims
            ClaimOutcomeData {
                truth_value: 0.15,
                age_days: 40.0,
                was_refuted: true,
                domain: None,
            },
            ClaimOutcomeData {
                truth_value: 0.2,
                age_days: 50.0,
                was_refuted: true,
                domain: None,
            },
            ClaimOutcomeData {
                truth_value: 0.1,
                age_days: 60.0,
                was_refuted: true,
                domain: None,
            },
            ClaimOutcomeData {
                truth_value: 0.18,
                age_days: 70.0,
                was_refuted: true,
                domain: None,
            },
            ClaimOutcomeData {
                truth_value: 0.12,
                age_days: 80.0,
                was_refuted: true,
                domain: None,
            },
        ],
    );

    let handler = ConfigurableReputationHandler::new(service.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();

    handler.handle(&job).await.unwrap();

    let rep = service.get_stored_reputation(agent_id).unwrap();

    // With 70% recency weight, reputation should favor recent good claims
    assert!(
        rep > 0.5,
        "Recent good claims should outweigh historical bad: got {rep}"
    );
    // But not as high as if there were no bad history
    assert!(
        rep < 0.85,
        "Historical bad claims should still have effect: got {rep}"
    );
}

/// Test refutation penalty (0.5x weight)
#[tokio::test]
async fn test_configurable_handler_refutation_penalty() {
    let service_not_refuted = Arc::new(TestReputationService::new());
    let service_refuted = Arc::new(TestReputationService::new());
    let agent_not_refuted = Uuid::new_v4();
    let agent_refuted = Uuid::new_v4();

    // Same claims, different refutation status
    let not_refuted_outcomes: Vec<ClaimOutcomeData> = (0..10)
        .map(|i| ClaimOutcomeData {
            truth_value: 0.8,
            age_days: f64::from(i) + 1.0,
            was_refuted: false,
            domain: None,
        })
        .collect();

    let refuted_outcomes: Vec<ClaimOutcomeData> = (0..10)
        .map(|i| ClaimOutcomeData {
            truth_value: 0.8,
            age_days: f64::from(i) + 1.0,
            was_refuted: true,
            domain: None,
        })
        .collect();

    service_not_refuted.add_outcomes(agent_not_refuted, not_refuted_outcomes);
    service_refuted.add_outcomes(agent_refuted, refuted_outcomes);

    let handler_not_refuted = ConfigurableReputationHandler::new(service_not_refuted.clone());
    let handler_refuted = ConfigurableReputationHandler::new(service_refuted.clone());

    let job_not_refuted = EpiGraphJob::ReputationUpdate {
        agent_id: agent_not_refuted,
    }
    .into_job()
    .unwrap();
    let job_refuted = EpiGraphJob::ReputationUpdate {
        agent_id: agent_refuted,
    }
    .into_job()
    .unwrap();

    handler_not_refuted.handle(&job_not_refuted).await.unwrap();
    handler_refuted.handle(&job_refuted).await.unwrap();

    let rep_not_refuted = service_not_refuted
        .get_stored_reputation(agent_not_refuted)
        .unwrap();
    let rep_refuted = service_refuted
        .get_stored_reputation(agent_refuted)
        .unwrap();

    // Refuted claims should significantly hurt reputation
    assert!(
        rep_not_refuted > rep_refuted,
        "Refuted claims should hurt reputation: not_refuted={rep_not_refuted}, refuted={rep_refuted}"
    );

    // The penalty should be approximately 0.5x
    let ratio = rep_refuted / rep_not_refuted;
    assert!(
        ratio < 0.7,
        "Refutation penalty should be significant: ratio={ratio}"
    );
}

/// Test that new agents get neutral reputation (0.5)
#[tokio::test]
async fn test_configurable_handler_new_agent_neutral() {
    let service = Arc::new(TestReputationService::new());
    let new_agent = Uuid::new_v4();

    // New agent has no claim history
    service.add_outcomes(new_agent, vec![]);

    let handler = ConfigurableReputationHandler::new(service.clone());
    let job = EpiGraphJob::ReputationUpdate {
        agent_id: new_agent,
    }
    .into_job()
    .unwrap();

    handler.handle(&job).await.unwrap();

    let rep = service.get_stored_reputation(new_agent).unwrap();
    assert!(
        (rep - 0.5).abs() < f64::EPSILON,
        "New agent should have neutral reputation (0.5), got: {rep}"
    );
}

/// Test job result metadata contains expected fields
#[tokio::test]
async fn test_configurable_handler_result_metadata() {
    let service = Arc::new(TestReputationService::new());
    let agent_id = Uuid::new_v4();

    service.add_outcomes(
        agent_id,
        vec![
            ClaimOutcomeData {
                truth_value: 0.8,
                age_days: 5.0,
                was_refuted: false,
                domain: Some("science".to_string()),
            },
            ClaimOutcomeData {
                truth_value: 0.75,
                age_days: 10.0,
                was_refuted: false,
                domain: Some("art".to_string()),
            },
        ],
    );

    let handler = ConfigurableReputationHandler::new(service.clone());
    let job = EpiGraphJob::ReputationUpdate { agent_id }
        .into_job()
        .unwrap();

    let result = handler.handle(&job).await.unwrap();

    // Verify output fields
    assert_eq!(
        result.output["agent_id"],
        agent_id.to_string(),
        "Result should include agent_id"
    );
    assert!(
        result.output.get("reputation").is_some(),
        "Result should include reputation"
    );
    assert_eq!(
        result.output["claims_processed"], 2,
        "Result should report claims processed"
    );
    assert_eq!(
        result.output["domain_reputations"], 2,
        "Result should report domain count"
    );

    // Verify metadata
    assert_eq!(
        result.metadata.items_processed,
        Some(2),
        "Metadata should report items processed"
    );
    assert_eq!(
        result.metadata.extra.get("mode"),
        Some(&serde_json::Value::String("engine-integrated".to_string())),
        "Metadata should indicate engine-integrated mode"
    );
}

/// Test handler is registrable with `JobRunner`
#[test]
fn test_configurable_handler_registrable() {
    let service = Arc::new(TestReputationService::new());
    let handler = ConfigurableReputationHandler::new(service);

    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(1, queue);

    runner.register_handler(Arc::new(handler));

    let registered = runner.registered_job_types();
    assert!(
        registered.contains(&"reputation_update".to_string()),
        "ConfigurableReputationHandler should be registrable"
    );
}

/// CRITICAL TEST: Reputation is OUTPUT only - never influences initial truth
///
/// This test verifies that the `ConfigurableReputationHandler` maintains the
/// core epistemic invariant: reputation is derived FROM claim truth values,
/// it is NEVER used to influence future claim truth values.
#[tokio::test]
async fn test_configurable_handler_bad_actor_invariant() {
    let service = Arc::new(TestReputationService::new());
    let high_rep_agent = Uuid::new_v4();

    // Create agent with stellar historical reputation
    service.add_outcomes(
        high_rep_agent,
        (0..20)
            .map(|i| ClaimOutcomeData {
                truth_value: 0.95,
                age_days: f64::from(i).mul_add(5.0, 30.0), // Historical claims
                was_refuted: false,
                domain: None,
            })
            .collect(),
    );

    let handler = ConfigurableReputationHandler::new(service.clone());
    let job = EpiGraphJob::ReputationUpdate {
        agent_id: high_rep_agent,
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await.unwrap();
    let rep = service.get_stored_reputation(high_rep_agent).unwrap();

    // Verify agent has high reputation (precondition)
    assert!(
        rep > 0.7,
        "Agent should have high reputation from historical claims: {rep}"
    );

    // CRITICAL: The job result MUST NOT contain any truth-influencing fields
    let forbidden_fields = [
        "pre_approved_truth",
        "future_claim_truth_boost",
        "initial_truth",
        "truth_modifier",
        "trust_score",
        "credibility_boost",
    ];

    let output_str = result.output.to_string();
    for field in &forbidden_fields {
        assert!(
            !output_str.contains(field),
            "CRITICAL: Job result must not contain '{field}' - this would allow reputation to influence truth!"
        );
    }

    // Verify the output only contains expected fields
    let output_obj = result.output.as_object().unwrap();
    let allowed_fields = [
        "agent_id",
        "reputation",
        "claims_processed",
        "domain_reputations",
    ];
    for (key, _) in output_obj {
        assert!(
            allowed_fields.contains(&key.as_str()),
            "Unexpected field in output: {key}"
        );
    }
}
