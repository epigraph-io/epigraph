//! Multi-agent trust framework
//!
//! Computes agent trust from evidence quality and classifies contradictions
//! into resolution categories.
//!
//! # Design Principle (DD-13)
//!
//! Trust is evidence-based: `f(truth_values, contradiction_rate, corroboration_rate)`.
//! NOT reputation-based — avoids circular reasoning where reputation inflates trust.
//!
//! # Conflict Classification (DD-14)
//!
//! Three categories:
//! - `AutoResolvable`: Clear evidence winner (one side has >2x evidence weight)
//! - `NeedsData`: Insufficient evidence on both sides
//! - `NeedsExpert`: Substantial evidence on both sides, requires human judgment

use uuid::Uuid;

/// Trust score for an agent, derived purely from evidence quality.
#[derive(Debug, Clone)]
pub struct AgentTrust {
    pub agent_id: Uuid,
    /// Average truth value of the agent's claims, weighted by evidence count.
    pub mean_truth: f64,
    /// Fraction of agent's claims that have CONTRADICTS edges.
    pub contradiction_rate: f64,
    /// Fraction of agent's claims that have CORROBORATES edges.
    pub corroboration_rate: f64,
    /// Overall trust score in [0, 1].
    pub trust_score: f64,
    /// Number of claims used in computation.
    pub claim_count: usize,
}

/// Classification of a contradiction for resolution routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Clear evidence winner — one side has >2x the evidence weight.
    AutoResolvable {
        winner_claim_id: Uuid,
        loser_claim_id: Uuid,
    },
    /// Insufficient evidence on both sides — gather more data.
    NeedsData {
        claim_a: Uuid,
        claim_b: Uuid,
    },
    /// Substantial evidence on both sides — requires human judgment.
    NeedsExpert {
        claim_a: Uuid,
        claim_b: Uuid,
    },
}

/// Input data for trust computation: one claim's contribution.
#[derive(Debug, Clone)]
pub struct ClaimTrustInput {
    pub claim_id: Uuid,
    pub truth_value: f64,
    pub evidence_count: usize,
    pub contradiction_count: usize,
    pub corroboration_count: usize,
}

/// Input data for conflict classification.
#[derive(Debug, Clone)]
pub struct ConflictInput {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    /// Total evidence weight supporting claim A.
    pub evidence_weight_a: f64,
    /// Total evidence weight supporting claim B.
    pub evidence_weight_b: f64,
    /// Number of distinct evidence sources for A.
    pub evidence_count_a: usize,
    /// Number of distinct evidence sources for B.
    pub evidence_count_b: usize,
}

/// Configuration for trust computation.
#[derive(Debug, Clone)]
pub struct TrustConfig {
    /// Weight for contradiction penalty (higher = more punishing).
    pub contradiction_penalty: f64,
    /// Weight for corroboration bonus.
    pub corroboration_bonus: f64,
    /// Minimum evidence count for auto-resolution.
    pub min_evidence_for_auto: usize,
    /// Ratio threshold for auto-resolution (winner must have this multiple).
    pub auto_resolve_ratio: f64,
    /// Minimum evidence count to qualify as "substantial" (needs_expert).
    pub min_evidence_for_expert: usize,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            contradiction_penalty: 0.3,
            corroboration_bonus: 0.1,
            min_evidence_for_auto: 2,
            auto_resolve_ratio: 2.0,
            min_evidence_for_expert: 3,
        }
    }
}

/// Compute trust score for an agent from their claim history.
///
/// Trust = mean_truth * (1 - contradiction_penalty * contradiction_rate)
///                    * (1 + corroboration_bonus * corroboration_rate)
///
/// Clamped to [0.0, 1.0].
#[must_use]
pub fn compute_agent_trust(claims: &[ClaimTrustInput], config: &TrustConfig) -> AgentTrust {
    let agent_id = claims.first().map_or(Uuid::nil(), |c| c.claim_id);

    if claims.is_empty() {
        return AgentTrust {
            agent_id,
            mean_truth: 0.5,
            contradiction_rate: 0.0,
            corroboration_rate: 0.0,
            trust_score: 0.5,
            claim_count: 0,
        };
    }

    let n = claims.len() as f64;
    let mean_truth = claims.iter().map(|c| c.truth_value).sum::<f64>() / n;

    let contradicted = claims.iter().filter(|c| c.contradiction_count > 0).count() as f64;
    let corroborated = claims.iter().filter(|c| c.corroboration_count > 0).count() as f64;

    let contradiction_rate = contradicted / n;
    let corroboration_rate = corroborated / n;

    let trust_score = (mean_truth
        * (1.0 - config.contradiction_penalty * contradiction_rate)
        * (1.0 + config.corroboration_bonus * corroboration_rate))
    .clamp(0.0, 1.0);

    AgentTrust {
        agent_id,
        mean_truth,
        contradiction_rate,
        corroboration_rate,
        trust_score,
        claim_count: claims.len(),
    }
}

/// Classify a contradiction into a resolution category.
///
/// - Auto-resolvable: one side has ≥2x the evidence weight AND min evidence count met
/// - Needs expert: both sides have substantial evidence (≥min_evidence_for_expert)
/// - Needs data: everything else (insufficient evidence to decide)
#[must_use]
pub fn classify_conflict(input: &ConflictInput, config: &TrustConfig) -> ConflictResolution {
    let (weight_a, weight_b) = (input.evidence_weight_a, input.evidence_weight_b);
    let (count_a, count_b) = (input.evidence_count_a, input.evidence_count_b);

    // Check for auto-resolvable: clear evidence winner
    if count_a >= config.min_evidence_for_auto
        && count_b >= 1
        && weight_a >= weight_b * config.auto_resolve_ratio
    {
        return ConflictResolution::AutoResolvable {
            winner_claim_id: input.claim_a,
            loser_claim_id: input.claim_b,
        };
    }
    if count_b >= config.min_evidence_for_auto
        && count_a >= 1
        && weight_b >= weight_a * config.auto_resolve_ratio
    {
        return ConflictResolution::AutoResolvable {
            winner_claim_id: input.claim_b,
            loser_claim_id: input.claim_a,
        };
    }

    // Check for needs_expert: substantial evidence on both sides
    if count_a >= config.min_evidence_for_expert && count_b >= config.min_evidence_for_expert {
        return ConflictResolution::NeedsExpert {
            claim_a: input.claim_a,
            claim_b: input.claim_b,
        };
    }

    // Default: needs more data
    ConflictResolution::NeedsData {
        claim_a: input.claim_a,
        claim_b: input.claim_b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_claims_return_default_trust() {
        let config = TrustConfig::default();
        let trust = compute_agent_trust(&[], &config);
        assert!((trust.trust_score - 0.5).abs() < f64::EPSILON);
        assert_eq!(trust.claim_count, 0);
    }

    #[test]
    fn high_truth_no_contradictions_gives_high_trust() {
        let config = TrustConfig::default();
        let claims: Vec<ClaimTrustInput> = (0..10)
            .map(|_| ClaimTrustInput {
                claim_id: Uuid::new_v4(),
                truth_value: 0.9,
                evidence_count: 3,
                contradiction_count: 0,
                corroboration_count: 2,
            })
            .collect();
        let trust = compute_agent_trust(&claims, &config);
        assert!(trust.trust_score > 0.8);
        assert!((trust.contradiction_rate).abs() < f64::EPSILON);
    }

    #[test]
    fn contradictions_reduce_trust() {
        let config = TrustConfig::default();
        let no_contradictions: Vec<ClaimTrustInput> = (0..10)
            .map(|_| ClaimTrustInput {
                claim_id: Uuid::new_v4(),
                truth_value: 0.7,
                evidence_count: 2,
                contradiction_count: 0,
                corroboration_count: 0,
            })
            .collect();
        let with_contradictions: Vec<ClaimTrustInput> = (0..10)
            .map(|_| ClaimTrustInput {
                claim_id: Uuid::new_v4(),
                truth_value: 0.7,
                evidence_count: 2,
                contradiction_count: 3,
                corroboration_count: 0,
            })
            .collect();
        let trust_clean = compute_agent_trust(&no_contradictions, &config);
        let trust_dirty = compute_agent_trust(&with_contradictions, &config);
        assert!(trust_clean.trust_score > trust_dirty.trust_score);
    }

    #[test]
    fn auto_resolvable_clear_winner() {
        let config = TrustConfig::default();
        let input = ConflictInput {
            claim_a: Uuid::new_v4(),
            claim_b: Uuid::new_v4(),
            evidence_weight_a: 0.9,
            evidence_weight_b: 0.3,
            evidence_count_a: 5,
            evidence_count_b: 2,
        };
        let result = classify_conflict(&input, &config);
        assert!(matches!(result, ConflictResolution::AutoResolvable { .. }));
        if let ConflictResolution::AutoResolvable { winner_claim_id, .. } = result {
            assert_eq!(winner_claim_id, input.claim_a);
        }
    }

    #[test]
    fn needs_expert_substantial_both_sides() {
        let config = TrustConfig::default();
        let input = ConflictInput {
            claim_a: Uuid::new_v4(),
            claim_b: Uuid::new_v4(),
            evidence_weight_a: 0.7,
            evidence_weight_b: 0.6,
            evidence_count_a: 5,
            evidence_count_b: 4,
        };
        let result = classify_conflict(&input, &config);
        assert!(matches!(result, ConflictResolution::NeedsExpert { .. }));
    }

    #[test]
    fn needs_data_insufficient_evidence() {
        let config = TrustConfig::default();
        let input = ConflictInput {
            claim_a: Uuid::new_v4(),
            claim_b: Uuid::new_v4(),
            evidence_weight_a: 0.5,
            evidence_weight_b: 0.4,
            evidence_count_a: 1,
            evidence_count_b: 1,
        };
        let result = classify_conflict(&input, &config);
        assert!(matches!(result, ConflictResolution::NeedsData { .. }));
    }

    #[test]
    fn trust_score_clamped() {
        let config = TrustConfig {
            corroboration_bonus: 10.0, // Extreme bonus to test clamping
            ..TrustConfig::default()
        };
        let claims = vec![ClaimTrustInput {
            claim_id: Uuid::new_v4(),
            truth_value: 1.0,
            evidence_count: 10,
            contradiction_count: 0,
            corroboration_count: 10,
        }];
        let trust = compute_agent_trust(&claims, &config);
        assert!(trust.trust_score <= 1.0);
    }
}
