//! Promotion gate: determines if a hypothesis is ready to move from
//! hypothesis_assessment to research_validity frame.
//!
//! All four criteria must be met:
//! 1. Real evidence exists (experiment with completed analysis)
//! 2. Provenance independence (v1: at least one completed experiment)
//! 3. Belief threshold: Bel({supported}) >= 0.60 OR Bel({unsupported}) >= 0.60
//! 4. Scope is explicit (analysis has non-empty scope_limitations)

/// Inputs gathered from the database for promotion evaluation.
#[derive(Debug, Clone)]
pub struct PromotionInput {
    /// Belief in {supported} from hypothesis_assessment frame
    pub bel_supported: f64,
    /// Belief in {unsupported} from hypothesis_assessment frame
    pub bel_unsupported: f64,
    /// Number of completed experiments with analysis nodes
    pub completed_experiments_with_analysis: usize,
    /// Whether any analysis has non-empty scope_limitations
    pub has_explicit_scope: bool,
}

/// Result of promotion gate evaluation.
#[derive(Debug, Clone)]
pub struct PromotionResult {
    pub ready: bool,
    pub failures: Vec<PromotionFailure>,
}

/// Individual promotion criterion failure.
#[derive(Debug, Clone, PartialEq)]
pub enum PromotionFailure {
    NoRealEvidence,
    InsufficientBelief {
        bel_supported: f64,
        bel_unsupported: f64,
        threshold: f64,
    },
    NoExplicitScope,
}

const PROMOTION_THRESHOLD: f64 = 0.60;

/// The frame a hypothesis is assessed on until it is promoted.
pub const HYPOTHESIS_ASSESSMENT_FRAME: &str = "hypothesis_assessment";

/// The frame a promotion MOVES the hypothesis's latest assessment onto (the
/// source row is retired in the same transaction, backlog 846b808e).
pub const RESEARCH_VALIDITY_FRAME: &str = "research_validity";

/// The `properties.hypothesis_status` a promotion writes.
pub const PROMOTED_STATUS: &str = "promoted";

/// The frame a hypothesis's status reads its belief from, given its
/// `properties.hypothesis_status`: [`RESEARCH_VALIDITY_FRAME`] once it is
/// promoted, since the promotion moved its evidence there, and
/// [`HYPOTHESIS_ASSESSMENT_FRAME`] otherwise. Reading the old frame after a
/// promotion reports zero belief, or another agent's later BBA (backlog
/// 090221d9).
#[must_use]
pub fn status_belief_frame(hypothesis_status: Option<&str>) -> &'static str {
    if hypothesis_status == Some(PROMOTED_STATUS) {
        RESEARCH_VALIDITY_FRAME
    } else {
        HYPOTHESIS_ASSESSMENT_FRAME
    }
}

/// Evaluate whether a hypothesis meets promotion criteria.
pub fn evaluate_promotion(input: &PromotionInput) -> PromotionResult {
    let mut failures = Vec::new();

    // Criterion 1 & 2: Real evidence from completed experiment
    if input.completed_experiments_with_analysis == 0 {
        failures.push(PromotionFailure::NoRealEvidence);
    }

    // Criterion 3: Belief threshold (either direction)
    if input.bel_supported < PROMOTION_THRESHOLD && input.bel_unsupported < PROMOTION_THRESHOLD {
        failures.push(PromotionFailure::InsufficientBelief {
            bel_supported: input.bel_supported,
            bel_unsupported: input.bel_unsupported,
            threshold: PROMOTION_THRESHOLD,
        });
    }

    // Criterion 4: Explicit scope
    if !input.has_explicit_scope {
        failures.push(PromotionFailure::NoExplicitScope);
    }

    PromotionResult {
        ready: failures.is_empty(),
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reads_research_validity_only_once_promoted() {
        assert_eq!(status_belief_frame(Some("promoted")), "research_validity");
        for other in [None, Some("open"), Some("testing"), Some("Promoted")] {
            assert_eq!(
                status_belief_frame(other),
                "hypothesis_assessment",
                "{other:?}"
            );
        }
    }

    #[test]
    fn all_criteria_met_supported() {
        let input = PromotionInput {
            bel_supported: 0.72,
            bel_unsupported: 0.05,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(result.ready);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn all_criteria_met_unsupported() {
        let input = PromotionInput {
            bel_supported: 0.05,
            bel_unsupported: 0.65,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(result.ready);
    }

    #[test]
    fn no_evidence_fails() {
        let input = PromotionInput {
            bel_supported: 0.72,
            bel_unsupported: 0.05,
            completed_experiments_with_analysis: 0,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(!result.ready);
        assert!(result.failures.contains(&PromotionFailure::NoRealEvidence));
    }

    #[test]
    fn insufficient_belief_fails() {
        let input = PromotionInput {
            bel_supported: 0.45,
            bel_unsupported: 0.30,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(!result.ready);
        assert!(result
            .failures
            .iter()
            .any(|f| matches!(f, PromotionFailure::InsufficientBelief { .. })));
    }

    #[test]
    fn no_scope_fails() {
        let input = PromotionInput {
            bel_supported: 0.72,
            bel_unsupported: 0.05,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: false,
        };
        let result = evaluate_promotion(&input);
        assert!(!result.ready);
        assert!(result.failures.contains(&PromotionFailure::NoExplicitScope));
    }

    #[test]
    fn multiple_failures_collected() {
        let input = PromotionInput {
            bel_supported: 0.30,
            bel_unsupported: 0.20,
            completed_experiments_with_analysis: 0,
            has_explicit_scope: false,
        };
        let result = evaluate_promotion(&input);
        assert!(!result.ready);
        assert_eq!(result.failures.len(), 3);
    }

    #[test]
    fn exactly_at_threshold_passes() {
        let input = PromotionInput {
            bel_supported: 0.60,
            bel_unsupported: 0.10,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(result.ready);
    }
}
