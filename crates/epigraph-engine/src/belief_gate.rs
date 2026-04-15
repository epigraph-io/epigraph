//! CDST belief-interval convergence gate for evidence inclusion
//!
//! Inspired by xMemory's uncertainty-adaptive expansion, but using
//! Dempster-Shafer belief intervals instead of LLM token entropy.
//!
//! When assembling evidence for a claim, iteratively include items
//! and stop when the belief interval [Bel, Pl] narrows below a
//! threshold (ignorance = Pl - Bel < threshold).

use serde::{Deserialize, Serialize};

/// Current belief state for a claim
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BeliefState {
    /// Lower bound of belief interval (Bel)
    pub bel: f64,
    /// Upper bound of belief interval (Pl)
    pub pl: f64,
}

impl BeliefState {
    /// Epistemic ignorance: Pl - Bel (width of the belief interval)
    pub fn ignorance(&self) -> f64 {
        (self.pl - self.bel).max(0.0)
    }
}

/// Should we include more evidence given the current belief state?
///
/// Returns true if the belief interval is still wide (ignorance > threshold),
/// meaning more evidence could meaningfully narrow the interval.
pub fn should_include_evidence(current: &BeliefState, ignorance_threshold: f64) -> bool {
    current.ignorance() > ignorance_threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_include_wide_interval() {
        // Wide interval (high ignorance) -- should include more evidence
        let current = BeliefState { bel: 0.2, pl: 0.8 };
        assert!(should_include_evidence(&current, 0.1));
    }

    #[test]
    fn test_should_stop_narrow_interval() {
        // Narrow interval (low ignorance) -- should stop
        let current = BeliefState {
            bel: 0.72,
            pl: 0.78,
        };
        assert!(!should_include_evidence(&current, 0.1));
    }

    #[test]
    fn test_ignorance_calculation() {
        let state = BeliefState { bel: 0.3, pl: 0.9 };
        assert!((state.ignorance() - 0.6).abs() < 1e-6);
    }

    #[test]
    fn test_converged_at_threshold() {
        // Use exact f64 values to avoid floating-point subtraction imprecision.
        // ignorance = pl - bel must be <= threshold to stop.
        let state = BeliefState { bel: 0.4, pl: 0.5 };
        // ignorance = 0.1 exactly (0.5 - 0.4 = 0.1 in f64), threshold = 0.1 -- should stop
        assert!(!should_include_evidence(&state, 0.1));
    }
}
