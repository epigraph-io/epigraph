//! BetP-based CDST claim classifier.
//!
//! Ports the deterministic 7-rule cascade from `scripts/classify_mass_functions.py`
//! to Rust. The cascade classifies a claim as `supported`, `contradicted`, or
//! `not_enough_info` based on pignistic (BetP) probabilities and conflict mass.
//!
//! # Calibrated Thresholds
//!
//! Default values match the SciFact-calibrated constants in `calibration.toml`
//! (0.948 F1). Rule 4 is a dead branch with default thresholds but is preserved
//! for Python parity.

use std::fmt;

use crate::calibration::ClassifierThresholds;

// ── Classification label ─────────────────────────────────────────────────────

/// Output label of the BetP 7-rule cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdstClassification {
    Supported,
    Contradicted,
    NotEnoughInfo,
}

impl fmt::Display for CdstClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CdstClassification::Supported => f.write_str("supported"),
            CdstClassification::Contradicted => f.write_str("contradicted"),
            CdstClassification::NotEnoughInfo => f.write_str("not_enough_info"),
        }
    }
}

// ── Default thresholds ───────────────────────────────────────────────────────

impl Default for ClassifierThresholds {
    /// SciFact-calibrated defaults — holdout sweep (5-fold CV, 0.940 F1 on held-out test).
    fn default() -> Self {
        Self {
            nei_threshold: 0.85,
            support_threshold: 0.15,
            conflict_threshold: 0.05,
            has_opposing_threshold: 0.1,
        }
    }
}

// ── Classifier ───────────────────────────────────────────────────────────────

/// Classify a claim using the deterministic 7-rule BetP cascade.
///
/// Rules are evaluated top-to-bottom; the first match wins.
///
/// # Parameters
/// - `conflict_k`: combined conflict mass K from DS combination
/// - `theta`: ignorance / open-world mass (Θ component)
/// - `betp_sup`: pignistic probability for the `supported` focal element
/// - `betp_unsup`: pignistic probability for the `contradicted` focal element
/// - `has_opposing`: true when any single evidence item has BetP(unsup) > `has_opposing_threshold`
/// - `thresholds`: decision thresholds (use `ClassifierThresholds::default()` for production)
pub fn classify(
    conflict_k: f64,
    theta: f64,
    betp_sup: f64,
    betp_unsup: f64,
    has_opposing: bool,
    thresholds: &ClassifierThresholds,
) -> CdstClassification {
    let ct = thresholds.conflict_threshold;
    let nt = thresholds.nei_threshold;
    let st = thresholds.support_threshold;

    // Rule 1: high conflict with opposing evidence → contradicted
    if conflict_k >= ct && has_opposing {
        return CdstClassification::Contradicted;
    }

    // Rule 2: BetP unsupported dominates → contradicted
    if betp_unsup > betp_sup && betp_unsup >= st {
        return CdstClassification::Contradicted;
    }

    // Rule 3: high ignorance, low conflict → not_enough_info
    if theta > nt && conflict_k < ct {
        return CdstClassification::NotEnoughInfo;
    }

    // Rule 4: dead branch — nt is 0.87 with default thresholds, never ≤ 0.0.
    // Preserved verbatim for Python parity.
    #[allow(clippy::absurd_extreme_comparisons)]
    if nt <= 0.0 {
        if betp_sup >= betp_unsup {
            return CdstClassification::Supported;
        } else {
            return CdstClassification::Contradicted;
        }
    }

    // Rule 5: strong support, low conflict → supported
    if betp_sup >= st && conflict_k < ct {
        return CdstClassification::Supported;
    }

    // Rule 6: moderate conflict, weak support → contradicted
    if conflict_k >= ct * 0.5 && betp_sup < st {
        return CdstClassification::Contradicted;
    }

    // Rule 7: fallback → not_enough_info
    CdstClassification::NotEnoughInfo
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn thresholds() -> ClassifierThresholds {
        ClassifierThresholds::default()
    }

    /// Rule 1: high conflict + opposing evidence → contradicted
    #[test]
    fn rule1_high_conflict_with_opposing_is_contradicted() {
        let t = thresholds();
        // conflict_k at threshold, has_opposing = true
        let result = classify(t.conflict_threshold, 0.05, 0.5, 0.2, true, &t);
        assert_eq!(result, CdstClassification::Contradicted);
        assert_eq!(result.to_string(), "contradicted");
    }

    /// Rule 2: betp_unsup strictly dominates and meets support threshold → contradicted
    #[test]
    fn rule2_betp_unsup_dominates_is_contradicted() {
        let t = thresholds();
        // No opposing (rule 1 skipped), betp_unsup > betp_sup and betp_unsup >= st
        let result = classify(0.0, 0.05, 0.1, 0.5, false, &t);
        assert_eq!(result, CdstClassification::Contradicted);
    }

    /// Rule 3: high ignorance, low conflict → not_enough_info
    #[test]
    fn rule3_high_ignorance_low_conflict_is_nei() {
        let t = thresholds();
        // theta above nei_threshold, conflict below conflict_threshold
        let result = classify(0.0, t.nei_threshold + 0.01, 0.1, 0.05, false, &t);
        assert_eq!(result, CdstClassification::NotEnoughInfo);
        assert_eq!(result.to_string(), "not_enough_info");
    }

    /// Rule 5: strong support, low conflict → supported
    #[test]
    fn rule5_strong_support_low_conflict_is_supported() {
        let t = thresholds();
        // theta is low (rule 3 skipped), betp_sup meets threshold, conflict is low
        let result = classify(0.0, 0.1, t.support_threshold, 0.1, false, &t);
        assert_eq!(result, CdstClassification::Supported);
        assert_eq!(result.to_string(), "supported");
    }

    /// Rule 6: moderate conflict, weak support → contradicted
    #[test]
    fn rule6_moderate_conflict_weak_support_is_contradicted() {
        let t = thresholds();
        // conflict_k >= ct * 0.5 but < ct (rules 1+3 skipped), betp_sup below threshold
        let conflict_moderate = t.conflict_threshold * 0.6;
        let result = classify(conflict_moderate, 0.1, 0.1, 0.05, false, &t);
        assert_eq!(result, CdstClassification::Contradicted);
    }

    /// Rule 7: default fallback → not_enough_info
    #[test]
    fn rule7_default_fallback_is_nei() {
        let t = thresholds();
        // All thresholds miss: no conflict, moderate theta (below nei), weak betp_sup
        let result = classify(0.0, 0.5, 0.1, 0.05, false, &t);
        assert_eq!(result, CdstClassification::NotEnoughInfo);
    }

    /// Display impl covers all three variants
    #[test]
    fn display_all_variants() {
        assert_eq!(CdstClassification::Supported.to_string(), "supported");
        assert_eq!(CdstClassification::Contradicted.to_string(), "contradicted");
        assert_eq!(
            CdstClassification::NotEnoughInfo.to_string(),
            "not_enough_info"
        );
    }

    /// Default thresholds match holdout-calibrated values
    #[test]
    fn default_thresholds_match_calibration() {
        let t = ClassifierThresholds::default();
        assert_eq!(t.nei_threshold, 0.85);
        assert_eq!(t.support_threshold, 0.15);
        assert_eq!(t.conflict_threshold, 0.05);
        assert_eq!(t.has_opposing_threshold, 0.1);
    }
}
