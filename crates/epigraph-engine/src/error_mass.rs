//! Error-derived CDST mass function builder.
//!
//! Converts experimental error budgets (random, systematic, scope) into
//! properly normalized mass functions on the hypothesis_assessment frame.
//! See spec: docs/superpowers/specs/2026-03-17-experimental-epistemic-loop-design.md

use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use std::collections::{BTreeMap, BTreeSet};

/// Scope limitation types with their ignorance weights.
#[derive(Debug, Clone)]
pub enum ScopeLimitation {
    SingleTemperaturePoint,
    SingleMaterialSystem,
    NonStandardEnvironment,
    SmallSampleSize,
    ProxyMeasurement,
    Custom(f64),
}

impl ScopeLimitation {
    fn weight(&self) -> f64 {
        match self {
            Self::SingleTemperaturePoint => 0.05,
            Self::SingleMaterialSystem => 0.05,
            Self::NonStandardEnvironment => 0.03,
            Self::SmallSampleSize => 0.05,
            Self::ProxyMeasurement => 0.08,
            Self::Custom(w) => *w,
        }
    }
}

/// Direction of evidence relative to the hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceDirection {
    Supports,
    Refutes,
}

/// Input parameters for building an error-derived mass function.
#[derive(Debug, Clone)]
pub struct ErrorBudget {
    pub random_error: f64,
    pub systematic_error: f64,
    pub scope_limitations: Vec<ScopeLimitation>,
    pub effect_size: f64,
    pub direction: EvidenceDirection,
}

/// Output: the computed mass function components (for inspection/storage).
#[derive(Debug, Clone)]
pub struct ErrorMassResult {
    pub mass_function: MassFunction,
    pub precision_ratio: f64,
    pub evidence_strength: f64,
    pub systematic_fraction: f64,
    pub m_open_world: f64,
    pub m_evidence: f64,
    /// Frame ignorance: m_systematic + m_theta (mass on Theta from both sources)
    pub m_frame_ignorance: f64,
}

/// Build a CDST mass function from an experimental error budget.
///
/// The hypothesis_assessment frame is binary: ["supported", "unsupported"]
/// where index 0 = supported, index 1 = unsupported.
///
/// # Errors
/// Returns error if frame construction fails (shouldn't happen for valid input).
pub fn build_error_mass(budget: &ErrorBudget) -> Result<ErrorMassResult, String> {
    // Input validation
    if !budget.random_error.is_finite() || budget.random_error < 0.0 {
        return Err(format!(
            "random_error must be finite and non-negative, got {}",
            budget.random_error
        ));
    }
    if !budget.systematic_error.is_finite() || budget.systematic_error < 0.0 {
        return Err(format!(
            "systematic_error must be finite and non-negative, got {}",
            budget.systematic_error
        ));
    }
    if !budget.effect_size.is_finite() || budget.effect_size < 0.0 {
        return Err(format!(
            "effect_size must be finite and non-negative, got {}",
            budget.effect_size
        ));
    }

    let frame = FrameOfDiscernment::new(
        "hypothesis_assessment",
        vec!["supported".into(), "unsupported".into()],
    )
    .map_err(|e| format!("Frame creation failed: {e}"))?;

    // Step 1: Precision ratio
    let total_uncertainty = (budget.random_error.powi(2) + budget.systematic_error.powi(2))
        .sqrt()
        .max(1e-10);
    let precision_ratio = budget.effect_size / total_uncertainty;

    // Step 2: Evidence strength (CDF-derived)
    let evidence_strength = 1.0 - (-0.5 * precision_ratio.powi(2)).exp();

    // Step 3: Open-world ignorance from scope
    let scope_penalty: f64 = budget.scope_limitations.iter().map(|s| s.weight()).sum();
    let m_open_world = scope_penalty.min(0.30);

    // Step 4: Systematic fraction
    let systematic_fraction = budget.systematic_error.powi(2) / total_uncertainty.powi(2);

    // Step 5: Assemble and normalize
    let available = 1.0 - m_open_world;
    let m_evidence = available * evidence_strength * (1.0 - systematic_fraction);
    let m_systematic = available * evidence_strength * systematic_fraction;
    let m_theta = available * (1.0 - evidence_strength);

    // Build mass function
    let evidence_idx = match budget.direction {
        EvidenceDirection::Supports => 0usize, // "supported"
        EvidenceDirection::Refutes => 1usize,  // "unsupported"
    };

    let mut masses = BTreeMap::new();

    if m_evidence > 1e-12 {
        masses.insert(
            FocalElement::positive(BTreeSet::from([evidence_idx])),
            m_evidence,
        );
    }

    let m_frame_ignorance = m_systematic + m_theta;
    if m_frame_ignorance > 1e-12 {
        masses.insert(FocalElement::theta(&frame), m_frame_ignorance);
    }

    if m_open_world > 1e-12 {
        masses.insert(FocalElement::vacuous(), m_open_world);
    }

    // Handle edge case: all masses rounded to zero
    if masses.is_empty() {
        masses.insert(FocalElement::theta(&frame), 1.0);
    }

    // Renormalize to handle floating-point drift
    let sum: f64 = masses.values().sum();
    if (sum - 1.0).abs() > 1e-12 {
        for v in masses.values_mut() {
            *v /= sum;
        }
    }

    let mass_function = MassFunction::from_raw(frame, masses);

    Ok(ErrorMassResult {
        mass_function,
        precision_ratio,
        evidence_strength,
        systematic_fraction,
        m_open_world,
        m_evidence,
        m_frame_ignorance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_masses_sum_to_one(result: &ErrorMassResult) {
        let sum: f64 = result.mass_function.masses().values().sum();
        assert!(
            (sum - 1.0).abs() < 1e-9,
            "Masses must sum to 1.0, got {sum}"
        );
    }

    #[test]
    fn strong_evidence_high_precision() {
        let budget = ErrorBudget {
            random_error: 0.05,
            systematic_error: 0.0,
            scope_limitations: vec![],
            effect_size: 0.10,
            direction: EvidenceDirection::Supports,
        };
        let result = build_error_mass(&budget).unwrap();
        assert_masses_sum_to_one(&result);
        assert!(result.precision_ratio > 1.9 && result.precision_ratio < 2.1);
        assert!(result.evidence_strength > 0.80);
        assert!(result.m_evidence > 0.80);
        assert!(result.m_open_world.abs() < 1e-10);
    }

    #[test]
    fn weak_evidence_low_precision() {
        let budget = ErrorBudget {
            random_error: 1.0,
            systematic_error: 0.0,
            scope_limitations: vec![],
            effect_size: 0.5,
            direction: EvidenceDirection::Supports,
        };
        let result = build_error_mass(&budget).unwrap();
        assert_masses_sum_to_one(&result);
        assert!(result.precision_ratio < 1.0);
        assert!(result.evidence_strength < 0.40);
    }

    #[test]
    fn refuting_evidence_goes_to_unsupported() {
        let budget = ErrorBudget {
            random_error: 0.05,
            systematic_error: 0.0,
            scope_limitations: vec![],
            effect_size: 0.10,
            direction: EvidenceDirection::Refutes,
        };
        let result = build_error_mass(&budget).unwrap();
        assert_masses_sum_to_one(&result);
        let fe_unsupported = FocalElement::positive(BTreeSet::from([1]));
        let m_unsupported = result.mass_function.mass_of(&fe_unsupported);
        assert!(m_unsupported > 0.80);
    }

    #[test]
    fn scope_limitations_add_open_world_ignorance() {
        let budget = ErrorBudget {
            random_error: 0.05,
            systematic_error: 0.0,
            scope_limitations: vec![
                ScopeLimitation::SingleTemperaturePoint,
                ScopeLimitation::SingleMaterialSystem,
                ScopeLimitation::NonStandardEnvironment,
            ],
            effect_size: 0.10,
            direction: EvidenceDirection::Supports,
        };
        let result = build_error_mass(&budget).unwrap();
        assert_masses_sum_to_one(&result);
        assert!((result.m_open_world - 0.13).abs() < 1e-10);
        assert!(result.m_evidence < 0.80);
    }

    #[test]
    fn scope_penalty_capped_at_030() {
        let budget = ErrorBudget {
            random_error: 0.05,
            systematic_error: 0.0,
            scope_limitations: vec![
                ScopeLimitation::Custom(0.15),
                ScopeLimitation::Custom(0.15),
                ScopeLimitation::Custom(0.15),
            ],
            effect_size: 0.10,
            direction: EvidenceDirection::Supports,
        };
        let result = build_error_mass(&budget).unwrap();
        assert_masses_sum_to_one(&result);
        assert!((result.m_open_world - 0.30).abs() < 1e-10);
    }

    #[test]
    fn systematic_error_increases_theta() {
        let budget_no_sys = ErrorBudget {
            random_error: 0.05,
            systematic_error: 0.0,
            scope_limitations: vec![],
            effect_size: 0.10,
            direction: EvidenceDirection::Supports,
        };
        let budget_with_sys = ErrorBudget {
            random_error: 0.05,
            systematic_error: 0.05,
            scope_limitations: vec![],
            effect_size: 0.10,
            direction: EvidenceDirection::Supports,
        };
        let r1 = build_error_mass(&budget_no_sys).unwrap();
        let r2 = build_error_mass(&budget_with_sys).unwrap();
        assert!(r2.m_evidence < r1.m_evidence);
        assert!(r2.m_frame_ignorance > r1.m_frame_ignorance);
    }

    #[test]
    fn zero_effect_size_yields_zero_evidence() {
        let budget = ErrorBudget {
            random_error: 0.05,
            systematic_error: 0.0,
            scope_limitations: vec![],
            effect_size: 0.0,
            direction: EvidenceDirection::Supports,
        };
        let result = build_error_mass(&budget).unwrap();
        assert_masses_sum_to_one(&result);
        assert!(result.precision_ratio.abs() < 1e-10);
        assert!(result.evidence_strength.abs() < 1e-10);
        assert!(result.m_evidence.abs() < 1e-10);
    }

    #[test]
    fn zero_error_uses_epsilon_guard() {
        let budget = ErrorBudget {
            random_error: 0.0,
            systematic_error: 0.0,
            scope_limitations: vec![],
            effect_size: 1.0,
            direction: EvidenceDirection::Supports,
        };
        let result = build_error_mass(&budget).unwrap();
        assert_masses_sum_to_one(&result);
        assert!(result.evidence_strength > 0.99);
    }

    #[test]
    fn normalization_algebraic_proof() {
        for &(re, se, es, scope) in &[
            (0.1, 0.05, 0.5, 0.1),
            (0.0, 0.0, 1.0, 0.0),
            (1.0, 1.0, 0.1, 0.3),
            (0.01, 0.5, 10.0, 0.0),
        ] {
            let budget = ErrorBudget {
                random_error: re,
                systematic_error: se,
                scope_limitations: if scope > 0.0 {
                    vec![ScopeLimitation::Custom(scope)]
                } else {
                    vec![]
                },
                effect_size: es,
                direction: EvidenceDirection::Supports,
            };
            let result = build_error_mass(&budget).unwrap();
            assert_masses_sum_to_one(&result);
        }
    }
}
