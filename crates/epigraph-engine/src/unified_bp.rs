//! Unified BP dispatcher: selects scalar or interval-aware BP by interval coverage.
//!
//! When more than 50 % of the variables in the factor graph have explicit
//! `EpistemicInterval` beliefs supplied the interval track is used; otherwise
//! the cheaper scalar track runs.  Callers do not need to know which track was
//! selected — the returned [`UnifiedBpResult`] exposes a uniform surface.

use std::collections::HashMap;
use uuid::Uuid;

use crate::bp::{run_bp, BpConfig, BpResult, FactorPotential};
use crate::cdst_bp::CdstBpResult;
use crate::epistemic_interval::EpistemicInterval;
use crate::interval_bp::{run_interval_bp, IntervalBpConfig, IntervalBpResult};

// ── Result wrapper ──────────────────────────────────────────────────────────

/// Result of a unified BP dispatch, wrapping either the scalar, interval, or CDST track.
#[derive(Debug, Clone)]
pub enum UnifiedBpResult {
    Scalar(BpResult),
    Interval(IntervalBpResult),
    Cdst(CdstBpResult),
}

impl UnifiedBpResult {
    /// Extract pignistic probabilities from whichever track ran.
    ///
    /// For scalar BP this is the belief directly.
    /// For interval BP this is [`EpistemicInterval::betp`] — the pignistic
    /// midpoint of `[Bel, Pl]`.
    pub fn updated_betps(&self) -> Vec<(Uuid, f64)> {
        match self {
            UnifiedBpResult::Scalar(r) => r.updated_beliefs.clone(),
            UnifiedBpResult::Interval(r) => r
                .updated_intervals
                .iter()
                .map(|(id, iv)| (*id, iv.betp()))
                .collect(),
            UnifiedBpResult::Cdst(r) => r.updated_betps.clone(),
        }
    }

    /// Whether BP converged within the iteration limit.
    pub fn converged(&self) -> bool {
        match self {
            UnifiedBpResult::Scalar(r) => r.converged,
            UnifiedBpResult::Interval(r) => r.converged,
            UnifiedBpResult::Cdst(r) => r.converged,
        }
    }

    /// Number of iterations actually performed.
    pub fn iterations(&self) -> usize {
        match self {
            UnifiedBpResult::Scalar(r) => r.iterations,
            UnifiedBpResult::Interval(r) => r.iterations,
            UnifiedBpResult::Cdst(r) => r.iterations,
        }
    }
}

// ── Dispatcher ──────────────────────────────────────────────────────────────

/// Run belief propagation over a mixed scalar/interval factor graph.
///
/// # Track selection
///
/// The function counts distinct variable IDs that appear in `factors`.
/// If more than 50 % of those variables have an entry in
/// `initial_interval_beliefs`, the interval track (`run_interval_bp`) is
/// selected.  Otherwise the scalar track (`run_bp`) runs.
///
/// When no factors are provided both tracks would converge immediately; the
/// scalar track is used for efficiency.
///
/// # Arguments
///
/// * `factors` — `(factor_id, potential, variable_ids)` triples, shared by
///   both tracks (interval BP reuses the same [`FactorPotential`] type).
/// * `initial_scalar_beliefs` — scalar priors used by the scalar track.
///   May be empty when the interval track is selected.
/// * `initial_interval_beliefs` — interval priors used by the interval track.
///   May be empty when the scalar track is selected.
/// * `max_iterations` — forwarded to whichever config is constructed.
/// * `damping` — forwarded to whichever config is constructed.
pub fn run_unified_bp(
    factors: &[(Uuid, FactorPotential, Vec<Uuid>)],
    initial_scalar_beliefs: &HashMap<Uuid, f64>,
    initial_interval_beliefs: &HashMap<Uuid, EpistemicInterval>,
    max_iterations: usize,
    damping: f64,
) -> UnifiedBpResult {
    // Collect distinct variable IDs referenced by factors.
    let mut all_vars: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for (_, _, vars) in factors {
        for &v in vars {
            all_vars.insert(v);
        }
    }

    let total = all_vars.len();
    let interval_count = all_vars
        .iter()
        .filter(|v| initial_interval_beliefs.contains_key(v))
        .count();

    // Use interval track when > 50 % of variables have interval beliefs.
    // When there are no variables (empty factors) the scalar track is cheaper.
    let use_interval = total > 0 && interval_count * 2 > total;

    if use_interval {
        let config = IntervalBpConfig {
            max_iterations,
            damping,
            ..Default::default()
        };
        UnifiedBpResult::Interval(run_interval_bp(factors, initial_interval_beliefs, &config))
    } else {
        let config = BpConfig {
            max_iterations,
            convergence_threshold: 0.01,
            damping,
        };
        UnifiedBpResult::Scalar(run_bp(factors, initial_scalar_beliefs, &config))
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_factor(
        potential: FactorPotential,
        vars: Vec<Uuid>,
    ) -> (Uuid, FactorPotential, Vec<Uuid>) {
        (Uuid::new_v4(), potential, vars)
    }

    // ── selects scalar when no interval beliefs are provided ─────────────

    #[test]
    fn test_selects_scalar_when_no_intervals() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let factors = vec![make_factor(
            FactorPotential::EvidentialSupport { strength: 0.8 },
            vec![a, b],
        )];

        let scalar_beliefs = HashMap::from([(a, 0.7), (b, 0.3)]);
        let interval_beliefs: HashMap<Uuid, EpistemicInterval> = HashMap::new();

        let result = run_unified_bp(&factors, &scalar_beliefs, &interval_beliefs, 20, 0.5);

        // Must be scalar track.
        assert!(
            matches!(result, UnifiedBpResult::Scalar(_)),
            "Expected scalar track when no interval beliefs provided"
        );

        // Sanity: betp values are present and in [0, 1].
        let betps = result.updated_betps();
        assert!(!betps.is_empty());
        for (_, v) in &betps {
            assert!(*v >= 0.0 && *v <= 1.0, "betp out of range: {v}");
        }

        assert!(result.iterations() > 0 || result.converged());
    }

    // ── selects interval when all variables have interval beliefs ────────

    #[test]
    fn test_selects_interval_when_intervals_dominate() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let factors = vec![make_factor(
            FactorPotential::EvidentialSupport { strength: 0.8 },
            vec![a, b],
        )];

        // Both variables have interval beliefs → 100 % coverage → interval track.
        let scalar_beliefs: HashMap<Uuid, f64> = HashMap::new();
        let interval_beliefs = HashMap::from([
            (a, EpistemicInterval::new(0.6, 0.8, 0.1)),
            (b, EpistemicInterval::VACUOUS),
        ]);

        let result = run_unified_bp(&factors, &scalar_beliefs, &interval_beliefs, 20, 0.5);

        assert!(
            matches!(result, UnifiedBpResult::Interval(_)),
            "Expected interval track when all variables have interval beliefs"
        );

        let betps = result.updated_betps();
        assert!(!betps.is_empty());
        for (_, v) in &betps {
            assert!(*v >= 0.0 && *v <= 1.0, "betp out of range: {v}");
        }
    }

    // ── boundary: exactly 50 % interval coverage uses scalar ─────────────

    #[test]
    fn test_exactly_50_percent_coverage_uses_scalar() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let factors = vec![make_factor(FactorPotential::MutualExclusion, vec![a, b])];

        // Only one of two variables has an interval belief (50 % = not > 50 %).
        let scalar_beliefs = HashMap::from([(a, 0.6), (b, 0.4)]);
        let interval_beliefs = HashMap::from([(a, EpistemicInterval::certain(0.6))]);

        let result = run_unified_bp(&factors, &scalar_beliefs, &interval_beliefs, 20, 0.5);

        assert!(
            matches!(result, UnifiedBpResult::Scalar(_)),
            "Expected scalar track at exactly 50 % interval coverage"
        );
    }

    // ── empty factor graph converges immediately ─────────────────────────

    #[test]
    fn test_empty_factors_converge() {
        let scalar_beliefs = HashMap::from([(Uuid::new_v4(), 0.5)]);
        let interval_beliefs: HashMap<Uuid, EpistemicInterval> = HashMap::new();

        let result = run_unified_bp(&[], &scalar_beliefs, &interval_beliefs, 20, 0.5);

        assert!(
            result.converged(),
            "Empty factor graph must converge immediately"
        );
        assert_eq!(result.iterations(), 0);
    }

    // ── helper methods work uniformly across both tracks ─────────────────

    #[test]
    fn test_helper_methods_uniform() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let factors = vec![make_factor(
            FactorPotential::SharedEvidence { strength: 0.7 },
            vec![a, b],
        )];

        // Scalar run.
        let scalar_r = run_unified_bp(
            &factors,
            &HashMap::from([(a, 0.8), (b, 0.3)]),
            &HashMap::new(),
            20,
            0.5,
        );
        assert!(!scalar_r.updated_betps().is_empty());
        let _ = scalar_r.converged();
        let _ = scalar_r.iterations();

        // Interval run.
        let interval_r = run_unified_bp(
            &factors,
            &HashMap::new(),
            &HashMap::from([
                (a, EpistemicInterval::new(0.7, 0.85, 0.1)),
                (b, EpistemicInterval::new(0.2, 0.5, 0.2)),
            ]),
            20,
            0.5,
        );
        assert!(!interval_r.updated_betps().is_empty());
        let _ = interval_r.converged();
        let _ = interval_r.iterations();
    }
}
