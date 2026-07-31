//! Belief, plausibility, and pignistic probability (CDST-aware)
//!
//! These are derived measures from a mass function. For mass functions
//! containing complement (negative) elements, the measures operate on
//! positive focal elements only — complement elements contribute to
//! missing-propositions mass rather than to belief/plausibility of
//! specific hypotheses.
//!
//! - **Belief** Bel(A): total mass committed to A and its subsets
//! - **Plausibility** Pl(A): total mass not contradicting A
//! - **Pignistic probability** `BetP`: decision-making transform

use crate::mass::{FocalElement, MassFunction};
use epigraph_core::TruthValue;

/// Normalize a raw measure onto the closed unit interval `[0.0, 1.0]`.
///
/// This is deliberately **not** `f64::clamp`. `clamp` is defined as
/// "return `self` unless it is outside the bounds", and `-0.0 < 0.0` is false,
/// so `(-0.0).clamp(0.0, 1.0)` returns `-0.0` with its sign bit intact
/// (`0x8000_0000_0000_0000`). A `-0.0` satisfies the `claims_belief_bounds`
/// CHECK constraint and is therefore persisted verbatim, where it leaks into
/// the divergence cache and into any downstream sign-sensitive comparison.
/// `clamp` also propagates `NaN` unchanged, and in Postgres `NaN > 1.0`, so a
/// `NaN` measure turns a claim write into a constraint violation.
///
/// This is not hypothetical: `impl Sum for f64` folds from `-0.0` (the true
/// additive identity, since `-0.0 + x == x` for every `x`), so the `.sum()` in
/// `belief`/`plausibility` returns `-0.0` whenever no focal element passes the
/// filter — every vacuous mass function, every target disjoint from the
/// support.
///
/// Explicit comparisons collapse every non-finite and every non-positive input
/// (including `-0.0`, `NaN`, and both infinities) to a positive `0.0`. Note
/// this makes `+inf` map to `0.0` rather than saturating to `1.0`: a
/// non-finite belief is garbage input, and `0.0` is the conservative value.
#[must_use]
fn normalize_unit_interval(x: f64) -> f64 {
    if !x.is_finite() || x <= 0.0 {
        0.0
    } else if x >= 1.0 {
        1.0
    } else {
        x
    }
}

/// Belief: sum of masses of all positive focal elements that are subsets of target
///
/// `Bel(A)` = sum `m(B)` for all B positive with `B.subset` subset of `A.subset`, B non-empty
///
/// Complement elements are excluded — they represent "outside" evidence.
///
/// Result is normalized onto [0, 1] via `normalize_unit_interval`; without it,
/// repeated folds accumulate floating-point drift that trips the
/// `claims_belief_bounds` CHECK constraint.
#[must_use]
pub fn belief(m: &MassFunction, target: &FocalElement) -> f64 {
    if target.complement {
        // For complement targets, belief is not directly meaningful
        // Return 0 — callers should use evaluate_to_classical first
        return 0.0;
    }
    let raw: f64 = m
        .masses()
        .iter()
        .filter(|(fe, _)| {
            fe.is_positive() && !fe.subset.is_empty() && fe.subset.is_subset(&target.subset)
        })
        .map(|(_, &mass)| mass)
        .sum();
    normalize_unit_interval(raw)
}

/// Plausibility: sum of masses of all positive focal elements intersecting target
///
/// Pl(A) = sum m(B) for all B positive with B.subset intersects A.subset
///
/// Complement elements are excluded.
///
/// Result is normalized onto [0, 1] via `normalize_unit_interval`; without it,
/// repeated folds accumulate floating-point drift that trips the
/// `claims_plausibility_bounds` CHECK constraint.
#[must_use]
pub fn plausibility(m: &MassFunction, target: &FocalElement) -> f64 {
    if target.complement {
        return 0.0;
    }
    let raw: f64 = m
        .masses()
        .iter()
        .filter(|(fe, _)| {
            fe.is_positive() && !fe.subset.is_empty() && !fe.subset.is_disjoint(&target.subset)
        })
        .map(|(_, &mass)| mass)
        .sum();
    normalize_unit_interval(raw)
}

/// Belief interval [Bel(A), Pl(A)]
///
/// The width Pl(A) - Bel(A) represents ignorance about A.
#[must_use]
pub fn belief_interval(m: &MassFunction, target: &FocalElement) -> (f64, f64) {
    (belief(m, target), plausibility(m, target))
}

/// Ignorance about a focal element: Pl(A) - Bel(A)
///
/// Zero ignorance means we have complete information about A.
#[must_use]
pub fn ignorance(m: &MassFunction, target: &FocalElement) -> f64 {
    plausibility(m, target) - belief(m, target)
}

/// Pignistic probability for a singleton hypothesis
///
/// BetP(x) = sum [m(A) / |A|] for all positive A containing x, A non-empty
/// normalized by `1 / (1 - m_conflict)`
///
/// Complement elements do not contribute to `BetP` directly.
#[must_use]
pub fn pignistic_probability(m: &MassFunction, hypothesis_idx: usize) -> f64 {
    let m_conflict = m.mass_of_conflict();

    // If all mass is on conflict, we have no information
    if (m_conflict - 1.0).abs() < 1e-9 {
        return 0.0;
    }

    // Sum of all non-positive mass (conflict + complement elements)
    let non_classical_mass: f64 = m
        .masses()
        .iter()
        .filter(|(fe, _)| fe.complement || fe.subset.is_empty())
        .map(|(_, &mass)| mass)
        .sum();

    if (non_classical_mass - 1.0).abs() < 1e-9 {
        return 0.0;
    }

    let normalizer = 1.0 / (1.0 - non_classical_mass);

    let sum: f64 = m
        .masses()
        .iter()
        .filter(|(fe, _)| {
            fe.is_positive() && !fe.subset.is_empty() && fe.subset.contains(&hypothesis_idx)
        })
        .map(|(fe, &mass)| {
            #[allow(clippy::cast_precision_loss)]
            let cardinality = fe.subset.len() as f64;
            mass / cardinality
        })
        .sum();

    // Floating-point combination can produce tiny negative values (e.g. -0.0) when
    // non_classical_mass is close to 1.0 and sum underflows, and can produce a
    // non-finite result when the normalizer blows up. `normalize_unit_interval`
    // (not `clamp`) strips the IEEE 754 -0.0 sign that would otherwise be stored
    // verbatim in the divergence cache.
    normalize_unit_interval(sum * normalizer)
}

/// Commonality function: total mass of all positive supersets of target
///
/// `q(A)` = sum `m(B)` for all B positive where `A.subset` subset of `B.subset`
///
/// Used in the cautious combination rule.
#[must_use]
pub fn commonality(m: &MassFunction, target: &FocalElement) -> f64 {
    m.masses()
        .iter()
        .filter(|(fe, _)| fe.is_positive() && target.subset.is_subset(&fe.subset))
        .map(|(_, &mass)| mass)
        .sum()
}

/// Convert pignistic probability to a `TruthValue` for backward compatibility
#[must_use]
pub fn to_truth_value(m: &MassFunction, hypothesis_idx: usize) -> TruthValue {
    let betp = pignistic_probability(m, hypothesis_idx);
    TruthValue::clamped(betp)
}

/// Evaluate a CDST mass function to classical form then compute belief
///
/// Convenience function for callers that need classical Bel from a CDST BBA.
#[must_use]
pub fn belief_classical(m: &MassFunction, target: &FocalElement) -> f64 {
    let classical = m.evaluate_to_classical();
    belief(&classical, target)
}

/// Evaluate a CDST mass function to classical form then compute plausibility
#[must_use]
pub fn plausibility_classical(m: &MassFunction, target: &FocalElement) -> f64 {
    let classical = m.evaluate_to_classical();
    plausibility(&classical, target)
}

/// Convert Beta distribution parameters to a CDST Complementary BPA
///
/// Maps Beta(alpha, beta) evidence to a mass function with:
/// - `m(({h}, false))` = evidence FOR hypothesis h
/// - `m(({h}, true))` = evidence AGAINST hypothesis h
/// - `m((empty, true))` = vacuous remainder (open-world ignorance)
///
/// Evidence strength `s = 1 - 2/(alpha + beta + 2)` — higher alpha+beta = more evidence.
///
/// # Errors
/// Returns error if `hypothesis_idx` is outside the frame or alpha/beta are negative.
pub fn beta_to_cbpa(
    frame: &crate::frame::FrameOfDiscernment,
    hypothesis_idx: usize,
    alpha: f64,
    beta: f64,
) -> Result<MassFunction, crate::errors::DsError> {
    use std::collections::{BTreeMap, BTreeSet};

    if !frame.is_valid_index(hypothesis_idx) {
        return Err(crate::errors::DsError::ElementOutsideFrame {
            element: format!("index {hypothesis_idx}"),
        });
    }
    if alpha < 0.0 {
        return Err(crate::errors::DsError::NegativeMass { value: alpha });
    }
    if beta < 0.0 {
        return Err(crate::errors::DsError::NegativeMass { value: beta });
    }

    let total = alpha + beta;
    let s = if total < 1e-12 {
        0.0 // No evidence -> fully vacuous
    } else {
        1.0 - 2.0 / (total + 2.0)
    };

    let mut masses = BTreeMap::new();

    if s < 1e-12 {
        // Fully vacuous (open-world)
        masses.insert(FocalElement::vacuous(), 1.0);
    } else {
        let p_for = (alpha / (alpha + beta)) * s;
        let p_against = (beta / (alpha + beta)) * s;
        let vacuous_remainder = 1.0 - s;

        if p_for > 1e-12 {
            masses.insert(
                FocalElement::positive(BTreeSet::from([hypothesis_idx])),
                p_for,
            );
        }
        if p_against > 1e-12 {
            masses.insert(
                FocalElement::negative(BTreeSet::from([hypothesis_idx])),
                p_against,
            );
        }
        if vacuous_remainder > 1e-12 {
            masses.insert(FocalElement::vacuous(), vacuous_remainder);
        }
    }

    Ok(MassFunction::from_raw(frame.clone(), masses))
}

/// Normalize the five belief-measure fields written to `claims` onto `[0.0, 1.0]`.
///
/// Each field goes through `normalize_unit_interval`, not `f64::clamp`: `clamp`
/// would return `-0.0` unchanged (it is not "outside" the bounds) and would
/// propagate `NaN`. `-0.0` satisfies the CHECK constraints below and is
/// persisted verbatim; `NaN` fails them, because Postgres orders `NaN` above
/// every other double, so it turns the write into a constraint violation.
///
/// Three of the five — `belief`, `plausibility`, `mass_on_empty` — are enforced
/// at the DB level by `claims_belief_bounds`, `claims_plausibility_bounds`, and
/// `claims_mass_empty_bounds` respectively (see
/// `migrations/001_initial_schema.sql:627-631`). `pignistic_prob` and
/// `mass_on_missing` have no CHECK constraint today but are clamped defensively
/// so a future `ALTER TABLE ... ADD CONSTRAINT ...` lands without surfacing a
/// new bug.
///
/// All callers that issue
/// `UPDATE claims SET belief|plausibility|pignistic_prob|mass_on_empty|mass_on_missing ...`
/// MUST route their values through this helper.
#[must_use]
pub fn clamp_claim_belief_measures(
    belief: f64,
    plausibility: f64,
    pignistic_prob: Option<f64>,
    mass_on_empty: f64,
    mass_on_missing: f64,
) -> (f64, f64, Option<f64>, f64, f64) {
    (
        normalize_unit_interval(belief),
        normalize_unit_interval(plausibility),
        pignistic_prob.map(normalize_unit_interval),
        normalize_unit_interval(mass_on_empty),
        normalize_unit_interval(mass_on_missing),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameOfDiscernment;
    use std::collections::{BTreeMap, BTreeSet};

    fn binary_frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("test", vec!["true".into(), "false".into()]).unwrap()
    }

    fn ternary_frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("tri", vec!["a".into(), "b".into(), "c".into()]).unwrap()
    }

    // ======== Commonality ========

    #[test]
    fn commonality_of_full_set() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let theta = FocalElement::theta(m.frame());
        // q(Theta) = m(Theta) = 0.3
        let q = commonality(&m, &theta);
        assert!((q - 0.3).abs() < 1e-10);
    }

    #[test]
    fn commonality_of_singleton() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        // q({0}) = m({0}) + m(Theta) = 0.7 + 0.3 = 1.0
        let q = commonality(&m, &fe0);
        assert!((q - 1.0).abs() < 1e-10);
    }

    #[test]
    fn commonality_of_empty_set() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let empty = FocalElement::conflict();
        // q(empty) = sum of ALL positive masses = 1.0
        let q = commonality(&m, &empty);
        assert!((q - 1.0).abs() < 1e-10);
    }

    #[test]
    fn commonality_vacuous_singleton() {
        let frame = binary_frame();
        let m = MassFunction::vacuous(frame);
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let q = commonality(&m, &fe0);
        assert!((q - 1.0).abs() < 1e-10);
    }

    #[test]
    fn commonality_ternary_partial() {
        let frame = ternary_frame();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::positive(BTreeSet::from([0])), 0.3);
        masses.insert(FocalElement::positive(BTreeSet::from([1, 2])), 0.2);
        masses.insert(FocalElement::theta(&frame), 0.5);
        let m = MassFunction::new(frame, masses).unwrap();

        // q({0}) = m({0}) + m(Theta) = 0.3 + 0.5 = 0.8
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let q0 = commonality(&m, &fe0);
        assert!((q0 - 0.8).abs() < 1e-10);

        // q({1,2}) = m({1,2}) + m(Theta) = 0.2 + 0.5 = 0.7
        let fe12 = FocalElement::positive(BTreeSet::from([1, 2]));
        let q12 = commonality(&m, &fe12);
        assert!((q12 - 0.7).abs() < 1e-10);
    }

    // ======== Belief ========

    #[test]
    fn belief_of_singleton() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let bel = belief(&m, &fe0);
        assert!((bel - 0.7).abs() < 1e-10);
    }

    #[test]
    fn belief_of_full_set() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let theta = FocalElement::theta(m.frame());
        let bel = belief(&m, &theta);
        assert!((bel - 1.0).abs() < 1e-10);
    }

    #[test]
    fn belief_from_vacuous_is_zero_for_proper_subsets() {
        let frame = binary_frame();
        let m = MassFunction::vacuous(frame);
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let bel = belief(&m, &fe0);
        assert!(bel.abs() < 1e-10);
    }

    // ======== Plausibility ========

    #[test]
    fn plausibility_of_singleton() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let pl = plausibility(&m, &fe0);
        assert!((pl - 1.0).abs() < 1e-10);
    }

    #[test]
    fn plausibility_from_vacuous_is_one() {
        let frame = binary_frame();
        let m = MassFunction::vacuous(frame);
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let pl = plausibility(&m, &fe0);
        assert!((pl - 1.0).abs() < 1e-10);
    }

    // ======== Belief interval ========

    #[test]
    fn belief_interval_simple() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let (bel, pl) = belief_interval(&m, &fe0);
        assert!((bel - 0.7).abs() < 1e-10);
        assert!((pl - 1.0).abs() < 1e-10);
        assert!(bel <= pl);
    }

    #[test]
    fn belief_interval_vacuous_is_zero_to_one() {
        let frame = binary_frame();
        let m = MassFunction::vacuous(frame);
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let (bel, pl) = belief_interval(&m, &fe0);
        assert!(bel.abs() < 1e-10);
        assert!((pl - 1.0).abs() < 1e-10);
    }

    #[test]
    fn belief_interval_categorical_is_tight() {
        let frame = binary_frame();
        let m = MassFunction::categorical(frame, 0).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let (bel, pl) = belief_interval(&m, &fe0);
        assert!((bel - 1.0).abs() < 1e-10);
        assert!((pl - 1.0).abs() < 1e-10);
    }

    // ======== Ignorance ========

    #[test]
    fn ignorance_simple() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let ign = ignorance(&m, &fe0);
        assert!((ign - 0.3).abs() < 1e-10);
    }

    #[test]
    fn ignorance_vacuous_is_maximal() {
        let frame = binary_frame();
        let m = MassFunction::vacuous(frame);
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let ign = ignorance(&m, &fe0);
        assert!((ign - 1.0).abs() < 1e-10);
    }

    #[test]
    fn ignorance_categorical_is_zero() {
        let frame = binary_frame();
        let m = MassFunction::categorical(frame, 0).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let ign = ignorance(&m, &fe0);
        assert!(ign.abs() < 1e-10);
    }

    // ======== Pignistic probability ========

    #[test]
    fn pignistic_from_vacuous_is_uniform() {
        let frame = binary_frame();
        let m = MassFunction::vacuous(frame);
        let betp0 = pignistic_probability(&m, 0);
        let betp1 = pignistic_probability(&m, 1);
        assert!((betp0 - 0.5).abs() < 1e-10);
        assert!((betp1 - 0.5).abs() < 1e-10);
    }

    #[test]
    fn pignistic_from_vacuous_ternary_is_uniform() {
        let frame = ternary_frame();
        let m = MassFunction::vacuous(frame);
        for i in 0..3 {
            let betp = pignistic_probability(&m, i);
            assert!(
                (betp - 1.0 / 3.0).abs() < 1e-10,
                "BetP({i}) should be 1/3, got {betp}"
            );
        }
    }

    #[test]
    fn pignistic_from_categorical() {
        let frame = binary_frame();
        let m = MassFunction::categorical(frame, 0).unwrap();
        assert!((pignistic_probability(&m, 0) - 1.0).abs() < 1e-10);
        assert!(pignistic_probability(&m, 1).abs() < 1e-10);
    }

    #[test]
    fn pignistic_simple() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let betp0 = pignistic_probability(&m, 0);
        // BetP({true}) = m({true})/1 + m(Theta)/2 = 0.7 + 0.15 = 0.85
        assert!((betp0 - 0.85).abs() < 1e-10);
    }

    #[test]
    fn pignistic_sums_to_one() {
        let frame = ternary_frame();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::positive(BTreeSet::from([0])), 0.3);
        masses.insert(FocalElement::positive(BTreeSet::from([1, 2])), 0.2);
        masses.insert(FocalElement::theta(&frame), 0.5);
        let m = MassFunction::new(frame, masses).unwrap();

        let total: f64 = (0..3).map(|i| pignistic_probability(&m, i)).sum();
        assert!(
            (total - 1.0).abs() < 1e-10,
            "Pignistic probabilities should sum to 1.0, got {total}"
        );
    }

    #[test]
    fn pignistic_with_conflict() {
        // Mass on conflict should be normalized away
        let frame = binary_frame();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::conflict(), 0.3);
        masses.insert(FocalElement::positive(BTreeSet::from([0])), 0.5);
        masses.insert(FocalElement::theta(&frame), 0.2);
        let m = MassFunction::new(frame, masses).unwrap();

        let betp0 = pignistic_probability(&m, 0);
        let betp1 = pignistic_probability(&m, 1);
        // normalizer = 1/(1-0.3) = 1/0.7
        // BetP(0) = (0.5/1 + 0.2/2) / 0.7 = 0.6 / 0.7 ~ 0.857
        assert!((betp0 + betp1 - 1.0).abs() < 1e-10);
        assert!(betp0 > betp1);
    }

    // ======== Tolerance boundary tests ========

    #[test]
    fn belief_plausibility_ordering_at_epsilon() {
        let frame = binary_frame();
        let eps = 1e-9;
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 1.0 - eps).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let bel = belief(&m, &fe0);
        let pl = plausibility(&m, &fe0);

        assert!(
            bel <= pl + 1e-12,
            "Bel must never exceed Pl: Bel={bel}, Pl={pl}"
        );
    }

    #[test]
    fn pignistic_single_mass_near_one() {
        let frame = binary_frame();
        let eps = 1e-9;
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 1.0 - eps).unwrap();

        let betp0 = pignistic_probability(&m, 0);
        let betp1 = pignistic_probability(&m, 1);

        assert!(
            (betp0 - 1.0).abs() < 1e-6,
            "BetP(0) should be near 1.0: {betp0}"
        );
        assert!(betp1 < 1e-6, "BetP(1) should be near 0.0: {betp1}");
        assert!(
            (betp0 + betp1 - 1.0).abs() < 1e-10,
            "BetP must sum to 1.0: {}",
            betp0 + betp1
        );
    }

    // ======== to_truth_value ========

    #[test]
    fn to_truth_value_from_simple() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let tv = to_truth_value(&m, 0);
        assert!((tv.value() - 0.85).abs() < 1e-10);
    }

    #[test]
    fn to_truth_value_from_vacuous() {
        let frame = binary_frame();
        let m = MassFunction::vacuous(frame);
        let tv = to_truth_value(&m, 0);
        assert!((tv.value() - 0.5).abs() < 1e-10);
    }

    // ======== Beta-to-CBPA bridge ========

    #[test]
    fn beta_to_cbpa_uniform_prior_is_vacuous() {
        let frame = binary_frame();
        // Alpha=0, Beta=0 -> no evidence -> vacuous
        let m = beta_to_cbpa(&frame, 0, 0.0, 0.0).unwrap();
        let vacuous_mass = m.mass_of(&FocalElement::vacuous());
        assert!(
            (vacuous_mass - 1.0).abs() < 1e-10,
            "Zero evidence should give vacuous: got {vacuous_mass}"
        );
    }

    #[test]
    fn beta_to_cbpa_strong_for_evidence() {
        let frame = binary_frame();
        // Alpha=10, Beta=0 -> strong evidence FOR hypothesis 0
        let m = beta_to_cbpa(&frame, 0, 10.0, 0.0).unwrap();
        let fe_for = FocalElement::positive(BTreeSet::from([0]));
        let mass_for = m.mass_of(&fe_for);
        assert!(
            mass_for > 0.7,
            "Strong alpha should give high mass for: {mass_for}"
        );
        // No evidence against
        let fe_against = FocalElement::negative(BTreeSet::from([0]));
        assert!(m.mass_of(&fe_against) < 1e-10);
    }

    #[test]
    fn beta_to_cbpa_strong_against_evidence() {
        let frame = binary_frame();
        // Alpha=0, Beta=10 -> strong evidence AGAINST hypothesis 0
        let m = beta_to_cbpa(&frame, 0, 0.0, 10.0).unwrap();
        let fe_against = FocalElement::negative(BTreeSet::from([0]));
        let mass_against = m.mass_of(&fe_against);
        assert!(
            mass_against > 0.7,
            "Strong beta should give high mass against: {mass_against}"
        );
    }

    #[test]
    fn beta_to_cbpa_balanced_evidence() {
        let frame = binary_frame();
        // Alpha=5, Beta=5 -> balanced evidence
        let m = beta_to_cbpa(&frame, 0, 5.0, 5.0).unwrap();
        let fe_for = FocalElement::positive(BTreeSet::from([0]));
        let fe_against = FocalElement::negative(BTreeSet::from([0]));
        let mass_for = m.mass_of(&fe_for);
        let mass_against = m.mass_of(&fe_against);
        // Should be roughly equal
        assert!(
            (mass_for - mass_against).abs() < 1e-10,
            "Balanced alpha/beta should give equal for/against: {mass_for} vs {mass_against}"
        );
        // Total should sum to 1
        let total: f64 = m.masses().values().sum();
        assert!((total - 1.0).abs() < 1e-10);
    }

    /// Regression: BetP must be in [0, 1] when nearly all mass is non-classical
    /// (high ignorance / under-studied frame, missing mass near 1.0).
    ///
    /// The affected claim (2026-04-16 enrichment) had ignorance = 0.707 and
    /// pignistic_prob was cached as -0.0 due to floating-point underflow in the
    /// sum * normalizer product when non_classical_mass ≈ 1.0.
    #[test]
    fn pignistic_non_negative_with_high_missing_mass() {
        let frame = binary_frame();
        // Construct a mass function where nearly all mass is on the complement
        // element (~{0}, true) — simulates "frame may be incomplete" scenario.
        let mut masses = BTreeMap::new();
        // A tiny positive mass for hypothesis 0 — everything else on complement
        masses.insert(FocalElement::positive(BTreeSet::from([0])), 1e-15_f64);
        // The complement element carries essentially all the mass
        let complement = FocalElement::negative(BTreeSet::from([0]));
        masses.insert(complement, 1.0 - 1e-15_f64);
        let m = MassFunction::new(frame.clone(), masses).unwrap();

        let betp0 = pignistic_probability(&m, 0);
        let betp1 = pignistic_probability(&m, 1);

        assert!(betp0 >= 0.0, "BetP(0) must be non-negative: {betp0}");
        assert!(betp0 <= 1.0, "BetP(0) must be <= 1.0: {betp0}");
        assert!(betp1 >= 0.0, "BetP(1) must be non-negative: {betp1}");
        assert!(betp1 <= 1.0, "BetP(1) must be <= 1.0: {betp1}");
        assert!(!betp0.is_nan(), "BetP(0) must not be NaN");
        assert!(!betp1.is_nan(), "BetP(1) must not be NaN");
    }

    /// Regression: BetP must be in [0, 1] when non_classical_mass is just below
    /// the 1e-9 tolerance (pathological case: denominator approaches zero).
    #[test]
    fn pignistic_non_negative_when_denominator_near_zero() {
        let frame = binary_frame();
        let near_one = 1.0 - 2e-9_f64; // just outside the 1e-9 guard
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::negative(BTreeSet::from([0])), near_one);
        // Tiny remainder on conflict to make masses sum to 1
        masses.insert(FocalElement::conflict(), 1.0 - near_one);
        let m = MassFunction::new(frame, masses).unwrap();

        let betp = pignistic_probability(&m, 0);
        assert!(betp >= 0.0, "BetP must be >= 0: {betp}");
        assert!(betp <= 1.0, "BetP must be <= 1: {betp}");
        assert!(!betp.is_nan(), "BetP must not be NaN");
    }

    #[test]
    fn beta_to_cbpa_invalid_index_errors() {
        let frame = binary_frame();
        let result = beta_to_cbpa(&frame, 5, 1.0, 1.0);
        assert!(result.is_err());
    }

    // ======== Classical evaluation helpers ========

    #[test]
    fn belief_classical_with_complement() {
        let frame = binary_frame();
        let m = MassFunction::simple_negative(frame, BTreeSet::from([1]), 0.6).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        // ~{1} on binary = {0}, so Bel({0}) should be 0.6 after evaluation
        let bel = belief_classical(&m, &fe0);
        assert!((bel - 0.6).abs() < 1e-10);
    }
}

#[cfg(test)]
mod clamp_tests {
    use super::clamp_claim_belief_measures;

    #[test]
    fn clamps_one_ulp_drift_to_one() {
        // Summing 0.05 twenty times yields 1.0 + 1 ULP in f64 — the drift
        // case from tests/order_independence_smoke.rs that tripped
        // claims_{belief,plausibility}_bounds pre-#149. (The product form
        // 0.05 * 20.0 rounds to exactly 1.0 and does NOT drift, despite what
        // the original plan suggested; only the summation drifts.)
        let drifted: f64 = [0.05_f64; 20].iter().sum();
        assert!(drifted > 1.0, "test setup: expected drift > 1.0");
        let (bel, pl, betp, me, mm) =
            clamp_claim_belief_measures(drifted, drifted, Some(drifted), drifted, drifted);
        assert_eq!(bel, 1.0);
        assert_eq!(pl, 1.0);
        assert_eq!(betp, Some(1.0));
        assert_eq!(me, 1.0);
        assert_eq!(mm, 1.0);
    }

    #[test]
    fn clamps_overshoot_and_undershoot() {
        let (bel, pl, betp, me, mm) = clamp_claim_belief_measures(1.5, -0.1, Some(2.0), -0.5, 1.7);
        assert_eq!(bel, 1.0);
        assert_eq!(pl, 0.0);
        assert_eq!(betp, Some(1.0));
        assert_eq!(me, 0.0);
        assert_eq!(mm, 1.0);
    }

    #[test]
    fn passes_through_in_range_values() {
        let (bel, pl, betp, me, mm) = clamp_claim_belief_measures(0.4, 0.9, Some(0.5), 0.1, 0.05);
        assert_eq!(bel, 0.4);
        assert_eq!(pl, 0.9);
        assert_eq!(betp, Some(0.5));
        assert_eq!(me, 0.1);
        assert_eq!(mm, 0.05);
    }

    #[test]
    fn preserves_none_pignistic() {
        let (_, _, betp, _, _) = clamp_claim_belief_measures(0.4, 0.9, None, 0.1, 0.05);
        assert_eq!(betp, None);
    }

    // ======== gh#364B: IEEE 754 sign / non-finite normalization ========
    //
    // NOTE for future readers: `assert_eq!(x, 0.0)` PASSES for `-0.0`, because
    // IEEE 754 defines `-0.0 == 0.0`. Every assertion below therefore inspects
    // the SIGN BIT via `is_sign_positive()`. An equality-only assertion here
    // would be a tautology that passes on the pre-fix `.clamp(0.0, 1.0)` code.

    /// `f64::clamp` returns `self` when it is not outside the bounds, and
    /// `-0.0 < 0.0` is false, so the pre-fix helper handed `-0.0` (bit pattern
    /// `0x8000_0000_0000_0000`) straight to `UPDATE claims SET belief = ...`.
    #[test]
    fn negative_zero_is_normalized_to_positive_zero_on_all_five_fields() {
        let neg_zero = -0.0_f64;
        assert!(
            neg_zero.is_sign_negative(),
            "test setup: literal -0.0 must carry the sign bit"
        );

        let (bel, pl, betp, me, mm) =
            clamp_claim_belief_measures(neg_zero, neg_zero, Some(neg_zero), neg_zero, neg_zero);

        assert!(
            bel.is_sign_positive(),
            "belief kept -0.0: bits {:#x}",
            bel.to_bits()
        );
        assert!(
            pl.is_sign_positive(),
            "plausibility kept -0.0: bits {:#x}",
            pl.to_bits()
        );
        let betp = betp.expect("pignistic_prob stays Some");
        assert!(
            betp.is_sign_positive(),
            "pignistic_prob kept -0.0: bits {:#x}",
            betp.to_bits()
        );
        assert!(
            me.is_sign_positive(),
            "mass_on_empty kept -0.0: bits {:#x}",
            me.to_bits()
        );
        assert!(
            mm.is_sign_positive(),
            "mass_on_missing kept -0.0: bits {:#x}",
            mm.to_bits()
        );

        // Belt and braces: the canonical positive zero has an all-zero bit pattern.
        assert_eq!(bel.to_bits(), 0_u64);
    }

    /// A tiny negative underflow (not merely `-0.0`) must also land on `+0.0`,
    /// since `.clamp` maps `-1e-18` to `+0.0` but the sign question only shows
    /// up for the exact `-0.0` input — this pins both halves of the branch.
    #[test]
    fn tiny_negative_underflow_lands_on_positive_zero() {
        let (bel, ..) = clamp_claim_belief_measures(-1e-18, 0.5, None, 0.0, 0.0);
        assert_eq!(bel, 0.0);
        assert!(bel.is_sign_positive(), "bits {:#x}", bel.to_bits());
    }

    /// `NaN.clamp(0.0, 1.0)` returns `NaN`. Postgres orders `NaN` above every
    /// other double, so a `NaN` belief fails `claims_belief_bounds` and aborts
    /// the write instead of being silently corrected.
    #[test]
    fn nan_is_normalized_to_zero_rather_than_propagated() {
        let nan = f64::NAN;
        let (bel, pl, betp, me, mm) = clamp_claim_belief_measures(nan, nan, Some(nan), nan, nan);

        for (name, v) in [
            ("belief", bel),
            ("plausibility", pl),
            ("pignistic_prob", betp.expect("stays Some")),
            ("mass_on_empty", me),
            ("mass_on_missing", mm),
        ] {
            assert!(!v.is_nan(), "{name} propagated NaN");
            assert!(v.is_finite(), "{name} is not finite: {v}");
            assert!((0.0..=1.0).contains(&v), "{name} out of range: {v}");
            assert!(v.is_sign_positive(), "{name} bits {:#x}", v.to_bits());
        }
    }

    /// Both infinities collapse to `+0.0`. This is a deliberate behaviour
    /// change: `.clamp` saturated `+inf` to `1.0`, which would write a
    /// maximally-confident belief from garbage input. Unifying on the
    /// `pignistic_probability` guard's semantics treats any non-finite measure
    /// as no-information instead.
    #[test]
    fn infinities_collapse_to_zero_not_to_one() {
        let (bel, pl, ..) =
            clamp_claim_belief_measures(f64::INFINITY, f64::NEG_INFINITY, None, 0.0, 0.0);
        assert_eq!(bel, 0.0, "+inf must not saturate to 1.0");
        assert!(bel.is_sign_positive());
        assert_eq!(pl, 0.0);
        assert!(pl.is_sign_positive());
    }
}

#[cfg(test)]
mod normalize_unit_interval_tests {
    use super::normalize_unit_interval;

    #[test]
    fn strips_the_negative_zero_sign_bit() {
        let out = normalize_unit_interval(-0.0);
        assert_eq!(
            out.to_bits(),
            0_u64,
            "expected +0.0, got bits {:#x}",
            out.to_bits()
        );
        assert!(out.is_sign_positive());
    }

    #[test]
    fn maps_non_finite_inputs_to_positive_zero() {
        for input in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let out = normalize_unit_interval(input);
            assert!(!out.is_nan(), "NaN escaped for input {input}");
            assert_eq!(out, 0.0, "input {input} did not collapse to 0.0");
            assert!(out.is_sign_positive(), "input {input} produced -0.0");
        }
    }

    #[test]
    fn saturates_above_one_and_below_zero() {
        assert_eq!(normalize_unit_interval(1.5), 1.0);
        assert_eq!(normalize_unit_interval(1.0), 1.0);
        let below = normalize_unit_interval(-0.5);
        assert_eq!(below, 0.0);
        assert!(below.is_sign_positive());
    }

    #[test]
    fn passes_interior_values_through_unchanged() {
        for v in [f64::MIN_POSITIVE, 1e-300, 0.5, 0.999_999_999] {
            assert!((normalize_unit_interval(v) - v).abs() < f64::EPSILON * v.max(1.0));
        }
    }
}

#[cfg(test)]
mod pignistic_sign_tests {
    use super::{belief, normalize_unit_interval, pignistic_probability, plausibility};
    use crate::frame::FrameOfDiscernment;
    use crate::mass::{FocalElement, MassFunction};
    use std::collections::{BTreeMap, BTreeSet};

    /// This is the PRIMARY `-0.0` path, not an edge case.
    ///
    /// `impl Sum for f64` folds from `-0.0` — the true additive identity for
    /// f64, since `-0.0 + x == x` for every `x` including `-0.0`, whereas
    /// `+0.0 + -0.0 == +0.0`. So `belief`'s `.sum()` over an empty filter
    /// returns `-0.0`, and the pre-fix `.clamp(0.0, 1.0)` preserved it
    /// (`-0.0 < 0.0` is false). Measured directly: for a vacuous mass
    /// function with a positive target, the raw sum was
    /// `0x8000_0000_0000_0000` and `.clamp` returned the same bits.
    ///
    /// Every vacuous mass function, and every target disjoint from all focal
    /// elements, hits this. Both functions now normalize at the return site.
    #[test]
    fn belief_and_plausibility_of_unsupported_target_are_positive_zero() {
        let frame = FrameOfDiscernment::new("t", vec!["a".into(), "b".into()]).unwrap();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::vacuous(), 1.0);
        let m = MassFunction::from_raw(frame, masses);
        let target = FocalElement::positive(BTreeSet::from([0]));

        let bel = belief(&m, &target);
        assert_eq!(bel, 0.0);
        assert!(bel.is_sign_positive(), "belief bits {:#x}", bel.to_bits());

        let pl = plausibility(&m, &target);
        assert!(
            pl.is_sign_positive(),
            "plausibility bits {:#x}",
            pl.to_bits()
        );
    }

    /// The all-conflict short circuit and the normalized path must agree on
    /// sign, so the divergence cache never sees `-0.0` from either exit.
    #[test]
    fn pignistic_all_conflict_returns_positive_zero() {
        let frame = FrameOfDiscernment::new("t", vec!["a".into(), "b".into()]).unwrap();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::positive(BTreeSet::new()), 1.0);
        let m = MassFunction::from_raw(frame, masses);

        let betp = pignistic_probability(&m, 0);
        assert_eq!(betp, 0.0);
        assert!(betp.is_sign_positive(), "bits {:#x}", betp.to_bits());
        assert_eq!(betp.to_bits(), normalize_unit_interval(-0.0).to_bits());
    }
}

#[cfg(test)]
mod proptest_properties {
    use crate::{
        combination,
        frame::FrameOfDiscernment,
        mass::{FocalElement, MassFunction},
        measures,
    };
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// Tolerance for floating-point comparisons in property tests
    const EPSILON: f64 = 1e-6;

    /// Strategy: generate a frame with 2-5 hypotheses
    fn arb_frame() -> impl Strategy<Value = FrameOfDiscernment> {
        (2usize..=5).prop_map(|n| {
            let hypotheses: Vec<String> = (0..n).map(|i| format!("h{i}")).collect();
            FrameOfDiscernment::new("prop_frame", hypotheses).unwrap()
        })
    }

    /// Strategy: generate a valid positive-only mass function on a given frame.
    ///
    /// Picks 1-4 random non-empty subsets, assigns random masses, normalizes to 1.0.
    /// Always includes Theta so the mass function is non-dogmatic.
    fn arb_mass_function(frame: FrameOfDiscernment) -> impl Strategy<Value = MassFunction> {
        let n = frame.hypothesis_count();
        // Generate 1-4 non-empty subsets as bitmasks, plus masses
        let max_focal = 4usize.min((1 << n) - 1);
        proptest::collection::vec((1usize..=(1 << n) - 1, 1u32..=1000), 1..=max_focal).prop_map(
            move |entries| {
                let mut masses: BTreeMap<FocalElement, f64> = BTreeMap::new();

                // Add each randomly generated subset
                for (mask, raw_mass) in &entries {
                    let mut subset = BTreeSet::new();
                    for bit in 0..n {
                        if mask & (1 << bit) != 0 {
                            subset.insert(bit);
                        }
                    }
                    let fe = FocalElement::positive(subset);
                    *masses.entry(fe).or_insert(0.0) += f64::from(*raw_mass);
                }

                // Always include Theta (ensures non-dogmatic + well-behaved BetP)
                let theta = FocalElement::theta(&frame);
                *masses.entry(theta).or_insert(0.0) += 1.0;

                // Normalize to sum to 1.0
                let total: f64 = masses.values().sum();
                for v in masses.values_mut() {
                    *v /= total;
                }

                // Remove zero-mass entries
                masses.retain(|_, v| *v > 0.0);

                MassFunction::from_raw(frame.clone(), masses)
            },
        )
    }

    /// Strategy: generate a frame and a mass function together
    fn arb_frame_and_mass() -> impl Strategy<Value = (FrameOfDiscernment, MassFunction)> {
        arb_frame().prop_flat_map(|frame| {
            let f = frame.clone();
            arb_mass_function(frame).prop_map(move |m| (f.clone(), m))
        })
    }

    /// Strategy: generate a frame and two mass functions on it
    fn arb_frame_and_two_masses(
    ) -> impl Strategy<Value = (FrameOfDiscernment, MassFunction, MassFunction)> {
        arb_frame().prop_flat_map(|frame| {
            let f1 = frame.clone();
            let f2 = frame.clone();
            (arb_mass_function(f1), arb_mass_function(f2))
                .prop_map(move |(m1, m2)| (frame.clone(), m1, m2))
        })
    }

    // ========================================================================
    // Property 1: Bel(A) <= Pl(A) for all mass functions and positive focal elements
    // ========================================================================

    proptest! {
        #[test]
        fn bel_leq_pl_for_all_positive_elements(
            (frame, m) in arb_frame_and_mass()
        ) {
            let n = frame.hypothesis_count();
            // Check every non-empty positive subset
            for mask in 1..(1usize << n) {
                let mut subset = BTreeSet::new();
                for bit in 0..n {
                    if mask & (1 << bit) != 0 {
                        subset.insert(bit);
                    }
                }
                let fe = FocalElement::positive(subset);
                let bel = measures::belief(&m, &fe);
                let pl = measures::plausibility(&m, &fe);
                prop_assert!(
                    bel <= pl + EPSILON,
                    "Bel({}) = {} > Pl({}) = {} (diff = {})",
                    fe, bel, fe, pl, bel - pl
                );
            }
        }
    }

    // ========================================================================
    // Property 2: BetP sums to 1.0 for all mass functions (within epsilon)
    // ========================================================================

    proptest! {
        #[test]
        fn betp_sums_to_one(
            (frame, m) in arb_frame_and_mass()
        ) {
            let n = frame.hypothesis_count();
            let total: f64 = (0..n)
                .map(|i| measures::pignistic_probability(&m, i))
                .sum();
            prop_assert!(
                (total - 1.0).abs() < EPSILON,
                "BetP sum = {} (expected 1.0, diff = {})",
                total, (total - 1.0).abs()
            );
        }
    }

    // ========================================================================
    // Property 3: conjunctive_combine is commutative for same-frame mass functions
    // ========================================================================

    proptest! {
        #[test]
        fn conjunctive_combine_is_commutative(
            (_frame, m1, m2) in arb_frame_and_two_masses()
        ) {
            let ab = combination::conjunctive_combine(&m1, &m2).unwrap();
            let ba = combination::conjunctive_combine(&m2, &m1).unwrap();

            // Compare every focal element's mass
            let mut all_keys: BTreeSet<FocalElement> = BTreeSet::new();
            for fe in ab.masses().keys() {
                all_keys.insert(fe.clone());
            }
            for fe in ba.masses().keys() {
                all_keys.insert(fe.clone());
            }

            for fe in &all_keys {
                let mass_ab = ab.mass_of(fe);
                let mass_ba = ba.mass_of(fe);
                prop_assert!(
                    (mass_ab - mass_ba).abs() < EPSILON,
                    "m1⊕m2({}) = {} != m2⊕m1({}) = {} (diff = {})",
                    fe, mass_ab, fe, mass_ba, (mass_ab - mass_ba).abs()
                );
            }
        }
    }

    // ========================================================================
    // Property 4: redistribute preserves total mass = 1.0 for all methods
    // ========================================================================

    proptest! {
        #[test]
        fn redistribute_preserves_total_mass(
            (_frame, m1, m2) in arb_frame_and_two_masses(),
            method_idx in 0u8..5,
        ) {
            let method = match method_idx {
                0 => combination::CombinationMethod::Conjunctive,
                1 => combination::CombinationMethod::YagerOpen,
                2 => combination::CombinationMethod::YagerClosed,
                3 => combination::CombinationMethod::DuboisPrade,
                4 => combination::CombinationMethod::Inagaki,
                _ => unreachable!(),
            };

            let result = combination::redistribute(&m1, &m2, method, Some(0.5));
            // Dempster can fail with TotalConflict, but these methods should not
            if let Ok(combined) = result {
                let total: f64 = combined.masses().values().sum();
                prop_assert!(
                    (total - 1.0).abs() < EPSILON,
                    "redistribute({:?}) total mass = {} (expected 1.0, diff = {})",
                    method, total, (total - 1.0).abs()
                );
            }
        }
    }

    // ========================================================================
    // Property 5: combining with vacuous is identity — m ⊕ vacuous = m
    // ========================================================================

    proptest! {
        #[test]
        fn combining_with_vacuous_is_identity(
            (frame, m) in arb_frame_and_mass()
        ) {
            let vacuous = MassFunction::vacuous(frame);
            let combined = combination::conjunctive_combine(&m, &vacuous).unwrap();

            // Every focal element in original should have same mass in combined
            let mut all_keys: BTreeSet<FocalElement> = BTreeSet::new();
            for fe in m.masses().keys() {
                all_keys.insert(fe.clone());
            }
            for fe in combined.masses().keys() {
                all_keys.insert(fe.clone());
            }

            for fe in &all_keys {
                let mass_orig = m.mass_of(fe);
                let mass_comb = combined.mass_of(fe);
                prop_assert!(
                    (mass_orig - mass_comb).abs() < EPSILON,
                    "m⊕vacuous({}) = {} != m({}) = {} (diff = {})",
                    fe, mass_comb, fe, mass_orig, (mass_orig - mass_comb).abs()
                );
            }
        }
    }

    /// Strategy: generate a frame and three mass functions on it
    fn arb_frame_and_three_masses(
    ) -> impl Strategy<Value = (FrameOfDiscernment, MassFunction, MassFunction, MassFunction)> {
        arb_frame().prop_flat_map(|frame| {
            let f1 = frame.clone();
            let f2 = frame.clone();
            let f3 = frame.clone();
            (
                arb_mass_function(f1),
                arb_mass_function(f2),
                arb_mass_function(f3),
            )
                .prop_map(move |(m1, m2, m3)| (frame.clone(), m1, m2, m3))
        })
    }

    // ========================================================================
    // Property 6: conjunctive_combine is associative (within floating-point tolerance)
    //   (m1 ⊕ m2) ⊕ m3 ≈ m1 ⊕ (m2 ⊕ m3)
    // ========================================================================

    proptest! {
        #[test]
        fn conjunctive_combine_is_associative(
            (_frame, m1, m2, m3) in arb_frame_and_three_masses()
        ) {
            let left = combination::conjunctive_combine(
                &combination::conjunctive_combine(&m1, &m2).unwrap(),
                &m3,
            ).unwrap();
            let right = combination::conjunctive_combine(
                &m1,
                &combination::conjunctive_combine(&m2, &m3).unwrap(),
            ).unwrap();

            // Compare every focal element's mass
            let mut all_keys: BTreeSet<FocalElement> = BTreeSet::new();
            for fe in left.masses().keys() {
                all_keys.insert(fe.clone());
            }
            for fe in right.masses().keys() {
                all_keys.insert(fe.clone());
            }

            for fe in &all_keys {
                let mass_left = left.mass_of(fe);
                let mass_right = right.mass_of(fe);
                prop_assert!(
                    (mass_left - mass_right).abs() < EPSILON,
                    "(m1⊕m2)⊕m3({}) = {} != m1⊕(m2⊕m3)({}) = {} (diff = {})",
                    fe, mass_left, fe, mass_right, (mass_left - mass_right).abs()
                );
            }
        }
    }
}
