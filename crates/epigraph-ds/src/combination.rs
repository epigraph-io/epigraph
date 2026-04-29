//! Evidence combination rules (CDST-aware)
//!
//! The conjunctive combination is the primitive. In CDST, intersection
//! uses the complement-aware algebra, distinguishing genuine conflict
//! `(empty, false)` from missing propositions `(Omega, true)`.
//!
//! Redistribution policies handle conflict mass:
//! - Dempster: normalize by `1 - K_c`
//! - `YagerOpen`: redirect `K_c` to `(empty, true)`
//! - `YagerClosed`: redirect `K_c` to `(Omega, false)`
//! - `DuboisPrade`: redirect to union of conflicting pairs
//! - `Inagaki(gamma)`: parameterized split

use crate::errors::DsError;
use crate::mass::{FocalElement, MassFunction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Tolerance for conflict detection
const CONFLICT_TOLERANCE: f64 = 1e-9;

/// Report from an adaptive combination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinationReport {
    /// Which combination method was used
    pub method_used: CombinationMethod,
    /// The conflict coefficient `K_c` (genuine conflict mass)
    pub conflict_k: f64,
    /// Mass on genuine conflict in the result
    pub mass_on_conflict: f64,
    /// Mass on missing propositions in the result
    pub mass_on_missing: f64,
}

/// Which combination method was applied
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CombinationMethod {
    /// Raw CDST conjunctive — conflict + missing preserved
    Conjunctive,
    /// Dempster's rule — normalize only by `K_c`, preserve missing
    Dempster,
    /// Yager open-world — redirect `K_c` to `(empty, true)`
    YagerOpen,
    /// Yager closed-world — redirect `K_c` to `(Omega, false)`
    YagerClosed,
    /// Dubois-Prade — redirect conflict to union of conflicting elements
    DuboisPrade,
    /// Inagaki — gamma-parameterized split
    Inagaki,
    /// Legacy TBM conjunctive (alias for Conjunctive)
    TbmConjunctive,
}

/// CDST intersection of two focal elements
///
/// | a.complement | b.complement | result |
/// |---|---|---|
/// | false | false | positive(a.subset AND b.subset) |
/// | false | true | positive(a.subset MINUS b.subset) |
/// | true | false | positive(b.subset MINUS a.subset) |
/// | true | true | negative(a.subset OR b.subset) |
#[must_use]
pub fn cdst_intersect(a: &FocalElement, b: &FocalElement) -> FocalElement {
    match (a.complement, b.complement) {
        (false, false) => {
            // Standard intersection
            let intersection: BTreeSet<usize> = a.subset.intersection(&b.subset).copied().collect();
            FocalElement::positive(intersection)
        }
        (false, true) => {
            // a \ b: elements in a but not in b
            let difference: BTreeSet<usize> = a.subset.difference(&b.subset).copied().collect();
            FocalElement::positive(difference)
        }
        (true, false) => {
            // b \ a: elements in b but not in a
            let difference: BTreeSet<usize> = b.subset.difference(&a.subset).copied().collect();
            FocalElement::positive(difference)
        }
        (true, true) => {
            // Complement of union
            let union: BTreeSet<usize> = a.subset.union(&b.subset).copied().collect();
            FocalElement::negative(union)
        }
    }
}

/// TBM/CDST conjunctive combination (unnormalized)
///
/// For each pair of focal elements A in m1, B in m2:
/// accumulate `m1(A) * m2(B)` onto `cdst_intersect(A, B)`.
/// Both genuine conflict and missing mass are preserved.
///
/// # Errors
/// Returns `DsError::IncompatibleFrames` if frames differ.
pub fn conjunctive_combine(m1: &MassFunction, m2: &MassFunction) -> Result<MassFunction, DsError> {
    check_frame_compat(m1, m2)?;

    let mut combined: BTreeMap<FocalElement, f64> = BTreeMap::new();

    for (a, &ma) in m1.masses() {
        for (b, &mb) in m2.masses() {
            if ma == 0.0 || mb == 0.0 {
                continue;
            }
            let result = cdst_intersect(a, b);
            *combined.entry(result).or_insert(0.0) += ma * mb;
        }
    }

    combined.retain(|_, v| *v > 0.0);

    Ok(MassFunction::from_raw(m1.frame().clone(), combined))
}

/// Result of conjunctive combination with conflict pair tracking
type TrackedResult = (BTreeMap<FocalElement, f64>, Vec<(FocalElement, f64)>);

/// Conjunctive combination with tracking of conflicting pairs
///
/// Returns the combined result plus a list of `(union_of_pair, conflict_mass)`
/// for use by Dubois-Prade redistribution.
fn conjunctive_combine_with_tracking(
    m1: &MassFunction,
    m2: &MassFunction,
) -> Result<TrackedResult, DsError> {
    check_frame_compat(m1, m2)?;

    let mut combined: BTreeMap<FocalElement, f64> = BTreeMap::new();
    let mut conflict_pairs: Vec<(FocalElement, f64)> = Vec::new();

    for (a, &ma) in m1.masses() {
        for (b, &mb) in m2.masses() {
            if ma == 0.0 || mb == 0.0 {
                continue;
            }
            let result = cdst_intersect(a, b);
            let mass = ma * mb;

            if result.is_conflict() {
                // Track the union of conflicting elements for Dubois-Prade
                let union_subset: BTreeSet<usize> = a.subset.union(&b.subset).copied().collect();
                conflict_pairs.push((FocalElement::positive(union_subset), mass));
            } else {
                *combined.entry(result).or_insert(0.0) += mass;
            }
        }
    }

    combined.retain(|_, v| *v > 0.0);

    Ok((combined, conflict_pairs))
}

/// Redistribute conflict mass according to a policy
///
/// Takes raw conjunctive result and handles `K_c` = `m((empty, false))`.
///
/// # Errors
/// - `DsError::TotalConflict` if Dempster normalization has `K_c` >= 1.0
/// - `DsError::InvalidDiscountFactor` if Inagaki gamma is out of [0, 1]
pub fn redistribute(
    m1: &MassFunction,
    m2: &MassFunction,
    method: CombinationMethod,
    gamma: Option<f64>,
) -> Result<MassFunction, DsError> {
    match method {
        CombinationMethod::Conjunctive | CombinationMethod::TbmConjunctive => {
            conjunctive_combine(m1, m2)
        }
        CombinationMethod::Dempster => dempster_combine(m1, m2),
        CombinationMethod::YagerOpen => yager_open_combine(m1, m2),
        CombinationMethod::YagerClosed => yager_closed_combine(m1, m2),
        CombinationMethod::DuboisPrade => dubois_prade_combine(m1, m2),
        CombinationMethod::Inagaki => {
            let g = gamma.unwrap_or(0.5);
            inagaki_combine(m1, m2, g)
        }
    }
}

/// Dempster's rule: normalize by dividing non-conflict masses by (1 - `K_c`)
///
/// Only normalizes genuine conflict `(empty, false)`. Missing mass `(Omega, true)`
/// is preserved.
///
/// # Errors
/// - `DsError::IncompatibleFrames` if frames differ
/// - `DsError::TotalConflict` if `K_c` >= 1.0
pub fn dempster_combine(m1: &MassFunction, m2: &MassFunction) -> Result<MassFunction, DsError> {
    let conj = conjunctive_combine(m1, m2)?;
    let k_c = conj.mass_of_conflict();

    if (k_c - 1.0).abs() < CONFLICT_TOLERANCE {
        return Err(DsError::TotalConflict);
    }

    let normalizer = 1.0 / (1.0 - k_c);
    let mut result_masses: BTreeMap<FocalElement, f64> = BTreeMap::new();

    for (fe, &mass) in conj.masses() {
        if fe.is_conflict() {
            continue; // Remove genuine conflict mass
        }
        let new_mass = mass * normalizer;
        if new_mass > 0.0 {
            result_masses.insert(fe.clone(), new_mass);
        }
    }

    Ok(MassFunction::from_raw(m1.frame().clone(), result_masses))
}

/// Yager open-world: redirect `K_c` to (empty, true) — open-world ignorance
fn yager_open_combine(m1: &MassFunction, m2: &MassFunction) -> Result<MassFunction, DsError> {
    let conj = conjunctive_combine(m1, m2)?;
    let k_c = conj.mass_of_conflict();

    let mut result_masses: BTreeMap<FocalElement, f64> = BTreeMap::new();

    for (fe, &mass) in conj.masses() {
        if fe.is_conflict() {
            continue;
        }
        if mass > 0.0 {
            result_masses.insert(fe.clone(), mass);
        }
    }

    if k_c > 0.0 {
        *result_masses.entry(FocalElement::vacuous()).or_insert(0.0) += k_c;
    }

    Ok(MassFunction::from_raw(m1.frame().clone(), result_masses))
}

/// Yager closed-world: redirect `K_c` to (Omega, false) — closed-world ignorance
fn yager_closed_combine(m1: &MassFunction, m2: &MassFunction) -> Result<MassFunction, DsError> {
    let conj = conjunctive_combine(m1, m2)?;
    let k_c = conj.mass_of_conflict();

    let mut result_masses: BTreeMap<FocalElement, f64> = BTreeMap::new();

    for (fe, &mass) in conj.masses() {
        if fe.is_conflict() {
            continue;
        }
        if mass > 0.0 {
            result_masses.insert(fe.clone(), mass);
        }
    }

    if k_c > 0.0 {
        let theta = FocalElement::theta(m1.frame());
        *result_masses.entry(theta).or_insert(0.0) += k_c;
    }

    Ok(MassFunction::from_raw(m1.frame().clone(), result_masses))
}

/// Dubois-Prade: redirect each conflict pair's mass to the union of its sources
fn dubois_prade_combine(m1: &MassFunction, m2: &MassFunction) -> Result<MassFunction, DsError> {
    let (mut combined, conflict_pairs) = conjunctive_combine_with_tracking(m1, m2)?;

    for (union_fe, mass) in conflict_pairs {
        *combined.entry(union_fe).or_insert(0.0) += mass;
    }

    combined.retain(|_, v| *v > 0.0);

    Ok(MassFunction::from_raw(m1.frame().clone(), combined))
}

/// Inagaki: (1-gamma) proportional redistribution + gamma to (Omega, true)
///
/// # Errors
/// Returns `DsError::InvalidDiscountFactor` if gamma is outside [0, 1].
fn inagaki_combine(
    m1: &MassFunction,
    m2: &MassFunction,
    gamma: f64,
) -> Result<MassFunction, DsError> {
    if !(0.0..=1.0).contains(&gamma) || gamma.is_nan() {
        return Err(DsError::InvalidDiscountFactor { alpha: gamma });
    }

    let conj = conjunctive_combine(m1, m2)?;
    let k_c = conj.mass_of_conflict();

    if k_c < CONFLICT_TOLERANCE {
        // No conflict to redistribute — return conjunctive as-is
        return Ok(conj);
    }

    let mut result_masses: BTreeMap<FocalElement, f64> = BTreeMap::new();

    // Sum of non-conflict masses for proportional redistribution
    let non_conflict_sum: f64 = conj
        .masses()
        .iter()
        .filter(|(fe, _)| !fe.is_conflict())
        .map(|(_, &m)| m)
        .sum();

    let proportional_share = (1.0 - gamma) * k_c;
    let missing_share = gamma * k_c;

    for (fe, &mass) in conj.masses() {
        if fe.is_conflict() {
            continue;
        }
        let mut new_mass = mass;
        // Proportional redistribution
        if non_conflict_sum > CONFLICT_TOLERANCE {
            new_mass += proportional_share * (mass / non_conflict_sum);
        }
        if new_mass > 0.0 {
            result_masses.insert(fe.clone(), new_mass);
        }
    }

    // Redirect gamma portion to missing (Omega, true)
    if missing_share > 0.0 {
        let missing = FocalElement::missing(m1.frame());
        *result_masses.entry(missing).or_insert(0.0) += missing_share;
    }

    // Handle edge case: no non-conflict mass + gamma < 1 => remainder to missing
    if non_conflict_sum < CONFLICT_TOLERANCE && proportional_share > 0.0 {
        let missing = FocalElement::missing(m1.frame());
        *result_masses.entry(missing).or_insert(0.0) += proportional_share;
    }

    Ok(MassFunction::from_raw(m1.frame().clone(), result_masses))
}

/// Reliability discounting
///
/// Weakens a mass function by factor `alpha in [0, 1]`:
/// - `alpha = 1` -> unchanged (fully reliable)
/// - `alpha = 0` -> vacuous (completely unreliable)
///
/// For A != Theta: `m_disc(A) = alpha * m(A)`
/// For Theta: `m_disc(Theta) = 1 - alpha + alpha * m(Theta)`
///
/// # Errors
/// Returns `DsError::InvalidDiscountFactor` if alpha is outside [0, 1].
pub fn discount(m: &MassFunction, alpha: f64) -> Result<MassFunction, DsError> {
    if !(0.0..=1.0).contains(&alpha) || alpha.is_nan() {
        return Err(DsError::InvalidDiscountFactor { alpha });
    }

    let theta = FocalElement::theta(m.frame());
    let mut discounted: BTreeMap<FocalElement, f64> = BTreeMap::new();

    for (fe, &mass) in m.masses() {
        if *fe == theta {
            continue; // Handle Theta separately
        }
        let new_mass = alpha * mass;
        if new_mass > 0.0 {
            discounted.insert(fe.clone(), new_mass);
        }
    }

    // Theta gets the remaining mass
    let theta_mass = alpha.mul_add(m.mass_of(&theta), 1.0 - alpha);
    if theta_mass > 0.0 {
        discounted.insert(theta, theta_mass);
    }

    Ok(MassFunction::from_raw(m.frame().clone(), discounted))
}

/// Compute the conflict coefficient K between two mass functions
///
/// K = sum `m1(A)` * `m2(B)` for all pairs where `cdst_intersect(A,B)` is conflict
///
/// # Errors
/// Returns `DsError::IncompatibleFrames` if frames differ.
pub fn conflict_coefficient(m1: &MassFunction, m2: &MassFunction) -> Result<f64, DsError> {
    check_frame_compat(m1, m2)?;

    let mut k = 0.0;
    for (a, &ma) in m1.masses() {
        for (b, &mb) in m2.masses() {
            if ma == 0.0 || mb == 0.0 {
                continue;
            }
            let result = cdst_intersect(a, b);
            if result.is_conflict() {
                k += ma * mb;
            }
        }
    }

    Ok(k)
}

/// Which combination rule to use, selected adaptively based on conflict and open-world fraction
///
/// This is the output of [`select_combination_rule`] and drives [`combine_multiple`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CombinationRule {
    /// Low conflict: Dempster normalization is safe
    Dempster,
    /// Moderate conflict: preserve conflict info via CDST conjunctive
    CdstConjunctive,
    /// High conflict + open-world mass: redirect conflict to open-world ignorance
    YagerOpen,
    /// High conflict + closed-world: Inagaki parametric redistribution
    Inagaki,
}

/// Select the appropriate combination rule based on conflict level and open-world fraction
///
/// Decision boundaries:
/// - K < 0.1: low conflict, Dempster normalization is safe
/// - 0.1 <= K < 0.5: moderate conflict, preserve via CDST conjunctive
/// - K >= 0.5 + open-world fraction > 0.03: redirect to open-world ignorance (Yager)
/// - K >= 0.5 + closed world: Inagaki parametric redistribution
#[must_use]
pub fn select_combination_rule(conflict_k: f64, open_world_fraction: f64) -> CombinationRule {
    if conflict_k < 0.1 {
        CombinationRule::Dempster
    } else if conflict_k < 0.5 {
        CombinationRule::CdstConjunctive
    } else if open_world_fraction > 0.03 {
        CombinationRule::YagerOpen
    } else {
        CombinationRule::Inagaki
    }
}

/// Adaptive combination: choose method based on conflict level
///
/// - If K < `conflict_threshold` -> Dempster's rule
/// - If K >= `conflict_threshold` -> CDST conjunctive (preserves conflict info)
///
/// # Errors
/// - `DsError::IncompatibleFrames` if frames differ
/// - `DsError::TotalConflict` if K ≈ 1.0 and Dempster's rule is selected
pub fn adaptive_combine(
    m1: &MassFunction,
    m2: &MassFunction,
    conflict_threshold: f64,
) -> Result<(MassFunction, CombinationReport), DsError> {
    let k = conflict_coefficient(m1, m2)?;

    if k < conflict_threshold {
        let result = dempster_combine(m1, m2)?;
        let report = CombinationReport {
            method_used: CombinationMethod::Dempster,
            conflict_k: k,
            mass_on_conflict: 0.0,
            mass_on_missing: result.mass_of_missing(),
        };
        Ok((result, report))
    } else {
        let result = conjunctive_combine(m1, m2)?;
        let report = CombinationReport {
            method_used: CombinationMethod::Conjunctive,
            conflict_k: k,
            mass_on_conflict: result.mass_of_conflict(),
            mass_on_missing: result.mass_of_missing(),
        };
        Ok((result, report))
    }
}

/// Combine multiple mass functions by pairwise adaptive folding
///
/// For each pairwise step, computes the conflict coefficient K and the
/// open-world fraction of the accumulated result, then uses
/// [`select_combination_rule`] to pick the best rule:
///
/// - Low K → Dempster (normalize away small conflict)
/// - Moderate K → CDST conjunctive (preserve conflict info)
/// - High K + open world → Yager open (redirect to ignorance)
/// - High K + closed world → Inagaki (parametric redistribution)
///
/// The `_conflict_threshold` parameter is retained for backward compatibility
/// but is no longer used; rule selection is fully adaptive.
///
/// # Errors
/// - `DsError::InsufficientSources` if `masses` is empty
/// - `DsError::IncompatibleFrames` if any frames differ
/// - `DsError::TotalConflict` if pairwise Dempster combination hits K ≈ 1.0
pub fn combine_multiple(
    masses: &[MassFunction],
    _conflict_threshold: f64,
) -> Result<(MassFunction, Vec<CombinationReport>), DsError> {
    if masses.is_empty() {
        return Err(DsError::InsufficientSources);
    }

    if masses.len() == 1 {
        return Ok((masses[0].clone(), Vec::new()));
    }

    let mut accumulated = masses[0].clone();
    let mut reports = Vec::with_capacity(masses.len() - 1);

    for m in &masses[1..] {
        let k = conflict_coefficient(&accumulated, m)?;
        let owf = accumulated.open_world_fraction();
        let rule = select_combination_rule(k, owf);

        let (combined, method_used) = match rule {
            CombinationRule::Dempster => {
                let result = dempster_combine(&accumulated, m)?;
                (result, CombinationMethod::Dempster)
            }
            CombinationRule::CdstConjunctive => {
                let result = conjunctive_combine(&accumulated, m)?;
                (result, CombinationMethod::Conjunctive)
            }
            CombinationRule::YagerOpen => {
                // Route conflict to missing=(Omega,true) not vacuous=(empty,true).
                // Vacuous is a neutral pass-through in cdst_intersect: it distributes
                // to Theta in subsequent steps, inflating Pl regardless of refutation
                // (the one-way ratchet). Missing creates genuine conflict with all
                // positives, so Pl contracts correctly as contradicting evidence accumulates.
                // Inagaki(γ=1.0) sends all conflict K to missing — equivalent semantics
                // to YagerOpen's open-world intent but without the ratchet.
                let result = inagaki_combine(&accumulated, m, 1.0)?;
                (result, CombinationMethod::Inagaki)
            }
            CombinationRule::Inagaki => {
                let result = inagaki_combine(&accumulated, m, 0.5)?;
                (result, CombinationMethod::Inagaki)
            }
        };

        reports.push(CombinationReport {
            method_used,
            conflict_k: k,
            mass_on_conflict: combined.mass_of_conflict(),
            mass_on_missing: combined.mass_of_missing(),
        });

        accumulated = combined;
    }

    Ok((accumulated, reports))
}

/// Apply a context modifier to a mass function
///
/// # Modifier Types
///
/// - `"filter"` — Zero out mass on hypotheses not matching a parameter predicate.
/// - `"discount"` — Apply an additional reliability discount based on context.
/// - `"temporal_decay"` — Reduce mass proportional to evidence age.
///
/// # Errors
/// Returns `DsError::InvalidDiscountFactor` if computed discount is out of range.
pub fn apply_context_modifier(
    m: &MassFunction,
    modifier_type: &str,
    params: &serde_json::Value,
) -> Result<MassFunction, DsError> {
    match modifier_type {
        "filter" => {
            #[allow(clippy::cast_possible_truncation)]
            let keep_indices: BTreeSet<usize> = params
                .get("keep_indices")
                .and_then(|v| v.as_array())
                .map_or_else(
                    || m.frame().full_set(),
                    |arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|n| n as usize))
                            .collect()
                    },
                );

            if keep_indices.is_empty() {
                return Ok(MassFunction::vacuous(m.frame().clone()));
            }

            let theta = FocalElement::theta(m.frame());
            let mut filtered: BTreeMap<FocalElement, f64> = BTreeMap::new();
            let mut redistributed = 0.0;

            for (fe, &mass) in m.masses() {
                if fe.is_conflict() {
                    // Preserve genuine conflict
                    *filtered.entry(FocalElement::conflict()).or_insert(0.0) += mass;
                    continue;
                }
                if fe.complement {
                    // Complement elements pass through (they reference what's excluded)
                    *filtered.entry(fe.clone()).or_insert(0.0) += mass;
                    continue;
                }
                // Positive elements: filter by kept indices
                if fe.subset.is_subset(&keep_indices) {
                    *filtered.entry(fe.clone()).or_insert(0.0) += mass;
                } else {
                    let intersection: BTreeSet<usize> =
                        fe.subset.intersection(&keep_indices).copied().collect();
                    if intersection.is_empty() {
                        redistributed += mass;
                    } else {
                        *filtered
                            .entry(FocalElement::positive(intersection))
                            .or_insert(0.0) += mass;
                    }
                }
            }

            if redistributed > 0.0 {
                *filtered.entry(theta).or_insert(0.0) += redistributed;
            }

            Ok(MassFunction::from_raw(m.frame().clone(), filtered))
        }
        "discount" => {
            let factor = params
                .get("factor")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(1.0);
            discount(m, factor)
        }
        "temporal_decay" => {
            let age = params
                .get("age_seconds")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0);
            let window = params
                .get("window_seconds")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(1.0);

            let decay_factor = if window <= 0.0 {
                0.0
            } else {
                (1.0 - age / window).clamp(0.0, 1.0)
            };

            discount(m, decay_factor)
        }
        _ => Ok(m.clone()),
    }
}

/// Cautious combination rule (Denoeux 2008 min-rule)
///
/// For non-independent sources. Uses minimum of commonality functions.
///
/// Note: operates on classical (positive-only) mass functions.
/// CDST extension of cautious rule is deferred.
///
/// # Errors
/// - `DsError::IncompatibleFrames` if frames differ.
pub fn cautious_combine(m1: &MassFunction, m2: &MassFunction) -> Result<MassFunction, DsError> {
    use crate::measures::commonality;

    check_frame_compat(m1, m2)?;

    let frame = m1.frame();
    let power_set = frame.power_set()?;

    // 1. Compute combined commonality: q(A) = min(q1(A), q2(A))
    let mut q_combined: BTreeMap<FocalElement, f64> = BTreeMap::new();
    for subset in &power_set {
        let fe = FocalElement::positive(subset.clone());
        let q1 = commonality(m1, &fe);
        let q2 = commonality(m2, &fe);
        q_combined.insert(fe, q1.min(q2));
    }
    // q(empty) = 1.0 by convention
    q_combined.insert(FocalElement::conflict(), 1.0);

    // 2. Moebius inversion: m(A) = sum (-1)^{|B\A|} q(B) for B containing A
    let mut masses: BTreeMap<FocalElement, f64> = BTreeMap::new();

    let mut all_subsets: Vec<FocalElement> = power_set
        .iter()
        .map(|s| FocalElement::positive(s.clone()))
        .collect();
    all_subsets.push(FocalElement::conflict());

    for a in &all_subsets {
        let mut m_a = 0.0;
        for b in &all_subsets {
            if a.subset.is_subset(&b.subset) {
                let diff_card = b.subset.len() - a.subset.len();
                let sign = if diff_card % 2 == 0 { 1.0 } else { -1.0 };
                let q_b = q_combined.get(b).copied().unwrap_or(0.0);
                m_a += sign * q_b;
            }
        }
        if m_a > 1e-12 {
            masses.insert(a.clone(), m_a);
        }
    }

    Ok(MassFunction::from_raw(frame.clone(), masses))
}

/// Cross-frame combination
///
/// Builds the union frame from both mass functions' frames, reindexes both
/// to the union frame, then combines using the specified method.
///
/// # Errors
/// - `DsError::IncompatibleFrames` if reindexing fails
/// - Propagates errors from the chosen combination method
pub fn cross_frame_combine(
    m1: &MassFunction,
    m2: &MassFunction,
    method: CombinationMethod,
    gamma: Option<f64>,
) -> Result<MassFunction, DsError> {
    let union_frame = m1.frame().union(m2.frame());
    let m1_reindexed = m1.reindex_to_frame(&union_frame)?;
    let m2_reindexed = m2.reindex_to_frame(&union_frame)?;
    redistribute(&m1_reindexed, &m2_reindexed, method, gamma)
}

/// Check that two mass functions are defined on the same frame
fn check_frame_compat(m1: &MassFunction, m2: &MassFunction) -> Result<(), DsError> {
    if m1.frame().id != m2.frame().id {
        return Err(DsError::IncompatibleFrames {
            left: m1.frame().id.clone(),
            right: m2.frame().id.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameOfDiscernment;

    fn binary_frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("test", vec!["true".into(), "false".into()]).unwrap()
    }

    fn ternary_frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("tri", vec!["a".into(), "b".into(), "c".into()]).unwrap()
    }

    // ======== CDST intersection ========

    #[test]
    fn cdst_intersect_positive_positive() {
        // (false, false) -> standard intersection
        let a = FocalElement::positive(BTreeSet::from([0, 1]));
        let b = FocalElement::positive(BTreeSet::from([1, 2]));
        let result = cdst_intersect(&a, &b);
        assert_eq!(result, FocalElement::positive(BTreeSet::from([1])));
        assert!(!result.complement);
    }

    #[test]
    fn cdst_intersect_positive_negative() {
        // (false, true) -> a \ b
        let a = FocalElement::positive(BTreeSet::from([0, 1, 2]));
        let b = FocalElement::negative(BTreeSet::from([1]));
        let result = cdst_intersect(&a, &b);
        assert_eq!(result, FocalElement::positive(BTreeSet::from([0, 2])));
    }

    #[test]
    fn cdst_intersect_negative_positive() {
        // (true, false) -> b \ a
        let a = FocalElement::negative(BTreeSet::from([1]));
        let b = FocalElement::positive(BTreeSet::from([0, 1, 2]));
        let result = cdst_intersect(&a, &b);
        assert_eq!(result, FocalElement::positive(BTreeSet::from([0, 2])));
    }

    #[test]
    fn cdst_intersect_negative_negative() {
        // (true, true) -> negative(a | b)
        let a = FocalElement::negative(BTreeSet::from([0]));
        let b = FocalElement::negative(BTreeSet::from([1]));
        let result = cdst_intersect(&a, &b);
        assert_eq!(result, FocalElement::negative(BTreeSet::from([0, 1])));
        assert!(result.complement);
    }

    // ======== Conjunctive combination ========

    #[test]
    fn conjunctive_two_agreeing_sources() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.8).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();

        let result = conjunctive_combine(&m1, &m2).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let theta = FocalElement::theta(result.frame());
        let m_true = result.mass_of(&fe0);
        let m_theta = result.mass_of(&theta);
        assert!((m_true - 0.92).abs() < 1e-10);
        assert!((m_theta - 0.08).abs() < 1e-10);
    }

    #[test]
    fn conjunctive_conflicting_sources() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let result = conjunctive_combine(&m1, &m2).unwrap();
        assert!((result.mass_of_conflict() - 0.81).abs() < 1e-10);
    }

    #[test]
    fn conjunctive_with_vacuous_is_identity() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let vacuous = MassFunction::vacuous(frame);

        let result = conjunctive_combine(&m1, &vacuous).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let theta = FocalElement::theta(result.frame());
        assert!((result.mass_of(&fe0) - 0.7).abs() < 1e-10);
        assert!((result.mass_of(&theta) - 0.3).abs() < 1e-10);
    }

    #[test]
    fn conjunctive_with_mixed_positive_negative() {
        // Source 1: m({0}, false) = 0.8, m(Theta, false) = 0.2
        // Source 2: m({0}, true) = 0.6, m(Theta, false) = 0.4
        // Intersections:
        //   ({0},f) x (~{0},t) = {0} \ {0} = (empty, false) -> conflict: 0.8*0.6 = 0.48
        //   ({0},f) x (Theta,f) = {0} & Theta = ({0}, false): 0.8*0.4 = 0.32
        //   (Theta,f) x (~{0},t) = Theta \ {0} = ({1}, false): 0.2*0.6 = 0.12
        //   (Theta,f) x (Theta,f) = (Theta, false): 0.2*0.4 = 0.08
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.8).unwrap();
        let m2 = MassFunction::simple_negative(frame.clone(), BTreeSet::from([0]), 0.6).unwrap();

        let result = conjunctive_combine(&m1, &m2).unwrap();
        assert!((result.mass_of_conflict() - 0.48).abs() < 1e-10);
        assert!(
            (result.mass_of(&FocalElement::positive(BTreeSet::from([0]))) - 0.32).abs() < 1e-10
        );
        assert!(
            (result.mass_of(&FocalElement::positive(BTreeSet::from([1]))) - 0.12).abs() < 1e-10
        );
    }

    // ======== Dempster's rule ========

    #[test]
    fn dempster_normalizes_conflict() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let result = dempster_combine(&m1, &m2).unwrap();
        assert!(result.mass_of_conflict() < 1e-10);

        let total: f64 = result.masses().values().sum();
        assert!((total - 1.0).abs() < 1e-10);
    }

    #[test]
    fn dempster_total_conflict_errors() {
        let frame = binary_frame();
        let m1 = MassFunction::categorical(frame.clone(), 0).unwrap();
        let m2 = MassFunction::categorical(frame, 1).unwrap();

        let result = dempster_combine(&m1, &m2);
        assert!(matches!(result, Err(DsError::TotalConflict)));
    }

    #[test]
    fn dempster_with_vacuous_is_identity() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let vacuous = MassFunction::vacuous(frame);

        let result = dempster_combine(&m1, &vacuous).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let theta = FocalElement::theta(result.frame());
        assert!((result.mass_of(&fe0) - 0.7).abs() < 1e-10);
        assert!((result.mass_of(&theta) - 0.3).abs() < 1e-10);
    }

    #[test]
    fn dempster_is_not_idempotent() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));

        let result = dempster_combine(&m, &m).unwrap();
        let original_mass = m.mass_of(&fe0);
        let combined_mass = result.mass_of(&fe0);

        assert!(
            combined_mass > original_mass,
            "Dempster combination should reinforce: {combined_mass} > {original_mass}"
        );
    }

    // ======== Redistribution policies ========

    #[test]
    fn yager_open_redirects_to_vacuous() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let result = yager_open_combine(&m1, &m2).unwrap();
        assert!(result.mass_of_conflict() < 1e-10);
        // `K_c` = 0.81 redirected to (empty, true)
        let vacuous_mass = result.mass_of(&FocalElement::vacuous());
        assert!((vacuous_mass - 0.81).abs() < 1e-10);
    }

    #[test]
    fn yager_closed_redirects_to_theta() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let result = yager_closed_combine(&m1, &m2).unwrap();
        assert!(result.mass_of_conflict() < 1e-10);
        let theta = FocalElement::theta(result.frame());
        // Theta gets: 0.1*0.1 original + 0.81 redirected = 0.82
        let theta_mass = result.mass_of(&theta);
        assert!((theta_mass - 0.82).abs() < 1e-10);
    }

    #[test]
    fn dubois_prade_redirects_to_union() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let result = dubois_prade_combine(&m1, &m2).unwrap();
        assert!(result.mass_of_conflict() < 1e-10);
        // Conflict between {0} and {1} -> redirected to {0,1} = Theta
        let theta = FocalElement::theta(result.frame());
        let theta_mass = result.mass_of(&theta);
        // 0.81 conflict + 0.01 original Theta*Theta = 0.82
        assert!((theta_mass - 0.82).abs() < 1e-10);
    }

    #[test]
    fn inagaki_gamma_zero_matches_proportional() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let result = inagaki_combine(&m1, &m2, 0.0).unwrap();
        // gamma=0 -> all conflict proportionally redistributed
        assert!(result.mass_of_conflict() < 1e-10);
        assert!(result.mass_of_missing() < 1e-10);
        let total: f64 = result.masses().values().sum();
        assert!((total - 1.0).abs() < 1e-10);
    }

    #[test]
    fn inagaki_gamma_one_all_to_missing() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let result = inagaki_combine(&m1, &m2, 1.0).unwrap();
        // gamma=1 -> all conflict to (Omega, true) missing
        assert!(result.mass_of_conflict() < 1e-10);
        let missing_mass = result.mass_of_missing();
        assert!((missing_mass - 0.81).abs() < 1e-10);
    }

    #[test]
    fn redistribute_dispatches_correctly() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();

        // Dempster via redistribute should match direct call
        let r1 = redistribute(&m1, &m2, CombinationMethod::Dempster, None).unwrap();
        let r2 = dempster_combine(&m1, &m2).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((r1.mass_of(&fe0) - r2.mass_of(&fe0)).abs() < 1e-10);
    }

    // ======== Zadeh's counterexample ========

    #[test]
    fn zadeh_counterexample_tbm_preserves_conflict() {
        let frame = FrameOfDiscernment::new(
            "diagnosis",
            vec!["meningitis".into(), "concussion".into(), "tumor".into()],
        )
        .unwrap();

        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.99).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.99).unwrap();

        let tbm_result = conjunctive_combine(&m1, &m2).unwrap();
        let k = tbm_result.mass_of_conflict();
        assert!(k > 0.98, "Conflict should be very high: {k}");

        let dempster_result = dempster_combine(&m1, &m2).unwrap();
        assert!(dempster_result.mass_of_conflict() < 1e-10);
        let total: f64 = dempster_result.masses().values().sum();
        assert!((total - 1.0).abs() < 1e-10);
    }

    // ======== Reliability discounting ========

    #[test]
    fn discount_alpha_zero_gives_vacuous() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.8).unwrap();
        let discounted = discount(&m, 0.0).unwrap();
        assert!(discounted.is_vacuous());
    }

    #[test]
    fn discount_alpha_one_is_identity() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.8).unwrap();
        let discounted = discount(&m, 1.0).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((discounted.mass_of(&fe0) - 0.8).abs() < 1e-10);
    }

    #[test]
    fn discount_half_reliability() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.8).unwrap();
        let discounted = discount(&m, 0.5).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let theta = FocalElement::theta(discounted.frame());
        assert!((discounted.mass_of(&fe0) - 0.4).abs() < 1e-10);
        assert!((discounted.mass_of(&theta) - 0.6).abs() < 1e-10);
    }

    #[test]
    fn discount_invalid_alpha() {
        let frame = binary_frame();
        let m = MassFunction::vacuous(frame);
        assert!(matches!(
            discount(&m, -0.1),
            Err(DsError::InvalidDiscountFactor { .. })
        ));
        assert!(matches!(
            discount(&m, 1.5),
            Err(DsError::InvalidDiscountFactor { .. })
        ));
    }

    // ======== Conflict coefficient ========

    #[test]
    fn conflict_coefficient_no_conflict() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.8).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();

        let k = conflict_coefficient(&m1, &m2).unwrap();
        assert!(
            k < 1e-10,
            "Same-hypothesis sources should have zero conflict: {k}"
        );
    }

    #[test]
    fn conflict_coefficient_full_conflict() {
        let frame = binary_frame();
        let m1 = MassFunction::categorical(frame.clone(), 0).unwrap();
        let m2 = MassFunction::categorical(frame, 1).unwrap();

        let k = conflict_coefficient(&m1, &m2).unwrap();
        assert!((k - 1.0).abs() < 1e-10, "Total conflict should be 1.0: {k}");
    }

    #[test]
    fn conflict_coefficient_partial() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let k = conflict_coefficient(&m1, &m2).unwrap();
        assert!((k - 0.81).abs() < 1e-10);
    }

    // ======== Frame compatibility ========

    #[test]
    fn incompatible_frames_rejected() {
        let f1 = binary_frame();
        let f2 = ternary_frame();
        let m1 = MassFunction::vacuous(f1);
        let m2 = MassFunction::vacuous(f2);

        assert!(matches!(
            conjunctive_combine(&m1, &m2),
            Err(DsError::IncompatibleFrames { .. })
        ));
        assert!(matches!(
            dempster_combine(&m1, &m2),
            Err(DsError::IncompatibleFrames { .. })
        ));
        assert!(matches!(
            conflict_coefficient(&m1, &m2),
            Err(DsError::IncompatibleFrames { .. })
        ));
    }

    // ======== Multi-source combination ========

    #[test]
    fn combine_multiple_empty_errors() {
        let result = combine_multiple(&[], 0.3);
        assert!(matches!(result, Err(DsError::InsufficientSources)));
    }

    #[test]
    fn combine_multiple_single_returns_clone() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();

        let (result, reports) = combine_multiple(&[m.clone()], 0.3).unwrap();
        assert!(reports.is_empty());
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((result.mass_of(&fe0) - 0.7).abs() < 1e-10);
    }

    #[test]
    fn combine_multiple_two_sources_matches_pairwise() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();

        let (multi_result, reports) = combine_multiple(&[m1.clone(), m2.clone()], 0.3).unwrap();
        let (pair_result, _) = adaptive_combine(&m1, &m2, 0.3).unwrap();

        assert_eq!(reports.len(), 1);
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let multi_mass = multi_result.mass_of(&fe0);
        let pair_mass = pair_result.mass_of(&fe0);
        assert!(
            (multi_mass - pair_mass).abs() < 1e-10,
            "Multi and pairwise should match: {multi_mass} vs {pair_mass}"
        );
    }

    #[test]
    fn combine_multiple_three_sources_reinforces() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.6).unwrap();
        let m2 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.5).unwrap();
        let m3 = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();

        let (result, reports) = combine_multiple(&[m1, m2, m3], 0.3).unwrap();
        assert_eq!(reports.len(), 2);
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let mass_true = result.mass_of(&fe0);
        assert!(
            mass_true > 0.9,
            "Three agreeing sources should reinforce: {mass_true}"
        );
    }

    #[test]
    fn combine_multiple_incompatible_frames_errors() {
        let f1 = binary_frame();
        let f2 = ternary_frame();
        let m1 = MassFunction::vacuous(f1);
        let m2 = MassFunction::vacuous(f2);

        let result = combine_multiple(&[m1, m2], 0.3);
        assert!(matches!(result, Err(DsError::IncompatibleFrames { .. })));
    }

    // ======== Adaptive combination ========

    #[test]
    fn adaptive_low_conflict_uses_dempster() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();

        let (_, report) = adaptive_combine(&m1, &m2, 0.3).unwrap();
        assert_eq!(report.method_used, CombinationMethod::Dempster);
        assert!(report.conflict_k < 0.3);
        assert!(report.mass_on_conflict.abs() < 1e-10);
    }

    #[test]
    fn adaptive_high_conflict_uses_conjunctive() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let (result, report) = adaptive_combine(&m1, &m2, 0.3).unwrap();
        assert_eq!(report.method_used, CombinationMethod::Conjunctive);
        assert!(report.conflict_k > 0.3);
        assert!(result.mass_of_conflict() > 0.0);
    }

    // ======== Context modifiers ========

    #[test]
    fn context_modifier_filter_keeps_subset() {
        let frame = ternary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();

        let params = serde_json::json!({"keep_indices": [0, 1]});
        let filtered = apply_context_modifier(&m, "filter", &params).unwrap();

        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((filtered.mass_of(&fe0) - 0.7).abs() < 1e-10);
    }

    #[test]
    fn context_modifier_filter_redistributes_excluded() {
        let frame = ternary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([2]), 0.6).unwrap();

        let params = serde_json::json!({"keep_indices": [0, 1]});
        let filtered = apply_context_modifier(&m, "filter", &params).unwrap();

        let fe2 = FocalElement::positive(BTreeSet::from([2]));
        assert!(filtered.mass_of(&fe2) < 1e-10);
        let theta = FocalElement::theta(filtered.frame());
        let theta_mass = filtered.mass_of(&theta);
        assert!(
            theta_mass > 0.5,
            "Excluded mass should go to Theta: {theta_mass}"
        );
    }

    #[test]
    fn context_modifier_discount_applies_factor() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.8).unwrap();

        let params = serde_json::json!({"factor": 0.5});
        let discounted = apply_context_modifier(&m, "discount", &params).unwrap();

        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((discounted.mass_of(&fe0) - 0.4).abs() < 1e-10);
    }

    #[test]
    fn context_modifier_temporal_decay_half_age() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.8).unwrap();

        let params = serde_json::json!({"age_seconds": 50.0, "window_seconds": 100.0});
        let decayed = apply_context_modifier(&m, "temporal_decay", &params).unwrap();

        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((decayed.mass_of(&fe0) - 0.4).abs() < 1e-10);
    }

    #[test]
    fn context_modifier_temporal_decay_expired() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.8).unwrap();

        let params = serde_json::json!({"age_seconds": 200.0, "window_seconds": 100.0});
        let decayed = apply_context_modifier(&m, "temporal_decay", &params).unwrap();

        assert!(decayed.is_vacuous());
    }

    #[test]
    fn context_modifier_unknown_type_is_noop() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();

        let params = serde_json::json!({});
        let result = apply_context_modifier(&m, "nonexistent", &params).unwrap();

        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((result.mass_of(&fe0) - 0.7).abs() < 1e-10);
    }

    // ======== Cautious combination ========

    #[test]
    fn cautious_with_vacuous_is_identity() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let vacuous = MassFunction::vacuous(frame);

        let result = cautious_combine(&m, &vacuous).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!(
            (result.mass_of(&fe0) - 0.7).abs() < 1e-10,
            "Cautious with vacuous should be identity, got {}",
            result.mass_of(&fe0)
        );
    }

    #[test]
    fn cautious_is_idempotent() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));

        let result = cautious_combine(&m, &m).unwrap();
        let original_mass = m.mass_of(&fe0);
        let combined_mass = result.mass_of(&fe0);

        assert!(
            (combined_mass - original_mass).abs() < 1e-10,
            "Cautious combination should be idempotent: {combined_mass} vs {original_mass}",
        );
    }

    #[test]
    fn cautious_incompatible_frames_errors() {
        let f1 = binary_frame();
        let f2 = ternary_frame();
        let m1 = MassFunction::vacuous(f1);
        let m2 = MassFunction::vacuous(f2);

        assert!(matches!(
            cautious_combine(&m1, &m2),
            Err(DsError::IncompatibleFrames { .. })
        ));
    }

    // ======== Tolerance boundary tests ========

    #[test]
    fn discount_at_epsilon_reliability() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.8).unwrap();
        let eps = 1e-9;

        let discounted = discount(&m, eps).unwrap();
        let theta = FocalElement::theta(discounted.frame());
        let theta_mass = discounted.mass_of(&theta);
        assert!(
            (theta_mass - 1.0).abs() < 1e-6,
            "Near-zero reliability should yield near-vacuous: Theta mass = {theta_mass}"
        );
    }

    #[test]
    fn discount_at_near_one_reliability() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.8).unwrap();
        let alpha = 1.0 - 1e-9;

        let discounted = discount(&m, alpha).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let focal_mass = discounted.mass_of(&fe0);
        assert!(
            (focal_mass - 0.8).abs() < 1e-6,
            "Near-one reliability should preserve mass: {focal_mass}"
        );
    }

    #[test]
    fn combination_near_total_conflict_just_below_threshold() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.999).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.999).unwrap();

        let k = conflict_coefficient(&m1, &m2).unwrap();
        assert!(k > 0.99, "Conflict should be very high: K = {k}");

        let result = dempster_combine(&m1, &m2);
        assert!(
            result.is_ok(),
            "Dempster should succeed when K = {k} < 1.0 - EPSILON"
        );

        let combined = result.unwrap();
        let m0 = combined.mass_of(&FocalElement::positive(BTreeSet::from([0])));
        let m1_val = combined.mass_of(&FocalElement::positive(BTreeSet::from([1])));
        assert!(
            (m0 - m1_val).abs() < 0.01,
            "With equal opposing evidence, masses should be nearly equal: m0={m0}, m1={m1_val}"
        );
    }

    #[test]
    fn cautious_two_agreeing_sources_no_reinforcement() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();

        let result = cautious_combine(&m1, &m2).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let combined = result.mass_of(&fe0);
        assert!(
            combined <= 0.7 + 1e-10,
            "Cautious should not reinforce: got {combined}"
        );
    }

    // ======== Appendix A: Zadeh counterexample (K=0.9999) ========

    #[test]
    fn zadeh_k_0_9999_adaptive_switches_to_conjunctive() {
        let frame = FrameOfDiscernment::new(
            "diagnosis",
            vec!["meningitis".into(), "concussion".into(), "tumor".into()],
        )
        .unwrap();

        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.99).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.99).unwrap();

        let (result, report) = adaptive_combine(&m1, &m2, 0.3).unwrap();

        assert_eq!(
            report.method_used,
            CombinationMethod::Conjunctive,
            "Should switch to conjunctive at K ~ 0.98"
        );

        let m_empty = result.mass_of_conflict();
        assert!(
            m_empty > 0.98,
            "Mass on conflict should be ~ 0.9801: got {m_empty}"
        );
        assert!(report.conflict_k > 0.95);
    }

    // ======== Vacuous BBA neutral element ========

    #[test]
    fn vacuous_bba_is_neutral_element() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let vacuous = MassFunction::vacuous(frame);
        let fe0 = FocalElement::positive(BTreeSet::from([0]));

        let dempster_result = dempster_combine(&m, &vacuous).unwrap();
        assert!(
            (dempster_result.mass_of(&fe0) - 0.7).abs() < 1e-10,
            "Vacuous is Dempster neutral element"
        );

        let conj_result = conjunctive_combine(&m, &vacuous).unwrap();
        assert!(
            (conj_result.mass_of(&fe0) - 0.7).abs() < 1e-10,
            "Vacuous is conjunctive neutral element"
        );
    }

    // ======== Categorical BBA ========

    #[test]
    fn categorical_bba_bel_equals_pl() {
        use crate::measures;

        let frame = binary_frame();
        let m = MassFunction::categorical(frame, 0).unwrap();

        let singleton = FocalElement::positive(BTreeSet::from([0]));
        let bel = measures::belief(&m, &singleton);
        let pl = measures::plausibility(&m, &singleton);

        assert!(
            (bel - 1.0).abs() < 1e-10,
            "Categorical Bel should be 1.0: {bel}"
        );
        assert!(
            (pl - 1.0).abs() < 1e-10,
            "Categorical Pl should be 1.0: {pl}"
        );
    }

    // ======== Total conflict ========

    #[test]
    fn total_conflict_dempster_undefined_tbm_all_to_empty() {
        let frame = binary_frame();
        let m1 = MassFunction::categorical(frame.clone(), 0).unwrap();
        let m2 = MassFunction::categorical(frame, 1).unwrap();

        assert!(matches!(
            dempster_combine(&m1, &m2),
            Err(DsError::TotalConflict)
        ));

        let tbm_result = conjunctive_combine(&m1, &m2).unwrap();
        assert!(
            (tbm_result.mass_of_conflict() - 1.0).abs() < 1e-10,
            "Total conflict TBM: all mass on conflict, got {}",
            tbm_result.mass_of_conflict()
        );
    }

    // ======== Single-hypothesis frame ========

    #[test]
    fn single_hypothesis_frame_only_theta_and_singleton() {
        let frame = FrameOfDiscernment::new("single", vec!["only_option".into()]).unwrap();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.8).unwrap();

        let theta = FocalElement::theta(m.frame());
        let theta_mass = m.mass_of(&theta);
        assert!(
            theta_mass > 0.0,
            "Single hypothesis frame should have mass on theta"
        );
    }

    // ======== Cross-frame combination ========

    #[test]
    fn cross_frame_combine_different_frames() {
        let f1 = FrameOfDiscernment::new("f1", vec!["a".into(), "b".into()]).unwrap();
        let f2 = FrameOfDiscernment::new("f2", vec!["b".into(), "c".into()]).unwrap();

        let m1 = MassFunction::simple(f1, BTreeSet::from([0]), 0.7).unwrap();
        let m2 = MassFunction::simple(f2, BTreeSet::from([0]), 0.6).unwrap();

        let result = cross_frame_combine(&m1, &m2, CombinationMethod::Dempster, None).unwrap();

        // Union frame should have 3 hypotheses: a, b, c
        assert_eq!(result.frame().hypothesis_count(), 3);
        assert_eq!(result.frame().id, "f1+f2");
    }

    #[test]
    fn cross_frame_combine_same_frame_matches_direct() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();

        let cross = cross_frame_combine(&m1, &m2, CombinationMethod::Dempster, None).unwrap();
        let direct = dempster_combine(&m1, &m2).unwrap();

        // Results should match (same-frame cross-frame == direct)
        let fe0_cross = FocalElement::positive(BTreeSet::from([0]));
        let fe0_direct = FocalElement::positive(BTreeSet::from([0]));
        assert!((cross.mass_of(&fe0_cross) - direct.mass_of(&fe0_direct)).abs() < 1e-10,);
    }

    // ======== Adaptive rule selection ========

    #[test]
    fn select_rule_low_conflict_returns_dempster() {
        assert_eq!(
            select_combination_rule(0.05, 0.0),
            CombinationRule::Dempster
        );
        assert_eq!(select_combination_rule(0.0, 0.5), CombinationRule::Dempster);
    }

    #[test]
    fn select_rule_moderate_conflict_returns_cdst_conjunctive() {
        assert_eq!(
            select_combination_rule(0.1, 0.0),
            CombinationRule::CdstConjunctive
        );
        assert_eq!(
            select_combination_rule(0.3, 0.5),
            CombinationRule::CdstConjunctive
        );
        assert_eq!(
            select_combination_rule(0.49, 0.0),
            CombinationRule::CdstConjunctive
        );
    }

    #[test]
    fn select_rule_high_conflict_open_world_returns_yager() {
        assert_eq!(
            select_combination_rule(0.5, 0.1),
            CombinationRule::YagerOpen
        );
        assert_eq!(
            select_combination_rule(0.9, 0.04),
            CombinationRule::YagerOpen
        );
    }

    #[test]
    fn select_rule_high_conflict_closed_world_returns_inagaki() {
        assert_eq!(select_combination_rule(0.5, 0.0), CombinationRule::Inagaki);
        assert_eq!(select_combination_rule(0.8, 0.03), CombinationRule::Inagaki);
    }

    #[test]
    fn combine_multiple_uses_dempster_for_low_conflict() {
        let frame = binary_frame();
        // Two agreeing sources: K is very low
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.6).unwrap();
        let m2 = MassFunction::simple(frame, BTreeSet::from([0]), 0.5).unwrap();

        let (result, reports) = combine_multiple(&[m1, m2], 0.1).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].method_used, CombinationMethod::Dempster);
        // Dempster removes conflict, so mass_on_conflict should be 0
        assert!(result.mass_of_conflict() < 1e-10);
    }

    #[test]
    fn combine_multiple_uses_different_rules_for_high_conflict() {
        let frame = binary_frame();
        // Highly conflicting sources: K = 0.9 * 0.9 = 0.81
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame.clone(), BTreeSet::from([1]), 0.9).unwrap();

        let (_result, reports) = combine_multiple(&[m1, m2], 0.1).unwrap();
        assert_eq!(reports.len(), 1);
        // K = 0.81 >= 0.5, and both sources are classical (owf=0), so Inagaki
        assert_eq!(reports[0].method_used, CombinationMethod::Inagaki);
    }

    #[test]
    fn combine_multiple_high_conflict_differs_from_pure_dempster() {
        let frame = binary_frame();
        let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.9).unwrap();
        let m2 = MassFunction::simple(frame.clone(), BTreeSet::from([1]), 0.9).unwrap();

        let (adaptive_result, _) = combine_multiple(&[m1.clone(), m2.clone()], 0.1).unwrap();
        let dempster_result = dempster_combine(&m1, &m2).unwrap();

        // With K=0.81, adaptive selects Inagaki, not Dempster
        // Results must differ
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let adaptive_m0 = adaptive_result.mass_of(&fe0);
        let dempster_m0 = dempster_result.mass_of(&fe0);
        assert!(
            (adaptive_m0 - dempster_m0).abs() > 1e-6,
            "Adaptive ({adaptive_m0}) should differ from Dempster ({dempster_m0}) at high conflict"
        );
    }

    #[test]
    fn combine_multiple_open_world_uses_inagaki_full() {
        // Renamed: the adaptive selector now routes YagerOpen-regime to Inagaki(γ=1.0)
        // to prevent the plausibility one-way ratchet (vacuous pass-through bug).
        let frame = binary_frame();
        // positive({0})=0.6 × positive({1})=0.9 → K_c=0.54 ≥ 0.5, owf=0.3 > 0.03
        // → select_combination_rule returns YagerOpen
        let mut masses1 = BTreeMap::new();
        masses1.insert(FocalElement::positive(BTreeSet::from([0])), 0.6);
        masses1.insert(FocalElement::negative(BTreeSet::from([0])), 0.3); // complement → owf
        masses1.insert(FocalElement::theta(&frame), 0.1);
        let m1 = MassFunction::new(frame.clone(), masses1).unwrap();

        // Second source disagrees strongly
        let m2 = MassFunction::simple(frame, BTreeSet::from([1]), 0.9).unwrap();

        let k = conflict_coefficient(&m1, &m2).unwrap();
        assert!(
            k >= 0.5,
            "test requires K≥0.5 to hit YagerOpen rule; got {k}"
        );
        assert!(m1.open_world_fraction() > 0.03, "test requires owf>0.03");

        // High owf+high K → YagerOpen rule selected, routed to Inagaki(γ=1.0) to avoid ratchet.
        let (_result, reports) = combine_multiple(&[m1, m2], 0.1).unwrap();
        assert_eq!(reports[0].method_used, CombinationMethod::Inagaki);
    }

    // ======== Plausibility ratchet regression ========

    /// Regression: plausibility must NOT be a one-way ratchet.
    ///
    /// Scenario: accumulated BBA has high open_world_fraction (triggers YagerOpen path).
    /// A new supporting BBA is combined. Then a strongly contradicting BBA is combined.
    /// Before the fix, vacuous=(empty,true) from YagerOpen passed through cdst_intersect
    /// as a neutral element and distributed to Theta, inflating Pl even after refutation.
    /// After the fix (Inagaki γ=1.0 replaces YagerOpen in combine_multiple), conflict
    /// goes to missing=(Omega,true) which creates genuine conflict in subsequent steps,
    /// keeping Pl low.
    #[test]
    fn pl_does_not_ratchet_after_supporting_evidence_in_high_conflict_regime() {
        use crate::measures::plausibility;

        let frame = binary_frame(); // hypotheses: {0}=supported, {1}=refuted
        let h0 = BTreeSet::from([0usize]);
        let h1 = BTreeSet::from([1usize]);

        // Build an accumulated BBA that already has open-world mass (owf > 0.03)
        // and high prior conflict so the YagerOpen rule would fire.
        let mut base_masses = BTreeMap::new();
        base_masses.insert(FocalElement::positive(h0.clone()), 0.05);
        base_masses.insert(FocalElement::positive(h1.clone()), 0.55);
        base_masses.insert(FocalElement::missing(&frame), 0.40); // owf = 0.40 > 0.03
        let accumulated = MassFunction::new(frame.clone(), base_masses).unwrap();
        assert!(accumulated.open_world_fraction() > 0.03);

        // Supporting evidence for H0
        let support = MassFunction::simple(frame.clone(), h0.clone(), 0.8).unwrap();
        // Contradicting evidence against H0 (strong support for H1)
        let refutation = MassFunction::simple(frame.clone(), h1.clone(), 0.9).unwrap();

        let fe_h0 = FocalElement::positive(h0.clone());

        // Step 1: combine accumulated + support (triggers YagerOpen/Inagaki path)
        let (after_support, reports1) = combine_multiple(&[accumulated, support], 0.1).unwrap();
        // Pin the routing: if this ever reverts to YagerOpen the ratchet will silently return.
        assert_eq!(
            reports1[0].method_used,
            CombinationMethod::Inagaki,
            "YagerOpen-regime must route to Inagaki to prevent the plausibility ratchet"
        );
        let pl_after_support = plausibility(&after_support, &fe_h0);

        // Step 2: combine result + strong refutation
        let (after_refutation, _) = combine_multiple(&[after_support, refutation], 0.1).unwrap();
        let pl_after_refutation = plausibility(&after_refutation, &fe_h0);

        // Pl MUST contract (or at least not increase) after adding contradicting evidence.
        assert!(
            pl_after_refutation <= pl_after_support + 1e-9,
            "Plausibility ratchet detected: Pl rose from {pl_after_support:.6} to \
             {pl_after_refutation:.6} after strong refutation evidence"
        );

        // Pl after refutation must be significantly below 1.0
        assert!(
            pl_after_refutation < 0.5,
            "Pl({pl_after_refutation:.6}) should be well below 0.5 after strong refutation"
        );
    }
}
