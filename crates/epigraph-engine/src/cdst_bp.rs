//! CDST-native belief propagation over the factor graph.
//!
//! Variables carry full `MassFunction` (from epigraph-ds) instead of scalars.
//! Factor messages use Shafer reliability discounting.
//! Evidence mass functions anchor each variable so graph messages cannot
//! wash out evidence-derived beliefs.

use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use uuid::Uuid;

use epigraph_ds::{
    combination::{adaptive_combine, discount},
    measures::pignistic_probability,
    FocalElement, FrameOfDiscernment, MassFunction,
};

use crate::bp::FactorPotential;
use crate::epistemic_interval::EpistemicInterval;

// -- Canonical binary frame ------------------------------------------------

static BINARY_FRAME: LazyLock<FrameOfDiscernment> = LazyLock::new(|| {
    FrameOfDiscernment::new("binary", vec!["supported".into(), "unsupported".into()])
        .expect("binary frame construction must not fail")
});

const H_SUPPORTED: usize = 0;
const H_UNSUPPORTED: usize = 1;

// -- Helper functions ------------------------------------------------------

/// Create a vacuous mass function on the binary frame.
pub fn vacuous() -> MassFunction {
    MassFunction::vacuous(BINARY_FRAME.clone())
}

/// Convert a mass function to an `EpistemicInterval` [Bel, Pl] with open-world.
pub fn mass_to_interval(m: &MassFunction) -> EpistemicInterval {
    let h_sup = FocalElement::positive(BTreeSet::from([H_SUPPORTED]));
    let bel = epigraph_ds::measures::belief(m, &h_sup);
    let pl = epigraph_ds::measures::plausibility(m, &h_sup);
    let ow = m.open_world_fraction();
    EpistemicInterval::from_mass_components(bel, pl, ow)
}

/// Build a mass function pushing belief toward "unsupported" with strength `betp_y`.
fn anti_support_mass(betp_y: f64) -> MassFunction {
    let betp_y = betp_y.clamp(0.0, 1.0);
    if betp_y < 1e-10 {
        return vacuous();
    }
    MassFunction::simple(
        BINARY_FRAME.clone(),
        BTreeSet::from([H_UNSUPPORTED]),
        betp_y,
    )
    .unwrap_or_else(|_| vacuous())
}

/// Parse a mass function from the JSON `masses` column in the database.
pub fn parse_mass_function_row(masses_json: &serde_json::Value) -> Result<MassFunction, String> {
    MassFunction::from_json_masses(BINARY_FRAME.clone(), masses_json)
        .map_err(|e| format!("Failed to parse mass function: {e}"))
}

// -- Factor message computation --------------------------------------------

/// Compute the CDST factor-to-variable message for `target_var`.
///
/// Uses Shafer reliability discounting: the message to a variable is the
/// discounted belief from adjacent variables, scaled by factor strength.
pub fn compute_cdst_factor_message(
    potential: &FactorPotential,
    factor_vars: &[Uuid],
    target_var: Uuid,
    beliefs: &HashMap<Uuid, MassFunction>,
) -> MassFunction {
    let vac = vacuous();

    match potential {
        FactorPotential::MutualExclusion => {
            // Each neighbour's support becomes anti-support for the target
            let mut result: Option<MassFunction> = None;
            for &var in factor_vars {
                if var == target_var {
                    continue;
                }
                let m_y = beliefs.get(&var).cloned().unwrap_or_else(vacuous);
                let betp_y = pignistic_probability(&m_y, H_SUPPORTED);
                let anti = anti_support_mass(betp_y);
                result = Some(match result {
                    None => anti,
                    Some(acc) => adaptive_combine(&acc, &anti, 0.3)
                        .map(|(m, _)| m)
                        .unwrap_or_else(|_| vacuous()),
                });
            }
            result.unwrap_or_else(vacuous)
        }

        FactorPotential::EvidentialSupport { strength }
        | FactorPotential::SharedEvidence { strength } => {
            if factor_vars.len() < 2 {
                return vac;
            }
            let other = if target_var == factor_vars[0] {
                factor_vars[1]
            } else {
                factor_vars[0]
            };
            let m_other = beliefs.get(&other).cloned().unwrap_or_else(vacuous);
            discount(&m_other, *strength).unwrap_or_else(|_| vacuous())
        }

        FactorPotential::DirectionalSupport {
            source_var,
            forward_strength,
            reverse_strength,
        } => {
            if factor_vars.len() < 2 {
                return vac;
            }
            let strength = if target_var == *source_var {
                *reverse_strength
            } else {
                *forward_strength
            };
            if strength < 1e-9 {
                return vac;
            }
            let other = if target_var == factor_vars[0] {
                factor_vars[1]
            } else {
                factor_vars[0]
            };
            let m_other = beliefs.get(&other).cloned().unwrap_or_else(vacuous);
            discount(&m_other, strength).unwrap_or_else(|_| vacuous())
        }

        FactorPotential::ConditionalDependence { .. }
        | FactorPotential::TemporalOrdering { .. } => vac,
    }
}

// -- Config and result types -----------------------------------------------

/// Configuration for CDST belief propagation.
///
/// **Iteration limit:** Keep `max_iterations` at 10-20 for full-graph runs.
/// The damping formula (discount+combine) injects monotonic Theta mass each
/// iteration; beyond ~25 iterations mass functions degenerate toward vacuous
/// and BetP oscillates. A structural fix (linear focal mass interpolation
/// or Theta clamping) is needed before raising the limit.
#[derive(Debug, Clone)]
pub struct CdstBpConfig {
    pub max_iterations: usize,
    pub convergence_threshold: f64,
    pub damping: f64,
    pub conflict_threshold: f64,
}

impl Default for CdstBpConfig {
    fn default() -> Self {
        Self {
            max_iterations: 20,
            convergence_threshold: 0.01,
            damping: 0.5,
            conflict_threshold: 0.3,
        }
    }
}

/// Result of a CDST BP run.
#[derive(Debug, Clone)]
pub struct CdstBpResult {
    pub iterations: usize,
    pub converged: bool,
    pub max_change: f64,
    pub updated_intervals: Vec<(Uuid, EpistemicInterval)>,
    pub updated_betps: Vec<(Uuid, f64)>,
    pub messages_sent: usize,
    pub max_conflict: f64,
    /// Frame closure candidates detected during iteration (empty for now;
    /// future extension will port detection logic from interval_bp.rs).
    pub frame_evidence_proposals: Vec<crate::cdst_sheaf::FrameEvidenceProposal>,
}

// -- BP iteration with evidence anchoring ----------------------------------

/// Run a single BP iteration.
///
/// Returns `(max_change, messages_sent, max_conflict)`.
///
/// **Evidence anchoring**: each variable's evidence mass re-enters the
/// combination every iteration, preventing graph messages from washing
/// out evidence-derived beliefs.
pub fn cdst_bp_iteration(
    factors: &[(Uuid, FactorPotential, Vec<Uuid>)],
    beliefs: &mut HashMap<Uuid, MassFunction>,
    evidence: &HashMap<Uuid, MassFunction>,
    messages: &mut HashMap<(Uuid, Uuid), MassFunction>,
    config: &CdstBpConfig,
) -> (f64, usize, f64) {
    let mut msg_count = 0_usize;
    let mut max_conflict = 0.0_f64;

    // Phase 1: factor->variable messages
    for (factor_id, potential, vars) in factors {
        for &var in vars {
            let msg = compute_cdst_factor_message(potential, vars, var, beliefs);
            messages.insert((*factor_id, var), msg);
            msg_count += 1;
        }
    }

    // Phase 2: variable updates with evidence anchoring
    let mut var_incoming: HashMap<Uuid, Vec<MassFunction>> = HashMap::new();
    for ((_, var), msg) in messages.iter() {
        var_incoming.entry(*var).or_default().push(msg.clone());
    }

    let mut max_change = 0.0_f64;

    for (var, msgs) in &var_incoming {
        if msgs.is_empty() {
            continue;
        }

        let old_m = beliefs.get(var).cloned().unwrap_or_else(vacuous);
        let old_iv = mass_to_interval(&old_m);

        // Combine all incoming factor messages
        let mut m_graph = msgs[0].clone();
        for next in &msgs[1..] {
            match adaptive_combine(&m_graph, next, config.conflict_threshold) {
                Ok((combined, report)) => {
                    max_conflict = max_conflict.max(report.conflict_k);
                    m_graph = combined;
                }
                Err(_) => {
                    m_graph = vacuous();
                }
            }
        }

        // Evidence anchoring: combine graph signal with evidence mass
        let m_evidence = evidence.get(var).cloned().unwrap_or_else(vacuous);
        let m_combined = match adaptive_combine(&m_graph, &m_evidence, config.conflict_threshold) {
            Ok((combined, report)) => {
                max_conflict = max_conflict.max(report.conflict_k);
                combined
            }
            Err(_) => m_evidence,
        };

        // Damping via discount+combine
        let d = config.damping.clamp(0.0, 1.0);
        let new_m = if (d - 1.0).abs() < 1e-10 {
            old_m.clone()
        } else if d < 1e-10 {
            m_combined
        } else {
            let m_new_disc = discount(&m_combined, 1.0 - d).unwrap_or_else(|_| vacuous());
            let m_old_disc = discount(&old_m, d).unwrap_or_else(|_| vacuous());
            adaptive_combine(&m_new_disc, &m_old_disc, config.conflict_threshold)
                .map(|(m, _)| m)
                .unwrap_or_else(|_| m_combined)
        };

        let new_iv = mass_to_interval(&new_m);
        let change = old_iv.hausdorff_distance(&new_iv);
        max_change = max_change.max(change);

        beliefs.insert(*var, new_m);
    }

    (max_change, msg_count, max_conflict)
}

// -- Entry point -----------------------------------------------------------

fn build_result(
    beliefs: &HashMap<Uuid, MassFunction>,
    iterations: usize,
    converged: bool,
    max_change: f64,
    messages_sent: usize,
    max_conflict: f64,
) -> CdstBpResult {
    let updated_betps: Vec<(Uuid, f64)> = beliefs
        .iter()
        .map(|(id, m)| (*id, pignistic_probability(m, H_SUPPORTED)))
        .collect();
    let updated_intervals: Vec<(Uuid, EpistemicInterval)> = beliefs
        .iter()
        .map(|(id, m)| (*id, mass_to_interval(m)))
        .collect();
    CdstBpResult {
        iterations,
        converged,
        max_change,
        updated_intervals,
        updated_betps,
        messages_sent,
        max_conflict,
        frame_evidence_proposals: Vec::new(),
    }
}

/// Run CDST belief propagation to convergence.
///
/// `factors` — list of (factor_id, potential, variable_ids).
/// `initial` — initial beliefs (mass functions) per variable.
/// `evidence` — evidence anchors per variable (never mutated).
/// `config` — iteration limits, damping, thresholds.
#[must_use]
pub fn run_cdst_bp(
    factors: &[(Uuid, FactorPotential, Vec<Uuid>)],
    initial: &HashMap<Uuid, MassFunction>,
    evidence: &HashMap<Uuid, MassFunction>,
    config: &CdstBpConfig,
) -> CdstBpResult {
    if factors.is_empty() {
        return build_result(initial, 0, true, 0.0, 0, 0.0);
    }

    let mut beliefs = initial.clone();
    let mut messages: HashMap<(Uuid, Uuid), MassFunction> = HashMap::new();
    let mut total_messages = 0_usize;
    let mut total_max_conflict = 0.0_f64;
    let mut last_max_change = 0.0_f64;

    for iter in 0..config.max_iterations {
        let (max_change, msg_count, max_conflict) =
            cdst_bp_iteration(factors, &mut beliefs, evidence, &mut messages, config);
        total_messages += msg_count;
        total_max_conflict = total_max_conflict.max(max_conflict);
        last_max_change = max_change;

        if max_change < config.convergence_threshold {
            return build_result(
                &beliefs,
                iter + 1,
                true,
                max_change,
                total_messages,
                total_max_conflict,
            );
        }
    }

    build_result(
        &beliefs,
        config.max_iterations,
        false,
        last_max_change,
        total_messages,
        total_max_conflict,
    )
}

// -- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn strong_supported(mass: f64) -> MassFunction {
        MassFunction::simple(BINARY_FRAME.clone(), BTreeSet::from([H_SUPPORTED]), mass).unwrap()
    }

    #[test]
    fn test_binary_frame_valid() {
        assert_eq!(BINARY_FRAME.hypothesis_count(), 2);
    }

    #[test]
    fn test_vacuous_betp_is_half() {
        let v = vacuous();
        let betp = pignistic_probability(&v, H_SUPPORTED);
        assert!(
            (betp - 0.5).abs() < 1e-6,
            "vacuous BetP should be 0.5, got {betp}"
        );
    }

    #[test]
    fn test_mass_to_interval_vacuous() {
        let v = vacuous();
        let iv = mass_to_interval(&v);
        assert!(iv.bel < 0.01, "vacuous bel should be ~0, got {}", iv.bel);
        assert!(iv.pl > 0.99, "vacuous pl should be ~1, got {}", iv.pl);
    }

    #[test]
    fn test_anti_support_mass_zero() {
        let m = anti_support_mass(0.0);
        let betp = pignistic_probability(&m, H_SUPPORTED);
        assert!((betp - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_anti_support_mass_high() {
        let m = anti_support_mass(0.9);
        let betp = pignistic_probability(&m, H_SUPPORTED);
        assert!(betp < 0.5, "anti-support should push below 0.5, got {betp}");
    }

    #[test]
    fn test_evidential_support_message_is_discounted() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let mut beliefs = HashMap::new();
        beliefs.insert(a, strong_supported(0.8));
        beliefs.insert(b, vacuous());

        let potential = FactorPotential::EvidentialSupport { strength: 0.6 };
        let msg = compute_cdst_factor_message(&potential, &[a, b], b, &beliefs);
        let betp = pignistic_probability(&msg, H_SUPPORTED);
        assert!(
            betp > 0.5 && betp < 0.9,
            "discounted message BetP should be in (0.5, 0.9), got {betp}"
        );
    }

    #[test]
    fn test_directional_support_asymmetric() {
        let source = Uuid::new_v4();
        let target = Uuid::new_v4();
        let mut beliefs = HashMap::new();
        beliefs.insert(source, strong_supported(0.8));
        beliefs.insert(target, strong_supported(0.8));

        let potential = FactorPotential::DirectionalSupport {
            source_var: source,
            forward_strength: 0.7,
            reverse_strength: 0.15,
        };

        let msg_fwd = compute_cdst_factor_message(&potential, &[source, target], target, &beliefs);
        let msg_rev = compute_cdst_factor_message(&potential, &[source, target], source, &beliefs);
        let betp_fwd = pignistic_probability(&msg_fwd, H_SUPPORTED);
        let betp_rev = pignistic_probability(&msg_rev, H_SUPPORTED);
        assert!(
            betp_fwd > betp_rev,
            "forward ({betp_fwd}) should be stronger than reverse ({betp_rev})"
        );
    }

    #[test]
    fn test_zero_strength_returns_vacuous() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let mut beliefs = HashMap::new();
        beliefs.insert(a, strong_supported(0.9));
        beliefs.insert(b, vacuous());

        let potential = FactorPotential::DirectionalSupport {
            source_var: a,
            forward_strength: 0.0,
            reverse_strength: 0.6,
        };
        let msg = compute_cdst_factor_message(&potential, &[a, b], b, &beliefs);
        let betp = pignistic_probability(&msg, H_SUPPORTED);
        assert!(
            (betp - 0.5).abs() < 1e-6,
            "zero-strength should be vacuous (0.5), got {betp}"
        );
    }

    #[test]
    fn test_mutual_exclusion_pushes_down() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let mut beliefs = HashMap::new();
        beliefs.insert(a, strong_supported(0.9));
        beliefs.insert(b, strong_supported(0.9));

        let msg =
            compute_cdst_factor_message(&FactorPotential::MutualExclusion, &[a, b], b, &beliefs);
        let betp = pignistic_probability(&msg, H_SUPPORTED);
        assert!(
            betp < 0.5,
            "mutual exclusion should push below 0.5, got {betp}"
        );
    }

    #[test]
    fn test_evidence_anchoring_resists_graph_pressure() {
        let parent = Uuid::new_v4();
        let child1 = Uuid::new_v4();
        let child2 = Uuid::new_v4();
        let child3 = Uuid::new_v4();

        let m_strong = strong_supported(0.85);
        let mut initial = HashMap::new();
        initial.insert(parent, m_strong.clone());
        initial.insert(child1, vacuous());
        initial.insert(child2, vacuous());
        initial.insert(child3, vacuous());

        let mut evidence = HashMap::new();
        evidence.insert(parent, m_strong.clone());
        evidence.insert(child1, vacuous());
        evidence.insert(child2, vacuous());
        evidence.insert(child3, vacuous());

        let factors = vec![
            (
                Uuid::new_v4(),
                FactorPotential::DirectionalSupport {
                    source_var: parent,
                    forward_strength: 0.0,
                    reverse_strength: 0.6,
                },
                vec![parent, child1],
            ),
            (
                Uuid::new_v4(),
                FactorPotential::DirectionalSupport {
                    source_var: parent,
                    forward_strength: 0.0,
                    reverse_strength: 0.6,
                },
                vec![parent, child2],
            ),
            (
                Uuid::new_v4(),
                FactorPotential::DirectionalSupport {
                    source_var: parent,
                    forward_strength: 0.0,
                    reverse_strength: 0.6,
                },
                vec![parent, child3],
            ),
        ];

        let result = run_cdst_bp(&factors, &initial, &evidence, &CdstBpConfig::default());
        let parent_betp = result
            .updated_betps
            .iter()
            .find(|(id, _)| *id == parent)
            .map(|(_, b)| *b)
            .unwrap_or(0.0);
        assert!(
            parent_betp > 0.7,
            "parent with strong evidence should resist graph pressure, got {parent_betp}"
        );
    }

    #[test]
    fn test_vacuous_anchor_follows_graph() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let mut initial = HashMap::new();
        initial.insert(a, strong_supported(0.9));
        initial.insert(b, vacuous());

        let mut evidence = HashMap::new();
        evidence.insert(a, strong_supported(0.9));
        evidence.insert(b, vacuous());

        let factors = vec![(
            Uuid::new_v4(),
            FactorPotential::EvidentialSupport { strength: 0.85 },
            vec![a, b],
        )];

        let result = run_cdst_bp(&factors, &initial, &evidence, &CdstBpConfig::default());
        let b_betp = result
            .updated_betps
            .iter()
            .find(|(id, _)| *id == b)
            .map(|(_, b)| *b)
            .unwrap_or(0.0);
        assert!(
            b_betp > 0.5,
            "unanchored claim should follow graph toward supported, got {b_betp}"
        );
    }

    #[test]
    fn test_empty_factors_returns_input() {
        let a = Uuid::new_v4();
        let mut initial = HashMap::new();
        initial.insert(a, strong_supported(0.7));
        let evidence = initial.clone();

        let result = run_cdst_bp(&[], &initial, &evidence, &CdstBpConfig::default());
        assert!(result.converged);
        assert_eq!(result.iterations, 0);
        assert_eq!(result.updated_betps.len(), 1);
    }
}
