//! Interval-aware belief propagation over CDST factor graphs.
//!
//! Runs loopy BP where each variable carries a full [`EpistemicInterval`]
//! instead of a scalar pignistic probability.  Open-world ignorance is
//! treated as structural: it propagates at full strength (worst-case max),
//! is never damped, and never decreases within a single BP run.
//!
//! The algorithm is scoped — it operates on the nodes and factors passed in
//! and does **not** touch the wider graph.  Boundary nodes (anchors) are
//! excluded from updates by omitting them from the `factors` list or by
//! marking them absent from `initial_intervals`.
//!
//! # Frame closure detection
//!
//! After every iteration the algorithm scans variables for evidence that a
//! downstream node is "certain enough" to validate an upstream frame.  Any
//! such candidate is collected in [`IntervalBpResult::frame_evidence_proposals`]
//! but is **not** acted upon — the caller decides whether to materialise them.

use std::collections::HashMap;

use uuid::Uuid;

use crate::bp::FactorPotential;
use crate::cdst_sheaf::FrameEvidenceProposal;
use crate::epistemic_interval::{restrict_epistemic_positive, EpistemicInterval};

// ── Configuration ──────────────────────────────────────────────────────────

/// Configuration for interval-aware belief propagation.
#[derive(Debug, Clone)]
pub struct IntervalBpConfig {
    /// Maximum number of message-passing iterations. Default 20.
    pub max_iterations: usize,
    /// Convergence threshold (Hausdorff distance). Default 0.01.
    pub convergence_threshold: f64,
    /// Damping coefficient applied to Bel/Pl updates (not OW). Default 0.5.
    pub damping: f64,
    /// Strength of open-world transmission across factors. Default 1.0.
    pub open_world_propagation: f64,
    /// A variable must have `width < frame_closure_width_max` to be a frame
    /// evidence source. Default 0.2.
    pub frame_closure_width_max: f64,
}

impl Default for IntervalBpConfig {
    fn default() -> Self {
        Self {
            max_iterations: 20,
            convergence_threshold: 0.01,
            damping: 0.5,
            open_world_propagation: 1.0,
            frame_closure_width_max: 0.2,
        }
    }
}

// ── Result ──────────────────────────────────────────────────────────────────

/// Result of an interval BP run.
#[derive(Debug, Clone)]
pub struct IntervalBpResult {
    pub iterations: usize,
    pub converged: bool,
    pub max_change: f64,
    /// Final interval for every variable that was updated.
    pub updated_intervals: Vec<(Uuid, EpistemicInterval)>,
    /// Frame evidence opportunities detected during iteration.
    /// Not acted on — callers decide whether to materialise them.
    pub frame_evidence_proposals: Vec<FrameEvidenceProposal>,
    pub messages_sent: usize,
}

// ── Factor message computation ──────────────────────────────────────────────

/// Compute the factor-to-variable message for `target_var` from `potential`.
///
/// Each factor potential type produces an interval message according to the
/// CDST restriction map semantics:
///
/// - **MutualExclusion**: For each other variable the "room left" is
///   `[1-pl, 1-bel]`.  Multiply the lower bounds together (conservative) and
///   the upper bounds together (optimistic).  OW is the max across others.
/// - **EvidentialSupport / SharedEvidence**: Apply `restrict_epistemic_positive`
///   from the other variable's interval using `strength` as the factor.
/// - **Others** (ConditionalDependence, TemporalOrdering): Pass through the
///   current belief for `target_var` unchanged.
pub fn compute_interval_factor_message(
    potential: &FactorPotential,
    factor_vars: &[Uuid],
    target_var: Uuid,
    intervals: &HashMap<Uuid, EpistemicInterval>,
) -> EpistemicInterval {
    match potential {
        FactorPotential::MutualExclusion => {
            // "Room left" = complement product of all competing variables.
            // bel_product: product of (1 - pl_other) — conservative lower bound.
            // pl_product:  product of (1 - bel_other) — optimistic upper bound.
            let mut bel_product = 1.0f64;
            let mut pl_product = 1.0f64;
            let mut max_ow = 0.0f64;

            for &var in factor_vars {
                if var == target_var {
                    continue;
                }
                let iv = intervals
                    .get(&var)
                    .copied()
                    .unwrap_or(EpistemicInterval::VACUOUS);
                bel_product *= 1.0 - iv.pl; // conservative: subtract upper bound
                pl_product *= 1.0 - iv.bel; // optimistic: subtract lower bound
                max_ow = max_ow.max(iv.open_world);
            }

            EpistemicInterval {
                bel: bel_product.clamp(0.0, 1.0),
                pl: pl_product.clamp(0.0, 1.0),
                open_world: max_ow,
            }
        }

        FactorPotential::EvidentialSupport { strength } => {
            // Source variable supports target.  Use restrict_epistemic_positive.
            if factor_vars.len() >= 2 {
                let other = if target_var == factor_vars[0] {
                    factor_vars[1]
                } else {
                    factor_vars[0]
                };
                let other_iv = intervals
                    .get(&other)
                    .copied()
                    .unwrap_or(EpistemicInterval::VACUOUS);
                restrict_epistemic_positive(&other_iv, *strength)
            } else {
                EpistemicInterval::VACUOUS
            }
        }

        FactorPotential::SharedEvidence { strength } => {
            // Symmetric shared evidence — same map as EvidentialSupport.
            if factor_vars.len() >= 2 {
                let other = if target_var == factor_vars[0] {
                    factor_vars[1]
                } else {
                    factor_vars[0]
                };
                let other_iv = intervals
                    .get(&other)
                    .copied()
                    .unwrap_or(EpistemicInterval::VACUOUS);
                restrict_epistemic_positive(&other_iv, *strength)
            } else {
                EpistemicInterval::VACUOUS
            }
        }

        // ConditionalDependence and TemporalOrdering: simplified pass-through.
        _ => intervals
            .get(&target_var)
            .copied()
            .unwrap_or(EpistemicInterval::VACUOUS),
    }
}

// ── Variable update ─────────────────────────────────────────────────────────

/// Aggregate interval messages into an updated variable belief.
///
/// - **Bel/Pl**: geometric mean across incoming messages (degree-invariant),
///   then blend 50 % prior + 50 % factor signal.
/// - **OW**: take the max across all incoming messages; then further max with
///   the prior OW.  Apply no damping — OW is structural.
/// - **Damping**: applied to Bel/Pl only.
fn aggregate_messages(
    msgs: &[EpistemicInterval],
    prior: EpistemicInterval,
    old: EpistemicInterval,
    damping: f64,
) -> EpistemicInterval {
    if msgs.is_empty() {
        return old;
    }

    let n = msgs.len() as f64;

    let bel_log_sum: f64 = msgs.iter().map(|m| m.bel.max(1e-12).ln()).sum();
    let pl_log_sum: f64 = msgs.iter().map(|m| m.pl.max(1e-12).ln()).sum();
    let ow_signal: f64 = msgs.iter().map(|m| m.open_world).fold(0.0f64, f64::max);

    let factor_bel = (bel_log_sum / n).exp().clamp(0.01, 0.99);
    let factor_pl = (pl_log_sum / n).exp().clamp(0.01, 0.99);

    // 50/50 blend: prior anchor + factor signal.
    let raw_bel = 0.5 * prior.bel + 0.5 * factor_bel;
    let raw_pl = 0.5 * prior.pl + 0.5 * factor_pl;

    // OW: never decreases — take max of signal and prior.
    let raw_ow = ow_signal.max(prior.open_world);

    // Damp Bel/Pl; OW is not damped (structural, not iterative).
    let dampened_bel = (damping * old.bel + (1.0 - damping) * raw_bel).clamp(0.01, 0.99);
    let dampened_pl = (damping * old.pl + (1.0 - damping) * raw_pl).clamp(0.01, 0.99);

    EpistemicInterval {
        bel: dampened_bel,
        pl: dampened_pl,
        open_world: raw_ow,
    }
}

// ── Frame closure detection ─────────────────────────────────────────────────

/// Scan variables for frame-closure candidates and emit proposals.
///
/// A variable is a candidate frame-evidence *source* if its **prior** state
/// shows it was already certain and nearly closed-frame before BP ran:
/// - `prior.open_world < 0.1`
/// - `prior.width < frame_closure_width_max`
///
/// The condition on the *neighbour* (frame-closure *target*) uses the current
/// post-iteration interval so we react to whatever OW level BP has propagated:
/// - neighbour's `current.open_world > 0.3`
///
/// We check the source against priors rather than current intervals because BP
/// may inflate a source's OW when high-OW neighbours propagate back through
/// shared factors.  The source's epistemic value as frame evidence derives from
/// what it *was* — a ground-truth observation — not from what BP pushed into it.
fn detect_frame_closure(
    priors: &HashMap<Uuid, EpistemicInterval>,
    current: &HashMap<Uuid, EpistemicInterval>,
    factors: &[(Uuid, FactorPotential, Vec<Uuid>)],
    frame_closure_width_max: f64,
) -> Vec<FrameEvidenceProposal> {
    let mut proposals = Vec::new();

    for (&var, &prior_iv) in priors {
        // Source condition checked against prior (pre-BP) state.
        if prior_iv.open_world >= 0.1 || prior_iv.width() >= frame_closure_width_max {
            continue;
        }

        // Find factor neighbours with high OW in the current (post-update) state.
        for (_, _, vars) in factors {
            if !vars.contains(&var) {
                continue;
            }
            for &neighbor in vars {
                if neighbor == var {
                    continue;
                }
                let n_iv = current
                    .get(&neighbor)
                    .copied()
                    .unwrap_or(EpistemicInterval::VACUOUS);
                if n_iv.open_world > 0.3 {
                    // `var` is certain and closed-frame; `neighbor` has high OW.
                    // Emit a proposal: `var` (evidence_source) validates `neighbor` (target).
                    proposals.push(FrameEvidenceProposal {
                        target_claim_id: neighbor,
                        evidence_source_id: var,
                        scope_boundary: vars
                            .iter()
                            .filter(|&&v| v != var && v != neighbor)
                            .copied()
                            .collect(),
                        proposed_reduction: 1.0 - prior_iv.open_world,
                        confidence: prior_iv.betp() * (1.0 - prior_iv.width()),
                        scope_description: format!(
                            "Interval BP frame closure: source {:?} (prior_ow={:.3}, width={:.3}) \
                             → target {:?} (ow={:.3})",
                            var,
                            prior_iv.open_world,
                            prior_iv.width(),
                            neighbor,
                            n_iv.open_world
                        ),
                    });
                }
            }
        }
    }

    proposals
}

// ── Public entry point ──────────────────────────────────────────────────────

/// Run interval-aware loopy belief propagation.
///
/// `factors` — `(factor_id, potential, variable_ids)` triples.
/// `initial_intervals` — prior belief for every variable; used as the prior
///   anchor throughout iteration.
///
/// Variables not present in `initial_intervals` are treated as vacuous.
/// Boundary (anchor) nodes should **not** have update entries written back if
/// the caller wishes to keep them fixed — this function updates every variable
/// that appears in at least one factor.
pub fn run_interval_bp(
    factors: &[(Uuid, FactorPotential, Vec<Uuid>)],
    initial_intervals: &HashMap<Uuid, EpistemicInterval>,
    config: &IntervalBpConfig,
) -> IntervalBpResult {
    // Trivial case: no factors → converged immediately.
    if factors.is_empty() {
        return IntervalBpResult {
            iterations: 0,
            converged: true,
            max_change: 0.0,
            updated_intervals: initial_intervals.iter().map(|(&k, &v)| (k, v)).collect(),
            frame_evidence_proposals: Vec::new(),
            messages_sent: 0,
        };
    }

    let priors = initial_intervals.clone();
    let mut current = initial_intervals.clone();

    let mut total_messages = 0usize;
    let mut last_max_change = 0.0f64;
    let mut all_proposals: Vec<FrameEvidenceProposal> = Vec::new();
    let mut converged = false;

    for iter in 0..config.max_iterations {
        // --- Factor → variable messages ---
        // Collect all messages keyed by target variable.
        let mut var_msgs: HashMap<Uuid, Vec<EpistemicInterval>> = HashMap::new();

        for (_, potential, vars) in factors {
            for &target in vars {
                let msg = compute_interval_factor_message(potential, vars, target, &current);
                var_msgs.entry(target).or_default().push(msg);
                total_messages += 1;
            }
        }

        // --- Variable update ---
        let mut max_change = 0.0f64;

        for (var, msgs) in &var_msgs {
            let old = current
                .get(var)
                .copied()
                .unwrap_or(EpistemicInterval::VACUOUS);
            let prior = priors
                .get(var)
                .copied()
                .unwrap_or(EpistemicInterval::VACUOUS);

            let updated = aggregate_messages(msgs, prior, old, config.damping);

            let change = old.hausdorff_distance(&updated);
            max_change = max_change.max(change);

            current.insert(*var, updated);
        }

        last_max_change = max_change;

        // --- Frame closure detection ---
        let proposals =
            detect_frame_closure(&priors, &current, factors, config.frame_closure_width_max);
        all_proposals.extend(proposals);

        // --- Convergence check ---
        if max_change < config.convergence_threshold {
            converged = true;
            last_max_change = max_change;

            return IntervalBpResult {
                iterations: iter + 1,
                converged,
                max_change: last_max_change,
                updated_intervals: current.into_iter().collect(),
                frame_evidence_proposals: all_proposals,
                messages_sent: total_messages,
            };
        }
    }

    IntervalBpResult {
        iterations: config.max_iterations,
        converged,
        max_change: last_max_change,
        updated_intervals: current.into_iter().collect(),
        frame_evidence_proposals: all_proposals,
        messages_sent: total_messages,
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

    // Helper: find an interval by ID in the result.
    fn find(result: &IntervalBpResult, id: Uuid) -> EpistemicInterval {
        result
            .updated_intervals
            .iter()
            .find(|(k, _)| *k == id)
            .map(|(_, v)| *v)
            .unwrap_or(EpistemicInterval::VACUOUS)
    }

    // ── test_mutual_exclusion_intervals ──────────────────────────────────

    #[test]
    fn test_mutual_exclusion_intervals() {
        // Two variables both start high — mutual exclusion should push at least
        // one of them down.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let factors = vec![make_factor(FactorPotential::MutualExclusion, vec![a, b])];

        let initial = HashMap::from([
            (a, EpistemicInterval::new(0.8, 0.95, 0.1)),
            (b, EpistemicInterval::new(0.8, 0.95, 0.1)),
        ]);

        let config = IntervalBpConfig {
            max_iterations: 50,
            convergence_threshold: 0.001,
            damping: 0.3,
            ..Default::default()
        };

        let result = run_interval_bp(&factors, &initial, &config);

        let fa = find(&result, a);
        let fb = find(&result, b);

        // At least one interval's bel should decrease below 0.8.
        assert!(
            fa.bel < 0.8 || fb.bel < 0.8,
            "Mutual exclusion should push down bel of at least one high variable: a={}, b={}",
            fa,
            fb
        );
    }

    // ── test_evidential_support_intervals ────────────────────────────────

    #[test]
    fn test_evidential_support_intervals() {
        // Source A is strong and certain; B starts vacuous.
        // After BP, B should shift toward A and OW should propagate.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let factors = vec![make_factor(
            FactorPotential::EvidentialSupport { strength: 0.9 },
            vec![a, b],
        )];

        let initial = HashMap::from([
            (a, EpistemicInterval::new(0.7, 0.85, 0.25)), // high OW source
            (b, EpistemicInterval::VACUOUS),
        ]);

        let config = IntervalBpConfig {
            max_iterations: 50,
            convergence_threshold: 0.001,
            ..Default::default()
        };

        let result = run_interval_bp(&factors, &initial, &config);

        let fb = find(&result, b);

        // B's bel should increase above VACUOUS (0.0).
        assert!(
            fb.bel > 0.01,
            "EvidentialSupport should raise target bel: got {}",
            fb
        );

        // OW must propagate: B's OW should be at least as high as A's prior OW.
        assert!(
            fb.open_world >= 0.24,
            "OW from source should propagate to target: got {}",
            fb.open_world
        );
    }

    // ── test_open_world_never_decreases ──────────────────────────────────

    #[test]
    fn test_open_world_never_decreases() {
        // Run BP and verify that every variable's OW at the end is >= its prior OW.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        // A chain: A supports B, B supports C.
        let factors = vec![
            make_factor(
                FactorPotential::EvidentialSupport { strength: 0.8 },
                vec![a, b],
            ),
            make_factor(
                FactorPotential::EvidentialSupport { strength: 0.8 },
                vec![b, c],
            ),
        ];

        let initial = HashMap::from([
            (a, EpistemicInterval::new(0.6, 0.8, 0.4)), // high OW
            (b, EpistemicInterval::new(0.3, 0.7, 0.1)),
            (c, EpistemicInterval::new(0.5, 0.6, 0.05)),
        ]);

        let config = IntervalBpConfig::default();
        let result = run_interval_bp(&factors, &initial, &config);

        for (id, &prior) in &initial {
            let final_iv = find(&result, *id);
            assert!(
                final_iv.open_world >= prior.open_world - 1e-10,
                "OW should never decrease for var {:?}: prior={:.4} final={:.4}",
                id,
                prior.open_world,
                final_iv.open_world
            );
        }
    }

    // ── test_frame_closure_detection ─────────────────────────────────────

    #[test]
    fn test_frame_closure_detection() {
        // Variable A: low OW, narrow (certain) → potential frame evidence source.
        // Variable B: high OW → frame closure target.
        // They share a factor.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // B has wide-open frame; A is certain and closed.
        // Use SharedEvidence so BP connects them.
        let factors = vec![make_factor(
            FactorPotential::SharedEvidence { strength: 0.5 },
            vec![a, b],
        )];

        // Set up intervals such that A satisfies the frame-closure criteria:
        // open_world < 0.1 AND width < 0.2.
        // B has open_world > 0.3.
        let initial = HashMap::from([
            (a, EpistemicInterval::new(0.78, 0.82, 0.01)), // narrow, near-zero OW
            (b, EpistemicInterval::new(0.3, 0.7, 0.4)),    // high OW
        ]);

        let config = IntervalBpConfig {
            max_iterations: 5,
            ..Default::default()
        };

        let result = run_interval_bp(&factors, &initial, &config);

        // There should be at least one frame evidence proposal.
        assert!(
            !result.frame_evidence_proposals.is_empty(),
            "Expected frame evidence proposals when certain low-OW node is adjacent to high-OW node"
        );

        // The proposal should target B from A.
        let prop = result
            .frame_evidence_proposals
            .iter()
            .find(|p| p.evidence_source_id == a && p.target_claim_id == b);

        assert!(
            prop.is_some(),
            "Expected proposal: evidence_source=A, target=B. Proposals: {:?}",
            result.frame_evidence_proposals
        );
    }

    // ── test_empty_factors_converges ─────────────────────────────────────

    #[test]
    fn test_empty_factors_converges() {
        let initial = HashMap::from([
            (Uuid::new_v4(), EpistemicInterval::new(0.5, 0.7, 0.1)),
            (Uuid::new_v4(), EpistemicInterval::new(0.3, 0.6, 0.2)),
        ]);

        let config = IntervalBpConfig::default();
        let result = run_interval_bp(&[], &initial, &config);

        assert!(
            result.converged,
            "Empty factor graph must converge immediately"
        );
        assert_eq!(result.iterations, 0);
        assert_eq!(result.messages_sent, 0);
        assert!(result.frame_evidence_proposals.is_empty());
        // All input intervals preserved.
        assert_eq!(result.updated_intervals.len(), initial.len());
    }

    // ── test_convergence_on_consistent_input ─────────────────────────────

    #[test]
    fn test_convergence_on_consistent_input() {
        // Two variables with consistent, complementary beliefs under mutual
        // exclusion: they sum to roughly 1, so the factor pressure is small.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let factors = vec![make_factor(FactorPotential::MutualExclusion, vec![a, b])];

        // Consistent starting point: a ≈ 0.6, b ≈ 0.4 → sum ≈ 1.
        let initial = HashMap::from([
            (a, EpistemicInterval::new(0.55, 0.65, 0.05)),
            (b, EpistemicInterval::new(0.35, 0.45, 0.05)),
        ]);

        let config = IntervalBpConfig {
            max_iterations: 100,
            convergence_threshold: 0.01,
            damping: 0.5,
            ..Default::default()
        };

        let result = run_interval_bp(&factors, &initial, &config);

        assert!(
            result.converged,
            "Consistent input should converge within {} iterations (used {})",
            config.max_iterations, result.iterations
        );
        assert!(
            result.iterations < config.max_iterations,
            "Should converge before exhausting iterations"
        );
    }
}
