//! Property tests: sheaf reconciliation (`reconciliation::reconcile`) does not
//! depend on the ORDER of its input.
//!
//! `reconcile` takes the detected obstructions as a `Vec` and the factor graph
//! as a slice. Neither order carries meaning: the obstructions are a set of
//! inconsistent edges, and the factors are a set of potentials. So the result
//! must be the same set of updated intervals, the same frame-evidence
//! proposals and the same cluster accounting whatever order the caller
//! enumerated them in (a database read with no `ORDER BY`, a `HashMap`
//! iteration upstream).
//!
//! Interval BP is synchronous (every factor message in an iteration is
//! computed from the previous iteration's intervals), so only floating-point
//! summation order can move, and the comparison tolerance below is set for
//! that and nothing larger.
//!
//! The generated input mixes obstructions above `min_inconsistency` with
//! obstructions below it, so the filtering step is exercised under
//! permutation too. Every case processes at least one cluster, which is
//! asserted, so no case passes on an empty result.
//!
//! Dempster-Shafer combination order-independence is covered in `epigraph-ds`
//! (`measures.rs::proptest_properties`, `combination.rs`,
//! `tests/order_independence_smoke.rs`) and is not repeated here.

use std::collections::HashMap;

use epigraph_engine::bp::FactorPotential;
use epigraph_engine::cdst_sheaf::{CdstSheafObstruction, FrameEvidenceProposal, ObstructionKind};
use epigraph_engine::epistemic_interval::EpistemicInterval;
use epigraph_engine::reconciliation::{reconcile, ReconciliationConfig, ReconciliationResult};
use proptest::prelude::*;
use uuid::Uuid;

/// Room for floating-point summation order only.
const TOL: f64 = 1e-9;

fn node(i: usize) -> Uuid {
    Uuid::from_u128(0x5eaf_0000_0000_0000_0000_0000_0000_0000 + i as u128 + 1)
}

fn interval() -> impl Strategy<Value = EpistemicInterval> {
    (0.0..=0.9_f64, 0.0..=1.0_f64, 0.0..=1.0_f64).prop_map(|(bel, width, ow)| {
        let pl = (bel + width * (1.0 - bel)).min(1.0);
        EpistemicInterval::new(bel, pl, ow * (pl - bel))
    })
}

fn obstruction(
    nodes: usize,
    inconsistency: std::ops::RangeInclusive<f64>,
) -> impl Strategy<Value = CdstSheafObstruction> {
    (
        0..nodes,
        1..nodes,
        inconsistency,
        interval(),
        interval(),
        interval(),
        prop_oneof![
            Just(ObstructionKind::BeliefConflict),
            Just(ObstructionKind::OpenWorldSpread),
            Just(ObstructionKind::FrameClosureOpportunity),
            Just(ObstructionKind::IgnoranceDrift),
        ],
    )
        .prop_map(move |(s, hop, inc, si, ti, ei, kind)| {
            let t = (s + hop) % nodes;
            CdstSheafObstruction {
                source_id: node(s),
                target_id: node(t),
                relationship: "supports".to_string(),
                source_interval: si,
                target_interval: ti,
                expected_interval: ei,
                interval_inconsistency: inc,
                conflict_component: inc * 0.6,
                ignorance_component: inc * 0.3,
                open_world_component: inc * 0.1,
                obstruction_kind: kind,
            }
        })
}

fn factor(nodes: usize) -> impl Strategy<Value = (Uuid, FactorPotential, Vec<Uuid>)> {
    (
        any::<u128>(),
        0..nodes,
        1..nodes,
        prop_oneof![
            (0.05..=0.99_f64).prop_map(|strength| (0u8, strength, 0.0)),
            (0.05..=0.99_f64, 0.0..=0.99_f64).prop_map(|(f, r)| (1u8, f, r)),
            Just((2u8, 0.0, 0.0)),
        ],
    )
        .prop_map(move |(id, a, hop, (kind, s1, s2))| {
            let (va, vb) = (node(a), node((a + hop) % nodes));
            let potential = match kind {
                0 => FactorPotential::EvidentialSupport { strength: s1 },
                1 => FactorPotential::DirectionalSupport {
                    source_var: va,
                    forward_strength: s1,
                    reverse_strength: s2,
                },
                _ => FactorPotential::MutualExclusion,
            };
            (Uuid::from_u128(id), potential, vec![va, vb])
        })
}

/// One reconciliation input: the obstructions (some above the default 0.15
/// threshold, some below), the intervals of every node, and the factors.
#[derive(Debug, Clone)]
struct Input {
    obstructions: Vec<CdstSheafObstruction>,
    intervals: HashMap<Uuid, EpistemicInterval>,
    factors: Vec<(Uuid, FactorPotential, Vec<Uuid>)>,
}

fn input() -> impl Strategy<Value = Input> {
    (3usize..=7).prop_flat_map(|nodes| {
        (
            prop::collection::vec(obstruction(nodes, 0.15..=1.0), 1..=8),
            prop::collection::vec(obstruction(nodes, 0.0..=0.149), 0..=4),
            prop::collection::vec(interval(), nodes),
            prop::collection::vec(factor(nodes), 1..=8),
        )
            .prop_map(move |(mut above, below, ivs, factors)| {
                above.extend(below);
                Input {
                    obstructions: above,
                    intervals: ivs.into_iter().enumerate().map(|(i, iv)| (node(i), iv)).collect(),
                    factors,
                }
            })
    })
}

/// An input and the same input with its obstructions permuted.
fn input_and_obstruction_permutation() -> impl Strategy<Value = (Input, Input)> {
    input().prop_flat_map(|a| {
        let shuffled = Just(a.obstructions.clone()).prop_shuffle();
        (Just(a.clone()), shuffled).prop_map(|(a, obstructions)| {
            let b = Input {
                obstructions,
                ..a.clone()
            };
            (a, b)
        })
    })
}

/// An input and the same input with its factors permuted.
fn input_and_factor_permutation() -> impl Strategy<Value = (Input, Input)> {
    input().prop_flat_map(|a| {
        let shuffled = Just(a.factors.clone()).prop_shuffle();
        (Just(a.clone()), shuffled).prop_map(|(a, factors)| {
            let b = Input {
                factors,
                ..a.clone()
            };
            (a, b)
        })
    })
}

fn run(input: &Input) -> ReconciliationResult {
    reconcile(
        input.obstructions.clone(),
        &input.intervals,
        &input.factors,
        &ReconciliationConfig::default(),
    )
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= TOL
}

fn close_iv(a: &EpistemicInterval, b: &EpistemicInterval) -> bool {
    close(a.bel, b.bel) && close(a.pl, b.pl) && close(a.open_world, b.open_world)
}

/// Proposals in a canonical order (they carry no id of their own).
fn sorted_proposals(r: &ReconciliationResult) -> Vec<FrameEvidenceProposal> {
    let mut p = r.frame_evidence_proposals.clone();
    for one in &mut p {
        one.scope_boundary.sort_unstable();
    }
    p.sort_by(|x, y| {
        (x.target_claim_id, x.evidence_source_id, &x.scope_boundary)
            .cmp(&(y.target_claim_id, y.evidence_source_id, &y.scope_boundary))
            .then(x.proposed_reduction.total_cmp(&y.proposed_reduction))
            .then(x.confidence.total_cmp(&y.confidence))
    });
    p
}

/// The two results describe the same reconciliation, or the first difference.
fn same_reconciliation(a: &ReconciliationResult, b: &ReconciliationResult) -> Result<(), String> {
    if a.clusters_processed != b.clusters_processed {
        return Err(format!(
            "clusters_processed {} vs {}",
            a.clusters_processed, b.clusters_processed
        ));
    }
    if a.converged != b.converged {
        return Err(format!("converged {} vs {}", a.converged, b.converged));
    }
    if a.total_iterations != b.total_iterations {
        return Err(format!(
            "total_iterations {} vs {}",
            a.total_iterations, b.total_iterations
        ));
    }
    if a.oversized_clusters.len() != b.oversized_clusters.len() {
        return Err("oversized cluster count differs".to_string());
    }

    let ma: HashMap<Uuid, EpistemicInterval> = a.updated_intervals.iter().copied().collect();
    let mb: HashMap<Uuid, EpistemicInterval> = b.updated_intervals.iter().copied().collect();
    if ma.len() != a.updated_intervals.len() || mb.len() != b.updated_intervals.len() {
        return Err("a node is updated twice in one result".to_string());
    }
    if ma.len() != mb.len() {
        return Err(format!("updated nodes {} vs {}", ma.len(), mb.len()));
    }
    for (id, iv) in &ma {
        match mb.get(id) {
            Some(other) if close_iv(iv, other) => {}
            other => return Err(format!("node {id}: {iv:?} vs {other:?}")),
        }
    }

    let (pa, pb) = (sorted_proposals(a), sorted_proposals(b));
    if pa.len() != pb.len() {
        return Err(format!("proposals {} vs {}", pa.len(), pb.len()));
    }
    for (x, y) in pa.iter().zip(&pb) {
        if x.target_claim_id != y.target_claim_id
            || x.evidence_source_id != y.evidence_source_id
            || x.scope_boundary != y.scope_boundary
            || !close(x.proposed_reduction, y.proposed_reduction)
            || !close(x.confidence, y.confidence)
        {
            return Err(format!("proposal {x:?} vs {y:?}"));
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Permuting the obstructions changes nothing in the result.
    #[test]
    fn reconcile_is_invariant_under_obstruction_order((a, b) in input_and_obstruction_permutation()) {
        let (ra, rb) = (run(&a), run(&b));
        prop_assert!(
            ra.clusters_processed >= 1,
            "CALIBRATION: every case must reconcile at least one cluster"
        );
        prop_assert!(
            !ra.updated_intervals.is_empty(),
            "CALIBRATION: a processed cluster must report its nodes' intervals"
        );
        if let Err(diff) = same_reconciliation(&ra, &rb) {
            prop_assert!(false, "obstruction order changed the result: {}", diff);
        }
    }

    /// Permuting the factors changes nothing in the result.
    #[test]
    fn reconcile_is_invariant_under_factor_order((a, b) in input_and_factor_permutation()) {
        let (ra, rb) = (run(&a), run(&b));
        prop_assert!(
            ra.clusters_processed >= 1,
            "CALIBRATION: every case must reconcile at least one cluster"
        );
        if let Err(diff) = same_reconciliation(&ra, &rb) {
            prop_assert!(false, "factor order changed the result: {}", diff);
        }
    }

    /// Running the same input twice gives the same result: the comparison
    /// above is not satisfied by a result that varies from run to run anyway
    /// (internal `HashMap` iteration order differs between the two calls).
    #[test]
    fn reconcile_is_deterministic(a in input()) {
        if let Err(diff) = same_reconciliation(&run(&a), &run(&a)) {
            prop_assert!(false, "two runs of one input differ: {}", diff);
        }
    }
}
