//! Property-based tests for epigraph-engine invariants
//!
//! These tests use proptest to verify that critical epistemic invariants
//! hold across the full input domain, not just hand-picked examples.
//!
//! # Invariants Verified
//!
//! 1. Bayesian updates always produce posteriors in [0.01, 0.99]
//! 2. Evidence weighting is deterministic: same inputs -> same weight
//! 3. Evidence weights are always non-negative
//! 4. DAG validator rejects self-references
//! 5. Reputation NEVER influences initial truth calculation
//! 6. Sheaf expected-BetP, sections and cohomology are permutation-invariant
//!    in their neighbour / obstruction order
//! 7. Sheaf expected BetP stays inside [0, 1]
//! 8. The `expected` half of an edge inconsistency is a function of the source
//!    and the relationship only, never of the target

use epigraph_core::TruthValue;
use epigraph_engine::sheaf::{
    compute_cohomology, compute_edge_inconsistency, compute_expected_betp, compute_section,
    restriction_kind, RestrictionKind, SheafObstruction,
};
#[expect(
    deprecated,
    reason = "exercises `BayesianUpdater`, deprecated in favour of CDST pignistic \
              probability but still on the live path (epigraph-api `submission.rs`, \
              engine `service.rs`); the invariant must keep being covered until those \
              callers migrate"
)]
use epigraph_engine::{BayesianUpdater, DagValidator, EvidenceWeighter};
use proptest::prelude::*;
use uuid::Uuid;

// =============================================================================
// BAYESIAN UPDATE INVARIANTS
// =============================================================================

proptest! {
    /// After ANY valid Bayesian update, the posterior truth value
    /// remains within [0.01, 0.99] (the configured clamp bounds).
    ///
    /// This prevents "certainty lock-in" where a truth value reaches
    /// 0.0 or 1.0 and can never be updated again.
    #[test]
    #[allow(
        deprecated,
        reason = "exercises `BayesianUpdater`, deprecated in favour of CDST pignistic \
                  probability but still on the live path (epigraph-api `submission.rs`, \
                  engine `service.rs`); the invariant must keep being covered until those \
                  callers migrate"
    )]
    fn bayesian_update_preserves_bounds(
        prior_val in 0.0..=1.0_f64,
        likelihood_true in 0.0..=1.0_f64,
        likelihood_false in 0.0..=1.0_f64,
    ) {
        let updater = BayesianUpdater::new();
        let prior = TruthValue::new(prior_val).unwrap();

        if let Ok(posterior) = updater.update(prior, likelihood_true, likelihood_false) {
            let v = posterior.value();
            prop_assert!(
                (0.01..=0.99).contains(&v),
                "Bayesian update({}, lt={}, lf={}) produced posterior {} outside [0.01, 0.99]",
                prior_val, likelihood_true, likelihood_false, v
            );
            prop_assert!(
                !v.is_nan(),
                "Bayesian update produced NaN for prior={}, lt={}, lf={}",
                prior_val, likelihood_true, likelihood_false
            );
        }
        // Error is acceptable for edge cases (e.g., both likelihoods zero
        // causing division by near-zero P(E))
    }

    /// Bayesian update with support always produces posteriors in [0.01, 0.99]
    #[test]
    #[allow(
        deprecated,
        reason = "exercises `BayesianUpdater`, deprecated in favour of CDST pignistic \
                  probability but still on the live path (epigraph-api `submission.rs`, \
                  engine `service.rs`); the invariant must keep being covered until those \
                  callers migrate"
    )]
    fn bayesian_update_with_support_preserves_bounds(
        prior_val in 0.0..=1.0_f64,
        strength in 0.0..=1.0_f64,
    ) {
        let updater = BayesianUpdater::new();
        let prior = TruthValue::new(prior_val).unwrap();

        if let Ok(posterior) = updater.update_with_support(prior, strength) {
            let v = posterior.value();
            prop_assert!(
                (0.01..=0.99).contains(&v),
                "update_with_support(prior={}, strength={}) produced {} outside [0.01, 0.99]",
                prior_val, strength, v
            );
        }
        // Error is acceptable for edge cases
    }

    /// Bayesian update with refutation always produces posteriors in [0.01, 0.99]
    #[test]
    #[allow(
        deprecated,
        reason = "exercises `BayesianUpdater`, deprecated in favour of CDST pignistic \
                  probability but still on the live path (epigraph-api `submission.rs`, \
                  engine `service.rs`); the invariant must keep being covered until those \
                  callers migrate"
    )]
    fn bayesian_update_with_refutation_preserves_bounds(
        prior_val in 0.0..=1.0_f64,
        strength in 0.0..=1.0_f64,
    ) {
        let updater = BayesianUpdater::new();
        let prior = TruthValue::new(prior_val).unwrap();

        if let Ok(posterior) = updater.update_with_refutation(prior, strength) {
            let v = posterior.value();
            prop_assert!(
                (0.01..=0.99).contains(&v),
                "update_with_refutation(prior={}, strength={}) produced {} outside [0.01, 0.99]",
                prior_val, strength, v
            );
        }
        // Error is acceptable for edge cases
    }

    /// Bayesian update rejects likelihoods outside [0, 1]
    #[test]
    #[allow(
        deprecated,
        reason = "exercises `BayesianUpdater`, deprecated in favour of CDST pignistic \
                  probability but still on the live path (epigraph-api `submission.rs`, \
                  engine `service.rs`); the invariant must keep being covered until those \
                  callers migrate"
    )]
    fn bayesian_update_rejects_invalid_likelihoods(
        prior_val in 0.0..=1.0_f64,
        bad_likelihood in prop::strategy::Union::new(vec![
            Just(1.5_f64).boxed(),
            Just(-0.1_f64).boxed(),
            Just(f64::NAN).boxed(),
            Just(f64::INFINITY).boxed(),
            Just(f64::NEG_INFINITY).boxed(),
            (1.01..=f64::MAX).boxed(),
            (f64::MIN..0.0_f64).boxed(),
        ]),
    ) {
        // Filter out -0.0 which is valid (== 0.0)
        prop_assume!(!(0.0..=1.0).contains(&bad_likelihood) || bad_likelihood.is_nan());
        let updater = BayesianUpdater::new();
        let prior = TruthValue::new(prior_val).unwrap();

        // At least one of the two likelihood positions should cause rejection
        let result1 = updater.update(prior, bad_likelihood, 0.5);
        let result2 = updater.update(prior, 0.5, bad_likelihood);

        prop_assert!(
            result1.is_err() || result2.is_err(),
            "Bayesian update should reject invalid likelihood {} \
             but got Ok for both positions",
            bad_likelihood
        );
    }
}

// =============================================================================
// EVIDENCE WEIGHTING INVARIANTS
// =============================================================================

/// Strategy to generate a random `EvidenceType`
fn evidence_type_strategy() -> impl Strategy<Value = epigraph_engine::EvidenceType> {
    prop_oneof![
        Just(epigraph_engine::EvidenceType::Empirical),
        Just(epigraph_engine::EvidenceType::Logical),
        Just(epigraph_engine::EvidenceType::Statistical),
        Just(epigraph_engine::EvidenceType::Testimonial),
        Just(epigraph_engine::EvidenceType::Circumstantial),
    ]
}

proptest! {
    /// Evidence weight is deterministic: identical inputs always produce identical output.
    /// This is critical for reproducibility and auditability.
    #[test]
    fn evidence_weight_deterministic(
        evidence_type in evidence_type_strategy(),
        source_truth_val in proptest::option::of(0.0..=1.0_f64),
        relevance in 0.0..=1.0_f64,
        age_days in 0.0..=365.0_f64,
    ) {
        let weighter = EvidenceWeighter::new();
        let source_truth = source_truth_val.map(|v| TruthValue::new(v).unwrap());

        let weight1 = weighter
            .calculate_weight(evidence_type, source_truth, relevance, age_days)
            .unwrap();
        let weight2 = weighter
            .calculate_weight(evidence_type, source_truth, relevance, age_days)
            .unwrap();

        prop_assert!(
            (weight1 - weight2).abs() < f64::EPSILON,
            "Evidence weight must be deterministic: got {} and {} for same inputs \
             (type={:?}, source_truth={:?}, relevance={}, age={})",
            weight1, weight2, evidence_type, source_truth_val, relevance, age_days
        );
    }

    /// All evidence weights are non-negative.
    /// Negative weights would break the epistemic model by turning
    /// supporting evidence into refuting evidence silently.
    #[test]
    fn evidence_weight_non_negative(
        evidence_type in evidence_type_strategy(),
        source_truth_val in proptest::option::of(0.0..=1.0_f64),
        relevance in 0.0..=1.0_f64,
        age_days in 0.0..=1000.0_f64,
    ) {
        let weighter = EvidenceWeighter::new();
        let source_truth = source_truth_val.map(|v| TruthValue::new(v).unwrap());

        let weight = weighter
            .calculate_weight(evidence_type, source_truth, relevance, age_days)
            .unwrap();

        prop_assert!(
            weight >= 0.0,
            "Evidence weight must be non-negative: got {} for type={:?}, \
             source_truth={:?}, relevance={}, age={}",
            weight, evidence_type, source_truth_val, relevance, age_days
        );
    }

    /// Evidence weight is bounded by [min_weight, max_weight] from config.
    /// Default config: min_weight = 0.01, max_weight = 1.0.
    #[test]
    fn evidence_weight_bounded_by_config(
        evidence_type in evidence_type_strategy(),
        source_truth_val in proptest::option::of(0.0..=1.0_f64),
        relevance in 0.0..=1.0_f64,
        age_days in 0.0..=365.0_f64,
    ) {
        let weighter = EvidenceWeighter::new();
        let source_truth = source_truth_val.map(|v| TruthValue::new(v).unwrap());

        let weight = weighter
            .calculate_weight(evidence_type, source_truth, relevance, age_days)
            .unwrap();

        prop_assert!(
            (0.01..=1.0).contains(&weight),
            "Evidence weight {} must be in [0.01, 1.0] (default config bounds) \
             for type={:?}, source_truth={:?}, relevance={}, age={}",
            weight, evidence_type, source_truth_val, relevance, age_days
        );
    }

    /// `combine_weights` always produces a value in [0.0, 1.0]
    #[test]
    fn combine_weights_bounded(
        weights in proptest::collection::vec(0.0..=1.0_f64, 0..20),
    ) {
        let weighter = EvidenceWeighter::new();
        let combined = weighter.combine_weights(&weights);

        prop_assert!(
            (0.0..=1.0).contains(&combined),
            "combine_weights({:?}) produced {} which is outside [0.0, 1.0]",
            weights, combined
        );
    }

    /// `combine_weights` is deterministic
    #[test]
    fn combine_weights_deterministic(
        weights in proptest::collection::vec(0.0..=1.0_f64, 0..10),
    ) {
        let weighter = EvidenceWeighter::new();
        let result1 = weighter.combine_weights(&weights);
        let result2 = weighter.combine_weights(&weights);

        prop_assert!(
            (result1 - result2).abs() < f64::EPSILON,
            "combine_weights must be deterministic: got {} and {} for {:?}",
            result1, result2, weights
        );
    }

    /// Evidence weight rejects invalid relevance values
    #[test]
    fn evidence_weight_rejects_invalid_relevance(
        evidence_type in evidence_type_strategy(),
        bad_relevance in prop::strategy::Union::new(vec![
            (1.01..=100.0_f64).boxed(),
            (-100.0..0.0_f64).boxed(),
        ]),
    ) {
        prop_assume!(!(0.0..=1.0).contains(&bad_relevance));
        let weighter = EvidenceWeighter::new();

        let result = weighter.calculate_weight(evidence_type, None, bad_relevance, 0.0);

        prop_assert!(
            result.is_err(),
            "Evidence weight should reject invalid relevance {}, got {:?}",
            bad_relevance, result
        );
    }
}

// =============================================================================
// DAG VALIDATION INVARIANTS
// =============================================================================

proptest! {
    /// A node can NEVER be its own parent. Self-referential reasoning
    /// is circular logic and must always be rejected.
    #[test]
    fn dag_rejects_self_reference(
        node_bytes in proptest::collection::vec(any::<u8>(), 16),
    ) {
        let mut validator = DagValidator::new();
        let bytes: [u8; 16] = node_bytes.try_into().unwrap();
        let node_id = Uuid::from_bytes(bytes);

        let result = validator.add_edge(node_id, node_id);

        prop_assert!(
            result.is_err(),
            "DAG must reject self-reference for node {}",
            node_id
        );
    }

    /// Adding A -> B then B -> A always creates a cycle and must be rejected.
    #[test]
    fn dag_rejects_direct_cycle(
        a_bytes in proptest::collection::vec(any::<u8>(), 16),
        b_bytes in proptest::collection::vec(any::<u8>(), 16),
    ) {
        let a: [u8; 16] = a_bytes.try_into().unwrap();
        let b: [u8; 16] = b_bytes.try_into().unwrap();
        let id_a = Uuid::from_bytes(a);
        let id_b = Uuid::from_bytes(b);

        // Skip if same ID (that is the self-reference test above)
        prop_assume!(id_a != id_b);

        let mut validator = DagValidator::new();

        // A -> B should always succeed
        let result1 = validator.add_edge(id_a, id_b);
        prop_assert!(result1.is_ok(), "A -> B should succeed");

        // B -> A should always fail (creates cycle)
        let result2 = validator.add_edge(id_b, id_a);
        prop_assert!(
            result2.is_err(),
            "B -> A should be rejected after A -> B (cycle)"
        );
    }

    /// After adding valid (acyclic) edges, the graph remains valid.
    /// A linear chain A -> B -> C -> D is always a valid DAG.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn dag_linear_chain_always_valid(
        chain_len in 2..=10_usize,
    ) {
        let mut validator = DagValidator::new();
        let nodes: Vec<Uuid> = (0..chain_len)
            .map(|i| Uuid::from_bytes([i as u8; 16]))
            .collect();

        for i in 0..nodes.len() - 1 {
            let result = validator.add_edge(nodes[i], nodes[i + 1]);
            prop_assert!(
                result.is_ok(),
                "Edge {} -> {} in linear chain should succeed",
                i, i + 1
            );
        }

        prop_assert!(
            validator.is_valid(),
            "Linear chain of {} nodes should be a valid DAG",
            chain_len
        );
    }
}

// =============================================================================
// REPUTATION ISOLATION INVARIANT
// =============================================================================

proptest! {
    /// CRITICAL INVARIANT: Reputation NEVER influences initial truth calculation.
    ///
    /// For ANY reputation value, `calculate_initial_truth` produces the SAME result
    /// given the same `evidence_weight` and `evidence_count`. This is because
    /// `calculate_initial_truth` does not accept a reputation parameter at all --
    /// the isolation is enforced at the type system level.
    ///
    /// This test verifies the invariant by showing that the function's output
    /// depends ONLY on evidence parameters.
    #[test]
    #[allow(
        deprecated,
        reason = "exercises `BayesianUpdater`, deprecated in favour of CDST pignistic \
                  probability but still on the live path (epigraph-api `submission.rs`, \
                  engine `service.rs`); the invariant must keep being covered until those \
                  callers migrate"
    )]
    fn reputation_never_influences_initial_truth(
        evidence_weight in 0.0..=1.0_f64,
        evidence_count in 0..=20_usize,
        _reputation_a in 0.0..=1.0_f64,
        _reputation_b in 0.0..=1.0_f64,
    ) {
        // calculate_initial_truth takes ONLY evidence_weight and evidence_count.
        // There is NO reputation parameter. This is the architectural guarantee.
        //
        // We call it twice with the same evidence params to prove determinism,
        // and the unused _reputation_a/_reputation_b parameters document that
        // no matter WHAT reputation values an agent has, the result is identical.
        let truth_a = BayesianUpdater::calculate_initial_truth(evidence_weight, evidence_count);
        let truth_b = BayesianUpdater::calculate_initial_truth(evidence_weight, evidence_count);

        prop_assert!(
            (truth_a.value() - truth_b.value()).abs() < f64::EPSILON,
            "Initial truth must be deterministic from evidence alone. \
             Got {} and {} for weight={}, count={}",
            truth_a.value(), truth_b.value(), evidence_weight, evidence_count
        );

        // Verify the result is always in valid bounds
        let v = truth_a.value();
        prop_assert!(
            (0.0..=1.0).contains(&v),
            "Initial truth {} out of bounds for weight={}, count={}",
            v, evidence_weight, evidence_count
        );
    }

    /// Initial truth is capped at 0.85 regardless of evidence parameters.
    /// No new claim should ever start with near-certain truth.
    #[test]
    #[allow(
        deprecated,
        reason = "exercises `BayesianUpdater`, deprecated in favour of CDST pignistic \
                  probability but still on the live path (epigraph-api `submission.rs`, \
                  engine `service.rs`); the invariant must keep being covered until those \
                  callers migrate"
    )]
    fn initial_truth_never_exceeds_cap(
        evidence_weight in 0.0..=1.0_f64,
        evidence_count in 0..=100_usize,
    ) {
        let truth = BayesianUpdater::calculate_initial_truth(evidence_weight, evidence_count);

        prop_assert!(
            truth.value() <= 0.85,
            "Initial truth {} exceeds cap of 0.85 for weight={}, count={}",
            truth.value(), evidence_weight, evidence_count
        );
    }

    /// With zero evidence (weight=0, count=0), initial truth is exactly 0.5
    /// (maximum uncertainty). This is the baseline.
    #[test]
    #[allow(
        deprecated,
        reason = "exercises `BayesianUpdater`, deprecated in favour of CDST pignistic \
                  probability but still on the live path (epigraph-api `submission.rs`, \
                  engine `service.rs`); the invariant must keep being covered until those \
                  callers migrate"
    )]
    fn zero_evidence_produces_maximum_uncertainty(
        _any_reputation in 0.0..=1.0_f64,
    ) {
        let truth = BayesianUpdater::calculate_initial_truth(0.0, 0);

        prop_assert!(
            (truth.value() - 0.5).abs() < f64::EPSILON,
            "Zero evidence should produce exactly 0.5, got {}",
            truth.value()
        );
    }
}

// =============================================================================
// SHEAF ORDER-INDEPENDENCE INVARIANTS
// =============================================================================

/// Tolerance for the sheaf properties. Tighter than the DS suite's 1e-6 because
/// these are single means and sums, not iterated combinations.
const SHEAF_EPSILON: f64 = 1e-9;

fn arb_restriction_kind() -> impl Strategy<Value = RestrictionKind> {
    prop_oneof![
        (0.01..=0.99_f64).prop_map(RestrictionKind::Positive),
        (0.01..=0.99_f64).prop_map(RestrictionKind::Negative),
        (0.01..=0.99_f64).prop_map(RestrictionKind::FrameEvidence),
        Just(RestrictionKind::Neutral),
    ]
}

/// Strategy: 0-7 neighbours. The zero-length lower bound matters — it is what
/// exercises the `count == 0 => None` branch of `compute_expected_betp`.
fn arb_neighbors() -> impl Strategy<Value = Vec<(f64, RestrictionKind)>> {
    proptest::collection::vec((0.0..=1.0_f64, arb_restriction_kind()), 0..8)
}

/// Deterministically permute `items` using `seed` as a sort key.
///
/// `prop_shuffle()` is deliberately NOT used: it yields an independently
/// shuffled *sample*, not a permutation of the same vector, so it cannot
/// express "same multiset, different order".
fn permute<T: Clone>(items: &[T], seed: &[u32]) -> Vec<T> {
    let mut idx: Vec<usize> = (0..items.len()).collect();
    idx.sort_by_key(|&i| (seed.get(i).copied().unwrap_or(0), i));
    idx.into_iter().map(|i| items[i].clone()).collect()
}

fn arb_obstruction() -> impl Strategy<Value = SheafObstruction> {
    (
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        0u8..=10,
        0.0..=1.0_f64,
        0.0..=1.0_f64,
    )
        .prop_map(|(s, t, tenths, sb, tb)| SheafObstruction {
            source_id: Uuid::from_bytes(s),
            target_id: Uuid::from_bytes(t),
            relationship: "supports".into(),
            source_betp: sb,
            target_betp: tb,
            expected_target_betp: 0.5,
            // Quantised to tenths on purpose: ties are exactly where a stable
            // sort with no secondary key is fragile, so we force plenty of them.
            edge_inconsistency: f64::from(tenths) / 10.0,
        })
}

proptest! {
    /// `compute_expected_betp` is a mean over the epistemic neighbours, so the
    /// order they arrive in must not change the answer.
    ///
    /// Tolerance rather than equality: the function is `sum / count` and
    /// floating-point addition is not associative.
    #[test]
    fn sheaf_expected_betp_is_permutation_invariant(
        neighbors in arb_neighbors(),
        perm_seed in proptest::collection::vec(any::<u32>(), 0..8),
    ) {
        let permuted = permute(&neighbors, &perm_seed);
        let mut reversed = neighbors.clone();
        reversed.reverse();

        let base = compute_expected_betp(&neighbors);

        for (label, other) in [("permuted", &permuted), ("reversed", &reversed)] {
            match (base, compute_expected_betp(other)) {
                (None, None) => {}
                (Some(x), Some(y)) => prop_assert!(
                    (x - y).abs() < SHEAF_EPSILON,
                    "expected_betp ({label}): {x} vs {y} (diff = {})",
                    (x - y).abs()
                ),
                (a, b) => prop_assert!(
                    false,
                    "expected_betp ({label}) disagreed on emptiness: {a:?} vs {b:?}"
                ),
            }
        }
    }

    /// Every contribution is in [0, 1] — `Positive(f)` contributes
    /// `betp * f` and `Negative(f)` contributes `(1 - betp) * f`, both with
    /// `betp, f` in [0, 1] — and the result is their mean, so it stays in [0, 1].
    #[test]
    fn sheaf_expected_betp_stays_in_unit_interval(
        neighbors in arb_neighbors(),
    ) {
        if let Some(e) = compute_expected_betp(&neighbors) {
            prop_assert!(
                (0.0..=1.0).contains(&e),
                "expected_betp = {e} escaped [0, 1] for {} neighbours",
                neighbors.len()
            );
        }
    }

    /// A section summarises its neighbourhood; permuting that neighbourhood
    /// must not move the summary.
    ///
    /// `neighbor_count` is an exact `usize` filter count, so it gets
    /// `prop_assert_eq!`; the two floats inherit `compute_expected_betp`'s
    /// `sum / count` and so get a tolerance.
    #[test]
    fn sheaf_section_is_permutation_invariant(
        neighbors in arb_neighbors(),
        perm_seed in proptest::collection::vec(any::<u32>(), 0..8),
        local_betp in 0.0..=1.0_f64,
        local_belief in 0.0..=1.0_f64,
        local_plausibility in 0.0..=1.0_f64,
    ) {
        let permuted = permute(&neighbors, &perm_seed);

        let a = compute_section(
            Uuid::nil(), local_betp, local_belief, local_plausibility, &neighbors,
        );
        let b = compute_section(
            Uuid::nil(), local_betp, local_belief, local_plausibility, &permuted,
        );

        prop_assert_eq!(a.neighbor_count, b.neighbor_count);
        prop_assert!(
            (a.expected_betp - b.expected_betp).abs() < SHEAF_EPSILON,
            "expected_betp: {} vs {}", a.expected_betp, b.expected_betp
        );
        prop_assert!(
            (a.consistency_radius - b.consistency_radius).abs() < SHEAF_EPSILON,
            "consistency_radius: {} vs {}", a.consistency_radius, b.consistency_radius
        );
    }

    /// `compute_cohomology`'s scalar outputs do not depend on the order the
    /// obstructions were collected in, and neither does the *set* that survives
    /// the threshold.
    ///
    /// The surviving obstructions are compared as a MULTISET, not as a `Vec`,
    /// and that weakening is deliberate: the stronger claim is false. The
    /// function sorts by `edge_inconsistency` DESC with a stable `sort_by` and
    /// no secondary key, so obstructions with EQUAL inconsistency come out in
    /// caller order — the emitted `Vec` order is genuinely permutation-
    /// dependent. Asserted as a `Vec` this test fails within a few dozen cases
    /// on a tied pair (falsified during development). Adding a tiebreak to the
    /// sort would be a behaviour change and belongs in its own item; nothing
    /// observable depends on the tie order today, as `compute_cohomology` has
    /// no production caller.
    ///
    /// `h0` and `edge_count` are exact counts; `h1` and `h1_normalized` are a
    /// sum over a re-ordered `Vec` and so need a tolerance.
    #[test]
    fn sheaf_cohomology_is_permutation_invariant(
        obstructions in proptest::collection::vec(arb_obstruction(), 0..10),
        perm_seed in proptest::collection::vec(any::<u32>(), 0..10),
        threshold in 0.0..=1.0_f64,
    ) {
        // `compute_cohomology` takes `&mut Vec<_>` and both sorts and retains it,
        // so each call gets its own clone.
        let mut base_input = obstructions.clone();
        let mut perm_input = permute(&obstructions, &perm_seed);

        let a = compute_cohomology(&mut base_input, threshold);
        let b = compute_cohomology(&mut perm_input, threshold);

        prop_assert_eq!(a.h0, b.h0);
        prop_assert_eq!(a.edge_count, b.edge_count);
        prop_assert!(
            (a.h1 - b.h1).abs() < SHEAF_EPSILON,
            "h1: {} vs {}", a.h1, b.h1
        );
        prop_assert!(
            (a.h1_normalized - b.h1_normalized).abs() < SHEAF_EPSILON,
            "h1_normalized: {} vs {}", a.h1_normalized, b.h1_normalized
        );

        // `SheafObstruction` derives only `Debug, Clone` — there is no
        // `PartialEq` to lean on, so project to a comparable key.
        let key = |o: &SheafObstruction| {
            (o.edge_inconsistency.to_bits(), o.source_id, o.target_id)
        };
        let mut ka: Vec<_> = a.obstructions.iter().map(key).collect();
        let mut kb: Vec<_> = b.obstructions.iter().map(key).collect();
        ka.sort_unstable();
        kb.sort_unstable();
        prop_assert_eq!(ka, kb);
    }

    /// The `expected` half of `compute_edge_inconsistency`'s return is a
    /// restriction map applied to the SOURCE: for `Positive`/`Negative` it is a
    /// function of `(source_betp, relationship)` alone and must be identical
    /// across different targets. For `Neutral`/`FrameEvidence` there is no
    /// transmission, so it echoes its own target back.
    ///
    /// This pins the restriction-map contract that a future refactor could
    /// quietly break.
    #[test]
    fn sheaf_edge_inconsistency_expected_is_independent_of_target(
        source in 0.0..=1.0_f64,
        t1 in 0.0..=1.0_f64,
        t2 in 0.0..=1.0_f64,
        rel in prop_oneof![
            Just("supports"),
            Just("refutes"),
            Just("contradicts"),
            Just("elaborates"),
            Just("generalizes"),
            Just("informs"),
            Just("frame_validates"),
            Just("derived_from"),
            Just("supersedes"),
        ],
    ) {
        let (inc1, exp1) = compute_edge_inconsistency(source, t1, rel);
        let (inc2, exp2) = compute_edge_inconsistency(source, t2, rel);

        prop_assert!(inc1 >= 0.0, "inconsistency went negative: {inc1} ({rel})");
        prop_assert!(inc2 >= 0.0, "inconsistency went negative: {inc2} ({rel})");

        match restriction_kind(rel) {
            RestrictionKind::Positive(_) | RestrictionKind::Negative(_) => {
                prop_assert!(
                    (exp1 - exp2).abs() < SHEAF_EPSILON,
                    "{rel}: expected target depends on the target ({exp1} vs {exp2})"
                );
            }
            RestrictionKind::Neutral | RestrictionKind::FrameEvidence(_) => {
                prop_assert!(
                    (exp1 - t1).abs() < SHEAF_EPSILON && (exp2 - t2).abs() < SHEAF_EPSILON,
                    "{rel}: non-transmitting edge should echo its target, got {exp1}/{exp2}"
                );
            }
        }
    }
}
