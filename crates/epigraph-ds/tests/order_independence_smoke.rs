//! Regression smoke for PR #149 (commit a5b908e) — DS combine fixes.
//!
//! 1. `combine_multiple` is order-independent across input permutations.
//! 2. `belief` / `plausibility` are clamped to [0, 1] when the raw mass-sum
//!    drifts past 1.0 by one ULP (the case that tripped the
//!    `claims_{belief,plausibility}_bounds` CHECK constraints pre-fix).
//!
//! Retires backlog item `cebb0043-5a8b-4f93-a60b-a666c50ad7cf`.

use epigraph_ds::{
    combination::combine_multiple,
    measures::{belief, plausibility},
    FocalElement, FrameOfDiscernment, MassFunction,
};
use std::collections::{BTreeMap, BTreeSet};

const EPS: f64 = 1e-12;

fn ternary_frame() -> FrameOfDiscernment {
    FrameOfDiscernment::new("smoke", vec!["a".into(), "b".into(), "c".into()]).unwrap()
}

#[test]
fn combine_multiple_order_independent_under_reversal() {
    let frame = ternary_frame();

    // Three sources with overlapping focal elements — supporting {a},
    // partial-conflict {a,b}, refuting {b}. This mix previously drove
    // adaptive rule-switching across permutations pre-#149.
    let m_support = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.7).unwrap();
    let m_partial = MassFunction::simple(frame.clone(), BTreeSet::from([0, 1]), 0.6).unwrap();
    let m_refute = MassFunction::simple(frame, BTreeSet::from([1]), 0.5).unwrap();

    let forward = vec![m_support.clone(), m_partial.clone(), m_refute.clone()];
    let reverse = vec![m_refute, m_partial, m_support];

    let (combined_forward, _) = combine_multiple(&forward, 0.1).unwrap();
    let (combined_reverse, _) = combine_multiple(&reverse, 0.1).unwrap();

    // Same focal-element keys.
    let fwd_keys: BTreeSet<_> = combined_forward.masses().keys().collect();
    let rev_keys: BTreeSet<_> = combined_reverse.masses().keys().collect();
    assert_eq!(
        fwd_keys, rev_keys,
        "reversed-order combine produced different focal-element set"
    );

    // Same mass values within float tolerance.
    for (fe, mass) in combined_forward.masses() {
        let other = combined_reverse.mass_of(fe);
        assert!(
            (mass - other).abs() < EPS,
            "reversed-order combine diverges on {fe}: forward={mass}, reverse={other}"
        );
    }
}

#[test]
fn belief_and_plausibility_clamp_floating_point_drift() {
    // Construct a mass function whose 20 focal elements each carry 0.05.
    // [0.05; 20].sum() = 1.0000000000000002 in f64 (one ULP above 1.0).
    // MassFunction::new accepts it (within SUM_TOLERANCE = 1e-9), but pre-#149
    // belief(theta) and plausibility(theta) would return 1.0000000000000002,
    // tripping the claims_{belief,plausibility}_bounds CHECK constraint.
    let frame = FrameOfDiscernment::new(
        "five",
        vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
    )
    .unwrap();

    // Pick 20 non-empty subsets out of 31 available.
    let subsets: Vec<BTreeSet<usize>> = vec![
        BTreeSet::from([0]),
        BTreeSet::from([1]),
        BTreeSet::from([2]),
        BTreeSet::from([3]),
        BTreeSet::from([4]),
        BTreeSet::from([0, 1]),
        BTreeSet::from([0, 2]),
        BTreeSet::from([0, 3]),
        BTreeSet::from([0, 4]),
        BTreeSet::from([1, 2]),
        BTreeSet::from([1, 3]),
        BTreeSet::from([1, 4]),
        BTreeSet::from([2, 3]),
        BTreeSet::from([2, 4]),
        BTreeSet::from([3, 4]),
        BTreeSet::from([0, 1, 2]),
        BTreeSet::from([0, 1, 3]),
        BTreeSet::from([0, 2, 3]),
        BTreeSet::from([1, 2, 3]),
        BTreeSet::from([0, 1, 2, 3, 4]),
    ];
    assert_eq!(subsets.len(), 20);

    let mut masses: BTreeMap<FocalElement, f64> = BTreeMap::new();
    for sub in subsets {
        masses.insert(FocalElement::positive(sub), 0.05);
    }
    let raw_sum: f64 = masses.values().sum();
    // Sanity-check our drift premise: pre-fix this would propagate to belief/pl.
    assert!(
        raw_sum > 1.0,
        "test premise broken: 20x0.05 no longer drifts above 1.0 (sum={raw_sum:.20e})"
    );

    let m = MassFunction::new(frame.clone(), masses).unwrap();

    let theta = FocalElement::theta(&frame);
    let bel_theta = belief(&m, &theta);
    let pl_theta = plausibility(&m, &theta);

    assert!(
        (0.0..=1.0).contains(&bel_theta),
        "belief(Theta) escaped [0,1]: {bel_theta:.20e}"
    );
    assert!(
        (0.0..=1.0).contains(&pl_theta),
        "plausibility(Theta) escaped [0,1]: {pl_theta:.20e}"
    );
    // Clamp pins drifted-above-1.0 sums to exactly 1.0.
    assert_eq!(bel_theta, 1.0, "belief(Theta) not pinned to 1.0 by clamp");
    assert_eq!(
        pl_theta, 1.0,
        "plausibility(Theta) not pinned to 1.0 by clamp"
    );

    // And the singletons stay in [0,1] too — each singleton intersects ~half
    // the focal elements, so plausibility could drift past 1.0 the same way.
    for i in 0..5 {
        let fe = FocalElement::positive(BTreeSet::from([i]));
        let b = belief(&m, &fe);
        let p = plausibility(&m, &fe);
        assert!(
            (0.0..=1.0).contains(&b),
            "belief({i}) escaped [0,1]: {b:.20e}"
        );
        assert!(
            (0.0..=1.0).contains(&p),
            "plausibility({i}) escaped [0,1]: {p:.20e}"
        );
        assert!(b <= p + EPS, "Bel({i})={b} > Pl({i})={p}");
    }
}
