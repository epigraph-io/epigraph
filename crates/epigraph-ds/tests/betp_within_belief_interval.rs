//! Backlog 0183a294: `BetP` must lie within `[Bel, Pl]`.
//!
//! `measures::pignistic_probability` divided its result by
//! `1 / (1 - non_classical_mass)` — where `non_classical_mass` sums BOTH the
//! empty-set (conflict) focal AND every complement (open-world) focal — while
//! `belief` and `plausibility` sum raw masses. `normalize_unit_interval` on the
//! latter two is a sign/NaN guard, explicitly "deliberately **not**
//! `f64::clamp`", not a renormalisation. So the three measures were reported on
//! two different denominators and BetP escaped its own interval.
//!
//! For a singleton target the un-normalized transform satisfies the bound
//! identically:
//!   Bel({x}) = m({x})
//!           <= m({x}) + sum_{A∋x, |A|>1} m(A)/|A|   = BetP(x)
//!           <= sum_{A∋x} m(A)                        = Pl({x})
//! Dividing only BetP by `(1 - non_classical)` breaks the upper bound by exactly
//! that factor.
//!
//! Renormalising the *complement* mass away is separately wrong on its own
//! terms: `m(Ω, complement)` encodes "the truth may lie outside this frame",
//! which is the open-world assumption CDST exists to represent. Redistributing
//! it onto the in-frame hypotheses silently reasserts a closed world.

use epigraph_ds::measures::{belief, pignistic_probability, plausibility};
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use std::collections::{BTreeMap, BTreeSet};

fn binary_frame() -> FrameOfDiscernment {
    FrameOfDiscernment::new("test", vec!["true".into(), "false".into()]).unwrap()
}

fn singleton(i: usize) -> FocalElement {
    FocalElement::positive(BTreeSet::from([i]))
}

fn build(pairs: Vec<(FocalElement, f64)>) -> MassFunction {
    let frame = binary_frame();
    let mut masses = BTreeMap::new();
    for (fe, v) in pairs {
        masses.insert(fe, v);
    }
    MassFunction::new(frame, masses).unwrap()
}

fn assert_within(m: &MassFunction, idx: usize, label: &str) {
    let target = singleton(idx);
    let bel = belief(m, &target);
    let pl = plausibility(m, &target);
    let betp = pignistic_probability(m, idx);
    assert!(
        betp >= bel - 1e-9,
        "{label}: BetP {betp} below Bel {bel} (Pl {pl})"
    );
    assert!(
        betp <= pl + 1e-9,
        "{label}: BetP {betp} above Pl {pl} (Bel {bel}) - BetP escaped its own \
         belief interval, a state no mass function can represent"
    );
}

/// Control: with no conflict and no open-world mass the normalizer was 1.0, so
/// this case must be byte-identical before and after the fix.
#[test]
fn case_a_no_conflict_no_open_world_is_unchanged() {
    let frame = binary_frame();
    let m = build(vec![
        (singleton(0), 0.6),
        (FocalElement::theta(&frame), 0.4),
    ]);
    assert!((pignistic_probability(&m, 0) - 0.8).abs() < 1e-9);
    assert_within(&m, 0, "case (a) control");
}

/// Conflict-only. This is the exact mass function the in-tree unit test
/// `measures::tests::pignistic_with_conflict` asserts against, where the comment
/// reads "Mass on conflict should be normalized away" and the documented
/// expectation 0.857 is ALREADY above Pl = 0.7.
#[test]
fn case_b_conflict_mass_keeps_betp_under_plausibility() {
    let frame = binary_frame();
    let m = build(vec![
        (FocalElement::conflict(), 0.3),
        (singleton(0), 0.5),
        (FocalElement::theta(&frame), 0.2),
    ]);
    // Pl is 0.7 raw, but conflict is divided out of all three measures alike, so
    // Pl = 0.7/0.7 = 1.0 and BetP = 0.6/0.7 = 0.857 now sits INSIDE it. Before the
    // fix BetP was renormalized and Pl was not, giving 0.857 > 0.7.
    let pl = plausibility(&m, &singleton(0));
    assert!(
        (pl - 1.0).abs() < 1e-9,
        "fixture check: Pl should renormalize to 1.0, got {pl}"
    );
    assert_within(&m, 0, "case (b) conflict-only");
}

/// Open-world-only. Renormalising `missing` mass away inflates BetP while Bel
/// and Pl stay put.
#[test]
fn case_c_open_world_mass_keeps_betp_under_plausibility() {
    let frame = binary_frame();
    let m = build(vec![
        (singleton(0), 0.5),
        (FocalElement::missing(&frame), 0.5),
    ]);
    assert_within(&m, 0, "case (c) open-world-only");
}

/// Both conflict and open-world mass present - the shape
/// `select_combination_rule` produces outside the Dempster branch, i.e. the
/// live corpus state.
#[test]
fn case_d_conflict_and_open_world_keeps_betp_under_plausibility() {
    let frame = binary_frame();
    let m = build(vec![
        (FocalElement::conflict(), 0.2),
        (singleton(0), 0.4),
        (FocalElement::theta(&frame), 0.2),
        (FocalElement::missing(&frame), 0.2),
    ]);
    assert_within(&m, 0, "case (d) conflict + open-world");
}

/// Residual identity. Conflict is divided out; open-world mass is not. So the
/// pignistic distribution plus the (equally renormalized) open-world mass
/// accounts for exactly the whole unit.
///
/// This is what pins the asymmetry: had BOTH halves been divided out, BetP alone
/// would sum to 1 and the open-world mass would have been silently redistributed
/// onto the in-frame hypotheses.
#[test]
fn betp_plus_non_classical_mass_sums_to_one() {
    let frame = binary_frame();
    let m = build(vec![
        (FocalElement::conflict(), 0.2),
        (singleton(0), 0.35),
        (singleton(1), 0.15),
        (FocalElement::theta(&frame), 0.2),
        (FocalElement::missing(&frame), 0.1),
    ]);
    let betp_sum: f64 = (0..2).map(|i| pignistic_probability(&m, i)).sum();
    let renormalized_open_world = m.open_world_fraction() / (1.0 - m.mass_of_conflict());
    let total = betp_sum + renormalized_open_world;
    assert!(
        (total - 1.0).abs() < 1e-9,
        "BetP distribution ({betp_sum}) plus renormalized open-world mass \
         ({renormalized_open_world}) should account for the whole unit, got {total}"
    );
}
