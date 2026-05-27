//! Regression: CDST BP groups a target's incoming supporter messages by
//! alternative-set equivalence class before Dempster-combining.
//!
//! Setup: three supporters A1, A2, A3 each evidentially-support a single
//! target T. A1 and A2 are marked `alternative_of` (mutually-exclusive
//! supporters); A3 is independent.
//!
//! - **Control run** (`AltSetMembership` empty): the engine treats the three
//!   supporter messages into T as independent and Dempster-combines all
//!   three pairwise (legacy behavior).
//! - **Treatment run** (`AltSetMembership = {A1 -> [A2], A2 -> [A1]}`):
//!   A1 and A2 share a canonical class. Their messages reduce via
//!   `combine_alternative_set` (max-Bel/max-Pl, "least restrictive
//!   alternative"). The reduced BBA then Dempster-combines with A3's.
//!
//! Assertions:
//! 1. The two BetP values differ by at least `1e-3` — the grouping path
//!    is firing (not a no-op).
//! 2. `betp_with_alt < betp_no_alt` — max-Pl reduction is less restrictive
//!    than the product rule, so combined Bel for T is lower.
//!
//! Approach A from the plan: drive the engine directly (no DB, no HTTP),
//! comparing two `run_cdst_bp` calls that differ only in their
//! `CdstBpConfig.alt_set_membership` field.

use std::collections::{BTreeSet, HashMap};

use epigraph_ds::{FrameOfDiscernment, MassFunction};
use epigraph_engine::bp::FactorPotential;
use epigraph_engine::cdst_bp::{run_cdst_bp, AltSetMembership, CdstBpConfig};
use uuid::Uuid;

const H_SUPPORTED: usize = 0;

fn binary_frame() -> FrameOfDiscernment {
    FrameOfDiscernment::new("binary", vec!["supported".into(), "unsupported".into()])
        .expect("binary frame construction must not fail")
}

fn vacuous() -> MassFunction {
    MassFunction::vacuous(binary_frame())
}

fn supported(mass: f64) -> MassFunction {
    MassFunction::simple(binary_frame(), BTreeSet::from([H_SUPPORTED]), mass)
        .expect("simple supported mass")
}

/// Deterministic UUIDs so the canonical-class min picks (a1, a2) the same
/// way every run, isolating the test from `Uuid::new_v4` ordering quirks.
fn fixed_uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn find_betp(result: &epigraph_engine::cdst_bp::CdstBpResult, var: Uuid) -> f64 {
    result
        .updated_betps
        .iter()
        .find(|(id, _)| *id == var)
        .map(|(_, p)| *p)
        .unwrap_or(f64::NAN)
}

#[test]
fn alt_set_grouping_shifts_target_betp_below_pure_dempster() {
    // A1 < A2 < A3 < T by raw byte order, but only the (A1, A2) class
    // is exercised by the alt-set wiring; A3 and T are not in any class.
    let a1 = fixed_uuid(0x01);
    let a2 = fixed_uuid(0x02);
    let a3 = fixed_uuid(0x03);
    let t = fixed_uuid(0x04);

    // Initial beliefs: A1, A2, A3 each carry strong "supported" mass;
    // T starts vacuous. Evidence anchors each supporter to itself and
    // leaves T unanchored so the graph signal drives its BetP.
    let mut initial = HashMap::new();
    initial.insert(a1, supported(0.8));
    initial.insert(a2, supported(0.8));
    initial.insert(a3, supported(0.5));
    initial.insert(t, vacuous());

    let mut evidence = HashMap::new();
    evidence.insert(a1, supported(0.8));
    evidence.insert(a2, supported(0.8));
    evidence.insert(a3, supported(0.5));
    evidence.insert(t, vacuous());

    // Three EvidentialSupport factors, one per supporter -> T.
    // `vars = [supporter, T]` matches the route's convention (see
    // crates/epigraph-api/src/routes/computation.rs factor construction).
    let factors = vec![
        (
            fixed_uuid(0x11),
            FactorPotential::EvidentialSupport { strength: 0.7 },
            vec![a1, t],
        ),
        (
            fixed_uuid(0x12),
            FactorPotential::EvidentialSupport { strength: 0.7 },
            vec![a2, t],
        ),
        (
            fixed_uuid(0x13),
            FactorPotential::EvidentialSupport { strength: 0.7 },
            vec![a3, t],
        ),
    ];

    // -- Control: empty AltSetMembership reproduces legacy pure-Dempster path
    let cfg_control = CdstBpConfig::default();
    assert!(
        cfg_control.alt_set_membership.is_empty(),
        "default CdstBpConfig must seed an empty alt-set; got {} entries",
        cfg_control.alt_set_membership.len()
    );
    let result_control = run_cdst_bp(&factors, &initial, &evidence, &cfg_control);
    let betp_no_alt = find_betp(&result_control, t);

    // -- Treatment: A1 and A2 in one alt-set equivalence class
    let mut alt_set: AltSetMembership = HashMap::new();
    alt_set.insert(a1, vec![a2]);
    alt_set.insert(a2, vec![a1]);
    let cfg_treatment = CdstBpConfig {
        alt_set_membership: alt_set,
        ..CdstBpConfig::default()
    };
    let result_treatment = run_cdst_bp(&factors, &initial, &evidence, &cfg_treatment);
    let betp_with_alt = find_betp(&result_treatment, t);

    eprintln!(
        "alt_set_cdst_integration: betp_no_alt={betp_no_alt:.6}, \
         betp_with_alt={betp_with_alt:.6}, delta={:.6}",
        betp_with_alt - betp_no_alt
    );

    // Sanity: both runs must produce a meaningful BetP (not NaN, not 0.5
    // vacuous — A3 alone still drives T above the prior in both runs).
    assert!(
        betp_no_alt.is_finite() && betp_with_alt.is_finite(),
        "BetP must be finite: no_alt={betp_no_alt}, with_alt={betp_with_alt}"
    );
    assert!(
        betp_no_alt > 0.5 && betp_with_alt > 0.5,
        "all three supporters push T above 0.5: no_alt={betp_no_alt}, with_alt={betp_with_alt}"
    );

    // Gate 1: the alt-set grouping path actually fires — BetP shifts.
    assert!(
        (betp_with_alt - betp_no_alt).abs() > 1e-3,
        "alt-set grouping must shift BetP — no_alt={betp_no_alt:.6}, with_alt={betp_with_alt:.6} \
         (delta {:.6} <= 1e-3 means grouping is a no-op)",
        betp_with_alt - betp_no_alt
    );

    // Gate 2: shift direction matches max-Pl semantics — the
    // least-restrictive-alternative rule is less informative than the
    // product rule, so combined BetP must be lower with alt-set on.
    assert!(
        betp_with_alt < betp_no_alt,
        "max-Pl reduction should lower combined BetP relative to pure Dempster: \
         no_alt={betp_no_alt:.6}, with_alt={betp_with_alt:.6}"
    );
}
