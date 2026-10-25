//! Belief profile, golden equivalence: a profile equal to today's constants
//! must reproduce the pre-profile fold BIT FOR BIT.
//!
//! The table below was recorded by folding every fixture in
//! `support/belief_fixtures.rs` with the calibration-taking reliability
//! functions and the literal conflict threshold, on the commit this branch
//! starts from, before any belief-profile code existed. It covers that
//! commit's `calibration.toml` (snapshotted as
//! `support/golden_calibration.toml`, so a later calibration tune cannot turn
//! a code-equivalence test red) AND `CalibrationConfig::default_for_phase2_fallback()`
//! (the configuration a process runs on when `calibration.toml` cannot be
//! found), across every tier of the per-BBA reliability chain.
//!
//! Each fold is compared as exact `f64` bit patterns: the per-row reliability
//! α, Bel/Pl/BetP of TRUE, the fold conflict and the open-world mass.

#[path = "support/belief_fixtures.rs"]
mod fixtures;

use epigraph_engine::belief_profile::{BeliefProfile, FrameTier, PerspectiveTier};
use epigraph_engine::belief_query::{combine_framed_bbas, FramedBeliefContext};
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::effective_source_strength_profiled;

struct Golden {
    config: &'static str,
    case: &'static str,
    alphas: &'static [u64],
    /// bel, pl, betp, conflict, missing
    measures: [u64; 5],
}

const fn golden(
    config: &'static str,
    case: &'static str,
    alphas: &'static [u64],
    measures: [u64; 5],
) -> Golden {
    Golden {
        config,
        case,
        alphas,
        measures,
    }
}

#[rustfmt::skip]
const GOLDEN: &[Golden] = &[
    golden("toml", "tier_mix_global", &[0x3fd3333333333333, 0x3feb333333333333, 0x3fe3333333333333, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fcae147ae147ae1], [0x3fe9c4af64d021c9, 0x3feda5cd6db92390, 0x3febb53e6944a2ac, 0x3fd4f016649b6aa2, 0x0000000000000000]),
    golden("toml", "tier_mix_per_frame", &[0x3fc999999999999a, 0x3feccccccccccccd, 0x3fe3333333333333, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fd6666666666666], [0x3fea0aa37ae93aaf, 0x3fedb6ca467d0cb9, 0x3febe0b6e0b323b4, 0x3fd55684b8c8dacc, 0x0000000000000000]),
    golden("toml", "tier_mix_perspective_partial", &[0x3fdccccccccccccd, 0x3fe147ae147ae148, 0x3feccccccccccccd, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fdae147ae147ae1, 0x3fd6666666666666, 0x3fd428f5c28f5c29], [0x3fe69d42bc63c66c, 0x3feb52d9485c3108, 0x3fe8f80e025ffbba, 0x3fda43e0be39bde0, 0x0000000000000000]),
    golden("toml", "tier_mix_perspective_empty", &[0x3fd3333333333333, 0x3feb333333333333, 0x3fe3333333333333, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fcae147ae147ae1], [0x3fe9c4af64d021c9, 0x3feda5cd6db92390, 0x3febb53e6944a2ac, 0x3fd4f016649b6aa2, 0x0000000000000000]),
    golden("toml", "upper_case_locality", &[0x3fceb851eb851eb8, 0x3feb333333333333], [0x3fbe1ad8c5bec045, 0x3fe66642d0158c04, 0x3fda299de8cd640c, 0x3fad3ed527e52150, 0x0000000000000000]),
    golden("toml", "same_source_repeats", &[0x3ff0000000000000, 0x3ff0000000000000, 0x3ff0000000000000, 0x3feb333333333333, 0x3feccccccccccccd], [0x3feae066ef2f8b2c, 0x3fedf35c5fac9e12, 0x3fec69e1a76e149f, 0x3fd6f8f47304039c, 0x0000000000000000]),
    golden("toml", "open_world", &[0x3ff0000000000000, 0x3fd051eb851eb852, 0x3fe0000000000000], [0x3fe6fca81ff94cb7, 0x3feebc3fb7b201e6, 0x3feadc73ebd5a74f, 0x3fdc65a9a8049666, 0x3f5687e12add39d6]),
    golden("toml", "single_row", &[0x3ff0000000000000], [0x3fe0000000000000, 0x3ff0000000000000, 0x3fe8000000000000, 0x0000000000000000, 0x0000000000000000]),
    golden("fallback", "tier_mix_global", &[0x3ff0000000000000, 0x3fe0000000000000, 0x3fe3333333333333, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fe4cccccccccccd, 0x3fe0000000000000, 0x3fe6666666666666], [0x3fee2bd886d4b7b3, 0x3fef41ff76e8b071, 0x3feeb6ebfedeb412, 0x3fd82ad6917364b8, 0x0000000000000000]),
    golden("fallback", "tier_mix_per_frame", &[0x3fc999999999999a, 0x3feccccccccccccd, 0x3fe3333333333333, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fe4cccccccccccd, 0x3fe0000000000000, 0x3fe6666666666666], [0x3feb26920df2b13c, 0x3fee08294b57c211, 0x3fec975daca539a7, 0x3fd68a950dbfded4, 0x0000000000000000]),
    golden("fallback", "tier_mix_perspective_partial", &[0x3ff0000000000000, 0x3fe147ae147ae148, 0x3feccccccccccccd, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fd8f5c28f5c28f6, 0x3fd6666666666666, 0x3fe6666666666666], [0x3fed742589377f26, 0x3feeae98263e87b6, 0x3fee115ed7bb036e, 0x3fdf0d8155569ae0, 0x0000000000000000]),
    golden("fallback", "tier_mix_perspective_empty", &[0x3ff0000000000000, 0x3fe0000000000000, 0x3fe3333333333333, 0x3fe6666666666666, 0x3fe0000000000000, 0x3fe4cccccccccccd, 0x3fe0000000000000, 0x3fe6666666666666], [0x3fee2bd886d4b7b3, 0x3fef41ff76e8b071, 0x3feeb6ebfedeb412, 0x3fd82ad6917364b8, 0x0000000000000000]),
    golden("fallback", "upper_case_locality", &[0x3fceb851eb851eb8, 0x3fe0000000000000], [0x3fc1cd239a47348e, 0x3fea7d74fae9f5d2, 0x3fdef0bde17bc2f6, 0x3fa13404ea4a8c10, 0x0000000000000000]),
    golden("fallback", "same_source_repeats", &[0x3fe0000000000000, 0x3fe0000000000000, 0x3fe0000000000000, 0x3fe0000000000000, 0x3fe0000000000000], [0x3fe2311578cf2758, 0x3fed3d044b5ca178, 0x3fe7b70ce215e468, 0x3fbfdb22d0e56040, 0x0000000000000000]),
    golden("fallback", "open_world", &[0x3fe0000000000000, 0x3fe0000000000000, 0x3fe0000000000000], [0x3fd4ad62bd217b67, 0x3feb6960d77fc34c, 0x3fe2e0091b084080, 0x3fd4d0e560418938, 0x3f52361080fef4e7]),
    golden("fallback", "single_row", &[0x3fe0000000000000], [0x3fd0000000000000, 0x3ff0000000000000, 0x3fe4000000000000, 0x0000000000000000, 0x0000000000000000]),
];

fn config(name: &str) -> CalibrationConfig {
    match name {
        "toml" => fixtures::golden_calibration(),
        "fallback" => CalibrationConfig::default_for_phase2_fallback(),
        other => panic!("unknown golden config {other}"),
    }
}

fn expected(g: &Golden) -> fixtures::FoldBits {
    fixtures::FoldBits {
        alphas: g.alphas.to_vec(),
        bel: g.measures[0],
        pl: g.measures[1],
        betp: g.measures[2],
        conflict: g.measures[3],
        missing: g.measures[4],
    }
}

fn case(name: &str) -> fixtures::Case {
    fixtures::cases()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no fixture case {name}"))
}

/// Fold a case through the profile path: the global profile resolved from the
/// calibration, the case's per-frame and perspective inputs layered on as the
/// frame and perspective tiers, then the context-carrying combine.
fn profile_fold(c: &fixtures::Case, cal: &CalibrationConfig) -> fixtures::FoldBits {
    fold_under(c, &BeliefProfile::from_calibration(cal))
}

/// [`profile_fold`] over a given global profile.
fn fold_under(c: &fixtures::Case, global: &BeliefProfile) -> fixtures::FoldBits {
    let pfw = fixtures::per_frame_weights(c);
    let persp = fixtures::perspective(c);
    let profile = global.resolve(
        FrameTier {
            overrides: None,
            intra_evidence_locality_factor: c.per_frame_intra,
            evidence_type_weights: pfw.as_ref(),
        },
        PerspectiveTier {
            overrides: None,
            reliability: persp.as_ref(),
        },
    );
    let ctx = FramedBeliefContext::from_profile(profile);
    let rows = fixtures::rows(c);
    let alphas: Vec<f64> = rows
        .iter()
        .map(|r| effective_source_strength_profiled(r, ctx.profile()))
        .collect();
    let (combined, conflict) =
        combine_framed_bbas(&fixtures::frame(), &rows, fixtures::source_keys(c), &ctx)
            .expect("fold")
            .expect("non-empty");
    fixtures::bits_of(&alphas, &combined, conflict)
}

#[test]
fn golden_table_covers_every_case_under_both_configs() {
    for cfg in ["toml", "fallback"] {
        for c in fixtures::cases() {
            assert!(
                GOLDEN.iter().any(|g| g.config == cfg && g.case == c.name),
                "no golden row for ({cfg}, {})",
                c.name
            );
        }
    }
}

#[test]
fn profile_equal_to_todays_constants_reproduces_the_pre_profile_fold_bit_for_bit() {
    for g in GOLDEN {
        let cal = config(g.config);
        let got = profile_fold(&case(g.case), &cal);
        assert_eq!(
            got,
            expected(g),
            "profile fold drifted from the pre-profile value for ({}, {})",
            g.config,
            g.case
        );
    }
}

#[test]
fn calibration_taking_reliability_functions_still_reproduce_the_golden_fold() {
    // The calibration-taking entry points stay public for existing callers;
    // they must keep producing exactly what they produced before the profile.
    for g in GOLDEN {
        let cal = config(g.config);
        assert_eq!(
            fixtures::legacy_fold(&case(g.case), &cal),
            expected(g),
            "calibration-taking fold drifted for ({}, {})",
            g.config,
            g.case
        );
    }
}

#[test]
fn a_named_global_profile_restating_todays_values_changes_nothing() {
    // The calibration.toml tier: a `[belief_profiles.<default name>]` table
    // that restates today's values must be a no-op, value for value. Inserted
    // into the parsed map (the shape the TOML table deserializes to), so the
    // test does not depend on the text of any calibration file.
    let mut cal = fixtures::golden_calibration();
    cal.belief_profiles.insert(
        epigraph_engine::belief_profile::DEFAULT_PROFILE_NAME.to_string(),
        serde_json::json!({
            "reliability": {
                "unknown_evidence_type_weight": 0.5,
                "cross_locality_factor": 1.0,
                "intra_evidence_locality_factor": 0.3
            },
            "combination": { "conflict_threshold": 0.9 }
        }),
    );
    let base = fixtures::golden_calibration();
    assert_eq!(
        BeliefProfile::from_calibration(&cal).profile_hash(),
        BeliefProfile::from_calibration(&base).profile_hash(),
        "restating today's values must resolve to the same profile"
    );
    for g in GOLDEN.iter().filter(|g| g.config == "toml") {
        assert_eq!(
            profile_fold(&case(g.case), &cal),
            expected(g),
            "({})",
            g.case
        );
    }
}

#[test]
fn the_named_global_profile_in_calibration_toml_is_honoured_by_the_fold() {
    // The same tier, moving a value: the unknown-type weight is what a row
    // with neither an evidence type nor a stored strength is discounted by.
    // Written as TOML so the file-to-profile path is exercised end to end; it
    // is appended to the frozen snapshot, which carries no active
    // `[belief_profiles]` table to collide with.
    let moved = format!(
        "{}\n[belief_profiles.\"{}\".reliability]\nunknown_evidence_type_weight = 0.25\n",
        fixtures::golden_calibration_text(),
        epigraph_engine::belief_profile::DEFAULT_PROFILE_NAME
    );
    let cal: CalibrationConfig = toml::from_str(&moved).expect("toml parses");
    let c = case("tier_mix_global");
    let base = fixtures::golden_calibration();
    let before = profile_fold(&c, &base);
    let after = profile_fold(&c, &cal);
    // Row 4 (index) is the NULL-type, NULL-strength row; row 6 is the
    // uncalibrated type with no stored strength. Both fall to the unknown
    // weight; every other row resolves above it and must not move.
    for (i, (a, b)) in before.alphas.iter().zip(&after.alphas).enumerate() {
        if i == 4 || i == 6 {
            assert_ne!(a, b, "row {i} falls to the unknown weight and must move");
            assert_eq!(f64::from_bits(*b), 0.25, "row {i}");
        } else {
            assert_eq!(a, b, "row {i} does not use the unknown weight");
        }
    }
    assert_ne!(before.bel, after.bel, "the fold must see the moved weight");
}

#[test]
fn the_combination_conflict_threshold_is_not_consumed_today() {
    // `combine_multiple` ignores its threshold argument, so the profile's
    // `combination.conflict_threshold` moves no value. This pins that, on a
    // fixture whose fold conflict is well inside (0, 1) so thresholds on BOTH
    // sides of it are tried: a later change that makes the threshold live
    // turns this red and has to update it (and the parameter's docs) on
    // purpose.
    let g = GOLDEN
        .iter()
        .find(|g| g.config == "toml" && g.case == "tier_mix_global")
        .expect("golden row");
    let conflict = f64::from_bits(g.measures[3]);
    assert!(
        conflict > 0.1 && conflict < 0.5,
        "the fixture must carry real conflict for this to mean anything ({conflict})"
    );
    let base = BeliefProfile::from_calibration(&fixtures::golden_calibration());
    let c = case(g.case);
    for threshold in [0.0, 0.1, 0.5, 1.0] {
        let moved = base
            .with_overrides(
                &serde_json::json!({ "combination": { "conflict_threshold": threshold } }),
            )
            .expect("a threshold in [0, 1] is a valid override");
        assert_ne!(
            moved.profile_hash(),
            base.profile_hash(),
            "the parameter is hashed ({threshold})"
        );
        assert_eq!(
            fold_under(&c, &moved),
            expected(g),
            "conflict_threshold = {threshold} moved the fold: it is now consumed; update \
             CombinationParams::conflict_threshold's docs and this test"
        );
    }
}
