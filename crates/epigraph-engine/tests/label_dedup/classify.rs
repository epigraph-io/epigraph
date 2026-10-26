//! Pair classification: matches, and the close calls that must stay apart.

use epigraph_engine::label_dedup::classify::{classify_pair, ConflictKind, PairVerdict};
use epigraph_engine::label_dedup::profile::Tier;
use epigraph_engine::label_dedup::ParsedRecord;

use crate::fixtures::{self as f, parsed, pass, prefix, t};

fn verdict(a: &ParsedRecord, b: &ParsedRecord) -> PairVerdict {
    let v = classify_pair(&pass(), a, b);
    // Symmetry is part of the contract: input order never changes a verdict.
    let w = classify_pair(&pass(), b, a);
    assert_eq!(
        std::mem::discriminant(&v),
        std::mem::discriminant(&w),
        "pair classification must be symmetric: {v:?} vs {w:?}"
    );
    v
}

fn merge_tier(a: &ParsedRecord, b: &ParsedRecord) -> Option<Tier> {
    match verdict(a, b) {
        PairVerdict::Merge { tier, .. } => Some(tier),
        _ => None,
    }
}

#[test]
fn same_record_from_two_sources_is_a_strong_id_match() {
    let feed = parsed(
        t::WING_FEED,
        f::WING_FEED,
        &["notice", "src-feed"],
        "2026-06-28T00:00:00Z",
    );
    let direct = parsed(
        t::WING_DIRECT,
        f::WING_DIRECT,
        &["notice", "src-direct-c"],
        "2026-06-29T00:00:00Z",
    );
    assert_eq!(merge_tier(&feed, &direct), Some(Tier::StrongId));
}

#[test]
fn cross_layout_duplicates_match_on_strong_id() {
    let early = parsed(
        t::WEIR_EARLY,
        f::WEIR_EARLY,
        &["notice"],
        "2026-04-27T00:00:00Z",
    );
    let late = parsed(
        t::WEIR_LATE,
        f::WEIR_LATE,
        &["notice"],
        "2026-06-20T00:00:00Z",
    );
    assert_eq!(merge_tier(&early, &late), Some(Tier::StrongId));
    let old = parsed(
        t::Q23_OLD,
        f::AGREEMENT_Q23_OLD,
        &["notice"],
        "2026-04-27T00:00:00Z",
    );
    let new = parsed(
        t::Q23_NEW,
        f::AGREEMENT_Q23_NEW,
        &["notice"],
        "2026-07-19T00:00:00Z",
    );
    assert_eq!(merge_tier(&old, &new), Some(Tier::StrongId));
}

#[test]
fn identical_title_without_ids_merges_on_entity() {
    let a = parsed(
        t::HOIST_LISTED,
        f::HOIST_LISTED,
        &["notice"],
        "2026-06-28T00:00:00Z",
    );
    let b = parsed(
        t::HOIST_REVIEW,
        f::HOIST_REVIEW,
        &["notice"],
        "2026-06-28T00:00:00Z",
    );
    assert_eq!(merge_tier(&a, &b), Some(Tier::TitleAndEntity));
}

#[test]
fn a_shared_weak_id_needs_a_matching_entity() {
    let a = parsed(
        1,
        "[OPEN] Roof Repairs Q77 | Acme Polytechnic | due 2026-09-01 | est. unknown",
        &["notice"],
        "2026-07-01T00:00:00Z",
    );
    let b = parsed(
        2,
        "[OPEN] Q77 roof work | Acme Polytechnic | due 2026-09-01 | est. unknown",
        &["notice"],
        "2026-07-01T00:00:00Z",
    );
    assert_eq!(merge_tier(&a, &b), Some(Tier::WeakIdAndEntity));
    let c = parsed(
        3,
        "[OPEN] Q77 roof work | Acme Harbor Board | due 2026-09-01 | est. unknown",
        &["notice"],
        "2026-07-01T00:00:00Z",
    );
    assert_eq!(merge_tier(&a, &c), None, "a weak id alone is not enough");
}

#[test]
fn revision_label_links_claim_to_its_original() {
    let orig = parsed(
        t::PANEL_OLD,
        f::PANEL_OLD,
        &["notice", "src-direct-b"],
        "2026-06-14T00:00:00Z",
    );
    let rev = parsed(
        t::PANEL_NEW,
        f::PANEL_NEW,
        &[
            "notice",
            "src-direct-b",
            &format!("revision-of-{}", prefix(t::PANEL_OLD)),
        ],
        "2026-07-05T00:00:00Z",
    );
    assert_eq!(merge_tier(&orig, &rev), Some(Tier::RevisionLabel));
}

#[test]
fn a_revision_label_wins_over_the_strong_id_veto() {
    let orig = parsed(1, f::STEAM_A, &["notice"], "2026-07-01T00:00:00Z");
    let rev = parsed(
        2,
        f::STEAM_B,
        &["notice", &format!("revision-of-{}", prefix(1))],
        "2026-07-02T00:00:00Z",
    );
    assert_eq!(merge_tier(&orig, &rev), Some(Tier::RevisionLabel));
    // Control: without the label the disjoint strong ids veto.
    let plain = parsed(2, f::STEAM_B, &["notice"], "2026-07-02T00:00:00Z");
    assert!(matches!(
        verdict(&orig, &plain),
        PairVerdict::Conflict {
            conflict: ConflictKind::StrongIdVeto,
            ..
        }
    ));
}

#[test]
fn same_entity_same_program_different_strong_ids_never_merge() {
    let popup = parsed(
        t::KIOSK_UNIT,
        f::KIOSK_UNIT,
        &["notice"],
        "2026-06-14T00:00:00Z",
    );
    let store = parsed(
        t::KIOSK_CAFE,
        f::KIOSK_CAFE,
        &["notice"],
        "2026-06-14T00:00:00Z",
    );
    assert_eq!(merge_tier(&popup, &store), None);
    let q22 = parsed(
        t::Q22_NEW,
        f::AGREEMENT_Q22_NEW,
        &["notice"],
        "2026-06-14T00:00:00Z",
    );
    let q23 = parsed(
        t::Q23_NEW,
        f::AGREEMENT_Q23_NEW,
        &["notice"],
        "2026-07-19T00:00:00Z",
    );
    assert!(
        matches!(
            verdict(&q22, &q23),
            PairVerdict::Conflict {
                conflict: ConflictKind::StrongIdVeto,
                ..
            }
        ),
        "Q22/…573 and Q23/…574 are separate agreements"
    );
    // Control: each matches its own re-filing.
    let q23_old = parsed(
        t::Q23_OLD,
        f::AGREEMENT_Q23_OLD,
        &["notice"],
        "2026-04-27T00:00:00Z",
    );
    assert_eq!(merge_tier(&q23, &q23_old), Some(Tier::StrongId));
}

#[test]
fn preference_track_variant_goes_to_review() {
    let msb = parsed(
        t::MURAL_MSB,
        f::MURAL_MSB,
        &["notice"],
        "2026-06-22T00:00:00Z",
    );
    let std = parsed(
        t::MURAL_STD,
        f::MURAL_STD,
        &["notice"],
        "2026-06-22T00:00:00Z",
    );
    match verdict(&msb, &std) {
        PairVerdict::Review { overlap, .. } => assert!(overlap >= 0.8, "{overlap}"),
        other => panic!("expected review, got {other:?}"),
    }
}

#[test]
fn distinct_items_from_one_entity_do_not_match() {
    let fire = parsed(
        t::COUNTY_DEPOT,
        f::COUNTY_DEPOT,
        &["notice"],
        "2026-04-27T00:00:00Z",
    );
    let oncall = parsed(
        t::COUNTY_STANDBY,
        f::COUNTY_STANDBY,
        &["notice"],
        "2026-04-27T00:00:00Z",
    );
    assert_eq!(verdict(&fire, &oncall), PairVerdict::NoMatch);
    // Control: the entity does match, so it is the titles that keep them apart.
    let p = pass();
    assert!(epigraph_engine::label_dedup::record::entities_match(
        &p,
        fire.keys.entity_tokens.as_ref(),
        oncall.keys.entity_tokens.as_ref()
    ));
}

#[test]
fn disjoint_strong_ids_veto_identical_titles() {
    let a = parsed(1, f::STEAM_A, &["notice"], "2026-07-01T00:00:00Z");
    let b = parsed(2, f::STEAM_B, &["notice"], "2026-07-01T00:00:00Z");
    assert!(matches!(
        verdict(&a, &b),
        PairVerdict::Conflict {
            conflict: ConflictKind::StrongIdVeto,
            ..
        }
    ));
    assert_eq!(
        a.keys.title_key, b.keys.title_key,
        "control: the titles are identical"
    );
}

#[test]
fn a_disabled_tier_never_fires() {
    let mut v = f::profile_value();
    v["tiers"] = serde_json::json!([
        "revision_label",
        "strong_id",
        "weak_id_and_entity",
        "fuzzy_review"
    ]);
    let p = f::load(&v);
    let a = epigraph_engine::label_dedup::parse_record(
        &p.pass,
        &f::claim(1, f::HOIST_LISTED, &["notice"], "2026-06-28T00:00:00Z"),
    );
    let b = epigraph_engine::label_dedup::parse_record(
        &p.pass,
        &f::claim(2, f::HOIST_REVIEW, &["notice"], "2026-06-28T00:00:00Z"),
    );
    assert!(
        matches!(classify_pair(&p.pass, &a, &b), PairVerdict::Review { .. }),
        "title_and_entity is disabled, so the pair falls through to review"
    );
    // Control: with every tier enabled the same pair merges on title.
    let full = pass();
    let a = epigraph_engine::label_dedup::parse_record(
        &full,
        &f::claim(1, f::HOIST_LISTED, &["notice"], "2026-06-28T00:00:00Z"),
    );
    let b = epigraph_engine::label_dedup::parse_record(
        &full,
        &f::claim(2, f::HOIST_REVIEW, &["notice"], "2026-06-28T00:00:00Z"),
    );
    assert!(matches!(
        classify_pair(&full, &a, &b),
        PairVerdict::Merge {
            tier: Tier::TitleAndEntity,
            ..
        }
    ));
}

/// A revision link auto-merges and overrides the strong-id veto, so it must
/// name the other claim as precisely as a `distinct-from` ruling does: a
/// label carrying only a short id prefix would link the labelled claim to
/// every claim whose id starts with it (one in sixteen for one hex digit).
#[test]
fn a_short_revision_prefix_links_nothing_and_the_veto_still_applies() {
    let orig = parsed(1, f::STEAM_A, &["notice"], "2026-07-01T00:00:00Z");
    for len in 1..8 {
        let short: String = prefix(1).chars().take(len).collect();
        let rev = parsed(
            2,
            f::STEAM_B,
            &["notice", &format!("revision-of-{short}")],
            "2026-07-02T00:00:00Z",
        );
        assert_eq!(
            merge_tier(&orig, &rev),
            None,
            "a {len}-char revision prefix must not link"
        );
        assert!(
            matches!(
                verdict(&orig, &rev),
                PairVerdict::Conflict {
                    conflict: ConflictKind::StrongIdVeto,
                    ..
                }
            ),
            "a {len}-char revision prefix must not override the strong-id veto"
        );
    }
}
