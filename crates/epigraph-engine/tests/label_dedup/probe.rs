//! Probe: a writer classifies its candidates against the index before filing.

use epigraph_engine::label_dedup::profile::Tier;
use epigraph_engine::label_dedup::{
    probe, ProbeCandidate, ProbeVerdictKind, Snapshot, PROBE_MAX_CANDIDATES,
};

use crate::fixtures::{self as f, claim, id, profile};

fn cand(key: &str, content: &str, labels: &[&str]) -> ProbeCandidate {
    ProbeCandidate {
        key: key.to_string(),
        content: content.to_string(),
        labels: labels.iter().map(|s| (*s).to_string()).collect(),
    }
}

fn index() -> Snapshot {
    Snapshot::from_capped(
        vec![
            claim(1, f::WING_FEED, &["notice", "src-feed"], "2026-06-28T00:00:00Z"),
            claim(2, f::MURAL_MSB, &["notice", "src-direct-a"], "2026-06-22T00:00:00Z"),
            claim(3, f::STEAM_A, &["notice"], "2026-07-01T00:00:00Z"),
            claim(4, f::DROPPED_SEATING, &["notice", "notice-dropped"], "2026-06-28T00:00:00Z"),
            claim(5, "[OPEN] Granite Weir works TND KX-4499 | Acme County PUA | due 2026-09-01 | est. unknown", &["notice", "also-id:KX4417"], "2026-06-28T00:00:00Z"),
        ],
        5000,
    )
}

#[test]
fn candidates_are_classified_with_the_plan_rules() {
    let out = probe(
        &profile(),
        &index(),
        None,
        &[
            cand("same", f::WING_DIRECT, &[]),
            cand("variant", f::MURAL_STD, &[]),
            cand("unrelated", f::COUNTY_DEPOT, &[]),
            cand("vetoed", f::STEAM_B, &[]),
            cand("refiled", f::WEIR_LATE, &[]),
            cand("retired-twin", f::DROPPED_SEATING, &[]),
        ],
    )
    .expect("probe");
    let by_key = |k: &str| {
        out.iter()
            .find(|v| v.key == k)
            .unwrap_or_else(|| panic!("{k}: {out:?}"))
    };
    assert_eq!(out.len(), 6);

    let same = by_key("same");
    assert_eq!(same.verdict, ProbeVerdictKind::Match);
    assert_eq!(same.matched_id, Some(id(1)));
    assert_eq!(same.tier, Some(Tier::StrongId));

    let variant = by_key("variant");
    assert_eq!(variant.verdict, ProbeVerdictKind::Review);
    assert_eq!(variant.matched_id, Some(id(2)));

    assert_eq!(by_key("unrelated").verdict, ProbeVerdictKind::New);

    // Identical title and entity, disjoint strong ids: new, and the veto is named.
    let vetoed = by_key("vetoed");
    assert_eq!(vetoed.verdict, ProbeVerdictKind::New);
    assert_eq!(vetoed.vetoed_by, vec![id(3)]);

    // A carried id on the index matches a re-filing that names only it.
    let refiled = by_key("refiled");
    assert_eq!(refiled.verdict, ProbeVerdictKind::Match, "{refiled:?}");
    assert_eq!(refiled.matched_id, Some(id(5)));

    // Hygiene claims are not in the index.
    assert_eq!(by_key("retired-twin").verdict, ProbeVerdictKind::New);
}

#[test]
fn a_match_against_a_closed_signal_only_is_match_only() {
    let closed = Snapshot::from_capped(
        vec![claim(
            9,
            f::LEAD_CHILLER,
            &["lead", "resolved"],
            "2026-06-29T00:00:00Z",
        )],
        5000,
    );
    let candidate = cand(
        "lab-lead",
        "Lead: Cold Room Chiller Swap PRJ-007731 | Acme Medical Center | sector:univ",
        &["lead"],
    );
    let out = probe(
        &profile(),
        &index(),
        Some(&closed),
        std::slice::from_ref(&candidate),
    )
    .expect("probe");
    assert_eq!(out[0].verdict, ProbeVerdictKind::MatchOnly);
    assert_eq!(out[0].matched_id, Some(id(9)));
    // Control: without the closed-signal index the candidate is new.
    let out = probe(&profile(), &index(), None, &[candidate]).expect("probe");
    assert_eq!(out[0].verdict, ProbeVerdictKind::New);
}

#[test]
fn a_probe_is_capped() {
    let many: Vec<_> = (0..=PROBE_MAX_CANDIDATES)
        .map(|i| cand(&format!("k{i}"), f::COUNTY_DEPOT, &[]))
        .collect();
    let err = probe(&profile(), &index(), None, &many).expect_err("over the cap");
    assert_eq!(err.code(), "TOO_MANY_CANDIDATES");
    let out = probe(&profile(), &index(), None, &many[..PROBE_MAX_CANDIDATES]).expect("at the cap");
    assert_eq!(out.len(), PROBE_MAX_CANDIDATES);
}

#[test]
fn a_probe_over_a_truncated_read_is_refused() {
    // The candidate's twin sorts past the read cap. A `new` verdict here
    // would tell the writer to file a duplicate, so the probe refuses.
    let rows = || {
        vec![
            claim(
                1,
                f::MURAL_MSB,
                &["notice", "src-direct-a"],
                "2026-06-22T00:00:00Z",
            ),
            claim(2, f::STEAM_A, &["notice"], "2026-07-01T00:00:00Z"),
            claim(
                9,
                f::WING_FEED,
                &["notice", "src-feed"],
                "2026-06-28T00:00:00Z",
            ),
        ]
    };
    let twin = [cand("same", f::WING_DIRECT, &[])];
    let capped = Snapshot::from_capped(rows(), 2);
    assert!(capped.truncated, "precondition: the twin is past the cap");
    let err = probe(&profile(), &capped, None, &twin).expect_err("truncated index");
    assert_eq!(err.code(), "TRUNCATED");
    // Control: a cap that fits the family finds the twin.
    let whole = Snapshot::from_capped(rows(), 3);
    let out = probe(&profile(), &whole, None, &twin).expect("complete index");
    assert_eq!(out[0].verdict, ProbeVerdictKind::Match);
    assert_eq!(out[0].matched_id, Some(id(9)));

    // A truncated closed-signal read is refused the same way.
    let closed = |cap| {
        Snapshot::from_capped(
            vec![
                claim(
                    7,
                    f::LEAD_PERMIT_OLD,
                    &["lead", "resolved"],
                    "2026-06-29T00:00:00Z",
                ),
                claim(
                    8,
                    f::LEAD_CHILLER,
                    &["lead", "resolved"],
                    "2026-06-29T00:00:00Z",
                ),
            ],
            cap,
        )
    };
    let lead = [cand(
        "lab-lead",
        "Lead: Cold Room Chiller Swap PRJ-007731 | Acme Medical Center | sector:univ",
        &["lead"],
    )];
    let err = probe(&profile(), &whole, Some(&closed(1)), &lead).expect_err("truncated signals");
    assert_eq!(err.code(), "TRUNCATED");
    let out = probe(&profile(), &whole, Some(&closed(2)), &lead).expect("complete signals");
    assert_eq!(out[0].verdict, ProbeVerdictKind::MatchOnly);
    assert_eq!(out[0].matched_id, Some(id(8)));
}
