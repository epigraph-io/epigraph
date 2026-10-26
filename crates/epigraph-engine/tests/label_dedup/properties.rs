//! Determinism and the plan hash.

use epigraph_engine::label_dedup::{plan, DedupClaim, PlanInputs, PlanRequest, Section, Snapshot};
use proptest::prelude::*;

use crate::fixtures::{
    self as f, all_sections, apply_units, claim, corpus, date, plan_graph_as_given, profile,
    RUN_TAG,
};

/// The corpus, plus a transitive veto chain, a carry, signals and a closed
/// member, so every stage has order-sensitive work.
fn rich_graph() -> Vec<DedupClaim> {
    let mut g = corpus();
    let chain = |tag: u32, token: &str| {
        claim(
            tag,
            &format!("[OPEN] Riverside Pump Station Upgrade | Acme Water Board | ref {token} | sector:city | due 2026-09-01 | est. unknown | pump design"),
            &["notice"],
            "2026-07-01T00:00:00Z",
        )
    };
    // A re-filing of the weir item that names an id the survivor lacks, so
    // the carried-id stage has work.
    g.push(claim(
        0x3800_0001,
        "Tender: GWX KX-4417 Granite Weir Channel Upgrade — Acme County PUA, due 2026-07-15, ref ZR-880011.",
        &["notice"],
        "2026-09-01T00:00:00Z",
    ));
    g.push(chain(0x3000_0001, "TND 55501A"));
    g.push(chain(0x3000_0002, ""));
    g.push(chain(0x3000_0003, "TND 55502C"));
    // A pair whose survivor gains a carried value.
    g.push(claim(
        0x3100_0001,
        f::FENDER_DIRECT_NO_DUE,
        &["notice", "src-direct-a"],
        "2026-05-01T00:00:00Z",
    ));
    g.push(claim(
        0x3100_0002,
        f::FENDER_FEED,
        &["notice"],
        "2026-05-10T00:00:00Z",
    ));
    g.push(claim(
        0x7000_0001,
        f::LEAD_CHILLER,
        &["lead", "src-direct-c"],
        "2026-06-29T00:00:00Z",
    ));
    g.push(claim(
        0x7000_0002,
        f::LEAD_PERMIT_OLD,
        &["lead"],
        "2026-06-29T00:00:00Z",
    ));
    g.push(claim(
        0x7000_0003,
        f::NOTICE_CHILLER,
        &["notice", "src-direct-c"],
        "2026-10-04T00:00:00Z",
    ));
    g.push(claim(
        0x7000_0004,
        f::NOTICE_CHILLER,
        &["notice", "resolved"],
        "2026-09-04T00:00:00Z",
    ));
    g
}

/// The rich graph plus claims whose LABEL order is read somewhere: two
/// carried dates on one survivor, two carried values on one loser, two
/// retirement labels, labels from two rank groups, and several ruling labels.
fn label_rich_graph() -> Vec<DedupClaim> {
    let mut g = rich_graph();
    let spill = |due: &str| {
        format!("Tender: GWX KX-5520 Granite Weir Spillway Refit — Acme County PUA, due {due}, est. TBD.")
    };
    g.push(claim(
        0x3200_0001,
        &spill("2026-07-10"),
        &[
            "notice",
            "src-direct-a",
            "due-carried:2026-07-15",
            "due-carried:2026-07-01",
        ],
        "2026-04-27T00:00:00Z",
    ));
    g.push(claim(
        0x3200_0002,
        &spill("2026-08-30"),
        &["notice"],
        "2026-07-20T00:00:00Z",
    ));
    let crane = "[OPEN] Harbor Crane Rail Survey | Acme Port Board | ref HX-77310 | sector:city | due unknown | est. unknown | rail survey";
    g.push(claim(
        0x3300_0001,
        crane,
        &["notice", "src-direct-a"],
        "2026-05-01T00:00:00Z",
    ));
    g.push(claim(
        0x3300_0002,
        crane,
        &[
            "notice",
            "value-carried:900K",
            "value-carried:1.2M",
            "src-feed",
        ],
        "2026-05-02T00:00:00Z",
    ));
    g.push(claim(
        0x3400_0001,
        "[OPEN] Ferry Ramp Lighting Swap | Acme Port Board | ref HX-80021 | sector:city | due unknown | est. unknown | ramp lights",
        &["notice", "listed-final", "notice-dropped", "src-feed"],
        "2026-05-03T00:00:00Z",
    ));
    let ruled = format!("distinct-from:{}", f::prefix(0x3000_0003));
    let revises = format!("revision-of-{}", f::prefix(0x3000_0001));
    g.push(claim(
        0x3000_0004,
        "[OPEN] Riverside Pump Station Upgrade | Acme Water Board | ref TND 55501A | sector:city | due 2026-09-03 | est. unknown | pump design",
        &["notice", &ruled, &revises, "class:open", "src-feed", "src-direct-c"],
        "2026-07-02T00:00:00Z",
    ));
    g
}

fn plan_json(graph: &[DedupClaim], sections: &[Section]) -> (String, String) {
    let p = plan_graph_as_given(&profile(), graph, sections, Some(date("2026-10-05")));
    // Guard: identical EMPTY plans would make the comparison vacuous.
    assert!(
        p.clusters.len() >= 7 && !p.vetoed_chains.is_empty(),
        "{:?}",
        p.clusters
    );
    (
        p.plan_hash.clone(),
        serde_json::to_string(&p).expect("serialize plan"),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn the_plan_is_input_order_independent(
        order in Just((0..label_rich_graph().len()).collect::<Vec<usize>>()).prop_shuffle(),
        label_keys in proptest::collection::vec(proptest::collection::vec(any::<u32>(), 12), label_rich_graph().len()),
    ) {
        // Rows AND each claim's labels arrive in a random order; nothing on
        // the way in sorts them (plan_graph_as_given), so this pins the
        // engine's own normalization.
        let base = label_rich_graph();
        let shuffled: Vec<DedupClaim> = order
            .iter()
            .map(|i| {
                let mut c = base[*i].clone();
                let mut keyed: Vec<(u32, String)> = label_keys[*i]
                    .iter()
                    .copied()
                    .zip(c.labels.drain(..))
                    .collect();
                keyed.sort();
                c.labels = keyed.into_iter().map(|(_, l)| l).collect();
                c
            })
            .collect();
        let (h0, j0) = plan_json(&base, &all_sections());
        let (h1, j1) = plan_json(&shuffled, &all_sections());
        prop_assert_eq!(h0, h1);
        prop_assert_eq!(j0, j1);
    }

    #[test]
    fn any_subset_replans_empty_after_apply(mask in proptest::collection::vec(any::<bool>(), 33)) {
        let base = rich_graph();
        // The wing pair is always kept, so every case has at least one write.
        let pinned = [f::id(f::t::WING_FEED), f::id(f::t::WING_DIRECT)];
        let graph: Vec<DedupClaim> = base
            .iter()
            .zip(mask.iter().cycle())
            .filter(|(c, keep)| **keep || pinned.contains(&c.id))
            .map(|(c, _)| c.clone())
            .collect();
        let first = f::plan_graph(&profile(), &graph, &all_sections(), Some(date("2026-10-05")));
        prop_assert!(!first.is_empty(), "the pinned pair always plans a merge");
        let applied = apply_units(&graph, &first.write_units());
        let second = f::plan_graph(&profile(), &applied, &all_sections(), Some(date("2026-10-05")));
        prop_assert!(second.is_empty(), "{:?}", second.write_units());
    }
}

#[test]
fn the_label_rich_claims_reach_their_label_order_paths() {
    // Guard on the permutation fixture: each added claim must hit a rule that
    // takes the first matching label, or shuffling its labels proves nothing.
    let p = plan_graph_as_given(
        &profile(),
        &label_rich_graph(),
        &all_sections(),
        Some(date("2026-10-05")),
    );
    let by_survivor = |tag: u32| {
        p.clusters
            .iter()
            .find(|c| c.survivor == f::id(tag))
            .unwrap_or_else(|| panic!("no cluster survived by {tag:x}: {:?}", p.clusters))
    };
    // The carried-date and carried-value label paths these two claims were
    // added for are gone (a later date or a value stays on the marked
    // duplicate); they still cluster, and still write no such label.
    for tag in [0x3200_0001, 0x3300_0001] {
        let c = by_survivor(tag);
        assert!(
            !c.carry_add.iter().any(|l| l.contains("-carried:")),
            "{:?}",
            c.carry_add
        );
    }
    // Two retirement labels: both are named.
    let h = p
        .hygiene
        .iter()
        .find(|h| h.id == f::id(0x3400_0001))
        .expect("hygiene item");
    assert_eq!(
        h.reason.matches("retired_label:").count(),
        2,
        "{}",
        h.reason
    );
}

#[test]
fn the_rich_graph_exercises_every_stage() {
    // Guard on the property fixture: the permutation test is only meaningful
    // if each stage has work.
    let p = f::plan_graph(
        &profile(),
        &rich_graph(),
        &all_sections(),
        Some(date("2026-10-05")),
    );
    assert!(!p.hygiene.is_empty());
    assert!(p.clusters.len() >= 7, "{:?}", p.clusters.len());
    assert!(!p.vetoed_chains.is_empty());
    assert!(p.clusters.iter().any(|c| !c.carry_add.is_empty()));
    assert!(!p.past_due.is_empty());
    assert!(!p.lifecycle.is_empty());
    assert!(!p.review_pairs.is_empty());
}

fn plan_with(
    profile_hash: &str,
    run_tag: &str,
    sections: &[Section],
    graph: &[DedupClaim],
) -> epigraph_engine::label_dedup::Plan {
    plan_at(profile_hash, run_tag, sections, graph, "2026-10-05")
}

fn plan_at(
    profile_hash: &str,
    run_tag: &str,
    sections: &[Section],
    graph: &[DedupClaim],
    as_of: &str,
) -> epigraph_engine::label_dedup::Plan {
    let prof = profile();
    let req = PlanRequest {
        profile: &prof,
        profile_hash,
        run_tag,
        as_of: Some(date(as_of)),
        sections,
    };
    let inputs = PlanInputs {
        members: Snapshot::from_capped(
            graph
                .iter()
                .filter(|c| {
                    c.labels.iter().any(|l| l == "notice")
                        && !c.labels.iter().any(|l| l == "resolved")
                })
                .cloned()
                .collect(),
            5000,
        ),
        ..PlanInputs::default()
    };
    plan(&req, &inputs).expect("plan")
}

#[test]
fn the_plan_hash_covers_the_writes_and_the_inputs_that_define_them() {
    let h = "a".repeat(64);
    let base = plan_with(&h, RUN_TAG, &[Section::Hygiene, Section::Dedup], &corpus());
    assert_eq!(base.plan_hash.len(), 64);
    // Deterministic.
    assert_eq!(
        plan_with(&h, RUN_TAG, &[Section::Hygiene, Section::Dedup], &corpus()).plan_hash,
        base.plan_hash
    );
    // Section order and repetition are normalized away.
    assert_eq!(
        plan_with(
            &h,
            RUN_TAG,
            &[Section::Dedup, Section::Hygiene, Section::Dedup],
            &corpus()
        )
        .plan_hash,
        base.plan_hash
    );
    // The profile hash, the run tag and the writes are covered.
    assert_ne!(
        plan_with(
            &"b".repeat(64),
            RUN_TAG,
            &[Section::Hygiene, Section::Dedup],
            &corpus()
        )
        .plan_hash,
        base.plan_hash
    );
    assert_ne!(
        plan_with(
            &h,
            "notice-dedup-other",
            &[Section::Hygiene, Section::Dedup],
            &corpus()
        )
        .plan_hash,
        base.plan_hash
    );
    let mut fewer = corpus();
    fewer.retain(|c| c.id != f::id(f::t::WING_FEED));
    assert_ne!(
        plan_with(&h, RUN_TAG, &[Section::Hygiene, Section::Dedup], &fewer).plan_hash,
        base.plan_hash
    );
    // A new review pair (no write) is NOT covered: no spurious drift.
    let mut more = corpus();
    more.push(claim(
        0x6000_0001,
        "[LISTED-OPP] TND Standby Mural Conservation Support 2026 Track B | AC Department of Public Operations | sector:city | due unknown | est. unknown | track b",
        &["notice", "src-direct-a"],
        "2026-06-22T00:00:00Z",
    ));
    let with_pair = plan_with(&h, RUN_TAG, &[Section::Hygiene, Section::Dedup], &more);
    assert!(
        with_pair.review_pairs.len() > base.review_pairs.len(),
        "precondition: a new review pair"
    );
    assert_eq!(
        with_pair.write_units(),
        base.write_units(),
        "precondition: no new write"
    );
    assert_eq!(with_pair.plan_hash, base.plan_hash);
    // The hash is the documented function of its inputs.
    assert_eq!(
        epigraph_engine::label_dedup::compute_plan_hash(
            &h,
            RUN_TAG,
            Some(date("2026-10-05")),
            &[Section::Hygiene, Section::Dedup],
            &base.write_units()
        ),
        base.plan_hash
    );
}

#[test]
fn the_plan_hash_covers_as_of_and_the_section_set_even_with_equal_writes() {
    let h = "a".repeat(64);
    let dedup = [Section::Hygiene, Section::Dedup];
    // Two dates, dedup only: the writes cannot differ, the hash must.
    let a = plan_at(&h, RUN_TAG, &dedup, &corpus(), "2026-10-05");
    let b = plan_at(&h, RUN_TAG, &dedup, &corpus(), "2026-10-06");
    assert!(!a.write_units().is_empty(), "precondition: real writes");
    assert_eq!(a.write_units(), b.write_units(), "precondition");
    assert_ne!(a.plan_hash, b.plan_hash, "as_of is covered");
    // Adding close-out at a date before every deadline adds no write, but
    // a plan for a different section set must not verify as this one.
    let early = "2026-01-01";
    let without = plan_at(&h, RUN_TAG, &dedup, &corpus(), early);
    let with = plan_at(
        &h,
        RUN_TAG,
        &[Section::Hygiene, Section::Dedup, Section::Closeout],
        &corpus(),
        early,
    );
    assert!(
        with.past_due.is_empty(),
        "precondition: {:?}",
        with.past_due
    );
    assert_eq!(with.write_units(), without.write_units(), "precondition");
    assert_ne!(
        with.plan_hash, without.plan_hash,
        "the section set is covered"
    );
}

#[test]
fn the_plan_hash_does_not_depend_on_how_the_profile_hash_is_spelled() {
    // The pin is accepted case-insensitively and trimmed, so a caller may
    // forward either spelling; plan and apply must still agree.
    let canonical = "ab".repeat(32);
    let spelled = format!("  {}\n", canonical.to_ascii_uppercase());
    let dedup = [Section::Hygiene, Section::Dedup];
    let a = plan_with(&canonical, RUN_TAG, &dedup, &corpus());
    let b = plan_with(&spelled, RUN_TAG, &dedup, &corpus());
    assert_eq!(
        b.profile_hash, canonical,
        "the plan echoes the canonical hash"
    );
    assert_eq!(a.plan_hash, b.plan_hash);
    assert_eq!(
        epigraph_engine::label_dedup::compute_plan_hash(
            &spelled,
            RUN_TAG,
            Some(date("2026-10-05")),
            &dedup,
            &a.write_units()
        ),
        a.plan_hash,
        "the apply-side recomputation agrees"
    );
    // Control: a different hash is still a different plan.
    let other = plan_with(&"cd".repeat(32), RUN_TAG, &dedup, &corpus());
    assert_ne!(other.plan_hash, a.plan_hash);
}
