//! Determinism and the plan hash.

use epigraph_engine::label_dedup::{plan, DedupClaim, PlanInputs, PlanRequest, Section, Snapshot};
use proptest::prelude::*;

use crate::fixtures::{
    self as f, all_sections, apply_units, claim, corpus, date, profile, RUN_TAG,
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
    g.push(chain(0x3000_0001, "TND 55501A"));
    g.push(chain(0x3000_0002, ""));
    g.push(chain(0x3000_0003, "TND 55502C"));
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

fn plan_json(graph: &[DedupClaim], sections: &[Section]) -> (String, String) {
    let p = f::plan_graph(&profile(), graph, sections, Some(date("2026-10-05")));
    // Guard: identical EMPTY plans would make the comparison vacuous.
    assert!(
        p.clusters.len() >= 6 && !p.vetoed_chains.is_empty(),
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
    fn the_plan_is_input_order_independent(order in Just((0..rich_graph().len()).collect::<Vec<usize>>()).prop_shuffle()) {
        let base = rich_graph();
        let shuffled: Vec<DedupClaim> = order.iter().map(|i| base[*i].clone()).collect();
        let (h0, j0) = plan_json(&base, &all_sections());
        let (h1, j1) = plan_json(&shuffled, &all_sections());
        prop_assert_eq!(h0, h1);
        prop_assert_eq!(j0, j1);
    }

    #[test]
    fn any_subset_replans_empty_after_apply(mask in proptest::collection::vec(any::<bool>(), 31)) {
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
    assert!(p.clusters.len() >= 6, "{:?}", p.clusters.len());
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
    let prof = profile();
    let req = PlanRequest {
        profile: &prof,
        profile_hash,
        run_tag,
        as_of: Some(date("2026-10-05")),
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
