//! Carry labels: a loser's ids, the index's keys, move onto the survivor as
//! labels. Nothing else does: a loser's later date or a value the survivor
//! lacks stays on the loser, which is marked a duplicate of the survivor and
//! read through it (`DedupClaim::duplicates`).

use crate::fixtures::{
    self as f, apply_units, claim, cluster_shape, dedup_sections, id, legacy_profile, plan_graph,
    profile,
};

#[test]
fn a_loser_id_the_survivor_lacks_is_carried_once() {
    let graph = vec![
        claim(
            1,
            f::WEIR_EARLY,
            &["notice", "src-direct-a"],
            "2026-04-27T00:00:00Z",
        ),
        claim(2, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z"),
    ];
    let p = plan_graph(&profile(), &graph, &dedup_sections(), None);
    let c = &p.clusters[0];
    assert_eq!(c.survivor, id(1));
    // The loser's weak bid number is carried; the shared strong id is not.
    assert!(
        c.carry_add.contains(&"also-id:5174".to_string()),
        "{:?}",
        c.carry_add
    );
    assert!(
        !c.carry_add.iter().any(|l| l == "also-id:KX4417"),
        "{:?}",
        c.carry_add
    );
    assert!(
        c.survivor_add.contains(&"also-id:5174".to_string()),
        "carry labels are survivor writes"
    );
    // Control: the legacy profile carries nothing.
    let legacy = plan_graph(&legacy_profile(), &graph, &dedup_sections(), None);
    assert!(
        legacy.clusters[0].carry_add.is_empty(),
        "{:?}",
        legacy.clusters[0].carry_add
    );
}

#[test]
fn an_also_id_label_matches_a_later_refiling() {
    // Run 1 merged a re-filing into the survivor and carried its id. A later
    // claim that only names that id must still match the survivor.
    let survivor = claim(
        1,
        "[OPEN] Granite Weir Upgrade TND KX-4499 | Acme County PUA | sector:city | due 2026-07-15 | est. unknown | weir work",
        &["notice", "src-direct-a", "also-id:KX4417"],
        "2026-04-27T00:00:00Z",
    );
    let refiling = claim(2, f::WEIR_LATE, &["notice"], "2026-09-20T00:00:00Z");
    let p = plan_graph(
        &profile(),
        &[survivor.clone(), refiling.clone()],
        &dedup_sections(),
        None,
    );
    assert_eq!(cluster_shape(&p), vec![(id(1), vec![id(2)])]);
    // Control: without the carried label the two strong ids are disjoint and veto.
    let mut bare = survivor;
    bare.labels.retain(|l| !l.starts_with("also-id:"));
    let p = plan_graph(&profile(), &[bare, refiling], &dedup_sections(), None);
    assert!(p.clusters.is_empty(), "{:?}", p.clusters);
}

#[test]
fn a_missing_value_stays_on_the_marked_duplicate() {
    let graph = vec![
        claim(
            1,
            f::FENDER_DIRECT_NO_DUE,
            &["notice", "src-direct-a"],
            "2026-05-01T00:00:00Z",
        ),
        claim(2, f::FENDER_FEED, &["notice"], "2026-05-10T00:00:00Z"),
    ];
    let p = plan_graph(&profile(), &graph, &dedup_sections(), None);
    assert_eq!(cluster_shape(&p), vec![(id(1), vec![id(2)])]);
    let c = &p.clusters[0];
    assert!(
        !c.carry_add.iter().any(|l| l.contains("-carried:")),
        "the value is not copied onto the survivor: {:?}",
        c.carry_add
    );
    // It stays on the loser, which the plan marks a duplicate of the survivor
    // and the next read returns under it.
    let applied = apply_units(&graph, &p.write_units());
    assert_eq!(applied.len(), 1, "the marked duplicate left the index");
    assert_eq!(applied[0].duplicates.len(), 1);
    assert!(
        applied[0].duplicates[0].content.contains("1,600,000"),
        "{}",
        applied[0].duplicates[0].content
    );
}

#[test]
fn a_later_date_stays_on_the_duplicate_and_counts_through_it() {
    // The loser holds the later deadline. Nothing is copied onto the survivor;
    // after the marks apply, close-out judges the survivor by the later date
    // its duplicate holds.
    let survivor = claim(
        1,
        f::WEIR_EARLY,
        &["notice", "src-direct-a"],
        "2026-04-27T00:00:00Z",
    );
    let loser = claim(
        2,
        "Tender: GWX KX-4417 Granite Weir Channel Upgrade — Acme County PUA, due 2026-08-30, est. $48M.",
        &["notice"],
        "2026-07-20T00:00:00Z",
    );
    let graph = vec![survivor.clone(), loser];
    let p = plan_graph(&profile(), &graph, &dedup_sections(), None);
    let c = &p.clusters[0];
    assert_eq!(c.survivor, id(1));
    assert!(
        !c.carry_add.iter().any(|l| l.starts_with("due-carried:")),
        "{:?}",
        c.carry_add
    );
    let applied = apply_units(&graph, &p.write_units());
    let closeout = [epigraph_engine::label_dedup::Section::Closeout];
    let open = plan_graph(&profile(), &applied, &closeout, Some(f::date("2026-08-01")));
    assert!(
        open.past_due.is_empty(),
        "08-30 via the duplicate: {:?}",
        open.past_due
    );
    // Control: the survivor alone (06-17) is past due on that date.
    let alone = plan_graph(
        &profile(),
        &[survivor],
        &closeout,
        Some(f::date("2026-08-01")),
    );
    assert_eq!(alone.past_due.len(), 1, "{:?}", alone.past_due);
}

#[test]
fn carry_is_idempotent_across_runs() {
    let graph = vec![
        claim(
            1,
            f::WEIR_EARLY,
            &["notice", "src-direct-a"],
            "2026-04-27T00:00:00Z",
        ),
        claim(2, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z"),
    ];
    let first = plan_graph(&profile(), &graph, &dedup_sections(), None);
    let applied = apply_units(&graph, &first.write_units());
    // A new re-filing of the same item arrives: only the genuinely new id is
    // carried, nothing already carried is written twice.
    let mut next = applied;
    next.push(claim(
        3,
        "Tender: GWX KX-4417 Granite Weir upgrade — Acme County PUA, due 2026-07-15, ref no 5174, ref ZR-880011.",
        &["notice"],
        "2026-09-01T00:00:00Z",
    ));
    let second = plan_graph(&profile(), &next, &dedup_sections(), None);
    assert_eq!(cluster_shape(&second), vec![(id(1), vec![id(3)])]);
    let c = &second.clusters[0];
    assert!(
        c.carry_add.contains(&"also-id:ZR880011".to_string()),
        "{:?}",
        c.carry_add
    );
    assert!(
        !c.carry_add.contains(&"also-id:5174".to_string()),
        "already carried: {:?}",
        c.carry_add
    );
    assert!(
        !c.carry_add.iter().any(|l| l.contains("-carried:")),
        "no value or date is carried: {:?}",
        c.carry_add
    );
}

#[test]
fn an_id_a_kept_apart_claim_carries_is_never_carried() {
    // L names both ids and joins S; D shares only L's second id and conflicts
    // with S. Carrying that id onto S would merge D into S on the NEXT run,
    // undoing the split this plan made.
    let s = claim(1, "[OPEN] Riverside Pump Station Upgrade | Acme Water Board | ref TND 55501A | due 2026-09-01 | est. unknown", &["notice", "src-direct-a"], "2026-07-01T00:00:00Z");
    let l = claim(2, "[OPEN] Riverside Pump Station Upgrade | Acme Water Board | ref TND 55501A amended as TND 55509Z | due 2026-09-01 | est. unknown", &["notice"], "2026-07-01T00:00:00Z");
    let d = claim(3, "[OPEN] Riverside Pump Station Upgrade | Acme Water Board | ref TND 55509Z | due 2026-09-01 | est. unknown", &["notice"], "2026-07-01T00:00:00Z");
    let graph = vec![s.clone(), l.clone(), d];
    let first = plan_graph(&profile(), &graph, &dedup_sections(), None);
    assert_eq!(
        cluster_shape(&first),
        vec![(id(1), vec![id(2)])],
        "{:?}",
        first.clusters
    );
    assert_eq!(first.vetoed_chains.len(), 1);
    assert!(
        !first.clusters[0]
            .carry_add
            .contains(&"also-id:55509Z".to_string()),
        "{:?}",
        first.clusters[0].carry_add
    );
    let applied = apply_units(&graph, &first.write_units());
    let second = plan_graph(&profile(), &applied, &dedup_sections(), None);
    assert!(
        second.is_empty(),
        "the split holds on the next run: {:?}",
        second.write_units()
    );
    // Control: with no kept-apart claim the id is carried.
    let alone = plan_graph(&profile(), &[s, l], &dedup_sections(), None);
    assert!(
        alone.clusters[0]
            .carry_add
            .contains(&"also-id:55509Z".to_string()),
        "{:?}",
        alone.clusters[0].carry_add
    );
}

#[test]
fn an_odd_loser_value_never_fails_the_plan_and_is_never_written() {
    let survivor = || {
        claim(
            1,
            f::FENDER_DIRECT_NO_DUE,
            &["notice", "src-direct-a"],
            "2026-05-01T00:00:00Z",
        )
    };
    let pipe = |est: &str| {
        format!(
            "[OPEN] Dock 4 Fender Rebuild TND 0000029912 | Acme Port Authority | sector:city | due unknown | est. {est} | Fender rebuild"
        )
    };
    let long_tail = "ca ".repeat(80) + "é".repeat(80).as_str();
    for value in [
        pipe("2.4M\u{7}approx"),
        pipe(&long_tail),
        f::FENDER_FEED.to_string(),
    ] {
        let graph = vec![
            survivor(),
            claim(2, &value, &["notice"], "2026-05-10T00:00:00Z"),
        ];
        let p = f::try_plan_graph(&profile(), &graph, &dedup_sections(), None, 5000)
            .expect("a loser's value never fails the plan");
        assert_eq!(cluster_shape(&p), vec![(id(1), vec![id(2)])]);
        let written: Vec<String> = p
            .write_units()
            .iter()
            .flat_map(|u| u.writes.iter().flat_map(|w| w.add.clone()))
            .collect();
        assert!(
            !written.iter().any(|l| l.contains("-carried:")),
            "{written:?}"
        );
        epigraph_db::reject_unexpanded_labels(&written).expect("valid labels");
    }
}
