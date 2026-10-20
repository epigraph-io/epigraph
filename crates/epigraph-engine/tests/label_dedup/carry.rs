//! Carry labels: what a loser knew moves onto the survivor as labels, because
//! claim content is never rewritten.

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
fn a_missing_value_is_carried_label_safe() {
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
    let c = &p.clusters[0];
    let carried: Vec<_> = c
        .carry_add
        .iter()
        .filter(|l| l.starts_with("value-carried:"))
        .collect();
    assert_eq!(carried.len(), 1, "{:?}", c.carry_add);
    assert!(
        !carried[0].contains('$'),
        "a `$` label is refused by the write path: {}",
        carried[0]
    );
    assert!(carried[0].contains("1,600,000"), "{}", carried[0]);
    epigraph_db::reject_unexpanded_labels(&c.carry_add).expect("valid labels");
}

#[test]
fn a_later_carried_date_replaces_the_older_one() {
    // The survivor already carries 07-15 from an earlier merge; a new loser
    // carries 08-30. The old carry label is removed and the new one added in
    // the same unit.
    let survivor = claim(
        1,
        f::WEIR_EARLY,
        &["notice", "src-direct-a", "due-carried:2026-07-15"],
        "2026-04-27T00:00:00Z",
    );
    let loser = claim(
        2,
        "Tender: GWX KX-4417 Granite Weir Channel Upgrade — Acme County PUA, due 2026-08-30, est. $48M.",
        &["notice"],
        "2026-07-20T00:00:00Z",
    );
    let p = plan_graph(
        &profile(),
        &[survivor.clone(), loser],
        &dedup_sections(),
        None,
    );
    let c = &p.clusters[0];
    assert_eq!(c.survivor, id(1));
    assert!(
        c.carry_add.contains(&"due-carried:2026-08-30".to_string()),
        "{:?}",
        c.carry_add
    );
    assert_eq!(
        c.survivor_remove,
        vec!["due-carried:2026-07-15".to_string()]
    );
    // Control: a loser EARLIER than the carried date carries nothing.
    let older = claim(2, f::WEIR_LATE, &["notice"], "2026-07-20T00:00:00Z");
    let p = plan_graph(&profile(), &[survivor, older], &dedup_sections(), None);
    let c = &p.clusters[0];
    assert!(
        !c.carry_add.iter().any(|l| l.starts_with("due-carried:")),
        "{:?}",
        c.carry_add
    );
    assert!(c.survivor_remove.is_empty());
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
        !c.carry_add.iter().any(|l| l.starts_with("due-carried:")),
        "07-15 is already carried: {:?}",
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
fn a_carried_value_is_made_writable_and_bounded() {
    let survivor = || {
        claim(
            1,
            f::FENDER_DIRECT_NO_DUE,
            &["notice", "src-direct-a"],
            "2026-05-01T00:00:00Z",
        )
    };
    let carried = |loser_content: &str| -> Vec<String> {
        let graph = vec![
            survivor(),
            claim(2, loser_content, &["notice"], "2026-05-10T00:00:00Z"),
        ];
        // One odd loser value must never fail the whole plan.
        let p = f::try_plan_graph(&profile(), &graph, &dedup_sections(), None, 5000)
            .expect("a loser's value never fails the plan");
        assert_eq!(cluster_shape(&p), vec![(id(1), vec![id(2)])]);
        p.clusters[0]
            .carry_add
            .iter()
            .filter(|l| l.starts_with("value-carried:"))
            .cloned()
            .collect()
    };
    let pipe = |est: &str| {
        format!(
            "[OPEN] Dock 4 Fender Rebuild TND 0000029912 | Acme Port Authority | sector:city | due unknown | est. {est} | Fender rebuild"
        )
    };
    // A control character inside the value is dropped, not fatal.
    let bell = carried(&pipe("2.4M\u{7}approx"));
    assert_eq!(bell, vec!["value-carried:2.4Mapprox".to_string()]);
    // A run-on value is cut to a bounded label on a character boundary.
    let long_tail = "ca ".repeat(80) + "é".repeat(80).as_str();
    let long = carried(&pipe(&long_tail));
    assert_eq!(long.len(), 1, "{long:?}");
    let value = long[0].strip_prefix("value-carried:").expect("prefix");
    assert!(
        value.chars().count() <= epigraph_engine::label_dedup::plan::MAX_CARRIED_VALUE_CHARS,
        "{} chars: {value}",
        value.chars().count()
    );
    assert!(value.starts_with("ca-ca-"), "{value}");
    assert!(!value.ends_with('-'), "{value}");
    epigraph_db::reject_unexpanded_labels(&long).expect("valid label");
    // Control: a clean value is carried whole.
    let clean = carried(f::FENDER_FEED);
    assert_eq!(clean, vec!["value-carried:1,600,000".to_string()]);
}
