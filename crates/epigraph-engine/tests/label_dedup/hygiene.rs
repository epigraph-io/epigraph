//! Hygiene: retired and bookkeeping claims leave the family and never cluster.

use epigraph_engine::label_dedup::hygiene_reason;

use crate::fixtures::{
    self as f, claim, dedup_sections, id, parsed, pass, plan_graph, profile, RUN_TAG,
};

#[test]
fn retired_and_bookkeeping_claims_leave_the_family() {
    let graph = vec![
        claim(
            1,
            f::DROPPED_SEATING,
            &["notice", "notice-dropped", "src-feed"],
            "2026-06-28T00:00:00Z",
        ),
        claim(
            2,
            f::RUN_STATUS,
            &["notice", "src-direct-b"],
            "2026-06-21T00:00:00Z",
        ),
        claim(
            3,
            f::WING_DIRECT,
            &["notice", "src-direct-c"],
            "2026-06-29T00:00:00Z",
        ),
        claim(
            4,
            "Weekly tally",
            &["notice", "notice-run-status"],
            "2026-06-29T00:00:00Z",
        ),
    ];
    let p = plan_graph(&profile(), &graph, &dedup_sections(), None);
    let ids: Vec<_> = p.hygiene.iter().map(|h| h.id).collect();
    assert_eq!(ids, vec![id(1), id(2), id(4)], "{:?}", p.hygiene);
    for h in &p.hygiene {
        assert_eq!(h.remove, vec!["notice".to_string()]);
        assert_eq!(h.add, vec![RUN_TAG.to_string()]);
    }
    assert!(
        p.hygiene[0].reason.contains("retired_label:notice-dropped"),
        "{}",
        p.hygiene[0].reason
    );
    assert!(
        p.hygiene[0].reason.contains("retired_flag:DROPPED"),
        "{}",
        p.hygiene[0].reason
    );
    assert_eq!(p.hygiene[1].reason, "non_member_body");
    assert_eq!(p.hygiene[2].reason, "non_member_label:notice-run-status");
    assert_eq!(p.coverage.members, 4);
}

#[test]
fn a_review_flag_is_not_a_review_status_report() {
    // A `[REVIEW]` flag marks an item awaiting a judgement; the status pattern
    // runs on the flag-stripped body, or every flagged item would leave.
    let item = parsed(
        1,
        f::HOIST_REVIEW,
        &["notice", "src-direct-c"],
        "2026-06-28T00:00:00Z",
    );
    assert_eq!(hygiene_reason(&pass(), &item), None);
    let status = parsed(
        2,
        f::REVIEW_STATUS,
        &["notice", "src-direct-a"],
        "2026-07-19T00:00:00Z",
    );
    assert_eq!(
        hygiene_reason(&pass(), &status).as_deref(),
        Some("non_member_body")
    );
}

#[test]
fn hygiene_claims_never_become_survivors() {
    // A retired twin must not represent the item, whatever its rank.
    let graph = vec![
        claim(
            1,
            f::WING_FEED,
            &["notice", "notice-dropped", "src-direct-c"],
            "2026-06-29T00:00:00Z",
        ),
        claim(
            2,
            f::WING_DIRECT,
            &["notice", "src-feed"],
            "2026-06-28T00:00:00Z",
        ),
    ];
    let p = plan_graph(&profile(), &graph, &dedup_sections(), None);
    assert!(
        p.clusters.is_empty(),
        "one live claim cannot form a cluster: {:?}",
        p.clusters
    );
    assert_eq!(p.hygiene.len(), 1);
    assert_eq!(p.hygiene[0].id, id(1));
    // Control: without the retired label the two cluster and the direct one wins.
    let graph = vec![
        claim(
            1,
            f::WING_FEED,
            &["notice", "src-direct-c"],
            "2026-06-29T00:00:00Z",
        ),
        claim(
            2,
            f::WING_DIRECT,
            &["notice", "src-feed"],
            "2026-06-28T00:00:00Z",
        ),
    ];
    let p = plan_graph(&profile(), &graph, &dedup_sections(), None);
    assert_eq!(p.clusters.len(), 1);
    assert_eq!(p.clusters[0].survivor, id(1));
}

#[test]
fn partially_retired_loser_is_hygiene_not_a_survivor() {
    // A loser that gained the duplicate label but kept the family label (the
    // remove half of its retirement was skipped). Its rank beats the live
    // claim, so treated as live it would re-cluster and WIN.
    let graph = vec![
        claim(
            1,
            f::WING_FEED,
            &[
                "notice",
                "notice-duplicate",
                &format!("duplicate-of:{}", id(2)),
                "src-direct-c",
            ],
            "2026-06-29T00:00:00Z",
        ),
        claim(
            2,
            f::WING_DIRECT,
            &["notice", "src-feed"],
            "2026-06-28T00:00:00Z",
        ),
    ];
    let p = plan_graph(&profile(), &graph, &dedup_sections(), None);
    assert!(p.clusters.is_empty(), "{:?}", p.clusters);
    assert_eq!(p.hygiene.len(), 1);
    assert_eq!(p.hygiene[0].id, id(1));
    assert_eq!(p.hygiene[0].remove, vec!["notice".to_string()]);
    assert!(
        p.hygiene[0].reason.contains("notice-duplicate"),
        "{}",
        p.hygiene[0].reason
    );
}

#[test]
fn hygiene_classification_holds_even_when_the_section_is_not_planned() {
    // Planning only `dedup` writes no hygiene, but a retired claim still never
    // clusters.
    let graph = vec![
        claim(
            1,
            f::WING_FEED,
            &["notice", "notice-dropped", "src-direct-c"],
            "2026-06-29T00:00:00Z",
        ),
        claim(
            2,
            f::WING_DIRECT,
            &["notice", "src-feed"],
            "2026-06-28T00:00:00Z",
        ),
        claim(3, f::WEIR_EARLY, &["notice"], "2026-04-27T00:00:00Z"),
        claim(4, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z"),
    ];
    let p = plan_graph(
        &profile(),
        &graph,
        &[epigraph_engine::label_dedup::Section::Dedup],
        None,
    );
    assert!(p.hygiene.is_empty());
    assert_eq!(
        f::cluster_shape(&p),
        vec![(id(4), vec![id(3)])],
        "control: the live pair clusters"
    );
}
