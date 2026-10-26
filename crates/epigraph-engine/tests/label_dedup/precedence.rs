//! Survivor precedence: rank group, then completeness, then recency, then id.

use crate::fixtures::{self as f, claim, dedup_sections, id, plan_graph, profile};

fn survivor(graph: &[epigraph_engine::label_dedup::DedupClaim]) -> uuid::Uuid {
    let p = plan_graph(&profile(), graph, &dedup_sections(), None);
    assert_eq!(
        p.clusters.len(),
        1,
        "the pair must cluster: {:?}",
        p.clusters
    );
    p.clusters[0].survivor
}

#[test]
fn first_rank_group_beats_later_group() {
    // The feed claim is newer, but a direct source is authoritative.
    let graph = vec![
        claim(
            1,
            f::WING_FEED,
            &["notice", "src-feed"],
            "2026-06-29T00:00:00Z",
        ),
        claim(
            2,
            f::WING_DIRECT,
            &["notice", "src-direct-c"],
            "2026-06-28T00:00:00Z",
        ),
    ];
    assert_eq!(survivor(&graph), id(2));
    // Control: swap the sources and the survivor follows the source.
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
    assert_eq!(survivor(&graph), id(1));
}

#[test]
fn within_a_rank_the_fresher_claim_wins() {
    // Same rank and completeness: the newer claim wins.
    let graph = vec![
        claim(
            1,
            f::WEIR_EARLY,
            &["notice", "class:review"],
            "2026-04-27T00:00:00Z",
        ),
        claim(
            2,
            f::WEIR_LATE,
            &["notice", "class:review"],
            "2026-06-20T00:00:00Z",
        ),
    ];
    assert_eq!(survivor(&graph), id(2));
}

#[test]
fn completeness_outranks_recency() {
    let graph = vec![
        claim(
            1,
            f::WIDGET_SPARSE,
            &["notice", "src-direct-a"],
            "2026-07-20T00:00:00Z",
        ),
        claim(
            2,
            f::WIDGET_FULL,
            &["notice", "src-direct-a"],
            "2026-07-01T00:00:00Z",
        ),
    ];
    assert_eq!(survivor(&graph), id(2));
}

#[test]
fn total_tie_breaks_on_smallest_id_in_any_order() {
    let a = claim(
        1,
        f::HOIST_REVIEW,
        &["notice", "src-direct-c"],
        "2026-06-28T00:00:00Z",
    );
    let b = claim(
        2,
        f::HOIST_LISTED,
        &["notice", "src-direct-c"],
        "2026-06-28T00:00:00Z",
    );
    assert_eq!(survivor(&[a.clone(), b.clone()]), id(1));
    assert_eq!(survivor(&[b, a]), id(1));
}

#[test]
fn rank_explain_names_the_deciding_keys() {
    let graph = vec![
        claim(
            1,
            f::WING_FEED,
            &["notice", "src-feed"],
            "2026-06-29T00:00:00Z",
        ),
        claim(
            2,
            f::WING_DIRECT,
            &["notice", "src-direct-c"],
            "2026-06-28T00:00:00Z",
        ),
    ];
    let p = plan_graph(&profile(), &graph, &dedup_sections(), None);
    let explain = &p.clusters[0].survivor_rank_explain;
    assert!(explain.contains("rank=0"), "{explain}");
    assert!(explain.contains("unknown="), "{explain}");
}
