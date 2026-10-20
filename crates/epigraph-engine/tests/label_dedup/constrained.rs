//! The constrained union-find: a chain never joins two claims that conflict
//! directly, whatever order the edges arrive in.

use epigraph_engine::label_dedup::classify::ConflictKind;
use epigraph_engine::label_dedup::profile::Tier;
use epigraph_engine::label_dedup::DedupClaim;

use crate::fixtures::{
    self as f, claim, cluster_shape, dedup_sections, id, plan_graph, plan_graph_as_given, prefix,
    profile,
};

const TITLE: &str = "Riverside Pump Station Upgrade";

fn item(tag: u32, id_token: &str, extra_labels: &[&str]) -> DedupClaim {
    let mut labels = vec!["notice"];
    labels.extend_from_slice(extra_labels);
    claim(
        tag,
        &format!("[OPEN] {TITLE} | Acme Water Board | ref {id_token} | sector:city | due 2026-09-01 | est. unknown | pump design"),
        &labels,
        "2026-07-01T00:00:00Z",
    )
}

#[test]
fn a_veto_chain_splits_at_the_boundary() {
    // A and C carry disjoint strong ids (a direct veto); B has no id and
    // matches both on title and entity. A plain union-find merges all three.
    let a = item(1, "TND 55501A", &[]);
    let b = item(2, "", &[]);
    let c = item(3, "TND 55502C", &[]);
    let p = plan_graph(
        &profile(),
        &[a.clone(), b.clone(), c.clone()],
        &dedup_sections(),
        None,
    );
    // Equal tiers: the edge with the smaller id pair (A,B) is processed first.
    assert_eq!(
        cluster_shape(&p),
        vec![(id(1), vec![id(2)])],
        "{:?}",
        p.clusters
    );
    assert_eq!(p.vetoed_chains.len(), 1, "{:?}", p.vetoed_chains);
    let v = &p.vetoed_chains[0];
    assert_eq!(v.ids, vec![id(2), id(3)]);
    assert_eq!(v.boundary, vec![id(1), id(3)]);
    assert_eq!(v.conflict, ConflictKind::StrongIdVeto);
    assert_eq!(v.tier, Tier::TitleAndEntity);
    // Control: without C's id nothing conflicts and all three cluster.
    let c_bare = item(3, "", &[]);
    let p = plan_graph(&profile(), &[a, b, c_bare], &dedup_sections(), None);
    assert_eq!(cluster_shape(&p).len(), 1);
    assert_eq!(cluster_shape(&p)[0].1.len(), 2);
    assert!(p.vetoed_chains.is_empty());
}

#[test]
fn a_stronger_edge_is_joined_first() {
    // B shares a weak id with C (weak_id_and_entity) and only title+entity
    // with A, so B joins C first even though (A,B) has the smaller ids.
    let a = item(1, "TND 55501A", &[]);
    let b = item(2, "ref Q31", &[]);
    let c = item(3, "TND 55502C ref Q31", &[]);
    // Rows are handed over as given (no sort on the way in), so the reversed
    // order really reaches the engine.
    for graph in [
        vec![a.clone(), b.clone(), c.clone()],
        vec![c.clone(), b.clone(), a.clone()],
    ] {
        let p = plan_graph_as_given(&profile(), &graph, &dedup_sections(), None);
        let shape = cluster_shape(&p);
        assert_eq!(shape.len(), 1, "{shape:?}");
        let mut members = vec![shape[0].0];
        members.extend(shape[0].1.iter().copied());
        members.sort();
        assert_eq!(
            members,
            vec![id(2), id(3)],
            "B joins C by the stronger tier: {shape:?}"
        );
        assert_eq!(p.vetoed_chains.len(), 1);
        assert_eq!(p.vetoed_chains[0].boundary, vec![id(1), id(3)]);
    }
}

#[test]
fn a_revision_with_a_new_strong_id_still_links_but_never_drags_in_a_veto() {
    // R revises O and carries a new id. T is another copy of O's id.
    let o = item(1, "TND 55501A", &[]);
    let r = item(2, "TND 55509R", &[&format!("revision-of-{}", prefix(1))]);
    let t = item(3, "TND 55501A", &[]);
    let p = plan_graph(
        &profile(),
        &[o.clone(), r.clone(), t],
        &dedup_sections(),
        None,
    );
    // The revision edge is strongest and joins O and R. T shares O's id, but
    // T and R carry disjoint strong ids and no revision label links them.
    let shape = cluster_shape(&p);
    assert_eq!(shape.len(), 1, "{shape:?}");
    let mut members = vec![shape[0].0];
    members.extend(shape[0].1.iter().copied());
    members.sort();
    assert_eq!(members, vec![id(1), id(2)]);
    assert_eq!(p.vetoed_chains.len(), 1, "{:?}", p.vetoed_chains);
    assert_eq!(p.vetoed_chains[0].tier, Tier::StrongId);
    assert_eq!(p.vetoed_chains[0].boundary, vec![id(2), id(3)]);
    // Control: O and R alone cluster despite their disjoint ids.
    let p = plan_graph(&profile(), &[o, r], &dedup_sections(), None);
    assert_eq!(cluster_shape(&p).len(), 1);
}

#[test]
fn a_distinct_from_ruling_is_never_flagged_again() {
    let msb = claim(
        1,
        f::MURAL_MSB,
        &["notice", "src-direct-a"],
        "2026-06-22T00:00:00Z",
    );
    let std = claim(
        2,
        f::MURAL_STD,
        &["notice", "src-direct-a"],
        "2026-06-22T00:00:00Z",
    );
    let p = plan_graph(
        &profile(),
        &[msb.clone(), std.clone()],
        &dedup_sections(),
        None,
    );
    assert_eq!(
        p.review_pairs.len(),
        1,
        "control: the pair is queued without a ruling"
    );
    let mut ruled = msb;
    ruled.labels.push(format!("distinct-from:{}", prefix(2)));
    let p = plan_graph(
        &profile(),
        &[ruled.clone(), std.clone()],
        &dedup_sections(),
        None,
    );
    assert!(
        p.review_pairs.is_empty(),
        "a ruled pair is not re-filed: {:?}",
        p.review_pairs
    );
    assert!(p.clusters.is_empty());
    // The ruling also beats an auto-merge tier.
    let x = claim(
        3,
        f::HOIST_LISTED,
        &["notice", &format!("distinct-from:{}", prefix(4))],
        "2026-06-28T00:00:00Z",
    );
    let y = claim(4, f::HOIST_REVIEW, &["notice"], "2026-06-28T00:00:00Z");
    let p = plan_graph(&profile(), &[x, y], &dedup_sections(), None);
    assert!(p.clusters.is_empty(), "{:?}", p.clusters);
    // The legacy profile reads no rulings: the pair is queued again.
    let p = plan_graph(&f::legacy_profile(), &[ruled, std], &dedup_sections(), None);
    assert_eq!(p.review_pairs.len(), 1);
}

#[test]
fn a_distinct_from_ruling_blocks_a_transitive_chain() {
    let a = item(1, "", &[&format!("distinct-from:{}", prefix(3))]);
    let b = item(2, "", &[]);
    let c = item(3, "", &[]);
    let p = plan_graph(&profile(), &[a, b, c], &dedup_sections(), None);
    assert_eq!(
        cluster_shape(&p),
        vec![(id(1), vec![id(2)])],
        "{:?}",
        p.clusters
    );
    assert_eq!(p.vetoed_chains.len(), 1);
    assert_eq!(p.vetoed_chains[0].conflict, ConflictKind::DistinctLabel);
}

#[test]
fn a_partition_prefix_is_never_crossed() {
    let mut v = f::profile_value();
    v["partition"] = serde_json::json!({
        "must_agree_label_prefixes": ["kind:"],
        "no_merge_without_strong_id_label_values": ["kind:early-notice"]
    });
    let prof = f::load(&v);
    // Different kinds never pair, even with identical titles and entities.
    let p = plan_graph(
        &prof,
        &[item(1, "", &["kind:a"]), item(2, "", &["kind:b"])],
        &dedup_sections(),
        None,
    );
    assert!(
        p.clusters.is_empty() && p.review_pairs.is_empty(),
        "{:?}",
        p.clusters
    );
    // Control: the same kind pairs.
    let p = plan_graph(
        &prof,
        &[item(1, "", &["kind:a"]), item(2, "", &["kind:a"])],
        &dedup_sections(),
        None,
    );
    assert_eq!(p.clusters.len(), 1);
    // A chain through an unlabelled claim is split at the kind boundary.
    let p = plan_graph(
        &prof,
        &[
            item(1, "", &["kind:a"]),
            item(2, "", &[]),
            item(3, "", &["kind:b"]),
        ],
        &dedup_sections(),
        None,
    );
    assert_eq!(cluster_shape(&p), vec![(id(1), vec![id(2)])]);
    assert!(matches!(
        p.vetoed_chains[0].conflict,
        ConflictKind::PartitionMismatch { ref prefix } if prefix == "kind:"
    ));
}

#[test]
fn a_no_strong_id_class_pairs_only_through_a_shared_strong_id() {
    let mut v = f::profile_value();
    v["partition"] = serde_json::json!({
        "no_merge_without_strong_id_label_values": ["kind:early-notice"]
    });
    let prof = f::load(&v);
    let early = item(1, "", &["kind:early-notice"]);
    let full = item(2, "", &[]);
    let p = plan_graph(&prof, &[early, full], &dedup_sections(), None);
    assert!(p.clusters.is_empty(), "{:?}", p.clusters);
    // Control: with a shared strong id the early notice merges.
    let p = plan_graph(
        &prof,
        &[
            item(1, "TND 55501A", &["kind:early-notice"]),
            item(2, "TND 55501A", &[]),
        ],
        &dedup_sections(),
        None,
    );
    assert_eq!(p.clusters.len(), 1);
}

#[test]
fn a_distinct_from_ruling_needs_an_unambiguous_id_prefix() {
    // `distinct-from:0` would name every claim whose id starts with `0`
    // (all of these fixtures), silently splitting real duplicates.
    let short = item(1, "", &["distinct-from:0"]);
    let other = item(2, "", &[]);
    let p = plan_graph(&profile(), &[short, other.clone()], &dedup_sections(), None);
    assert_eq!(
        cluster_shape(&p),
        vec![(id(1), vec![id(2)])],
        "a 1-char prefix is not a ruling: {:?}",
        p.vetoed_chains
    );
    // Control: the 8-hex prefix of the other claim's id is a ruling.
    let ruled = item(1, "", &[&format!("distinct-from:{}", prefix(2))]);
    let p = plan_graph(&profile(), &[ruled, other], &dedup_sections(), None);
    assert!(p.clusters.is_empty(), "{:?}", p.clusters);
}
