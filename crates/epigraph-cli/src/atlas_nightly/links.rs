//! The cross-group links of one map's run (Atlas W9): each group level's
//! `bundles` and `targets` and each leaf's `outgoing`, aggregated from the
//! links between the claims the run draws. The nightly computes them once
//! every theme of the map is final (built or carried) and before W6's layout,
//! which pulls linked children together from the sibling bundles.
//!
//! # Which links
//!
//! The same edge set and map rule as the "by links" hierarchy (W5) and the
//! leaves (W3): claim-to-claim edges whose relationship
//! [`is_counted`] (the epistemic edges plus `decomposes_to`), whose row the
//! map's whole audience may read (public, or owned by the team with no
//! co-owner; [`AtlasLeafRepository::map_claim_links`]), between two
//! different claims that each sit in a leaf of the run. A co-owned edge is
//! never one. Rows repeating one (source, target, lower-cased relationship)
//! are ONE link, as in a leaf's edges: a resubmission is not more support.
//!
//! # Where a link shows
//!
//! Each hierarchy is aggregated on its own, and a target is always a level of
//! the same hierarchy. For a link from claim `s` to claim `t` in different
//! leaves, with `ps` and `pt` the paths from each theme root down to the
//! leaf holding `s` and `t`:
//!
//! * **Same theme.** At the lowest common ancestor, a sibling bundle from the
//!   child towards `s` to the child towards `t`, in the stored direction.
//!   Every level below that ancestor on `s`'s side lists the link towards
//!   `pt[k]`, the child of the common ancestor that holds `t`: the shallowest
//!   group holding `t` that is outside the level, so the stub flies as far
//!   up as the viewer can navigate and no further.
//! * **Another theme.** Every level on `s`'s path, the theme root included,
//!   lists the link towards the other theme's root in the same hierarchy
//!   (depth 0).
//!
//! A link is listed from its SOURCE end only, as the contract defines a
//! bundle ("all links from one child") and an `outgoing` entry ("all links
//! leaving the leaf", its `sources` the nodes they leave from): in a group
//! level a bundle from the child holding `s` to a sibling or a `targets`
//! entry, in a leaf an `outgoing` entry with `s` among its `sources`. The
//! levels on `t`'s side list nothing for it, so a stub always reads as "this
//! claim links to that group", never the other way round. A leaf whose claims
//! are only linked TO shows no stub for those links.
//!
//! # Count and sign
//!
//! `count` is the number of links; `net_sign` is the sign of the sum of each
//! link's W7 sign ([`link_sign`]: +1 supporting, -1 opposing, 0 other).
//!
//! # Caps
//!
//! A group keeps its [`MAX_GROUP_TARGETS`] heaviest outside targets (by link
//! count, ties to the smaller id), then its [`MAX_GROUP_BUNDLES`] heaviest
//! bundles; a leaf its [`MAX_LEAF_OUTGOING`] heaviest `outgoing` targets.
//! What is cut is counted in [`LinksReport`], never an error. A group child
//! count over [`epigraph_atlas_contract::MAX_GROUP_CHILDREN`] is the tree's
//! cap, already enforced there.
//!
//! # Determinism
//!
//! Every output is built from ordered maps and sorted, so it depends only on
//! the documents' trees and the SET of links: a night over unchanged input
//! writes the same bytes, and only the levels a changed link (or a changed
//! group id) passes through change.
//!
//! [`AtlasLeafRepository::map_claim_links`]: epigraph_db::repos::atlas_leaf::AtlasLeafRepository::map_claim_links

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use epigraph_atlas_contract::{
    Bundle, Hierarchy, LevelDocument, LinkTarget, Node, Outgoing, MAX_GROUP_BUNDLES,
    MAX_GROUP_TARGETS, MAX_LEAF_OUTGOING,
};
use epigraph_engine::atlas_flow::link_sign;
use serde::Serialize;
use uuid::Uuid;

use crate::atlas_links::graph::is_counted;

/// What one map's cross-group links came to: counts only (no ids), so it
/// can go into the run's `params` as well as the night's report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LinksReport {
    /// Distinct counted links read: `(source, target, lower-cased
    /// relationship)` between two different claims.
    pub links: usize,
    /// Claims found in two leaves of one hierarchy (a malformed run); their
    /// links are left out in that hierarchy.
    pub ambiguous_claims: usize,
    /// Outside targets cut from group levels over [`MAX_GROUP_TARGETS`].
    pub dropped_targets: usize,
    /// Bundles cut from group levels: those to a cut target, and those over
    /// [`MAX_GROUP_BUNDLES`].
    pub dropped_bundles: usize,
    /// `outgoing` entries cut from leaves over [`MAX_LEAF_OUTGOING`].
    pub dropped_outgoing: usize,
    /// The links the cut bundles and `outgoing` entries counted.
    pub dropped_links: u64,
}

/// A running count and sign sum.
#[derive(Debug, Clone, Copy, Default)]
struct Tally {
    count: u32,
    signs: i64,
}

impl Tally {
    fn add(&mut self, sign: i8) {
        self.count += 1;
        self.signs += i64::from(sign);
    }

    fn net_sign(self) -> i8 {
        // `signum` of an i64 is -1, 0 or 1.
        i8::try_from(self.signs.signum()).unwrap_or(0)
    }
}

/// One hierarchy's tallies.
#[derive(Default)]
struct Tallies {
    /// group level -> (child, target) -> tally.
    groups: BTreeMap<Uuid, BTreeMap<(Uuid, Uuid), Tally>>,
    /// leaf -> target -> (tally, source claims).
    leaves: BTreeMap<Uuid, BTreeMap<Uuid, (Tally, BTreeSet<Uuid>)>>,
}

impl Tallies {
    /// List a link at every level of `path` from index `from` down, towards
    /// `target`, from the link's source claim `source`.
    fn anchor(&mut self, path: &[Uuid], from: usize, target: Uuid, source: Uuid, sign: i8) {
        for i in from..path.len() {
            if let Some(child) = path.get(i + 1) {
                self.groups
                    .entry(path[i])
                    .or_default()
                    .entry((*child, target))
                    .or_default()
                    .add(sign);
            } else {
                let (t, sources) = self
                    .leaves
                    .entry(path[i])
                    .or_default()
                    .entry(target)
                    .or_default();
                t.add(sign);
                sources.insert(source);
            }
        }
    }
}

fn hierarchy_of(doc: &LevelDocument) -> Hierarchy {
    match doc {
        LevelDocument::Group(g) => g.hierarchy,
        LevelDocument::Leaf(l) => l.hierarchy,
    }
}

/// The heaviest `n` of `items` by `weight` (ties to the smaller key), and
/// the rest.
fn heaviest<K: Ord + Copy>(mut items: Vec<(K, u64)>, n: usize) -> (BTreeSet<K>, Vec<(K, u64)>) {
    items.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let rest = items.split_off(n.min(items.len()));
    (items.into_iter().map(|(k, _)| k).collect(), rest)
}

/// Fill every group level's `bundles` and `targets` and every leaf's
/// `outgoing` in `docs` (one map's run, every theme and both hierarchies)
/// from `links` (`(source, target, relationship)` rows, as
/// `AtlasLeafRepository::map_claim_links` returns them), replacing what they
/// held. Target names are left null for the naming step to fill. See the
/// module documentation for the rules.
///
/// # Errors
/// A document that breaks the contract once filled (a malformed tree).
pub fn fill_cross_links(
    docs: &mut [LevelDocument],
    links: &[(Uuid, Uuid, String)],
) -> anyhow::Result<LinksReport> {
    let links: BTreeSet<(Uuid, Uuid, String)> = links
        .iter()
        .filter(|(s, t, rel)| s != t && is_counted(rel))
        .map(|(s, t, rel)| (*s, *t, rel.to_ascii_lowercase()))
        .collect();
    let mut report = LinksReport {
        links: links.len(),
        ..LinksReport::default()
    };
    for h in [Hierarchy::Meaning, Hierarchy::Links] {
        fill_hierarchy(docs, h, &links, &mut report)?;
    }
    for doc in docs.iter() {
        doc.validate().map_err(|v| {
            anyhow::anyhow!(
                "level {} breaks the contract once its links are filled: {v}",
                doc.level_id()
            )
        })?;
    }
    Ok(report)
}

#[allow(clippy::too_many_lines)]
fn fill_hierarchy(
    docs: &mut [LevelDocument],
    h: Hierarchy,
    links: &BTreeSet<(Uuid, Uuid, String)>,
    report: &mut LinksReport,
) -> anyhow::Result<()> {
    // Each level's theme and depth, and each claim's leaf with the path from
    // its theme root.
    let mut levels: BTreeMap<Uuid, (Uuid, u8)> = BTreeMap::new();
    let mut leaf_of: BTreeMap<Uuid, Uuid> = BTreeMap::new();
    let mut ambiguous: BTreeSet<Uuid> = BTreeSet::new();
    let mut paths: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
    for doc in docs.iter().filter(|d| hierarchy_of(d) == h) {
        match doc {
            LevelDocument::Group(g) => {
                levels.insert(g.level_id, (g.theme_id, g.depth));
            }
            LevelDocument::Leaf(l) => {
                levels.insert(l.level_id, (l.theme_id, l.depth));
                let mut path: Vec<Uuid> = l.breadcrumbs.iter().map(|b| b.level_id).collect();
                path.push(l.level_id);
                paths.insert(l.level_id, path);
                for n in &l.nodes {
                    if let Node::Claim(c) = n {
                        if leaf_of.insert(c.id, l.level_id).is_some() {
                            ambiguous.insert(c.id);
                        }
                    }
                }
            }
        }
    }
    report.ambiguous_claims += ambiguous.len();

    let mut tallies = Tallies::default();
    for (s, t, rel) in links {
        if ambiguous.contains(s) || ambiguous.contains(t) {
            continue;
        }
        let (Some(ls), Some(lt)) = (leaf_of.get(s), leaf_of.get(t)) else {
            continue;
        };
        if ls == lt {
            continue;
        }
        let sign = link_sign(rel);
        let (ps, pt) = (&paths[ls], &paths[lt]);
        if ps[0] == pt[0] {
            // Same theme: the common prefix holds at least the root, and
            // stops before either leaf (a leaf has no descendants).
            let k = ps.iter().zip(pt.iter()).take_while(|(a, b)| a == b).count();
            tallies
                .groups
                .entry(ps[k - 1])
                .or_default()
                .entry((ps[k], pt[k]))
                .or_default()
                .add(sign);
            tallies.anchor(ps, k, pt[k], *s, sign);
        } else {
            tallies.anchor(ps, 0, pt[0], *s, sign);
        }
    }

    let target_of = |id: Uuid| -> anyhow::Result<LinkTarget> {
        let (theme_id, depth) = *levels
            .get(&id)
            .with_context(|| format!("link target {id} is not a level of the run"))?;
        Ok(LinkTarget {
            level_id: id,
            theme_id,
            name: None,
            depth,
        })
    };

    for doc in docs.iter_mut().filter(|d| hierarchy_of(d) == h) {
        match doc {
            LevelDocument::Group(g) => {
                let tally = tallies.groups.remove(&g.level_id).unwrap_or_default();
                let children: BTreeSet<Uuid> = g.children.iter().map(|c| c.id).collect();
                // 1. The heaviest outside targets.
                let mut per_target: BTreeMap<Uuid, u64> = BTreeMap::new();
                for ((_, target), t) in &tally {
                    if !children.contains(target) {
                        *per_target.entry(*target).or_default() += u64::from(t.count);
                    }
                }
                let (kept_targets, cut) =
                    heaviest(per_target.into_iter().collect(), MAX_GROUP_TARGETS);
                report.dropped_targets += cut.len();
                let mut bundles: Vec<((Uuid, Uuid), Tally)> = Vec::new();
                for (key, t) in tally {
                    if children.contains(&key.1) || kept_targets.contains(&key.1) {
                        bundles.push((key, t));
                    } else {
                        report.dropped_bundles += 1;
                        report.dropped_links += u64::from(t.count);
                    }
                }
                // 2. The heaviest bundles.
                let (kept, cut) = heaviest(
                    bundles
                        .iter()
                        .map(|(k, t)| (*k, u64::from(t.count)))
                        .collect(),
                    MAX_GROUP_BUNDLES,
                );
                report.dropped_bundles += cut.len();
                report.dropped_links += cut.iter().map(|(_, n)| n).sum::<u64>();
                bundles.retain(|(k, _)| kept.contains(k));
                // 3. A target only while a kept bundle leads to it.
                let used: BTreeSet<Uuid> = bundles
                    .iter()
                    .map(|((_, target), _)| *target)
                    .filter(|t| !children.contains(t))
                    .collect();
                g.bundles = bundles
                    .into_iter()
                    .map(|((source, target), t)| Bundle {
                        source,
                        target,
                        count: t.count,
                        net_sign: t.net_sign(),
                    })
                    .collect();
                g.targets = used
                    .into_iter()
                    .map(target_of)
                    .collect::<anyhow::Result<_>>()?;
            }
            LevelDocument::Leaf(l) => {
                let tally = tallies.leaves.remove(&l.level_id).unwrap_or_default();
                let (kept, cut) = heaviest(
                    tally
                        .iter()
                        .map(|(target, (t, _))| (*target, u64::from(t.count)))
                        .collect(),
                    MAX_LEAF_OUTGOING,
                );
                report.dropped_outgoing += cut.len();
                report.dropped_links += cut.iter().map(|(_, n)| n).sum::<u64>();
                l.outgoing = tally
                    .into_iter()
                    .filter(|(target, _)| kept.contains(target))
                    .map(|(target, (t, sources))| {
                        Ok(Outgoing {
                            target: target_of(target)?,
                            count: t.count,
                            net_sign: t.net_sign(),
                            sources: sources.into_iter().collect(),
                        })
                    })
                    .collect::<anyhow::Result<_>>()?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_atlas_contract::{
        Breadcrumb, Child, ChildKind, ClaimNode, GroupLevel, LeafLevel, MapScope, Switch,
        SCHEMA_VERSION,
    };

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn crumbs(path: &[Uuid]) -> Vec<Breadcrumb> {
        path.iter()
            .enumerate()
            .map(|(i, l)| Breadcrumb {
                level_id: *l,
                name: None,
                depth: u8::try_from(i).unwrap(),
            })
            .collect()
    }

    fn switch() -> Switch {
        Switch {
            hierarchy: Hierarchy::Links,
            level_id: id(0xfff),
        }
    }

    fn group(
        theme: Uuid,
        path: &[Uuid],
        level: Uuid,
        children: &[(Uuid, ChildKind)],
    ) -> LevelDocument {
        LevelDocument::Group(GroupLevel {
            schema_version: SCHEMA_VERSION,
            map_scope: MapScope::Public,
            map_group_id: None,
            hierarchy: Hierarchy::Meaning,
            theme_id: theme,
            run_id: Uuid::nil(),
            level_id: level,
            depth: u8::try_from(path.len()).unwrap(),
            name: None,
            needs_naming: true,
            breadcrumbs: crumbs(path),
            switch: switch(),
            children: children
                .iter()
                .map(|(c, kind)| Child {
                    id: *c,
                    kind: *kind,
                    name: None,
                    needs_naming: true,
                    claim_count: 1,
                    x: 0.0,
                    y: 0.0,
                    r: 0.1,
                })
                .collect(),
            bundles: Vec::new(),
            targets: Vec::new(),
        })
    }

    fn leaf(theme: Uuid, path: &[Uuid], level: Uuid, claims: &[Uuid]) -> LevelDocument {
        LevelDocument::Leaf(LeafLevel {
            schema_version: SCHEMA_VERSION,
            map_scope: MapScope::Public,
            map_group_id: None,
            hierarchy: Hierarchy::Meaning,
            theme_id: theme,
            run_id: Uuid::nil(),
            level_id: level,
            depth: u8::try_from(path.len()).unwrap(),
            name: None,
            needs_naming: true,
            breadcrumbs: crumbs(path),
            switch: switch(),
            nodes: claims
                .iter()
                .map(|c| {
                    Node::Claim(ClaimNode {
                        id: *c,
                        label: "c".into(),
                        x: 0.0,
                        y: 0.0,
                        truth_value: None,
                    })
                })
                .collect(),
            edges: Vec::new(),
            outgoing: Vec::new(),
        })
    }

    fn find(docs: &[LevelDocument], level: Uuid) -> &LevelDocument {
        docs.iter().find(|d| d.level_id() == level).unwrap()
    }

    fn bundles(docs: &[LevelDocument], level: Uuid) -> Vec<(Uuid, Uuid, u32, i8)> {
        match find(docs, level) {
            LevelDocument::Group(g) => g
                .bundles
                .iter()
                .map(|b| (b.source, b.target, b.count, b.net_sign))
                .collect(),
            LevelDocument::Leaf(_) => panic!("a leaf"),
        }
    }

    fn targets(docs: &[LevelDocument], level: Uuid) -> Vec<(Uuid, Uuid, u8)> {
        match find(docs, level) {
            LevelDocument::Group(g) => g
                .targets
                .iter()
                .map(|t| (t.level_id, t.theme_id, t.depth))
                .collect(),
            LevelDocument::Leaf(_) => panic!("a leaf"),
        }
    }

    fn outgoing(docs: &[LevelDocument], level: Uuid) -> Vec<(Uuid, u32, i8, Vec<Uuid>)> {
        match find(docs, level) {
            LevelDocument::Leaf(l) => l
                .outgoing
                .iter()
                .map(|o| (o.target.level_id, o.count, o.net_sign, o.sources.clone()))
                .collect(),
            LevelDocument::Group(_) => panic!("a group"),
        }
    }

    // Theme 1: root R -> {leaf A, group G -> {leaf B, leaf C}}.
    // Theme 2: root leaf T.
    const T1: u128 = 0x1000;
    const T2: u128 = 0x2000;
    const R: u128 = 0x10;
    const G: u128 = 0x11;
    const A: u128 = 0x20;
    const B: u128 = 0x21;
    const C: u128 = 0x22;
    const T: u128 = 0x30;

    fn corpus() -> Vec<LevelDocument> {
        let (t1, t2) = (id(T1), id(T2));
        vec![
            group(
                t1,
                &[],
                id(R),
                &[(id(A), ChildKind::Leaf), (id(G), ChildKind::Group)],
            ),
            group(
                t1,
                &[id(R)],
                id(G),
                &[(id(B), ChildKind::Leaf), (id(C), ChildKind::Leaf)],
            ),
            leaf(t1, &[id(R)], id(A), &[id(0xa1), id(0xa2), id(0xa3)]),
            leaf(t1, &[id(R), id(G)], id(B), &[id(0xb1), id(0xb2)]),
            leaf(t1, &[id(R), id(G)], id(C), &[id(0xc1)]),
            leaf(t2, &[], id(T), &[id(0xd1)]),
        ]
    }

    fn l(s: u128, t: u128, rel: &str) -> (Uuid, Uuid, String) {
        (id(s), id(t), rel.to_string())
    }

    #[test]
    fn links_are_aggregated_at_every_level_towards_the_shallowest_outside_group() {
        let mut docs = corpus();
        let report = fill_cross_links(
            &mut docs,
            &[
                // A -> B twice (supports, refutes), once repeated in the
                // other spelling: two links, net 0.
                l(0xa1, 0xb1, "supports"),
                l(0xa1, 0xb1, "SUPPORTS"),
                l(0xa2, 0xb2, "refutes"),
                // B -> C inside G: opposing.
                l(0xb1, 0xc1, "contradicts"),
                // A -> T: another theme, sign 0.
                l(0xa3, 0xd1, "cites"),
                // C -> A, stored that way round: supporting.
                l(0xc1, 0xa1, "elaborates"),
                // Not links: a self-loop, a relationship W5 does not count,
                // a claim no leaf holds, and one inside a leaf.
                l(0xa1, 0xa1, "supports"),
                l(0xa1, 0xb2, "authored"),
                l(0xa1, 0xeee, "supports"),
                l(0xa1, 0xa2, "supports"),
            ],
        )
        .unwrap();
        assert_eq!(
            report.dropped_targets + report.dropped_bundles + report.dropped_outgoing,
            0
        );
        let (t1, t2) = (id(T1), id(T2));

        // The root: sibling bundles in the stored direction, the other
        // theme's root as an outside target at depth 0.
        assert_eq!(
            bundles(&docs, id(R)),
            vec![
                (id(G), id(A), 1, 1),
                (id(A), id(G), 2, 0),
                (id(A), id(T), 1, 0),
            ]
        );
        assert_eq!(targets(&docs, id(R)), vec![(id(T), t2, 0)]);
        // G: B -> C a sibling bundle; C -> A leaves G towards A, listed
        // once. A -> B arrives in G and is listed only from A's side.
        assert_eq!(
            bundles(&docs, id(G)),
            vec![(id(B), id(C), 1, -1), (id(C), id(A), 1, 1)]
        );
        assert_eq!(targets(&docs, id(G)), vec![(id(A), t1, 1)]);
        // Leaf A: B is reached through G (the shallowest group outside A
        // that holds it), the other theme through its root. C -> A arrives
        // in A, so it is no stub of A's.
        assert_eq!(
            outgoing(&docs, id(A)),
            vec![
                (id(G), 2, 0, vec![id(0xa1), id(0xa2)]),
                (id(T), 1, 0, vec![id(0xa3)]),
            ]
        );
        // Each link is a stub of its source leaf only: B's claims are
        // linked to from A, and C's from B, and neither shows those.
        assert_eq!(outgoing(&docs, id(B)), vec![(id(C), 1, -1, vec![id(0xb1)])]);
        assert_eq!(outgoing(&docs, id(C)), vec![(id(A), 1, 1, vec![id(0xc1)])]);
        // T's claim is only cited, so T has no stub.
        assert_eq!(outgoing(&docs, id(T)), vec![]);
        // Seven distinct counted links were read; the one to a claim no leaf
        // holds and the one inside leaf A show nowhere.
        assert_eq!(report.links, 7, "{report:?}");
        for d in &docs {
            d.validate().unwrap();
        }
    }

    #[test]
    fn the_result_does_not_depend_on_link_order_and_replaces_what_was_there() {
        let links = vec![
            l(0xa1, 0xb1, "supports"),
            l(0xb2, 0xc1, "refutes"),
            l(0xa3, 0xd1, "cites"),
        ];
        let mut a = corpus();
        fill_cross_links(&mut a, &links).unwrap();
        let mut b = corpus();
        let mut rev = links.clone();
        rev.reverse();
        fill_cross_links(&mut b, &rev).unwrap();
        assert_eq!(a, b);
        // A second fill with no links clears every bundle and stub.
        fill_cross_links(&mut b, &[]).unwrap();
        assert_eq!(b, corpus());
    }

    /// A root with one leaf child linked into `n` other themes' root leaves,
    /// target `i` with `weight(i)` links.
    fn fan_out(
        n: u128,
        weight: impl Fn(u128) -> u128,
    ) -> (Vec<LevelDocument>, Vec<(Uuid, Uuid, String)>) {
        let t1 = id(T1);
        let mut docs = vec![
            group(
                t1,
                &[],
                id(R),
                &[(id(A), ChildKind::Leaf), (id(B), ChildKind::Leaf)],
            ),
            leaf(
                t1,
                &[id(R)],
                id(A),
                &(0..100).map(|i| id(0xa000 + i)).collect::<Vec<_>>(),
            ),
            leaf(t1, &[id(R)], id(B), &[id(0xb000)]),
        ];
        let mut links = Vec::new();
        for i in 0..n {
            let claims: Vec<Uuid> = (0..weight(i))
                .map(|j| id(0x50_0000 + i * 0x100 + j))
                .collect();
            docs.push(leaf(id(0x60_0000 + i), &[], id(0x70_0000 + i), &claims));
            for (j, c) in claims.iter().enumerate() {
                links.push((id(0xa000 + j as u128), *c, "supports".to_string()));
            }
        }
        (docs, links)
    }

    #[test]
    fn a_leaf_over_the_outgoing_cap_keeps_its_heaviest_targets_and_reports_the_rest() {
        let n = MAX_LEAF_OUTGOING as u128 + 3;
        // Targets 0, 1 and 2 carry one link; every other target two.
        let (mut docs, links) = fan_out(n, |i| if i < 3 { 1 } else { 2 });
        let report = fill_cross_links(&mut docs, &links).unwrap();
        let out = outgoing(&docs, id(A));
        assert_eq!(out.len(), MAX_LEAF_OUTGOING);
        assert!(
            out.iter().all(|(_, count, _, _)| *count == 2),
            "a light target was kept"
        );
        assert_eq!(report.dropped_outgoing, 3);
        assert_eq!(report.dropped_links, 3);
        // The root lists all of them (its cap is larger).
        assert_eq!(targets(&docs, id(R)).len(), n as usize);
        for d in &docs {
            d.validate().unwrap();
        }
    }

    #[test]
    fn a_group_over_the_target_cap_keeps_its_heaviest_targets_and_reports_the_rest() {
        let n = MAX_GROUP_TARGETS as u128 + 2;
        // Targets 7 and 9 carry one link, every other three.
        let (mut docs, links) = fan_out(n, |i| if i == 7 || i == 9 { 1 } else { 3 });
        let report = fill_cross_links(&mut docs, &links).unwrap();
        let kept: BTreeSet<Uuid> = targets(&docs, id(R)).into_iter().map(|t| t.0).collect();
        assert_eq!(kept.len(), MAX_GROUP_TARGETS);
        assert!(!kept.contains(&id(0x70_0007)) && !kept.contains(&id(0x70_0009)));
        // Every bundle leads to a kept target; none to a cut one.
        assert!(bundles(&docs, id(R)).iter().all(|b| kept.contains(&b.1)));
        assert_eq!(report.dropped_targets, 2);
        assert_eq!(report.dropped_bundles, 2);
        // The leaf's own cap cuts too: the root's cut is reported once per
        // level that makes it.
        assert_eq!(report.dropped_outgoing, n as usize - MAX_LEAF_OUTGOING);
        for d in &docs {
            d.validate().unwrap();
        }
    }

    #[test]
    fn a_group_over_the_bundle_cap_keeps_its_heaviest_bundles() {
        // 128 leaf children, every one linked to 16 or 17 outside targets
        // (160 in all): 2,176 bundles, over the 2,048 cap.
        let t1 = id(T1);
        let kids: Vec<Uuid> = (0..128).map(|i| id(0x1_0000 + i)).collect();
        let mut docs = vec![group(
            t1,
            &[],
            id(R),
            &kids
                .iter()
                .map(|k| (*k, ChildKind::Leaf))
                .collect::<Vec<_>>(),
        )];
        let mut links = Vec::new();
        for (i, k) in kids.iter().enumerate() {
            let claims: Vec<Uuid> = (0..20)
                .map(|j| id(0x2_0000 + i as u128 * 0x100 + j))
                .collect();
            docs.push(leaf(t1, &[id(R)], *k, &claims));
            for j in 0..17_u128 {
                let target = (i as u128 * 17 + j) % 160;
                // Child 0's links weigh 2 each (two claims), the rest 1.
                for c in claims.iter().take(if i == 0 { 2 } else { 1 }) {
                    links.push((*c, id(0x3_0000 + target), "supports".to_string()));
                }
            }
        }
        for t in 0..160_u128 {
            docs.push(leaf(
                id(0x4_0000 + t),
                &[],
                id(0x3_0000 + t),
                &[id(0x3_0000 + t)],
            ));
        }
        let report = fill_cross_links(&mut docs, &links).unwrap();
        let b = bundles(&docs, id(R));
        assert_eq!(b.len(), MAX_GROUP_BUNDLES);
        assert_eq!(report.dropped_bundles, 128 * 17 - MAX_GROUP_BUNDLES);
        assert_eq!(report.dropped_targets, 0);
        // Child 0's heavier bundles are all kept.
        assert_eq!(b.iter().filter(|x| x.0 == kids[0]).count(), 17);
        for d in &docs {
            d.validate().unwrap();
        }
    }
}
