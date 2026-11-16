//! The level documents of one "by meaning" tree, built from the Atlas level
//! contract's types (W10a, schema v1) and stored as
//! [`LevelDocument::to_stored_json`] returns them, so every stored document
//! has passed the contract's validation and its gzip budget (pure: no
//! database).
//!
//! What W4 knows and fills: ids, parents, depths, breadcrumbs, children with
//! their kinds and claim counts, the switch to the links hierarchy's root,
//! and each leaf's claims with their labels. What later items fill, with the
//! neutral values the contract allows until then:
//!
//! * **names** (W8): null, `needs_naming: true`, everywhere;
//! * **positions** (W6): PLACEHOLDERS. A group's children sit evenly on a
//!   ring of radius [`CHILD_RING`] with the largest radius that keeps them
//!   apart, at most [`CHILD_R_MAX`]; a leaf's claims sit evenly on a ring of
//!   radius [`NODE_RING`];
//! * **links**: `bundles`, `targets` and `outgoing` are empty. The nightly
//!   (W9) fills them over the whole map's run (`atlas_nightly::links`);
//! * **a leaf's agents, evidence and edges** (W3 node set, W7 flow weights):
//!   not drawn. A W4 leaf is a SKELETON of claim nodes only. W3 still counted
//!   its agents and evidence against the cap before it was written
//!   ([`super::tree::resolve_tree`]);
//! * **`truth_value`**: null (W4 reads no belief or truth column; the
//!   nightly fills each claim's stored value as its colour).

use std::collections::BTreeMap;
use std::f64::consts::PI;

use anyhow::Context;
use epigraph_atlas_contract::{
    Breadcrumb, Child, ChildKind, ClaimNode, GroupLevel, Hierarchy, LeafLevel, LevelDocument,
    MapScope, Node, Switch, MAX_LABEL_CHARS, SCHEMA_VERSION,
};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, LevelDoc};
use uuid::Uuid;

use super::tree::{root_id, MeaningTree, NodeBody, TreeNode};

/// The radius of the ring a group's children sit on (placeholder for W6).
pub const CHILD_RING: f64 = 0.6;
/// The largest placeholder child radius.
pub const CHILD_R_MAX: f64 = 0.35;
/// The radius of the ring a leaf's claims sit on (placeholder for W6).
pub const NODE_RING: f64 = 0.8;

/// Shown for a claim whose text is empty.
const EMPTY_LABEL: &str = "(no text)";

fn round4(v: f64) -> f64 {
    (v * 10_000.0).round() / 10_000.0
}

/// Point `i` of `n` evenly spaced on a ring of radius `radius`.
fn ring(i: usize, n: usize, radius: f64) -> (f64, f64) {
    if n <= 1 {
        return (0.0, 0.0);
    }
    #[allow(clippy::cast_precision_loss)]
    let a = 2.0 * PI * i as f64 / n as f64;
    (round4(radius * a.cos()), round4(radius * a.sin()))
}

/// The placeholder radius of each of `n` children on the child ring.
fn child_r(n: usize) -> f64 {
    if n <= 1 {
        return CHILD_R_MAX;
    }
    #[allow(clippy::cast_precision_loss)]
    let fit = CHILD_RING * (PI / n as f64).sin() * 0.9;
    (fit.min(CHILD_R_MAX) * 10_000.0).floor() / 10_000.0
}

/// A claim's text as a node label: whitespace collapsed, cut to the
/// contract's [`MAX_LABEL_CHARS`] characters with an ellipsis.
#[must_use]
pub fn claim_label(content: &str) -> String {
    let flat = content.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.is_empty() {
        return EMPTY_LABEL.to_string();
    }
    if flat.chars().count() <= MAX_LABEL_CHARS {
        return flat;
    }
    let mut out: String = flat.chars().take(MAX_LABEL_CHARS - 1).collect();
    out.push('…');
    out
}

const fn contract_hierarchy(h: AtlasHierarchy) -> Hierarchy {
    match h {
        AtlasHierarchy::Meaning => Hierarchy::Meaning,
        AtlasHierarchy::Links => Hierarchy::Links,
    }
}

const fn other(h: AtlasHierarchy) -> AtlasHierarchy {
    match h {
        AtlasHierarchy::Meaning => AtlasHierarchy::Links,
        AtlasHierarchy::Links => AtlasHierarchy::Meaning,
    }
}

/// Every level document of `tree` in run `run_id`, in the tree's pre-order,
/// ready for `AtlasMapRepository::put_level`. `labels` holds the text of every
/// claim of the tree (`AtlasMeaningRepository::claim_labels`). Every level's
/// switch leads to the other hierarchy's root of the same theme.
///
/// # Errors
/// A claim with no label, or a document the contract refuses (validation or
/// the gzip budget).
pub fn level_documents(
    tree: &MeaningTree,
    run_id: Uuid,
    labels: &BTreeMap<Uuid, String>,
) -> anyhow::Result<Vec<LevelDoc>> {
    let to_root = root_id(tree.map, other(tree.hierarchy), tree.theme_id);
    level_documents_with_switch(tree, run_id, labels, &|_| Ok(to_root))
}

/// [`level_documents`] with each level's switch target chosen by `switch`:
/// the id of a level of the OTHER hierarchy of the same theme, for the
/// level `TreeNode` (the "by links" hierarchy points each level at its best
/// overlapping meaning group).
///
/// # Errors
/// What [`level_documents`] refuses, or an error from `switch`.
pub fn level_documents_with_switch(
    tree: &MeaningTree,
    run_id: Uuid,
    labels: &BTreeMap<Uuid, String>,
    switch: &dyn Fn(&TreeNode) -> anyhow::Result<Uuid>,
) -> anyhow::Result<Vec<LevelDoc>> {
    let (map_scope, map_group_id) = match tree.map {
        AtlasMap::Public => (MapScope::Public, None),
        AtlasMap::Team(t) => (MapScope::Team, Some(t)),
    };
    let switch_of = |node: &TreeNode| -> anyhow::Result<Switch> {
        Ok(Switch {
            hierarchy: contract_hierarchy(other(tree.hierarchy)),
            level_id: switch(node)?,
        })
    };
    let by_id: BTreeMap<Uuid, &TreeNode> = tree.nodes.iter().map(|n| (n.id, n)).collect();
    let mut out = Vec::with_capacity(tree.nodes.len());
    for node in &tree.nodes {
        let mut breadcrumbs = Vec::new();
        let mut up = node.parent;
        while let Some(p) = up {
            let parent = by_id.get(&p).context("a parent missing from the tree")?;
            breadcrumbs.push(Breadcrumb {
                level_id: parent.id,
                name: None,
                depth: parent.depth,
            });
            up = parent.parent;
        }
        breadcrumbs.reverse();
        let level_switch = switch_of(node)?;
        let doc = match &node.body {
            NodeBody::Group(children) => {
                let n = children.len();
                let r = child_r(n);
                let children = children
                    .iter()
                    .enumerate()
                    .map(|(i, cid)| {
                        let child = by_id.get(cid).context("a child missing from the tree")?;
                        let (x, y) = ring(i, n, CHILD_RING);
                        Ok(Child {
                            id: *cid,
                            kind: match child.body {
                                NodeBody::Leaf(_) => ChildKind::Leaf,
                                NodeBody::Group(_) => ChildKind::Group,
                            },
                            name: None,
                            needs_naming: true,
                            claim_count: u32::try_from(child.claims.len())?,
                            x,
                            y,
                            r,
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                LevelDocument::Group(GroupLevel {
                    schema_version: SCHEMA_VERSION,
                    map_scope,
                    map_group_id,
                    hierarchy: contract_hierarchy(tree.hierarchy),
                    theme_id: tree.theme_id,
                    run_id,
                    level_id: node.id,
                    depth: node.depth,
                    name: None,
                    needs_naming: true,
                    breadcrumbs,
                    switch: level_switch.clone(),
                    children,
                    bundles: Vec::new(),
                    targets: Vec::new(),
                })
            }
            NodeBody::Leaf(members) => {
                let n = members.len();
                let nodes = members
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        let text = labels
                            .get(c)
                            .with_context(|| format!("no label for claim {c}"))?;
                        let (x, y) = ring(i, n, NODE_RING);
                        Ok(Node::Claim(ClaimNode {
                            id: *c,
                            label: claim_label(text),
                            x,
                            y,
                            truth_value: None,
                        }))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                LevelDocument::Leaf(LeafLevel {
                    schema_version: SCHEMA_VERSION,
                    map_scope,
                    map_group_id,
                    hierarchy: contract_hierarchy(tree.hierarchy),
                    theme_id: tree.theme_id,
                    run_id,
                    level_id: node.id,
                    depth: node.depth,
                    name: None,
                    needs_naming: true,
                    breadcrumbs,
                    switch: level_switch.clone(),
                    nodes,
                    edges: Vec::new(),
                    outgoing: Vec::new(),
                })
            }
        };
        let body = doc
            .to_stored_json()
            .map_err(|v| anyhow::anyhow!("level {} breaks the contract: {v}", node.id))?;
        out.push(LevelDoc {
            hierarchy: tree.hierarchy,
            group_id: node.id,
            parent_group_id: node.parent,
            theme_id: tree.theme_id,
            level: i32::from(node.depth),
            schema_version: i32::try_from(SCHEMA_VERSION)?,
            payload: serde_json::from_slice(&body)?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas_meaning::tree::{check_tree, group_id, WireGroup, WireKind};
    use std::collections::BTreeSet;

    const TEAM: Uuid = Uuid::from_u128(0x5e5e_0000_0000_4000_8000_0000_0000_7ea0);
    const THEME: Uuid = Uuid::from_u128(0x3c88_6e23_925e_4966_b135_a7ef_81df_30a4);

    fn c(n: u128) -> Uuid {
        Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0000 | n)
    }

    /// root -> {group g -> {leaf a: 1..=3, leaf b: 4}, leaf d: 5..=104}.
    fn tree(map: AtlasMap) -> MeaningTree {
        let m = AtlasHierarchy::Meaning;
        let set = |r: std::ops::RangeInclusive<u128>| -> BTreeSet<Uuid> { r.map(c).collect() };
        let root = root_id(map, m, THEME);
        let a = group_id(map, m, THEME, &set(1..=3));
        let b = group_id(map, m, THEME, &set(4..=4));
        let g = group_id(map, m, THEME, &set(1..=4));
        let d = group_id(map, m, THEME, &set(5..=104));
        let wire = |id, parent, depth, kind, members: Option<Vec<Uuid>>, children| WireGroup {
            id,
            parent,
            depth,
            kind,
            claim_count: 0,
            weight: 0,
            members,
            children,
        };
        let groups = vec![
            wire(root, None, 0, WireKind::Group, None, Some(vec![d, g])),
            wire(
                d,
                Some(root),
                1,
                WireKind::Leaf,
                Some((5..=104).map(c).collect()),
                None,
            ),
            wire(g, Some(root), 1, WireKind::Group, None, Some(vec![a, b])),
            wire(
                a,
                Some(g),
                2,
                WireKind::Leaf,
                Some((1..=3).map(c).collect()),
                None,
            ),
            wire(b, Some(g), 2, WireKind::Leaf, Some(vec![c(4)]), None),
        ];
        check_tree(map, m, THEME, &groups, &set(1..=104)).unwrap()
    }

    fn labels() -> BTreeMap<Uuid, String> {
        (1..=104)
            .map(|n| (c(n), format!("claim  number\n{n}")))
            .collect()
    }

    #[test]
    fn every_document_validates_and_chains_to_its_parent() {
        for map in [AtlasMap::Team(TEAM), AtlasMap::Public] {
            let t = tree(map);
            let run = Uuid::from_u128(42);
            let docs = level_documents(&t, run, &labels()).unwrap();
            assert_eq!(docs.len(), 5);
            for (d, n) in docs.iter().zip(&t.nodes) {
                let body = serde_json::to_vec(&d.payload).unwrap();
                let parsed = epigraph_atlas_contract::parse_and_validate(&body).unwrap();
                assert_eq!(parsed.level_id(), n.id);
                assert_eq!((d.group_id, d.parent_group_id), (n.id, n.parent));
                assert_eq!(d.level, i32::from(n.depth));
                assert_eq!(d.payload["run_id"], serde_json::json!(run));
                assert_eq!(d.payload["needs_naming"], serde_json::json!(true));
                assert!(d.payload["name"].is_null());
                assert_eq!(
                    d.payload["switch"]["level_id"],
                    serde_json::json!(root_id(map, AtlasHierarchy::Links, THEME))
                );
            }
            let root = &docs[0].payload;
            assert_eq!(root["kind"], "group");
            assert_eq!(root["children"][0]["kind"], "leaf");
            assert_eq!(root["children"][0]["claim_count"], 100);
            assert_eq!(root["children"][1]["kind"], "group");
            assert_eq!(root["children"][1]["claim_count"], 4);
            let deep = &docs[3].payload;
            assert_eq!(deep["depth"], 2);
            let crumbs: Vec<Uuid> = deep["breadcrumbs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| serde_json::from_value(b["level_id"].clone()).unwrap())
                .collect();
            assert_eq!(crumbs, vec![t.nodes[0].id, t.nodes[2].id]);
            let claims: Vec<Uuid> = deep["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| serde_json::from_value(n["id"].clone()).unwrap())
                .collect();
            assert_eq!(claims, vec![c(1), c(2), c(3)]);
            assert_eq!(deep["nodes"][0]["label"], "claim number 1");
            assert!(deep["nodes"][0]["truth_value"].is_null());
            assert_eq!(deep["edges"], serde_json::json!([]));
            match map {
                AtlasMap::Team(t) => assert_eq!(root["map_group_id"], serde_json::json!(t)),
                AtlasMap::Public => assert!(root["map_group_id"].is_null()),
            }
        }
    }

    #[test]
    fn a_missing_label_is_refused() {
        let mut l = labels();
        l.remove(&c(7));
        let err = level_documents(&tree(AtlasMap::Public), Uuid::nil(), &l).unwrap_err();
        assert!(err.to_string().contains("no label"), "{err}");
    }

    #[test]
    fn labels_are_cut_to_the_contract_length() {
        let long = "é".repeat(400);
        let l = claim_label(&long);
        assert_eq!(l.chars().count(), MAX_LABEL_CHARS);
        assert!(l.ends_with('…'));
        assert_eq!(claim_label("  \n "), EMPTY_LABEL);
        assert_eq!(claim_label("a\tb"), "a b");
    }

    #[test]
    fn placeholder_positions_stay_inside_the_contract_ranges() {
        for n in [2, 3, 16, 20, 128] {
            let r = child_r(n);
            assert!(r > 0.0 && r <= CHILD_R_MAX, "{n}: {r}");
            for i in 0..n {
                let (x, y) = ring(i, n, CHILD_RING);
                assert!(x.abs() <= 1.0 && y.abs() <= 1.0);
            }
        }
    }
}
