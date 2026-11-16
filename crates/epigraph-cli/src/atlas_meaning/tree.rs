//! The "by meaning" tree of one theme on one map: the group-id mint, the
//! result file's tree checked against the live members, and the W3 re-check
//! that splits a leaf found over the node cap (pure: no database).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context};
use epigraph_db::repos::atlas_leaf::{assemble_leaf, fallback_split, LeafOutcome, LeafRows};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `uuid5(NAMESPACE_URL, "urn:epigraph:atlas-group:v1")`, the namespace of
/// every Atlas group id. Pinned with `scripts/atlas_meaning_core.py`.
pub const NAMESPACE: Uuid = Uuid::from_u128(0xfe26_24a2_be4f_595a_be4c_2e14_830d_2a5b);

/// The deepest level below the theme root (the contract's breadcrumb limit).
pub const MAX_DEPTH: u8 = epigraph_atlas_contract::MAX_DEPTH;
/// The most children of one group level (the contract's).
pub const MAX_CHILDREN: usize = epigraph_atlas_contract::MAX_GROUP_CHILDREN;

/// A map's spelling in the id mint and the files: `public` or `team:<uuid>`.
#[must_use]
pub fn map_key(map: AtlasMap) -> String {
    match map {
        AtlasMap::Public => "public".to_string(),
        AtlasMap::Team(t) => format!("team:{t}"),
    }
}

/// The inverse of [`map_key`].
///
/// # Errors
/// Anything but `public` or `team:<uuid>`.
pub fn parse_map_key(s: &str) -> anyhow::Result<AtlasMap> {
    if s == "public" {
        return Ok(AtlasMap::Public);
    }
    let g = s
        .strip_prefix("team:")
        .with_context(|| format!("a map is `public` or `team:<group uuid>`, not {s:?}"))?;
    let id = Uuid::parse_str(g).with_context(|| format!("{g:?} is not a uuid"))?;
    ensure!(
        id.to_string() == g,
        "write the team id lowercase and hyphenated: {g:?}"
    );
    Ok(AtlasMap::Team(id))
}

/// The id of a theme's root (depth 0) in one hierarchy of one map:
/// `"{map}|{hierarchy}|{theme}|root"`. It does not depend on membership, so
/// the theme root keeps its id while claims come and go, and the other
/// hierarchy's root id is known without its members (the level switch).
#[must_use]
pub fn root_id(map: AtlasMap, hierarchy: AtlasHierarchy, theme_id: Uuid) -> Uuid {
    let name = format!("{}|{}|{theme_id}|root", map_key(map), hierarchy.as_str());
    Uuid::new_v5(&NAMESPACE, name.as_bytes())
}

/// The id of any other group: `"{map}|{hierarchy}|{theme}|members|"` and
/// every claim id under it, lowercase and hyphenated, sorted, comma-joined.
/// A `BTreeSet<Uuid>` iterates in byte order, which is the order of those
/// strings. So a group whose member set is unchanged keeps its id across
/// runs, with no matching against an earlier run.
#[must_use]
pub fn group_id(
    map: AtlasMap,
    hierarchy: AtlasHierarchy,
    theme_id: Uuid,
    members: &BTreeSet<Uuid>,
) -> Uuid {
    let mut name = format!(
        "{}|{}|{theme_id}|members|",
        map_key(map),
        hierarchy.as_str()
    );
    for (i, m) in members.iter().enumerate() {
        if i > 0 {
            name.push(',');
        }
        name.push_str(&m.to_string());
    }
    Uuid::new_v5(&NAMESPACE, name.as_bytes())
}

/// A group's kind in the result file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireKind {
    Leaf,
    Group,
}

/// One group as the result file carries it (`scripts/atlas_meaning_core.py`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGroup {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    pub depth: u8,
    pub kind: WireKind,
    pub claim_count: u32,
    /// The core's weight (claims + distinct attachment nodes); informational:
    /// the apply re-counts with W3.
    pub weight: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<Uuid>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<Uuid>>,
}

/// A node of a checked tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeBody {
    /// The claims of a leaf, sorted.
    Leaf(Vec<Uuid>),
    /// The child ids of an inner group, in display order.
    Group(Vec<Uuid>),
}

/// One group of a checked tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeNode {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    pub depth: u8,
    pub body: NodeBody,
    /// Every claim under this group, sorted.
    pub claims: Vec<Uuid>,
}

/// The checked hierarchy of one theme on one map: its groups in pre-order,
/// the root first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeaningTree {
    pub map: AtlasMap,
    pub hierarchy: AtlasHierarchy,
    pub theme_id: Uuid,
    pub nodes: Vec<TreeNode>,
}

impl MeaningTree {
    /// The group `id`, if the tree has it.
    #[must_use]
    pub fn node(&self, id: Uuid) -> Option<&TreeNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// The leaves, in pre-order.
    pub fn leaves(&self) -> impl Iterator<Item = (&TreeNode, &[Uuid])> {
        self.nodes.iter().filter_map(|n| match &n.body {
            NodeBody::Leaf(m) => Some((n, m.as_slice())),
            NodeBody::Group(_) => None,
        })
    }
}

/// Lay `shape` out in pre-order (the group, then each child's subtree) with
/// depths, parents and the claims under each group filled in; returns the
/// claims under `id`, sorted.
fn emit(
    out: &mut Vec<TreeNode>,
    id: Uuid,
    parent: Option<Uuid>,
    depth: u8,
    shape: &Shape,
) -> Vec<Uuid> {
    let pos = out.len();
    out.push(TreeNode {
        id,
        parent,
        depth,
        body: NodeBody::Leaf(Vec::new()),
        claims: Vec::new(),
    });
    let (body, claims) = match shape {
        Shape::Leaf(m) => (NodeBody::Leaf(m.clone()), m.clone()),
        Shape::Group(children) => {
            let mut ids = Vec::with_capacity(children.len());
            let mut claims = Vec::new();
            for (cid, child) in children {
                ids.push(*cid);
                claims.extend(emit(out, *cid, Some(id), depth + 1, child));
            }
            claims.sort_unstable();
            (NodeBody::Group(ids), claims)
        }
    };
    out[pos].body = body;
    out[pos].claims.clone_from(&claims);
    claims
}

/// A subtree before ids are laid out in pre-order.
enum Shape {
    Leaf(Vec<Uuid>),
    Group(Vec<(Uuid, Shape)>),
}

/// Check a result file's groups for one theme against the members the map
/// draws now, and return the tree.
///
/// Refused: not exactly one root at depth 0; an id that is not the minted one
/// (the root's from the theme, every other group's from its claims); a parent
/// or depth that does not chain; a group with fewer than two children (the
/// empty level) or more than [`MAX_CHILDREN`]; a level below [`MAX_DEPTH`];
/// a claim in two leaves; a leaf with no claim; a group no path from the root
/// reaches; and leaves that do not cover `members` exactly (drift since the
/// export, or another map's claims).
///
/// # Errors
/// Each refusal above, with the group it concerns.
pub fn check_tree(
    map: AtlasMap,
    hierarchy: AtlasHierarchy,
    theme_id: Uuid,
    groups: &[WireGroup],
    members: &BTreeSet<Uuid>,
) -> anyhow::Result<MeaningTree> {
    let mut by_id: BTreeMap<Uuid, &WireGroup> = BTreeMap::new();
    for g in groups {
        ensure!(
            by_id.insert(g.id, g).is_none(),
            "group {} appears twice",
            g.id
        );
    }
    let roots: Vec<&WireGroup> = groups.iter().filter(|g| g.parent.is_none()).collect();
    ensure!(
        roots.len() == 1 && roots[0].depth == 0,
        "theme {theme_id}: a tree has exactly one root, at depth 0"
    );
    let root = roots[0];
    ensure!(
        root.id == root_id(map, hierarchy, theme_id),
        "theme {theme_id}: the root id {} is not the minted one",
        root.id
    );

    let mut seen: BTreeSet<Uuid> = BTreeSet::new();
    let mut reached: BTreeSet<Uuid> = BTreeSet::new();
    let shape = check_node(&by_id, root, 0, &mut seen, &mut reached, &|claims| {
        group_id(map, hierarchy, theme_id, claims)
    })?
    .1;
    ensure!(
        reached.len() == by_id.len(),
        "theme {theme_id}: {} groups are not reachable from the root",
        by_id.len() - reached.len()
    );
    if &seen != members {
        let missing = members.difference(&seen).count();
        let extra = seen.difference(members).count();
        bail!(
            "theme {theme_id}: the leaves do not cover the members the map draws now \
             ({missing} missing, {extra} not members); export and compute again"
        );
    }
    let mut nodes = Vec::new();
    emit(&mut nodes, root.id, None, 0, &shape);
    Ok(MeaningTree {
        map,
        hierarchy,
        theme_id,
        nodes,
    })
}

fn check_node(
    by_id: &BTreeMap<Uuid, &WireGroup>,
    g: &WireGroup,
    depth: u8,
    seen: &mut BTreeSet<Uuid>,
    reached: &mut BTreeSet<Uuid>,
    mint: &dyn Fn(&BTreeSet<Uuid>) -> Uuid,
) -> anyhow::Result<(BTreeSet<Uuid>, Shape)> {
    ensure!(
        g.depth == depth,
        "group {} has depth {}, expected {depth}",
        g.id,
        g.depth
    );
    ensure!(
        depth <= MAX_DEPTH,
        "group {} is deeper than {MAX_DEPTH}",
        g.id
    );
    reached.insert(g.id);
    let (under, shape) = match (g.kind, &g.members, &g.children) {
        (WireKind::Leaf, Some(members), None) => {
            ensure!(!members.is_empty(), "leaf {} has no claim", g.id);
            let mut sorted: Vec<Uuid> = members.clone();
            sorted.sort_unstable();
            for c in &sorted {
                ensure!(seen.insert(*c), "claim {c} is in more than one leaf");
            }
            (sorted.iter().copied().collect(), Shape::Leaf(sorted))
        }
        (WireKind::Group, None, Some(children)) => {
            ensure!(
                (2..=MAX_CHILDREN).contains(&children.len()),
                "group {} has {} children (2 to {MAX_CHILDREN}: a group that fits is a leaf)",
                g.id,
                children.len()
            );
            let mut under = BTreeSet::new();
            let mut kids = Vec::with_capacity(children.len());
            for k in children {
                let child = by_id
                    .get(k)
                    .with_context(|| format!("child {k} of group {} is not in the tree", g.id))?;
                ensure!(
                    child.parent == Some(g.id),
                    "child {k} of group {} does not point back to it",
                    g.id
                );
                ensure!(!reached.contains(k), "group {k} is reached twice");
                let (c_under, c_shape) = check_node(by_id, child, depth + 1, seen, reached, mint)?;
                under.extend(c_under);
                kids.push((*k, c_shape));
            }
            (under, Shape::Group(kids))
        }
        _ => bail!(
            "group {} must be a leaf with members or a group with children",
            g.id
        ),
    };
    if g.parent.is_some() {
        ensure!(
            g.id == mint(&under),
            "group {} is not the id minted from its claims",
            g.id
        );
    }
    Ok((under, shape))
}

/// What the W3 re-check did to one tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResolveStats {
    pub leaves: usize,
    pub groups: usize,
    /// Leaves W3 found over the cap and split with its fallback split (their
    /// agents or evidence grew since the export).
    pub resplit_leaves: usize,
    /// The largest leaf, in W3's node count.
    pub max_leaf_nodes: usize,
}

/// Re-count every leaf with W3's [`assemble_leaf`] over `rows` (the theme's
/// leaf rows, read in the build's snapshot) and split one it finds over `cap`
/// with W3's [`fallback_split`]: the leaf becomes a group of fitting leaves,
/// each minted from its claims (a leaf that was the root keeps the root id).
///
/// # Errors
/// A leaf with no claim the map draws, a split that would go deeper than
/// [`MAX_DEPTH`] or make more than [`MAX_CHILDREN`] children, or a fallback
/// part that does not fit (W3 rules that out).
pub fn resolve_tree(
    tree: &MeaningTree,
    rows: &LeafRows,
    cap: usize,
) -> anyhow::Result<(MeaningTree, ResolveStats)> {
    let mut stats = ResolveStats::default();
    let root = tree.nodes.first().context("an empty tree")?;
    let shape = resolve_node(tree, root, rows, cap, &mut stats)?;
    let mut nodes = Vec::new();
    emit(&mut nodes, root.id, None, 0, &shape);
    stats.leaves = nodes
        .iter()
        .filter(|n| matches!(n.body, NodeBody::Leaf(_)))
        .count();
    stats.groups = nodes.len() - stats.leaves;
    ensure!(
        nodes.iter().all(|n| n.depth <= MAX_DEPTH),
        "theme {}: a re-split goes deeper than {MAX_DEPTH}",
        tree.theme_id
    );
    Ok((
        MeaningTree {
            nodes,
            ..tree.clone()
        },
        stats,
    ))
}

fn fits(rows: &LeafRows, part: &[Uuid], cap: usize) -> anyhow::Result<Option<usize>> {
    Ok(match assemble_leaf(rows, part, cap)? {
        LeafOutcome::Fits(set) => Some(set.counts.nodes),
        LeafOutcome::NeedsSplit(_) => None,
        LeafOutcome::Empty { .. } => bail!("a leaf holds no claim the map draws"),
    })
}

fn resolve_node(
    tree: &MeaningTree,
    node: &TreeNode,
    rows: &LeafRows,
    cap: usize,
    stats: &mut ResolveStats,
) -> anyhow::Result<Shape> {
    match &node.body {
        NodeBody::Group(children) => {
            let mut kids = Vec::with_capacity(children.len());
            for c in children {
                let child = tree.node(*c).context("a child missing from the tree")?;
                kids.push((*c, resolve_node(tree, child, rows, cap, stats)?));
            }
            Ok(Shape::Group(kids))
        }
        NodeBody::Leaf(members) => {
            if let Some(n) = fits(rows, members, cap)? {
                stats.max_leaf_nodes = stats.max_leaf_nodes.max(n);
                return Ok(Shape::Leaf(members.clone()));
            }
            stats.resplit_leaves += 1;
            let mut parts = fallback_split(rows, members, cap)?;
            ensure!(
                (2..=MAX_CHILDREN).contains(&parts.len()),
                "leaf {} split into {} parts",
                node.id,
                parts.len()
            );
            for p in &mut parts {
                p.sort_unstable();
            }
            parts.sort_by(|a, b| b.len().cmp(&a.len()).then(a[0].cmp(&b[0])));
            let mut kids = Vec::with_capacity(parts.len());
            for p in parts {
                let n = fits(rows, &p, cap)?.with_context(|| {
                    format!("a fallback part of leaf {} is over the cap", node.id)
                })?;
                stats.max_leaf_nodes = stats.max_leaf_nodes.max(n);
                let set: BTreeSet<Uuid> = p.iter().copied().collect();
                kids.push((
                    group_id(tree.map, tree.hierarchy, tree.theme_id, &set),
                    Shape::Leaf(p),
                ));
            }
            Ok(Shape::Group(kids))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_db::repos::atlas_leaf::{LeafNode, StoredLeafEdge};

    const TEAM: Uuid = Uuid::from_u128(0x5e5e_0000_0000_4000_8000_0000_0000_7ea0);
    const THEME: Uuid = Uuid::from_u128(0x3c88_6e23_925e_4966_b135_a7ef_81df_30a4);
    const MAP: AtlasMap = AtlasMap::Team(TEAM);
    const M: AtlasHierarchy = AtlasHierarchy::Meaning;

    fn c(n: u128) -> Uuid {
        Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0000 | n)
    }

    #[test]
    fn ids_match_the_golden_vector() {
        // The same vector is pinned in tests/theme/test_atlas_meaning_core.py.
        assert_eq!(
            NAMESPACE,
            Uuid::new_v5(&Uuid::NAMESPACE_URL, b"urn:epigraph:atlas-group:v1")
        );
        assert_eq!(
            root_id(MAP, M, THEME).to_string(),
            "c21ff8e0-db41-5755-8a4f-4324dacdf211"
        );
        assert_eq!(
            root_id(AtlasMap::Public, AtlasHierarchy::Links, THEME).to_string(),
            "ea9a52a2-1e97-58f5-b155-74a2713eb4a4"
        );
        let members: BTreeSet<Uuid> = [c(2), c(1)].into_iter().collect();
        assert_eq!(
            group_id(MAP, M, THEME, &members).to_string(),
            "e0e7d398-32de-5302-8400-0d33ba7b254a"
        );
    }

    #[test]
    fn map_keys_round_trip_and_refuse_other_spellings() {
        for m in [AtlasMap::Public, MAP] {
            assert_eq!(parse_map_key(&map_key(m)).unwrap(), m);
        }
        for bad in [
            "team",
            "team:",
            "TEAM:x",
            "group:5e5e0000-0000-4000-8000-000000007ea0",
        ] {
            assert!(parse_map_key(bad).is_err(), "{bad}");
        }
        assert!(parse_map_key("team:5E5E0000-0000-4000-8000-000000007EA0").is_err());
    }

    fn leaf(id: Uuid, parent: Option<Uuid>, depth: u8, members: &[Uuid]) -> WireGroup {
        WireGroup {
            id,
            parent,
            depth,
            kind: WireKind::Leaf,
            claim_count: members.len() as u32,
            weight: 0,
            members: Some(members.to_vec()),
            children: None,
        }
    }

    fn group(id: Uuid, parent: Option<Uuid>, depth: u8, children: &[Uuid]) -> WireGroup {
        WireGroup {
            id,
            parent,
            depth,
            kind: WireKind::Group,
            claim_count: 0,
            weight: 0,
            members: None,
            children: Some(children.to_vec()),
        }
    }

    fn set(ids: &[Uuid]) -> BTreeSet<Uuid> {
        ids.iter().copied().collect()
    }

    /// root -> {leaf a: 1, 2; leaf b: 3}.
    fn two_leaves() -> (Vec<WireGroup>, BTreeSet<Uuid>) {
        let root = root_id(MAP, M, THEME);
        let a = group_id(MAP, M, THEME, &set(&[c(1), c(2)]));
        let b = group_id(MAP, M, THEME, &set(&[c(3)]));
        (
            vec![
                group(root, None, 0, &[a, b]),
                leaf(a, Some(root), 1, &[c(2), c(1)]),
                leaf(b, Some(root), 1, &[c(3)]),
            ],
            set(&[c(1), c(2), c(3)]),
        )
    }

    #[test]
    fn a_well_formed_tree_is_accepted_in_pre_order() {
        let (groups, members) = two_leaves();
        let tree = check_tree(MAP, M, THEME, &groups, &members).unwrap();
        assert_eq!(tree.nodes.len(), 3);
        assert_eq!(tree.nodes[0].claims, vec![c(1), c(2), c(3)]);
        assert_eq!(tree.nodes[1].body, NodeBody::Leaf(vec![c(1), c(2)]));
        assert_eq!(tree.nodes[2].depth, 1);
    }

    #[test]
    fn check_tree_refuses_each_malformed_tree() {
        let (good, members) = two_leaves();
        let root = good[0].id;
        let mut cases: Vec<(&str, Vec<WireGroup>, BTreeSet<Uuid>)> = Vec::new();

        let mut g = good.clone();
        g[2].id = Uuid::from_u128(77);
        g[0].children = Some(vec![g[1].id, g[2].id]);
        cases.push(("not the id minted", g, members.clone()));

        let mut g = good.clone();
        g[0].id = Uuid::from_u128(78);
        cases.push(("root id", g, members.clone()));

        // The empty level: a theme that fits, under a root with one child.
        let whole = group_id(MAP, M, THEME, &members);
        cases.push((
            "children",
            vec![
                group(root, None, 0, &[whole]),
                leaf(whole, Some(root), 1, &[c(1), c(2), c(3)]),
            ],
            members.clone(),
        ));

        let mut g = good.clone();
        g[2].members = Some(vec![c(3), c(1)]);
        cases.push(("more than one leaf", g, members.clone()));

        let mut g = good.clone();
        g[2].depth = 2;
        cases.push(("depth", g, members.clone()));

        cases.push(("do not cover", good.clone(), set(&[c(1), c(2), c(3), c(4)])));
        cases.push(("do not cover", good.clone(), set(&[c(1), c(2)])));

        let mut g = good.clone();
        g[1].parent = None;
        cases.push(("exactly one root", g, members.clone()));

        for (want, groups, members) in cases {
            let err = check_tree(MAP, M, THEME, &groups, &members)
                .expect_err(want)
                .to_string();
            assert!(err.contains(want), "{want}: {err}");
        }
    }

    #[test]
    fn a_tree_for_another_map_or_hierarchy_is_refused() {
        let (groups, members) = two_leaves();
        assert!(check_tree(AtlasMap::Public, M, THEME, &groups, &members).is_err());
        assert!(check_tree(MAP, AtlasHierarchy::Links, THEME, &groups, &members).is_err());
    }

    /// `n` claims, each with `per_claim` evidence rows of its own, all filed by
    /// one agent.
    fn rows(n: u128, per_claim: u128) -> LeafRows {
        let mut rows = LeafRows::default();
        let agent = Uuid::from_u128(9_000);
        rows.agents.insert(agent);
        for i in 1..=n {
            rows.requested.insert(c(i));
            rows.claims.insert(c(i), Some(agent));
            for k in 0..per_claim {
                let ev = Uuid::from_u128(100_000 + i * 1_000 + k);
                rows.evidence.insert(ev, Some(c(i)));
                rows.edges.push(StoredLeafEdge {
                    id: Uuid::from_u128(500_000 + i * 1_000 + k),
                    source: LeafNode::evidence(ev),
                    target: LeafNode::claim(c(i)),
                    relationship: "supports".to_string(),
                });
            }
        }
        rows
    }

    #[test]
    fn a_leaf_w3_finds_over_the_cap_is_split_into_minted_leaves() {
        // 60 claims, one filer, two evidence each: 60 + 1 + 120 = 181 nodes,
        // which the result put in ONE root leaf.
        let rows = rows(60, 2);
        let members: BTreeSet<Uuid> = rows.claims.keys().copied().collect();
        let all: Vec<Uuid> = members.iter().copied().collect();
        let root = root_id(MAP, M, THEME);
        let tree = check_tree(MAP, M, THEME, &[leaf(root, None, 0, &all)], &members).unwrap();
        let (out, stats) = resolve_tree(&tree, &rows, 100).unwrap();
        assert_eq!(stats.resplit_leaves, 1);
        assert!(stats.leaves >= 2 && stats.max_leaf_nodes <= 100);
        assert_eq!(out.nodes[0].id, root, "the root keeps its id");
        assert!(matches!(out.nodes[0].body, NodeBody::Group(_)));
        let mut covered = Vec::new();
        for (node, m) in out.leaves() {
            assert_eq!(node.depth, 1);
            assert_eq!(node.id, group_id(MAP, M, THEME, &set(m)));
            match assemble_leaf(&rows, m, 100).unwrap() {
                LeafOutcome::Fits(s) => assert!(s.counts.nodes <= 100),
                other => panic!("{other:?}"),
            }
            covered.extend_from_slice(m);
        }
        covered.sort_unstable();
        assert_eq!(covered, all);
        // The resolved tree is itself a well-formed tree for the same members.
        let wire: Vec<WireGroup> = out
            .nodes
            .iter()
            .map(|n| match &n.body {
                NodeBody::Leaf(m) => leaf(n.id, n.parent, n.depth, m),
                NodeBody::Group(k) => group(n.id, n.parent, n.depth, k),
            })
            .collect();
        assert_eq!(check_tree(MAP, M, THEME, &wire, &members).unwrap(), out);
        // And resolving it again changes nothing.
        assert_eq!(resolve_tree(&out, &rows, 100).unwrap().0, out);
    }

    #[test]
    fn a_leaf_that_fits_is_left_alone() {
        let rows = rows(30, 1);
        let members: BTreeSet<Uuid> = rows.claims.keys().copied().collect();
        let all: Vec<Uuid> = members.iter().copied().collect();
        let root = root_id(MAP, M, THEME);
        let tree = check_tree(MAP, M, THEME, &[leaf(root, None, 0, &all)], &members).unwrap();
        let (out, stats) = resolve_tree(&tree, &rows, 100).unwrap();
        assert_eq!(out, tree);
        assert_eq!((stats.resplit_leaves, stats.max_leaf_nodes), (0, 61));
    }
}
