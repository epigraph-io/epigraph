//! The pure parts of the "by links" hierarchy (no database): which edges
//! count as links, which claims are linked, the W5b mirror rule checked on a
//! resolved tree, and each level's switch target in the meaning hierarchy.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context};
use epigraph_db::repos::atlas_leaf::{LeafNodeKind, LeafRows};
use uuid::Uuid;

use crate::atlas_meaning::tree::{MeaningTree, NodeBody};

/// The relationships that make a link (design 2026-11-12 §7): the epistemic
/// edges plus `decomposes_to`, so a paper's chain of reasoning holds
/// together. Compared lower-cased, so both stored spellings (`supports` and
/// `SUPPORTS`) count.
pub const COUNTED_RELATIONSHIPS: &[&str] = &[
    "supports",
    "refutes",
    "contradicts",
    "cites",
    "elaborates",
    "corroborates",
    "decomposes_to",
];

/// Whether an edge of relationship `rel` is a link.
#[must_use]
pub fn is_counted(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    COUNTED_RELATIONSHIPS.contains(&lower.as_str())
}

/// The links among `members`: every claim-to-claim edge of `rows` with a
/// counted relationship and two different ends that are both members, as
/// unordered pairs `(smaller, larger)`.
///
/// `rows` is W3's read ([`AtlasLeafRepository::read_leaf_rows`]), so every
/// edge in it already passed the MAP edge rule: public, or owned by the team
/// with no co-owner (ATLAS-R3b). A co-owned edge, another team's edge or a
/// retracted one is never in `rows` and so never a link here. Keeping the
/// read in one place means an edge hidden from a leaf cannot shape the
/// grouping.
///
/// [`AtlasLeafRepository::read_leaf_rows`]: epigraph_db::repos::atlas_leaf::AtlasLeafRepository::read_leaf_rows
#[must_use]
pub fn counted_links(rows: &LeafRows, members: &BTreeSet<Uuid>) -> BTreeSet<(Uuid, Uuid)> {
    rows.edges
        .iter()
        .filter(|e| e.source.kind == LeafNodeKind::Claim && e.target.kind == LeafNodeKind::Claim)
        .filter(|e| e.source.id != e.target.id)
        .filter(|e| members.contains(&e.source.id) && members.contains(&e.target.id))
        .filter(|e| is_counted(&e.relationship))
        .map(|e| {
            let (a, b) = (e.source.id, e.target.id);
            (a.min(b), a.max(b))
        })
        .collect()
}

/// The claims with at least one link.
#[must_use]
pub fn linked_claims(links: &BTreeSet<(Uuid, Uuid)>) -> BTreeSet<Uuid> {
    links.iter().flat_map(|&(a, b)| [a, b]).collect()
}

/// Each claim of a resolved meaning tree, by the leaf that holds it.
#[must_use]
pub fn meaning_leaf_of(tree: &MeaningTree) -> BTreeMap<Uuid, Uuid> {
    tree.leaves()
        .flat_map(|(node, members)| members.iter().map(move |c| (*c, node.id)))
        .collect()
}

/// The W5b rule on a RESOLVED links tree: every leaf holding an unlinked
/// claim (a member not in `linked`) holds exactly the unlinked claims of that
/// claim's meaning leaf (`meaning_leaf`, from the meaning tree resolved in
/// the same snapshot). The one exception is a theme that is a single root
/// leaf, where both hierarchies are that one leaf. Returns the number of
/// mirror leaves.
///
/// A mirror fits whenever its meaning leaf does (it is a subset of it, read
/// in the same snapshot), so W3's re-check never splits one. A root leaf W3
/// had to split, a link that appeared or vanished since the export, or a
/// meaning leaf W3 split since the export all fail here: export and compute
/// again.
///
/// # Errors
/// A member with no meaning leaf, or a leaf that breaks the rule.
pub fn check_mirrors(
    tree: &MeaningTree,
    linked: &BTreeSet<Uuid>,
    meaning_leaf: &BTreeMap<Uuid, Uuid>,
) -> anyhow::Result<usize> {
    if tree.nodes.len() == 1 {
        return Ok(0);
    }
    let mut want: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
    for c in &tree.nodes[0].claims {
        if linked.contains(c) {
            continue;
        }
        let m = meaning_leaf
            .get(c)
            .with_context(|| format!("claim {c} has no meaning leaf"))?;
        want.entry(*m).or_default().insert(*c);
    }
    let mut mirrors = 0;
    for (node, members) in tree.leaves() {
        let Some(u) = members.iter().find(|c| !linked.contains(c)) else {
            continue;
        };
        let expected = &want[&meaning_leaf[u]];
        let got: BTreeSet<Uuid> = members.iter().copied().collect();
        ensure!(
            &got == expected,
            "theme {}: links leaf {} holds unlinked claim {u} but is not the mirror of its \
             meaning leaf {} ({} claims, the mirror has {}); export and compute again",
            tree.theme_id,
            node.id,
            meaning_leaf[u],
            got.len(),
            expected.len()
        );
        mirrors += 1;
    }
    Ok(mirrors)
}

/// Each level's switch target in the meaning tree of the same theme: the
/// links root leads to the meaning root; any other level to the meaning group
/// with the largest Jaccard overlap of claims, ties to the deeper group, then
/// the smaller id. (Plain largest overlap would always pick the meaning root,
/// which holds every claim.)
///
/// # Errors
/// A claim of the links tree that the meaning tree does not hold.
pub fn switch_targets(
    links: &MeaningTree,
    meaning: &MeaningTree,
) -> anyhow::Result<BTreeMap<Uuid, Uuid>> {
    let parent: BTreeMap<Uuid, Option<Uuid>> =
        meaning.nodes.iter().map(|n| (n.id, n.parent)).collect();
    let info: BTreeMap<Uuid, (usize, u8)> = meaning
        .nodes
        .iter()
        .map(|n| (n.id, (n.claims.len(), n.depth)))
        .collect();
    // Each claim's meaning leaf and every group above it.
    let mut chain: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
    for (node, members) in meaning.leaves() {
        let mut up = Vec::new();
        let mut at = Some(node.id);
        while let Some(id) = at {
            up.push(id);
            at = parent[&id];
        }
        for c in members {
            chain.insert(*c, up.clone());
        }
    }
    let root = meaning.nodes.first().context("an empty meaning tree")?.id;
    let mut out = BTreeMap::new();
    for node in &links.nodes {
        if node.parent.is_none() {
            out.insert(node.id, root);
            continue;
        }
        let mut overlap: BTreeMap<Uuid, usize> = BTreeMap::new();
        for c in &node.claims {
            let up = chain
                .get(c)
                .with_context(|| format!("claim {c} is in no meaning leaf"))?;
            for g in up {
                *overlap.entry(*g).or_default() += 1;
            }
        }
        let a = node.claims.len();
        let mut best: Option<(Uuid, usize, usize, u8)> = None;
        for (g, inter) in overlap {
            let (b, depth) = info[&g];
            let union = a + b - inter;
            let better = match best {
                None => true,
                Some((bg, bi, bu, bd)) => {
                    // inter/union against bi/bu, exactly.
                    let lhs = inter * bu;
                    let rhs = bi * union;
                    lhs > rhs || (lhs == rhs && (depth > bd || (depth == bd && g < bg)))
                }
            };
            if better {
                best = Some((g, inter, union, depth));
            }
        }
        out.insert(node.id, best.context("a links level with no claim")?.0);
    }
    Ok(out)
}

/// The number of leaves of `tree`.
#[must_use]
pub fn leaf_count(tree: &MeaningTree) -> usize {
    tree.nodes
        .iter()
        .filter(|n| matches!(n.body, NodeBody::Leaf(_)))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas_meaning::tree::{check_tree, group_id, root_id, WireGroup, WireKind};
    use epigraph_db::repos::atlas_leaf::{LeafNode, StoredLeafEdge};
    use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap};

    const TEAM: Uuid = Uuid::from_u128(0x5e5e_0000_0000_4000_8000_0000_0000_7ea0);
    const THEME: Uuid = Uuid::from_u128(0x3c88_6e23_925e_4966_b135_a7ef_81df_30a4);
    const MAP: AtlasMap = AtlasMap::Team(TEAM);
    const L: AtlasHierarchy = AtlasHierarchy::Links;
    const M: AtlasHierarchy = AtlasHierarchy::Meaning;

    fn c(n: u128) -> Uuid {
        Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0000 | n)
    }

    fn set(ids: &[Uuid]) -> BTreeSet<Uuid> {
        ids.iter().copied().collect()
    }

    #[test]
    fn links_ids_match_the_golden_vector() {
        // The same vectors are pinned in tests/theme/test_atlas_links_core.py.
        assert_eq!(
            root_id(MAP, L, THEME).to_string(),
            "a3f580a9-6493-540c-a047-19edb935e318"
        );
        assert_eq!(
            group_id(MAP, L, THEME, &set(&[c(2), c(1)])).to_string(),
            "3d72648d-1698-5960-8c99-42f5afd56350"
        );
    }

    fn edge(n: u128, s: LeafNode, t: LeafNode, rel: &str) -> StoredLeafEdge {
        StoredLeafEdge {
            id: Uuid::from_u128(900_000 + n),
            source: s,
            target: t,
            relationship: rel.to_string(),
        }
    }

    /// Only claim-to-claim edges between two different members with a counted
    /// relationship, in either spelling, are links, each pair once.
    #[test]
    fn only_counted_claim_links_between_members_count() {
        let mut rows = LeafRows::default();
        for i in 1..=5 {
            rows.claims.insert(c(i), None);
        }
        let ev = Uuid::from_u128(77);
        let agent = Uuid::from_u128(78);
        rows.edges = vec![
            edge(1, LeafNode::claim(c(1)), LeafNode::claim(c(2)), "supports"),
            edge(2, LeafNode::claim(c(2)), LeafNode::claim(c(1)), "SUPPORTS"),
            edge(
                3,
                LeafNode::claim(c(3)),
                LeafNode::claim(c(2)),
                "DECOMPOSES_TO",
            ),
            edge(4, LeafNode::claim(c(4)), LeafNode::claim(c(4)), "cites"),
            edge(5, LeafNode::claim(c(4)), LeafNode::claim(c(5)), "same_as"),
            edge(6, LeafNode::evidence(ev), LeafNode::claim(c(5)), "supports"),
            edge(7, LeafNode::agent(agent), LeafNode::claim(c(4)), "asserts"),
            edge(8, LeafNode::claim(c(5)), LeafNode::claim(c(9)), "refutes"),
        ];
        let links = counted_links(&rows, &set(&[c(1), c(2), c(3), c(4), c(5)]));
        assert_eq!(links, [(c(1), c(2)), (c(2), c(3))].into_iter().collect());
        assert_eq!(linked_claims(&links), set(&[c(1), c(2), c(3)]));
        for rel in COUNTED_RELATIONSHIPS {
            assert!(is_counted(rel) && is_counted(&rel.to_ascii_uppercase()));
        }
        assert!(!is_counted("same_as") && !is_counted("asserts"));
    }

    fn leaf(id: Uuid, parent: Option<Uuid>, depth: u8, members: &[Uuid]) -> WireGroup {
        WireGroup {
            id,
            parent,
            depth,
            kind: WireKind::Leaf,
            claim_count: 0,
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

    /// A flat tree in hierarchy `h`: the root over leaves `parts`.
    fn flat(h: AtlasHierarchy, parts: &[&[Uuid]]) -> MeaningTree {
        let root = root_id(MAP, h, THEME);
        let mut groups = vec![group(
            root,
            None,
            0,
            &parts
                .iter()
                .map(|p| group_id(MAP, h, THEME, &set(p)))
                .collect::<Vec<_>>(),
        )];
        let mut all = Vec::new();
        for p in parts {
            groups.push(leaf(group_id(MAP, h, THEME, &set(p)), Some(root), 1, p));
            all.extend_from_slice(p);
        }
        check_tree(MAP, h, THEME, &groups, &set(&all)).unwrap()
    }

    /// Meaning: {1,2,3,4} {5,6,7} {8,9}. Linked: 1, 2, 5, 6.
    fn meaning() -> MeaningTree {
        flat(
            M,
            &[
                &[c(1), c(2), c(3), c(4)],
                &[c(5), c(6), c(7)],
                &[c(8), c(9)],
            ],
        )
    }

    #[test]
    fn mirrors_hold_exactly_their_meaning_leafs_unlinked_claims() {
        let linked = set(&[c(1), c(2), c(5), c(6)]);
        let m = meaning_leaf_of(&meaning());
        let good = flat(
            L,
            &[
                &[c(1), c(2), c(5), c(6)],
                &[c(3), c(4)],
                &[c(7)],
                &[c(8), c(9)],
            ],
        );
        assert_eq!(check_mirrors(&good, &linked, &m).unwrap(), 3);

        let bad: Vec<(&str, MeaningTree)> = vec![
            // Two meaning leaves' unlinked claims in one leaf.
            (
                "merged",
                flat(
                    L,
                    &[
                        &[c(1), c(2), c(5), c(6)],
                        &[c(3), c(4), c(7)],
                        &[c(8), c(9)],
                    ],
                ),
            ),
            // An unlinked claim beside linked ones.
            (
                "with linked",
                flat(
                    L,
                    &[
                        &[c(1), c(2), c(5), c(6), c(7)],
                        &[c(3), c(4)],
                        &[c(8), c(9)],
                    ],
                ),
            ),
            // One meaning leaf's unlinked claims cut in two.
            (
                "cut",
                flat(
                    L,
                    &[
                        &[c(1), c(2), c(5), c(6)],
                        &[c(3)],
                        &[c(4)],
                        &[c(7)],
                        &[c(8), c(9)],
                    ],
                ),
            ),
        ];
        for (why, tree) in bad {
            let err = check_mirrors(&tree, &linked, &m)
                .expect_err(why)
                .to_string();
            assert!(err.contains("not the mirror"), "{why}: {err}");
        }
        // A claim the meaning tree does not hold is refused, not skipped.
        let mut short = m.clone();
        short.remove(&c(8));
        assert!(check_mirrors(&good, &linked, &short).is_err());
    }

    #[test]
    fn a_single_root_leaf_needs_no_mirror() {
        let all = [c(1), c(2), c(3)];
        let root = root_id(MAP, L, THEME);
        let tree = check_tree(MAP, L, THEME, &[leaf(root, None, 0, &all)], &set(&all)).unwrap();
        let m: BTreeMap<Uuid, Uuid> = all.iter().map(|x| (*x, Uuid::from_u128(5))).collect();
        assert_eq!(check_mirrors(&tree, &set(&[c(1), c(2)]), &m).unwrap(), 0);
    }

    #[test]
    fn switch_targets_pick_the_best_jaccard_meaning_group() {
        // Meaning: root -> {g: {a: 1..=4, b: 5..=6}, d: 7..=9}.
        let mroot = root_id(MAP, M, THEME);
        let a = group_id(MAP, M, THEME, &set(&[c(1), c(2), c(3), c(4)]));
        let b = group_id(MAP, M, THEME, &set(&[c(5), c(6)]));
        let g = group_id(MAP, M, THEME, &(1..=6).map(c).collect());
        let d = group_id(MAP, M, THEME, &set(&[c(7), c(8), c(9)]));
        let meaning = check_tree(
            MAP,
            M,
            THEME,
            &[
                group(mroot, None, 0, &[g, d]),
                group(g, Some(mroot), 1, &[a, b]),
                leaf(a, Some(g), 2, &[c(1), c(2), c(3), c(4)]),
                leaf(b, Some(g), 2, &[c(5), c(6)]),
                leaf(d, Some(mroot), 1, &[c(7), c(8), c(9)]),
            ],
            &(1..=9).map(c).collect(),
        )
        .unwrap();
        // Links: {1,2,3} -> a (3/4); {4,5,6} -> b (2/4) ties g (3/6)? 2/4 = 3/6:
        // the deeper b wins; {7,8,9} -> d (exact).
        let links = flat(
            L,
            &[
                &[c(1), c(2), c(3)],
                &[c(4), c(5), c(6)],
                &[c(7), c(8), c(9)],
            ],
        );
        let s = switch_targets(&links, &meaning).unwrap();
        assert_eq!(
            s[&links.nodes[0].id], mroot,
            "the root leads to the meaning root"
        );
        let by_members = |m: &[Uuid]| s[&group_id(MAP, L, THEME, &set(m))];
        assert_eq!(by_members(&[c(1), c(2), c(3)]), a);
        assert_eq!(by_members(&[c(4), c(5), c(6)]), b);
        assert_eq!(by_members(&[c(7), c(8), c(9)]), d);
    }
}
