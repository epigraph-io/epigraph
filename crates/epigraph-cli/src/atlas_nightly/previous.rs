//! The previous run's trees, rebuilt from its stored level rows (pure: no
//! database). Each row carries its group id, parent and depth; a group
//! document lists its children in display order and a leaf document its claim
//! nodes. That is everything the incremental update needs, so the nightly
//! keeps no tree of its own (W4: "membership needs no migration").

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context};
use epigraph_db::repos::atlas_map::AtlasHierarchy;
use epigraph_db::repos::atlas_naming::RunLevel;
use uuid::Uuid;

/// One group of a previous tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrevBody {
    /// A leaf's claims, sorted.
    Leaf(Vec<Uuid>),
    /// A group's child ids, in display order.
    Group(Vec<Uuid>),
}

/// The tree one hierarchy of one theme had in the previous run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrevTree {
    pub root: Uuid,
    pub nodes: BTreeMap<Uuid, PrevBody>,
}

impl PrevTree {
    /// Whether the root is itself a leaf (a theme that fit one leaf).
    #[must_use]
    pub fn root_is_leaf(&self) -> bool {
        matches!(self.nodes.get(&self.root), Some(PrevBody::Leaf(_)))
    }

    /// The claims of the leaves among `leaves` (ids of any level; the ones
    /// this tree does not hold as leaves are ignored).
    #[must_use]
    pub fn claims_of_leaves(&self, leaves: &BTreeSet<Uuid>) -> BTreeSet<Uuid> {
        leaves
            .iter()
            .filter_map(|id| match self.nodes.get(id) {
                Some(PrevBody::Leaf(c)) => Some(c.iter().copied()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// This tree with `drop` taken out of every leaf (a leaf may be left
    /// empty; the incremental update drops it), or `None` when no claim is
    /// left: a theme whose previous tree held only those claims has no
    /// previous tree to update.
    #[must_use]
    pub fn without_claims(&self, drop: &BTreeSet<Uuid>) -> Option<Self> {
        let nodes: BTreeMap<Uuid, PrevBody> = self
            .nodes
            .iter()
            .map(|(id, b)| {
                let b = match b {
                    PrevBody::Leaf(c) => {
                        PrevBody::Leaf(c.iter().filter(|x| !drop.contains(x)).copied().collect())
                    }
                    PrevBody::Group(k) => PrevBody::Group(k.clone()),
                };
                (*id, b)
            })
            .collect();
        let out = Self {
            root: self.root,
            nodes,
        };
        (!out.claims().is_empty()).then_some(out)
    }

    /// Every claim of every leaf.
    #[must_use]
    pub fn claims(&self) -> BTreeSet<Uuid> {
        self.nodes
            .values()
            .filter_map(|b| match b {
                PrevBody::Leaf(c) => Some(c.iter().copied()),
                PrevBody::Group(_) => None,
            })
            .flatten()
            .collect()
    }
}

/// The stored hierarchy spelling.
///
/// # Errors
/// Anything but `meaning` or `links`.
pub fn parse_hierarchy(s: &str) -> anyhow::Result<AtlasHierarchy> {
    match s {
        "meaning" => Ok(AtlasHierarchy::Meaning),
        "links" => Ok(AtlasHierarchy::Links),
        other => bail!("unknown hierarchy {other:?}"),
    }
}

/// The previous run's levels grouped by theme, then hierarchy.
#[must_use]
pub fn by_theme(levels: &[RunLevel]) -> BTreeMap<Uuid, Vec<&RunLevel>> {
    let mut out: BTreeMap<Uuid, Vec<&RunLevel>> = BTreeMap::new();
    for l in levels {
        out.entry(l.theme_id).or_default().push(l);
    }
    out
}

/// The tree of `hierarchy` among `rows` (one theme's stored levels), `None`
/// when the run has no level of that hierarchy for the theme.
///
/// # Errors
/// Not exactly one root, a group whose child has no row, a child pointing at
/// another parent, a payload that is neither a group nor a leaf, or a level
/// no path from the root reaches.
pub fn prev_tree(
    rows: &[&RunLevel],
    hierarchy: AtlasHierarchy,
) -> anyhow::Result<Option<PrevTree>> {
    let rows: Vec<&&RunLevel> = rows
        .iter()
        .filter(|r| r.hierarchy == hierarchy.as_str())
        .collect();
    if rows.is_empty() {
        return Ok(None);
    }
    let parent: BTreeMap<Uuid, Option<Uuid>> = rows
        .iter()
        .map(|r| (r.group_id, r.parent_group_id))
        .collect();
    ensure!(parent.len() == rows.len(), "a level is stored twice");
    let roots: Vec<Uuid> = rows
        .iter()
        .filter(|r| r.parent_group_id.is_none())
        .map(|r| r.group_id)
        .collect();
    ensure!(
        roots.len() == 1,
        "{} {} roots in one theme",
        roots.len(),
        hierarchy.as_str()
    );
    let mut nodes = BTreeMap::new();
    for r in &rows {
        let body = match r.payload.get("kind").and_then(|k| k.as_str()) {
            Some("group") => {
                let children = r
                    .payload
                    .get("children")
                    .and_then(|c| c.as_array())
                    .context("a group level with no children array")?
                    .iter()
                    .map(|c| {
                        c.get("id")
                            .and_then(|i| i.as_str())
                            .and_then(|i| Uuid::parse_str(i).ok())
                            .context("a child with no id")
                    })
                    .collect::<anyhow::Result<Vec<Uuid>>>()?;
                for c in &children {
                    ensure!(
                        parent.get(c) == Some(&Some(r.group_id)),
                        "child {c} of {} has no row under it",
                        r.group_id
                    );
                }
                PrevBody::Group(children)
            }
            Some("leaf") => {
                let mut claims = r
                    .payload
                    .get("nodes")
                    .and_then(|n| n.as_array())
                    .context("a leaf level with no nodes array")?
                    .iter()
                    .filter(|n| n.get("kind").and_then(|k| k.as_str()) == Some("claim"))
                    .map(|n| {
                        n.get("id")
                            .and_then(|i| i.as_str())
                            .and_then(|i| Uuid::parse_str(i).ok())
                            .context("a claim node with no id")
                    })
                    .collect::<anyhow::Result<Vec<Uuid>>>()?;
                claims.sort_unstable();
                PrevBody::Leaf(claims)
            }
            other => bail!("level {} has kind {other:?}", r.group_id),
        };
        nodes.insert(r.group_id, body);
    }
    // Every row reachable from the root.
    let mut seen = BTreeSet::new();
    let mut stack = vec![roots[0]];
    while let Some(id) = stack.pop() {
        ensure!(seen.insert(id), "level {id} is reached twice");
        if let Some(PrevBody::Group(children)) = nodes.get(&id) {
            stack.extend(children.iter().copied());
        }
    }
    ensure!(
        seen.len() == nodes.len(),
        "{} levels are not reachable from the root",
        nodes.len() - seen.len()
    );
    Ok(Some(PrevTree {
        root: roots[0],
        nodes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn row(h: &str, gid: u128, parent: Option<u128>, payload: serde_json::Value) -> RunLevel {
        RunLevel {
            hierarchy: h.to_string(),
            group_id: id(gid),
            parent_group_id: parent.map(id),
            theme_id: id(99),
            level: 0,
            schema_version: 1,
            payload,
        }
    }

    fn group(children: &[u128]) -> serde_json::Value {
        json!({"kind": "group", "children": children.iter().map(|c| json!({"id": id(*c)})).collect::<Vec<_>>()})
    }

    fn leaf(claims: &[u128]) -> serde_json::Value {
        let mut nodes: Vec<serde_json::Value> = claims
            .iter()
            .map(|c| json!({"kind": "claim", "id": id(*c)}))
            .collect();
        nodes.push(json!({"kind": "agent", "id": id(7777)}));
        json!({"kind": "leaf", "nodes": nodes})
    }

    #[test]
    fn a_stored_tree_is_rebuilt_with_its_child_order_and_claim_nodes_only() {
        let rows = [
            row("meaning", 1, None, group(&[3, 2])),
            row("meaning", 2, Some(1), leaf(&[12, 11])),
            row("meaning", 3, Some(1), leaf(&[13])),
            row("links", 5, None, leaf(&[11, 12, 13])),
        ];
        let refs: Vec<&RunLevel> = rows.iter().collect();
        let t = prev_tree(&refs, AtlasHierarchy::Meaning).unwrap().unwrap();
        assert_eq!(t.root, id(1));
        assert_eq!(t.nodes[&id(1)], PrevBody::Group(vec![id(3), id(2)]));
        assert_eq!(t.nodes[&id(2)], PrevBody::Leaf(vec![id(11), id(12)]));
        assert!(!t.root_is_leaf());
        let l = prev_tree(&refs, AtlasHierarchy::Links).unwrap().unwrap();
        assert!(l.root_is_leaf());
        assert_eq!(l.claims().len(), 3);
    }

    #[test]
    fn recorded_leaves_are_emptied_and_a_tree_left_with_no_claim_is_none() {
        let rows = [
            row("meaning", 1, None, group(&[3, 2])),
            row("meaning", 2, Some(1), leaf(&[12, 11])),
            row("meaning", 3, Some(1), leaf(&[13])),
        ];
        let refs: Vec<&RunLevel> = rows.iter().collect();
        let t = prev_tree(&refs, AtlasHierarchy::Meaning).unwrap().unwrap();
        let rec: BTreeSet<Uuid> = [id(3), id(1), id(42)].into_iter().collect();
        let gone = t.claims_of_leaves(&rec);
        assert_eq!(gone, [id(13)].into_iter().collect());
        let kept = t.without_claims(&gone).unwrap();
        assert_eq!(kept.nodes[&id(3)], PrevBody::Leaf(Vec::new()));
        assert_eq!(kept.nodes[&id(2)], t.nodes[&id(2)]);
        assert_eq!(kept.claims(), [id(11), id(12)].into_iter().collect());
        assert!(t.without_claims(&t.claims()).is_none());
    }

    #[test]
    fn a_tree_with_an_orphan_or_a_missing_child_is_refused() {
        let orphan = [
            row("meaning", 1, None, leaf(&[11])),
            row("meaning", 2, Some(1), leaf(&[12])),
        ];
        let refs: Vec<&RunLevel> = orphan.iter().collect();
        assert!(prev_tree(&refs, AtlasHierarchy::Meaning).is_err());
        let missing = [
            row("meaning", 1, None, group(&[2, 3])),
            row("meaning", 2, Some(1), leaf(&[12])),
        ];
        let refs: Vec<&RunLevel> = missing.iter().collect();
        assert!(prev_tree(&refs, AtlasHierarchy::Meaning).is_err());
        let refs: Vec<&RunLevel> = Vec::new();
        assert!(prev_tree(&refs, AtlasHierarchy::Links).unwrap().is_none());
    }
}
