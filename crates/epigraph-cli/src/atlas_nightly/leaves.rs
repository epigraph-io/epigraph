//! The REAL leaf documents (Atlas W9): W4 and W5 store skeleton leaves
//! (claim nodes only, placeholder positions). The nightly turns each into the
//! leaf the contract describes: W3's node set (`assemble_leaf`: the claims,
//! the agents that asserted or authored them, the evidence a stored edge
//! links to them) with W7's weighted edges (`weigh_leaf_edges`), labelled
//! from map-scoped reads. Positions stay for W6's fill and names for W8's.
//!
//! A leaf whose weighted edges exceed the contract's
//! [`MAX_LEAF_EDGES`] keeps its heaviest ones and reports the cut
//! ([`cap_leaf_edges`]), as the cross-group link caps do. W3 splits a leaf of
//! two or more claims on edges, so in practice only a leaf of ONE claim,
//! whose own agents and evidence carry more edges among them than the
//! contract allows, reaches the cap (backlog 8d09e6bc: such a claim used to
//! fail its theme on every night).
//!
//! A stored relationship name outside the contract's pattern (`edges` takes
//! any non-empty name, e.g. `has-part`) is served mapped to a contract name
//! and the mapping is reported ([`contract_edges`]); one such edge used to
//! fail its whole theme on every night (backlog 9de2ebad).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context};
use epigraph_atlas_contract::{
    is_relationship_name, ClaimNode, Edge, LeafLevel, Node, NodeKind, PlainNode, MAX_LEAF_EDGES,
    MAX_RELATIONSHIP_CHARS,
};
use epigraph_db::repos::atlas_flow::FlowInputs;
use epigraph_db::repos::atlas_leaf::{
    assemble_leaf, LeafNodeKind, LeafNodeSet, LeafOutcome, LeafRows,
};
use epigraph_engine::atlas_flow::weigh_leaf_edges;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::atlas_meaning::docs::claim_label;

/// The label of an agent with no display name.
#[must_use]
pub fn agent_fallback(id: Uuid) -> String {
    format!("Agent {}", &id.simple().to_string()[..8])
}

/// The label of an evidence row the label read did not return.
pub const EVIDENCE_FALLBACK: &str = "Evidence";

/// The claim ids of a leaf document.
#[must_use]
pub fn leaf_claims(leaf: &LeafLevel) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = leaf
        .nodes
        .iter()
        .filter_map(|n| match n {
            Node::Claim(c) => Some(c.id),
            Node::Agent(_) | Node::Evidence(_) => None,
        })
        .collect();
    out.sort_unstable();
    out
}

/// W3's node set of `claims` over `rows` (the theme's rows read in the
/// build's snapshot).
///
/// # Errors
/// A set W3 finds over `cap` or empty (the tree was resolved against the
/// same rows, so neither should happen), or W3's refusal of the cap.
pub fn node_set(rows: &LeafRows, claims: &[Uuid], cap: usize) -> anyhow::Result<LeafNodeSet> {
    match assemble_leaf(rows, claims, cap)? {
        LeafOutcome::Fits(set) => Ok(set),
        LeafOutcome::NeedsSplit(n) => bail!(
            "a resolved leaf of {} claims is over the cap ({} nodes)",
            claims.len(),
            n.counts.nodes
        ),
        LeafOutcome::Empty { .. } => bail!("a resolved leaf holds no claim the map draws"),
    }
}

/// Fill `leaf` (a skeleton: claim nodes only) with the real nodes and edges
/// of `set`. Claim labels are the skeleton's (W4's, from the map-scoped claim
/// read); agent and evidence labels come from `agents` and `evidence`
/// (`AtlasLeafRepository::node_labels`), with a fallback so none is empty,
/// whitespace-collapsed and clipped to the contract's label length. The
/// edges are W7's, weighed from `inputs`. Positions are left at 0 for W6.
///
/// Each claim's `truth_value` is its stored one from `truths`
/// (`AtlasMeaningRepository::claim_truth_values`, read under the map's
/// predicate): the colour value only, as at the region and theme levels. It
/// is never an input to a flow weight (the edges above are weighed before and
/// without it). A claim `truths` does not hold, or a value outside [0, 1],
/// carries none.
///
/// Each edge's relationship is served as a contract name
/// ([`contract_edges`]), then the edges are capped at the contract's
/// [`MAX_LEAF_EDGES`] ([`cap_leaf_edges`]). The names mapped and the number
/// cut are returned (none for almost every leaf).
///
/// # Errors
/// A claim of `set` the skeleton does not label.
pub fn fill_leaf(
    leaf: &mut LeafLevel,
    set: &LeafNodeSet,
    inputs: &FlowInputs,
    agents: &BTreeMap<Uuid, String>,
    evidence: &BTreeMap<Uuid, String>,
    truths: &BTreeMap<Uuid, f64>,
) -> anyhow::Result<LeafFill> {
    let claim_labels: BTreeMap<Uuid, String> = leaf
        .nodes
        .iter()
        .filter_map(|n| match n {
            Node::Claim(c) => Some((c.id, c.label.clone())),
            Node::Agent(_) | Node::Evidence(_) => None,
        })
        .collect();
    let mut nodes = Vec::with_capacity(set.nodes.len());
    for n in &set.nodes {
        nodes.push(match n.kind {
            LeafNodeKind::Claim => Node::Claim(ClaimNode {
                id: n.id,
                label: claim_labels
                    .get(&n.id)
                    .cloned()
                    .with_context(|| format!("claim {} has no label in the skeleton", n.id))?,
                x: 0.0,
                y: 0.0,
                truth_value: truths
                    .get(&n.id)
                    .copied()
                    .filter(|t| (0.0..=1.0).contains(t)),
            }),
            LeafNodeKind::Agent => Node::Agent(PlainNode {
                id: n.id,
                label: agents
                    .get(&n.id)
                    .map_or_else(|| agent_fallback(n.id), |s| claim_label(s)),
                x: 0.0,
                y: 0.0,
            }),
            LeafNodeKind::Evidence => Node::Evidence(PlainNode {
                id: n.id,
                label: evidence
                    .get(&n.id)
                    .map_or_else(|| EVIDENCE_FALLBACK.to_string(), |s| claim_label(s)),
                x: 0.0,
                y: 0.0,
            }),
        });
    }
    let (named, renamed) = contract_edges(weigh_leaf_edges(set, inputs));
    let (edges, cut) = cap_leaf_edges(&nodes, named, MAX_LEAF_EDGES);
    leaf.nodes = nodes;
    leaf.edges = edges;
    Ok(LeafFill { cut, renamed })
}

/// What [`fill_leaf`] changed from the weighted edges to make the leaf fit
/// the contract.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LeafFill {
    /// The edges the contract's edge limit cut ([`cap_leaf_edges`]).
    pub cut: usize,
    /// The relationship names served mapped ([`contract_edges`]).
    pub renamed: RenamedNames,
}

/// The relationship names a leaf (or a theme's leaves) serves mapped to a
/// contract name ([`contract_relationship_name`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RenamedNames {
    /// The weighted edges whose name was mapped, counted before two mapped
    /// to one edge collapse.
    pub edges: usize,
    /// Each stored name (lower-cased, as the builder serves names) and the
    /// contract name it is served as.
    pub names: BTreeMap<String, String>,
}

impl RenamedNames {
    pub fn add(&mut self, other: Self) {
        self.edges += other.edges;
        self.names.extend(other.names);
    }

    /// The report: `{"renamed_edges": n, "names": {stored: served}}`.
    #[must_use]
    pub fn json(&self) -> Value {
        json!({"renamed_edges": self.edges, "names": self.names})
    }
}

/// The contract name a stored relationship name is served as: the name
/// itself when the contract's pattern admits it; otherwise every character
/// outside `[A-Za-z0-9_]` becomes `_`, `r_` is prefixed when the result does
/// not start with a letter, and it is cut to [`MAX_RELATIONSHIP_CHARS`]. So
/// `has-part` is `has_part`, `2nd-order` is `r_2nd_order`.
///
/// Two stored names can map to one (`has-part` and `has_part`); the caller
/// collapses such edges as the builder collapses two spellings of one name.
#[must_use]
pub fn contract_relationship_name(stored: &str) -> String {
    if is_relationship_name(stored) {
        return stored.to_string();
    }
    let mut out: String = stored
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if !out.starts_with(|c: char| c.is_ascii_alphabetic()) {
        out.insert_str(0, "r_");
    }
    // ASCII only by now, so a byte cut is a character cut.
    out.truncate(MAX_RELATIONSHIP_CHARS);
    out
}

/// `edges` (W7's weighted edges of one leaf) with every relationship served
/// as a contract name ([`contract_relationship_name`]), and what was mapped.
///
/// The edges `edges` holds under one (source, target, mapped name) collapse
/// into one with the largest `flow_weight`, the first of them on a tie, as
/// `weigh_leaf_edges` collapses the stored rows of one name (the contract
/// refuses a duplicate triple). The result is ordered by (source, target,
/// name), the order `weigh_leaf_edges` returns, so a leaf whose names all
/// fit is returned unchanged and a night over unchanged input writes
/// nothing.
///
/// The nightly's builder and its carry check both read edges through this,
/// so a carried leaf is compared with the names it was served under.
#[must_use]
pub fn contract_edges(edges: Vec<Edge>) -> (Vec<Edge>, RenamedNames) {
    let mut renamed = RenamedNames::default();
    let mut out: BTreeMap<(Uuid, Uuid, String), Edge> = BTreeMap::new();
    for mut e in edges {
        let name = contract_relationship_name(&e.relationship);
        if name != e.relationship {
            renamed.edges += 1;
            renamed.names.insert(e.relationship.clone(), name.clone());
            e.relationship = name;
        }
        let key = (e.source, e.target, e.relationship.to_ascii_lowercase());
        match out.get_mut(&key) {
            Some(prev) if prev.flow_weight >= e.flow_weight => {}
            Some(prev) => *prev = e,
            None => {
                out.insert(key, e);
            }
        }
    }
    (out.into_values().collect(), renamed)
}

/// The edges of a leaf over `max`: its heaviest `max`, in their input order,
/// and how many were cut (0, and `edges` unchanged, when they fit).
///
/// The contract wants every agent and evidence node to keep an edge to a
/// claim, so the cut never orphans one: first each such node keeps its
/// heaviest edge to a claim (a leaf holds at most
/// [`epigraph_atlas_contract::MAX_LEAF_NODES`] nodes, so these always fit),
/// then the rest are kept by `flow_weight`, an edge at a claim before one
/// between two attachments, ties to the smaller (source, target,
/// relationship). The order is total, so the same input always keeps the same
/// edges (a night over unchanged input writes nothing).
///
/// Whatever is cut stays out of the served leaf only: the claim keeps every
/// one of its agents and evidence nodes. (A `max` below the number of agent
/// and evidence nodes still keeps one edge for each, so the result is over
/// `max` then; the nightly passes [`MAX_LEAF_EDGES`], far above any leaf's
/// node count.)
#[must_use]
pub fn cap_leaf_edges(nodes: &[Node], edges: Vec<Edge>, max: usize) -> (Vec<Edge>, usize) {
    if edges.len() <= max {
        return (edges, 0);
    }
    let kinds: BTreeMap<Uuid, NodeKind> = nodes.iter().map(|n| (n.id(), n.kind())).collect();
    let is_claim = |id: &Uuid| kinds.get(id) == Some(&NodeKind::Claim);
    let at_claim = |e: &Edge| is_claim(&e.source) || is_claim(&e.target);
    // Heaviest first; at a claim before not; then the smaller key.
    let rank = |a: &Edge, b: &Edge| {
        b.flow_weight
            .total_cmp(&a.flow_weight)
            .then_with(|| at_claim(b).cmp(&at_claim(a)))
            .then_with(|| {
                (a.source, a.target, &a.relationship).cmp(&(b.source, b.target, &b.relationship))
            })
    };
    let mut order: Vec<usize> = (0..edges.len()).collect();
    order.sort_by(|&i, &j| rank(&edges[i], &edges[j]));

    let mut keep: BTreeSet<usize> = BTreeSet::new();
    let mut anchored: BTreeSet<Uuid> = BTreeSet::new();
    for &i in &order {
        let e = &edges[i];
        if !at_claim(e) {
            continue;
        }
        let other = if is_claim(&e.source) {
            e.target
        } else {
            e.source
        };
        if !is_claim(&other) && anchored.insert(other) {
            keep.insert(i);
        }
    }
    for &i in &order {
        if keep.len() >= max {
            break;
        }
        keep.insert(i);
    }
    let cut = edges.len() - keep.len();
    let kept = edges
        .into_iter()
        .enumerate()
        .filter_map(|(i, e)| keep.contains(&i).then_some(e))
        .collect();
    (kept, cut)
}

/// The node ids and `(source, target, relationship)` of a leaf document:
/// what the carry-over check compares with a fresh assembly.
#[must_use]
pub fn leaf_shape(
    leaf: &LeafLevel,
) -> (
    std::collections::BTreeSet<Uuid>,
    std::collections::BTreeSet<(Uuid, Uuid, String)>,
) {
    (
        leaf.nodes.iter().map(Node::id).collect(),
        leaf.edges
            .iter()
            .map(|e| (e.source, e.target, e.relationship.clone()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_db::repos::atlas_leaf::LeafNode;

    #[test]
    fn labels_are_never_empty_and_never_longer_than_the_contract_allows() {
        let a = Uuid::from_u128(0xabcd_ef01_0000_4000_8000_0000_0000_0001);
        assert_eq!(agent_fallback(a), "Agent abcdef01");
        let long = "word ".repeat(100);
        assert!(claim_label(&long).chars().count() <= epigraph_atlas_contract::MAX_LABEL_CHARS);
        assert_eq!(claim_label("  a\n b  "), "a b");
    }

    #[test]
    fn a_filled_leaf_holds_the_node_set_in_order_with_fallback_labels() {
        let c = Uuid::from_u128(1);
        let ag = Uuid::from_u128(2);
        let ev = Uuid::from_u128(3);
        let mut rows = LeafRows::default();
        rows.claims.insert(c, Some(ag));
        rows.agents.insert(ag);
        rows.evidence.insert(ev, Some(c));
        rows.edges
            .push(epigraph_db::repos::atlas_leaf::StoredLeafEdge {
                id: Uuid::from_u128(9),
                source: LeafNode::evidence(ev),
                target: LeafNode::claim(c),
                relationship: "SUPPORTS".into(),
            });
        let set = node_set(&rows, &[c], 100).unwrap();
        let skeleton =
            serde_json::from_value::<epigraph_atlas_contract::LevelDocument>(serde_json::json!({
                "kind": "leaf", "schema_version": 1, "map_scope": "public", "map_group_id": null,
                "hierarchy": "meaning", "theme_id": Uuid::nil(), "run_id": Uuid::nil(),
                "level_id": Uuid::from_u128(5), "depth": 0, "name": null, "needs_naming": true,
                "breadcrumbs": [], "switch": {"hierarchy": "links", "level_id": Uuid::from_u128(6)},
                "nodes": [{"kind": "claim", "id": c, "label": "the claim", "x": 0.5, "y": 0.0,
                           "truth_value": null}],
                "edges": [], "outgoing": []
            }))
            .unwrap();
        let epigraph_atlas_contract::LevelDocument::Leaf(mut leaf) = skeleton else {
            panic!("a leaf")
        };
        fill_leaf(
            &mut leaf,
            &set,
            &FlowInputs::default(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let kinds: Vec<_> = leaf.nodes.iter().map(Node::kind).collect();
        assert_eq!(kinds.len(), 3);
        assert_eq!(
            leaf.edges.len(),
            2,
            "the stored evidence edge and the derived filer edge"
        );
        assert!(leaf.nodes.iter().all(|n| match n {
            Node::Claim(c) => c.label == "the claim",
            Node::Agent(a) => a.label == agent_fallback(ag),
            Node::Evidence(e) => e.label == EVIDENCE_FALLBACK,
        }));
        epigraph_atlas_contract::LevelDocument::Leaf(leaf)
            .validate()
            .expect("a filled leaf validates");
    }

    /// A skeleton leaf of `claims` (claim nodes only), as W4/W5 store it.
    fn skeleton(claims: &[Uuid]) -> LeafLevel {
        let nodes: Vec<serde_json::Value> = claims
            .iter()
            .map(|c| {
                serde_json::json!({"kind": "claim", "id": c, "label": "c", "x": 0.0,
                                        "y": 0.0, "truth_value": null})
            })
            .collect();
        let doc =
            serde_json::from_value::<epigraph_atlas_contract::LevelDocument>(serde_json::json!({
                "kind": "leaf", "schema_version": 1, "map_scope": "public", "map_group_id": null,
                "hierarchy": "meaning", "theme_id": Uuid::nil(), "run_id": Uuid::nil(),
                "level_id": Uuid::from_u128(5), "depth": 0, "name": null, "needs_naming": true,
                "breadcrumbs": [], "switch": {"hierarchy": "links", "level_id": Uuid::from_u128(6)},
                "nodes": nodes, "edges": [], "outgoing": []
            }))
            .unwrap();
        let epigraph_atlas_contract::LevelDocument::Leaf(leaf) = doc else {
            panic!("a leaf")
        };
        leaf
    }

    /// Backlog 8d09e6bc: ONE claim whose own evidence carries more edges
    /// among them than the contract allows (33 evidence rows, each linked to
    /// the claim and citing the 32 others: 33 + 1,056 + the filer's derived
    /// edge = 1,090) cannot be split, and its leaf used to break the
    /// contract. It now fills to a valid leaf of exactly the contract's
    /// 1,024 edges, every node kept and every attachment still anchored to
    /// the claim, the 66 cut edges reported, and the same edges on every
    /// fill.
    #[test]
    fn a_one_claim_leaf_over_the_edge_limit_keeps_its_heaviest_edges_and_validates() {
        let c = Uuid::from_u128(1);
        let ag = Uuid::from_u128(2);
        let ev: Vec<Uuid> = (0..33).map(|i| Uuid::from_u128(1_000 + i)).collect();
        let mut rows = LeafRows::default();
        rows.claims.insert(c, Some(ag));
        rows.agents.insert(ag);
        let mut n = 0_u128;
        let mut edge = |source: LeafNode, target: LeafNode, rel: &str| {
            n += 1;
            epigraph_db::repos::atlas_leaf::StoredLeafEdge {
                id: Uuid::from_u128(10_000 + n),
                source,
                target,
                relationship: rel.into(),
            }
        };
        for &e in &ev {
            rows.evidence.insert(e, Some(c));
            rows.edges
                .push(edge(LeafNode::evidence(e), LeafNode::claim(c), "supports"));
        }
        for &a in &ev {
            for &b in &ev {
                if a != b {
                    rows.edges
                        .push(edge(LeafNode::evidence(a), LeafNode::evidence(b), "cites"));
                }
            }
        }
        let set = node_set(&rows, &[c], 100).expect("one claim always fits the node cap");
        assert_eq!(set.counts.edges, 1_090, "the seed is over the edge limit");

        let fill = || {
            let mut leaf = skeleton(&[c]);
            let fill = fill_leaf(
                &mut leaf,
                &set,
                &FlowInputs::default(),
                &BTreeMap::new(),
                &BTreeMap::new(),
                &BTreeMap::new(),
            )
            .unwrap();
            (leaf, fill.cut)
        };
        let (leaf, cut) = fill();
        assert_eq!(cut, 1_090 - MAX_LEAF_EDGES);
        assert_eq!(leaf.edges.len(), MAX_LEAF_EDGES);
        assert_eq!(leaf.nodes.len(), 35, "the cut drops edges, never a node");
        let at_claim = leaf
            .edges
            .iter()
            .filter(|e| e.source == c || e.target == c)
            .count();
        assert_eq!(at_claim, 34, "every attachment keeps its edge to the claim");
        assert_eq!(fill().0, leaf, "the cut is deterministic");
        epigraph_atlas_contract::LevelDocument::Leaf(leaf)
            .validate()
            .expect("a capped leaf validates");
    }

    fn edge(source: Uuid, target: Uuid, rel: &str, w: f64) -> Edge {
        Edge {
            source,
            target,
            relationship: rel.into(),
            sign: if w > 0.0 { 1 } else { 0 },
            flow_weight: w,
            flow_basis: if w > 0.0 {
                epigraph_atlas_contract::FlowBasis::Proxy
            } else {
                epigraph_atlas_contract::FlowBasis::None
            },
        }
    }

    /// The cap keeps the heaviest edges, but never by orphaning an agent or
    /// evidence node: a weight-0 authorship edge outranked by every
    /// claim-to-claim link is kept anyway, since without it the agent has no
    /// edge to a claim and the contract refuses the leaf. Pure top-k by
    /// weight would keep the three links here.
    #[test]
    fn the_edge_cap_keeps_an_edge_for_every_attachment_then_the_heaviest() {
        let (c1, c2, c3, a) = (
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            Uuid::from_u128(9),
        );
        let claim = |id| {
            Node::Claim(ClaimNode {
                id,
                label: "c".into(),
                x: 0.0,
                y: 0.0,
                truth_value: None,
            })
        };
        let nodes = vec![
            claim(c1),
            claim(c2),
            claim(c3),
            Node::Agent(PlainNode {
                id: a,
                label: "a".into(),
                x: 0.0,
                y: 0.0,
            }),
        ];
        let edges = vec![
            edge(c1, c2, "supports", 0.5),
            edge(c1, c3, "supports", 0.9),
            edge(c2, c3, "supports", 0.5),
            edge(a, c1, "asserts", 0.0),
        ];
        let (kept, cut) = cap_leaf_edges(&nodes, edges.clone(), 3);
        assert_eq!(cut, 1);
        assert_eq!(
            kept,
            vec![edges[0].clone(), edges[1].clone(), edges[3].clone()],
            "the anchor, then the heaviest, ties to the smaller key, in input order"
        );
        let (same, none) = cap_leaf_edges(&nodes, edges.clone(), 4);
        assert_eq!((same, none), (edges, 0), "a leaf that fits is untouched");
    }

    /// Backlog 9de2ebad: a stored relationship name outside the contract's
    /// pattern is served mapped to a contract name (every character outside
    /// `[A-Za-z0-9_]` to `_`, a letter prefixed when it does not start with
    /// one, then cut to 32), and two stored names that map to one name on
    /// one (source, target) become one edge. The leaf validates instead of
    /// failing its theme.
    #[test]
    fn relationship_names_outside_the_contract_are_mapped_and_the_leaf_validates() {
        let (c, d, ag) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let mut rows = LeafRows::default();
        rows.claims.insert(c, Some(ag));
        rows.claims.insert(d, Some(ag));
        rows.agents.insert(ag);
        let long = "a".repeat(40);
        for (i, (s, t, rel)) in [
            (c, d, "has-part"),
            (c, d, "has_part"),
            (d, c, "2nd-order"),
            (c, d, long.as_str()),
            (d, c, "causé"),
        ]
        .into_iter()
        .enumerate()
        {
            rows.edges
                .push(epigraph_db::repos::atlas_leaf::StoredLeafEdge {
                    id: Uuid::from_u128(100 + i as u128),
                    source: LeafNode::claim(s),
                    target: LeafNode::claim(t),
                    relationship: rel.into(),
                });
        }
        let set = node_set(&rows, &[c, d], 100).unwrap();
        let mut leaf = skeleton(&[c, d]);
        fill_leaf(
            &mut leaf,
            &set,
            &FlowInputs::default(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let between: BTreeSet<(Uuid, Uuid, String)> = leaf
            .edges
            .iter()
            .filter(|e| e.source != ag)
            .map(|e| (e.source, e.target, e.relationship.clone()))
            .collect();
        let want: BTreeSet<(Uuid, Uuid, String)> = [
            (c, d, "has_part".to_string()),
            (c, d, "a".repeat(32)),
            (d, c, "r_2nd_order".to_string()),
            (d, c, "caus_".to_string()),
        ]
        .into_iter()
        .collect();
        assert_eq!(between, want);
        epigraph_atlas_contract::LevelDocument::Leaf(leaf)
            .validate()
            .expect("a leaf with mapped names validates");
    }

    /// Every mapped name is a contract name, and a contract name is kept.
    #[test]
    fn a_mapped_relationship_name_is_always_a_contract_name() {
        for kept in ["SUPPORTS", "has_part", "a"] {
            assert_eq!(contract_relationship_name(kept), kept);
        }
        for stored in [
            "-",
            "_x",
            "9",
            "is part of",
            "ünïcode-only",
            &"x-".repeat(40),
        ] {
            let name = contract_relationship_name(stored);
            assert!(
                epigraph_atlas_contract::is_relationship_name(&name),
                "{stored:?} -> {name:?}"
            );
        }
        assert_eq!(contract_relationship_name("_x"), "r__x");
        assert_eq!(contract_relationship_name("is part of"), "is_part_of");
    }

    /// A leaf claim's `truth_value` is its stored one; a claim the truth read
    /// did not return (not drawable on the map) carries none, never a
    /// default, and the value never changes an edge's weight.
    #[test]
    fn a_claims_truth_value_is_its_stored_one_and_none_without_one() {
        let (c, d, ag) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let mut rows = LeafRows::default();
        rows.claims.insert(c, Some(ag));
        rows.claims.insert(d, Some(ag));
        rows.agents.insert(ag);
        rows.edges
            .push(epigraph_db::repos::atlas_leaf::StoredLeafEdge {
                id: Uuid::from_u128(9),
                source: LeafNode::claim(c),
                target: LeafNode::claim(d),
                relationship: "supports".into(),
            });
        let set = node_set(&rows, &[c, d], 100).unwrap();
        let skeleton =
            serde_json::from_value::<epigraph_atlas_contract::LevelDocument>(serde_json::json!({
                "kind": "leaf", "schema_version": 1, "map_scope": "public", "map_group_id": null,
                "hierarchy": "meaning", "theme_id": Uuid::nil(), "run_id": Uuid::nil(),
                "level_id": Uuid::from_u128(5), "depth": 0, "name": null, "needs_naming": true,
                "breadcrumbs": [], "switch": {"hierarchy": "links", "level_id": Uuid::from_u128(6)},
                "nodes": [
                    {"kind": "claim", "id": c, "label": "c", "x": 0.0, "y": 0.0, "truth_value": null},
                    {"kind": "claim", "id": d, "label": "d", "x": 0.0, "y": 0.0, "truth_value": null}
                ],
                "edges": [], "outgoing": []
            }))
            .unwrap();
        let epigraph_atlas_contract::LevelDocument::Leaf(skeleton) = skeleton else {
            panic!("a leaf")
        };
        let fill = |truths: &BTreeMap<Uuid, f64>| {
            let mut leaf = skeleton.clone();
            fill_leaf(
                &mut leaf,
                &set,
                &FlowInputs::default(),
                &BTreeMap::new(),
                &BTreeMap::new(),
                truths,
            )
            .unwrap();
            leaf
        };
        let truth = |leaf: &LeafLevel, id: Uuid| {
            leaf.nodes.iter().find_map(|n| match n {
                Node::Claim(x) if x.id == id => Some(x.truth_value),
                _ => None,
            })
        };
        let only_c = fill(&BTreeMap::from([(c, 0.13)]));
        assert_eq!(truth(&only_c, c), Some(Some(0.13)));
        assert_eq!(truth(&only_c, d), Some(None), "no stored value, no value");
        let both = fill(&BTreeMap::from([(c, 0.91), (d, 0.02)]));
        assert_eq!(truth(&both, c), Some(Some(0.91)));
        assert_eq!(truth(&both, d), Some(Some(0.02)));
        assert_eq!(
            both.edges, only_c.edges,
            "a truth value never moves a weight"
        );
        epigraph_atlas_contract::LevelDocument::Leaf(both)
            .validate()
            .expect("a filled leaf validates");
    }
}
