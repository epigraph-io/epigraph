//! The REAL leaf documents (Atlas W9): W4 and W5 store skeleton leaves
//! (claim nodes only, placeholder positions). The nightly turns each into the
//! leaf the contract describes: W3's node set (`assemble_leaf`: the claims,
//! the agents that asserted or authored them, the evidence a stored edge
//! links to them) with W7's weighted edges (`weigh_leaf_edges`), labelled
//! from map-scoped reads. Positions stay for W6's fill and names for W8's.

use std::collections::BTreeMap;

use anyhow::{bail, Context};
use epigraph_atlas_contract::{ClaimNode, LeafLevel, Node, PlainNode};
use epigraph_db::repos::atlas_flow::FlowInputs;
use epigraph_db::repos::atlas_leaf::{
    assemble_leaf, LeafNodeKind, LeafNodeSet, LeafOutcome, LeafRows,
};
use epigraph_engine::atlas_flow::weigh_leaf_edges;
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
/// # Errors
/// A claim of `set` the skeleton does not label.
pub fn fill_leaf(
    leaf: &mut LeafLevel,
    set: &LeafNodeSet,
    inputs: &FlowInputs,
    agents: &BTreeMap<Uuid, String>,
    evidence: &BTreeMap<Uuid, String>,
    truths: &BTreeMap<Uuid, f64>,
) -> anyhow::Result<()> {
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
    leaf.nodes = nodes;
    leaf.edges = weigh_leaf_edges(set, inputs);
    Ok(())
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
