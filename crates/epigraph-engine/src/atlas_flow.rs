//! Flow weights for one Atlas leaf (Atlas W7, backlog 7a03f5e4).
//!
//! [`weigh_leaf_edges`] turns a leaf W3 assembled
//! ([`epigraph_db::repos::atlas_leaf::LeafNodeSet`]) and the rows
//! [`epigraph_db::AtlasFlowRepository::read_flow_inputs`] read for it into the
//! level contract's edge list ([`epigraph_atlas_contract::Edge`]): each edge
//! with a `sign`, a `flow_weight` in [0, 1] and a `flow_basis`. It is pure;
//! [`build_leaf_flow_edges`] is the read followed by it.
//!
//! # Claim to claim: `proxy`, strength × |sign|, NO belief
//!
//! `flow_weight` = the link's strength × |sign|. No belief value of either
//! claim enters it (no BetP, belief, plausibility, `truth_value`, BBA or
//! belief fold), so a served weight can never be divided back into a belief.
//! The strength of one stored edge row is its own stored strength
//! (`properties.strength`, a number in [0, 1]) when it has one, else the
//! belief engine's per-relationship transmission factor
//! ([`crate::sheaf::restriction_kind`], the profile the edge-factor wire
//! uses). Several stored rows of one (source, target, relationship) take the
//! largest weight among them.
//!
//! # Evidence to claim: `exact`, the stored mass
//!
//! A `supports` or `refutes` edge whose evidence has at least one usable mass
//! row on the claim is `exact`: its weight is the largest, over those rows, of
//! the row's stored mass on the singleton the edge names (`m({h})` for
//! `supports`, `m({1 − h})` for `refutes`, `h` the claim's hypothesis index on
//! the row's two-hypothesis frame). See [`exact_mass`].
//!
//! An evidence-to-claim edge with no usable mass row, or with another
//! relationship, gets `none` (weight 0, sign 0). **The v1 contract refuses
//! that**: `FlowBasis::for_kinds(evidence, claim)` is `exact`, and
//! `LevelDocument::validate` rejects any other basis for that pair. No mass
//! is invented to satisfy it; the contract rule (or W10's choice to drop such
//! edges) is the operator's call.
//!
//! # Everything else: `none`
//!
//! Authorship, the derived filer edge, evidence to agent, and a stored
//! `claim -> evidence` provenance row carry weight 0 and sign 0. A stored
//! `claim -> evidence` row is not re-oriented: the leaf draws stored
//! evidence-to-claim edges only.
//!
//! # Spelling
//!
//! The served relationship is the stored name lower-cased. W3 collapsed rows
//! on the exact stored spelling, so `supports` and `SUPPORTS` between one pair
//! arrive as two edges; they collapse here into one with the larger weight.

use std::collections::BTreeMap;

use epigraph_atlas_contract::{Edge, FlowBasis, NodeKind};
use epigraph_db::repos::atlas_flow::{EvidenceMassRow, FlowInputs};
use epigraph_db::repos::atlas_leaf::{LeafEdgeOrigin, LeafNodeKind, LeafNodeSet};
use epigraph_db::repos::atlas_map::AtlasMap;
use epigraph_db::{AtlasFlowRepository, DbError, Viewer};
use uuid::Uuid;

use crate::edge_factor::resolve_hypothesis_index;
use crate::sheaf::{restriction_kind, RestrictionKind};

/// Claim-to-claim relationships whose belief flows forward (sign +1),
/// lower-cased.
pub const SUPPORTING_LINKS: [&str; 5] = [
    "supports",
    "corroborates",
    "elaborates",
    "generalizes",
    "specializes",
];

/// Claim-to-claim relationships whose belief opposes (sign -1), lower-cased.
pub const OPPOSING_LINKS: [&str; 2] = ["contradicts", "refutes"];

/// The evidence-to-claim relationship that supports, lower-cased.
pub const EVIDENCE_SUPPORTS: &str = "supports";
/// The evidence-to-claim relationship that refutes, lower-cased.
pub const EVIDENCE_REFUTES: &str = "refutes";

/// The number of hypotheses of a frame whose evidence mass an exact weight
/// reads: the evidence BBA writer files on two-hypothesis frames, and the
/// belief fold reads exactly those.
const BINARY_FRAME_SIZE: i32 = 2;

/// The sign of a claim-to-claim link, from its lower-cased relationship:
/// +1 for [`SUPPORTING_LINKS`], -1 for [`OPPOSING_LINKS`], 0 for anything
/// else (`cites`, `qualifies`, the structural kinds).
#[must_use]
pub fn link_sign(relationship: &str) -> i8 {
    let rel = relationship.to_ascii_lowercase();
    if SUPPORTING_LINKS.contains(&rel.as_str()) {
        1
    } else if OPPOSING_LINKS.contains(&rel.as_str()) {
        -1
    } else {
        0
    }
}

/// The belief engine's per-relationship transmission factor: the strength of
/// a link with no stored strength of its own. `Positive(f)` and `Negative(f)`
/// give `f`; any other kind gives 0 (such a link has sign 0, so its strength
/// never shows).
#[must_use]
pub fn fallback_strength(relationship: &str) -> f64 {
    match restriction_kind(relationship) {
        RestrictionKind::Positive(f) | RestrictionKind::Negative(f) => f.clamp(0.0, 1.0),
        RestrictionKind::FrameEvidence(_) | RestrictionKind::Neutral => 0.0,
    }
}

/// An edge row's stored strength (`properties -> 'strength'`), when it is a
/// finite number in [0, 1]. Anything else is no stored strength.
#[must_use]
pub fn stored_strength(raw: Option<&serde_json::Value>) -> Option<f64> {
    raw.and_then(serde_json::Value::as_f64)
        .filter(|s| s.is_finite() && (0.0..=1.0).contains(s))
}

/// The strength of one stored claim-to-claim edge row: its stored strength,
/// else [`fallback_strength`].
#[must_use]
pub fn link_strength(raw: Option<&serde_json::Value>, relationship: &str) -> f64 {
    stored_strength(raw).unwrap_or_else(|| fallback_strength(relationship))
}

/// The exact mass one evidence-keyed BBA row gives an evidence-to-claim edge:
/// the row's stored mass on the singleton the edge names, `m({h})` when
/// `refutes` is false and `m({1 − h})` when it is true, with `h` the claim's
/// hypothesis index on the row's frame
/// ([`resolve_hypothesis_index`], 0 when absent).
///
/// The stored mass as it is, with no reliability discount (that is computed
/// at fold time, not stored). A singleton the BBA puts no mass on reads 0.
///
/// `None` (the row is not usable) when the frame does not have exactly two
/// hypotheses, or when `masses` is not an object of numbers in [0, 1].
#[must_use]
pub fn exact_mass(row: &EvidenceMassRow, refutes: bool) -> Option<f64> {
    if row.hypothesis_count != BINARY_FRAME_SIZE {
        return None;
    }
    let masses = row.masses.as_object()?;
    let mut values = BTreeMap::new();
    for (key, value) in masses {
        let m = value
            .as_f64()
            .filter(|m| m.is_finite() && (0.0..=1.0).contains(m))?;
        values.insert(key.as_str(), m);
    }
    let h = resolve_hypothesis_index(row.hypothesis_index, 2);
    let singleton = if refutes { 1 - h } else { h };
    Some(
        values
            .get(singleton.to_string().as_str())
            .copied()
            .unwrap_or(0.0),
    )
}

/// The (sign, weight, basis) of an evidence-to-claim edge.
fn evidence_flow(
    evidence: Uuid,
    claim: Uuid,
    relationship: &str,
    inputs: &FlowInputs,
) -> (i8, f64, FlowBasis) {
    let (sign, refutes) = match relationship {
        EVIDENCE_SUPPORTS => (1, false),
        EVIDENCE_REFUTES => (-1, true),
        _ => return (0, 0.0, FlowBasis::None),
    };
    let mass = inputs
        .evidence_masses
        .iter()
        .filter(|r| r.evidence == evidence && r.claim == claim)
        .filter_map(|r| exact_mass(r, refutes))
        .reduce(f64::max);
    match mass {
        Some(m) => (sign, m, FlowBasis::Exact),
        None => (0, 0.0, FlowBasis::None),
    }
}

const fn contract_kind(kind: LeafNodeKind) -> NodeKind {
    match kind {
        LeafNodeKind::Claim => NodeKind::Claim,
        LeafNodeKind::Agent => NodeKind::Agent,
        LeafNodeKind::Evidence => NodeKind::Evidence,
    }
}

/// The contract edge list of `set`, weighted from `inputs`. Sorted by
/// (source, target, relationship), one edge per such triple, the
/// relationship lower-cased. See the module documentation for each basis.
#[must_use]
pub fn weigh_leaf_edges(set: &LeafNodeSet, inputs: &FlowInputs) -> Vec<Edge> {
    let mut out: BTreeMap<(Uuid, Uuid, String), Edge> = BTreeMap::new();
    for e in &set.edges {
        let relationship = e.relationship.to_ascii_lowercase();
        let source = contract_kind(e.source.kind);
        let target = contract_kind(e.target.kind);
        let (sign, flow_weight, flow_basis) = match FlowBasis::for_kinds(source, target) {
            FlowBasis::Proxy => {
                let sign = link_sign(&relationship);
                let strength = match &e.origin {
                    LeafEdgeOrigin::Stored { edge_ids } => edge_ids
                        .iter()
                        .map(|id| {
                            let raw = inputs.link_strengths.get(id).and_then(Option::as_ref);
                            link_strength(raw, &relationship)
                        })
                        .fold(0.0, f64::max),
                    LeafEdgeOrigin::Filer => 0.0,
                };
                (
                    sign,
                    strength * f64::from(sign.unsigned_abs()),
                    FlowBasis::Proxy,
                )
            }
            FlowBasis::Exact => evidence_flow(e.source.id, e.target.id, &relationship, inputs),
            FlowBasis::None => (0, 0.0, FlowBasis::None),
        };
        let key = (e.source.id, e.target.id, relationship.clone());
        match out.get_mut(&key) {
            Some(prev) if prev.flow_weight >= flow_weight => {}
            Some(prev) => {
                prev.sign = sign;
                prev.flow_weight = flow_weight;
                prev.flow_basis = flow_basis;
            }
            None => {
                out.insert(
                    key,
                    Edge {
                        source: e.source.id,
                        target: e.target.id,
                        relationship,
                        sign,
                        flow_weight,
                        flow_basis,
                    },
                );
            }
        }
    }
    out.into_values().collect()
}

/// [`AtlasFlowRepository::read_flow_inputs`] then [`weigh_leaf_edges`]: the
/// weighted contract edges of `set`, read on `conn` (the build's snapshot
/// transaction, the one `set` was read on) for `map`, spliced on `viewer`.
///
/// # Errors
/// What the read returns.
pub async fn build_leaf_flow_edges(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    set: &LeafNodeSet,
) -> Result<Vec<Edge>, DbError> {
    let inputs = AtlasFlowRepository::read_flow_inputs(conn, viewer, map, set).await?;
    Ok(weigh_leaf_edges(set, &inputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_db::repos::atlas_leaf::{LeafCounts, LeafEdge, LeafNode};
    use serde_json::json;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn stored(source: LeafNode, target: LeafNode, rel: &str, ids: &[u128]) -> LeafEdge {
        LeafEdge {
            source,
            target,
            relationship: rel.to_string(),
            origin: LeafEdgeOrigin::Stored {
                edge_ids: ids.iter().map(|&n| id(n)).collect(),
            },
        }
    }

    fn set(edges: Vec<LeafEdge>) -> LeafNodeSet {
        let mut nodes: Vec<LeafNode> = edges.iter().flat_map(|e| [e.source, e.target]).collect();
        nodes.sort_unstable();
        nodes.dedup();
        LeafNodeSet {
            nodes,
            edges,
            capped: Vec::new(),
            counts: LeafCounts::default(),
        }
    }

    fn mass(
        ev: u128,
        claim: u128,
        n: i32,
        index: Option<i32>,
        masses: serde_json::Value,
    ) -> EvidenceMassRow {
        EvidenceMassRow {
            id: Uuid::new_v4(),
            evidence: id(ev),
            claim: id(claim),
            frame: id(900),
            hypothesis_count: n,
            hypothesis_index: index,
            masses,
        }
    }

    const A: u128 = 1;
    const B: u128 = 2;
    const EV: u128 = 10;

    #[test]
    fn the_sign_table_is_the_items_list_in_both_spellings() {
        for rel in [
            "supports",
            "SUPPORTS",
            "corroborates",
            "CORROBORATES",
            "elaborates",
            "generalizes",
            "specializes",
        ] {
            assert_eq!(link_sign(rel), 1, "{rel}");
        }
        for rel in ["contradicts", "CONTRADICTS", "refutes", "REFUTES"] {
            assert_eq!(link_sign(rel), -1, "{rel}");
        }
        // `informs` and `frame_validates` carry a factor in the engine but are
        // not on the item's lists: sign 0 until the operator says otherwise.
        for rel in [
            "cites",
            "qualifies",
            "decomposes_to",
            "supersedes",
            "derived_from",
            "informs",
            "frame_validates",
            "asserts",
        ] {
            assert_eq!(link_sign(rel), 0, "{rel}");
        }
    }

    #[test]
    fn the_fallback_is_the_engines_transmission_factor_not_the_sql_factor_table() {
        // `sheaf::restriction_kind` under the scientific profile. The SQL
        // `edge_to_factor_type` gives contradicts and refutes 0.0.
        assert_eq!(fallback_strength("supports"), 0.80);
        assert_eq!(fallback_strength("CORROBORATES"), 0.80);
        assert_eq!(fallback_strength("elaborates"), 0.60);
        assert_eq!(fallback_strength("specializes"), 0.60);
        assert_eq!(fallback_strength("generalizes"), 0.50);
        assert_eq!(fallback_strength("refutes"), 0.80);
        assert_eq!(fallback_strength("contradicts"), 0.90);
        assert_eq!(fallback_strength("cites"), 0.0);
    }

    #[test]
    fn a_stored_strength_wins_and_a_bad_one_falls_back() {
        assert_eq!(link_strength(Some(&json!(0.37)), "supports"), 0.37);
        assert_eq!(link_strength(Some(&json!(0)), "supports"), 0.0);
        for bad in [
            json!(1.5),
            json!(-0.1),
            json!("0.4"),
            json!(null),
            json!({"v": 0.4}),
        ] {
            assert_eq!(link_strength(Some(&bad), "supports"), 0.80, "{bad}");
        }
        assert_eq!(link_strength(None, "contradicts"), 0.90);
    }

    #[test]
    fn a_proxy_weight_is_strength_times_abs_sign_and_the_largest_collapsed_row_wins() {
        let (a, b) = (LeafNode::claim(id(A)), LeafNode::claim(id(B)));
        let s = set(vec![
            stored(a, b, "supports", &[100, 101, 102]),
            stored(b, a, "contradicts", &[103]),
            stored(a, b, "cites", &[104]),
        ]);
        let mut inputs = FlowInputs::default();
        inputs.link_strengths.insert(id(100), Some(json!(0.3)));
        inputs.link_strengths.insert(id(101), Some(json!(0.6)));
        inputs.link_strengths.insert(id(102), None); // falls back to 0.80
        inputs.link_strengths.insert(id(103), None);
        inputs.link_strengths.insert(id(104), Some(json!(0.8)));
        let edges = weigh_leaf_edges(&s, &inputs);
        let get = |src: u128, rel: &str| {
            edges
                .iter()
                .find(|e| e.source == id(src) && e.relationship == rel)
                .unwrap_or_else(|| panic!("{rel}"))
        };
        assert_eq!(get(A, "supports").flow_weight, 0.80);
        assert_eq!(get(A, "supports").sign, 1);
        assert_eq!(get(B, "contradicts").flow_weight, 0.90);
        assert_eq!(get(B, "contradicts").sign, -1);
        // A stored strength on a cites link does not show: sign 0, weight 0.
        assert_eq!(get(A, "cites").flow_weight, 0.0);
        assert_eq!(get(A, "cites").sign, 0);
        assert!(edges.iter().all(|e| e.flow_basis == FlowBasis::Proxy));
    }

    #[test]
    fn both_spellings_collapse_into_one_lower_cased_edge_with_the_larger_weight() {
        let (a, b) = (LeafNode::claim(id(A)), LeafNode::claim(id(B)));
        let s = set(vec![
            stored(a, b, "SUPPORTS", &[100]),
            stored(a, b, "supports", &[101]),
        ]);
        let mut inputs = FlowInputs::default();
        inputs.link_strengths.insert(id(100), Some(json!(0.7)));
        inputs.link_strengths.insert(id(101), Some(json!(0.2)));
        let edges = weigh_leaf_edges(&s, &inputs);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].relationship, "supports");
        assert_eq!(edges[0].flow_weight, 0.7);
    }

    #[test]
    fn the_exact_mass_reads_the_named_singleton_on_a_two_hypothesis_frame() {
        let m = json!({"0": 0.63, "1": 0.12, "0,1": 0.25});
        assert_eq!(
            exact_mass(&mass(EV, A, 2, None, m.clone()), false),
            Some(0.63)
        );
        assert_eq!(
            exact_mass(&mass(EV, A, 2, None, m.clone()), true),
            Some(0.12)
        );
        // The claim is hypothesis 1 of this frame: supported is {1}.
        assert_eq!(
            exact_mass(&mass(EV, A, 2, Some(1), m.clone()), false),
            Some(0.12)
        );
        assert_eq!(
            exact_mass(&mass(EV, A, 2, Some(1), m.clone()), true),
            Some(0.63)
        );
        // An index outside the frame reads as 0 (`resolve_hypothesis_index`).
        assert_eq!(
            exact_mass(&mass(EV, A, 2, Some(7), m.clone()), false),
            Some(0.63)
        );
        // A BBA with no mass on the singleton gives 0, not "no row".
        assert_eq!(
            exact_mass(&mass(EV, A, 2, None, json!({"1": 0.4, "0,1": 0.6})), false),
            Some(0.0)
        );
        // Not usable: three hypotheses, a value out of range or not a number.
        assert_eq!(exact_mass(&mass(EV, A, 3, None, m), false), None);
        assert_eq!(
            exact_mass(&mass(EV, A, 2, None, json!({"0": 1.2})), false),
            None
        );
        assert_eq!(
            exact_mass(&mass(EV, A, 2, None, json!({"0": "x"})), false),
            None
        );
        assert_eq!(exact_mass(&mass(EV, A, 2, None, json!([0.5])), false), None);
    }

    #[test]
    fn evidence_edges_take_the_largest_usable_mass_or_basis_none() {
        let (a, ev) = (LeafNode::claim(id(A)), LeafNode::evidence(id(EV)));
        let ev2 = LeafNode::evidence(id(EV + 1));
        let ev3 = LeafNode::evidence(id(EV + 2));
        let s = set(vec![
            stored(ev, a, "SUPPORTS", &[200]),
            stored(ev2, a, "refutes", &[201]),
            stored(ev3, a, "supports", &[202]),
            stored(ev, a, "provides_evidence", &[203]),
            stored(a, ev, "derived_from", &[204]),
        ]);
        let inputs = FlowInputs {
            link_strengths: BTreeMap::new(),
            evidence_masses: vec![
                mass(EV, A, 2, None, json!({"0": 0.4, "0,1": 0.6})),
                mass(EV, A, 2, None, json!({"0": 0.55, "0,1": 0.45})),
                // Larger, but on a three-hypothesis frame: not read.
                mass(EV, A, 3, None, json!({"0": 0.9, "0,1,2": 0.1})),
                mass(EV + 1, A, 2, None, json!({"1": 0.3, "0,1": 0.7})),
                // ev3's only row is on a three-hypothesis frame.
                mass(EV + 2, A, 3, None, json!({"0": 0.9, "0,1,2": 0.1})),
            ],
        };
        let edges = weigh_leaf_edges(&s, &inputs);
        let get = |src: u128, rel: &str| {
            edges
                .iter()
                .find(|e| e.source == id(src) && e.relationship == rel)
                .unwrap_or_else(|| panic!("{src} {rel}"))
        };
        let sup = get(EV, "supports");
        assert_eq!(
            (sup.sign, sup.flow_weight, sup.flow_basis),
            (1, 0.55, FlowBasis::Exact)
        );
        let refu = get(EV + 1, "refutes");
        assert_eq!(
            (refu.sign, refu.flow_weight, refu.flow_basis),
            (-1, 0.3, FlowBasis::Exact)
        );
        let none = get(EV + 2, "supports");
        assert_eq!(
            (none.sign, none.flow_weight, none.flow_basis),
            (0, 0.0, FlowBasis::None)
        );
        let other = get(EV, "provides_evidence");
        assert_eq!(
            (other.sign, other.flow_weight, other.flow_basis),
            (0, 0.0, FlowBasis::None)
        );
        let back = get(A, "derived_from");
        assert_eq!(
            (back.sign, back.flow_weight, back.flow_basis),
            (0, 0.0, FlowBasis::None)
        );
    }

    #[test]
    fn agent_edges_and_the_derived_filer_edge_carry_no_flow() {
        let (a, ag) = (LeafNode::claim(id(A)), LeafNode::agent(id(50)));
        let s = set(vec![
            stored(ag, a, "AUTHORED", &[300]),
            LeafEdge {
                source: ag,
                target: LeafNode::claim(id(B)),
                relationship: "asserts".into(),
                origin: LeafEdgeOrigin::Filer,
            },
        ]);
        let edges = weigh_leaf_edges(&s, &FlowInputs::default());
        assert_eq!(edges.len(), 2);
        for e in &edges {
            assert_eq!(
                (e.sign, e.flow_weight, e.flow_basis),
                (0, 0.0, FlowBasis::None)
            );
        }
        assert_eq!(edges[0].relationship, "authored");
    }
}
