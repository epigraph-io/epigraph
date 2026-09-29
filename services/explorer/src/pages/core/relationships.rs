//! Claim-page outlinks: `/claims/:id/ego` edges grouped by relationship
//! family (plan §3.4 "Outlink grouping").
//!
//! The families mirror the kernel's `GRAPH_VIEW_RELATIONSHIPS` readability
//! allowlist (`crates/epigraph-api/src/routes/graph.rs:29-66`) and its
//! comment groups. Stored relationship strings mix case and spelling
//! (`supports`/`SUPPORTS`, `derived_from`/`derives_from`), so every string is
//! case-folded and alias-merged before grouping; anything outside the
//! allowlist (`same_source`, `ATTRIBUTED_TO`, …) lands under "Other".
//!
//! Headings are direction-aware: `Supports →` lists claims the centre
//! supports, `← Supported by` lists claims that support the centre.

use serde::Serialize;
use uuid::Uuid;

use super::vocab::short_id;
use crate::links::Links;
use crate::upstream::{truncate_chars, EdgeDirection, EgoNode, EgoResponse};

/// Longest neighbour text shown in a list (upstream labels are ≤ 160).
const NEIGHBOUR_TEXT_CHARS: usize = 160;

/// A readable group of relationships, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Support,
    Contradiction,
    Hierarchy,
    Argument,
    Equivalence,
    Lineage,
    Reference,
    Other,
}

impl Family {
    pub fn title(&self) -> &'static str {
        match self {
            Family::Support => "Support and corroboration",
            Family::Contradiction => "Contradiction and challenge",
            Family::Hierarchy => "Decomposition and refinement",
            Family::Argument => "Argument",
            Family::Equivalence => "Equivalence and variants",
            Family::Lineage => "Lineage",
            Family::Reference => "Cross-references",
            Family::Other => "Other",
        }
    }

    /// CSS modifier for the family (`outlinks__family--support`, …).
    pub fn slug(&self) -> &'static str {
        match self {
            Family::Support => "support",
            Family::Contradiction => "refute",
            Family::Hierarchy => "hierarchy",
            Family::Argument => "argument",
            Family::Equivalence => "equivalence",
            Family::Lineage => "lineage",
            Family::Reference => "reference",
            Family::Other => "other",
        }
    }
}

/// One canonical (case-folded) relationship from the allowlist.
struct Rel {
    key: &'static str,
    family: Family,
    /// Heading when the centre is the source.
    out: &'static str,
    /// Heading when the centre is the target.
    inbound: &'static str,
}

const fn rel(key: &'static str, family: Family, out: &'static str, inbound: &'static str) -> Rel {
    Rel {
        key,
        family,
        out,
        inbound,
    }
}

/// `GRAPH_VIEW_RELATIONSHIPS`, case-folded (upper-case variants such as
/// `SUPPORTS`, `REFINES`, `CORROBORATES`, `CONTRADICTS`, `RELATES_TO`,
/// `SUPERSEDES`, `DERIVED_FROM` fold onto these keys). Order within a family
/// is display order.
const RELATIONSHIPS: &[Rel] = &[
    // Corroboration / support
    rel("supports", Family::Support, "Supports", "Supported by"),
    rel(
        "corroborates",
        Family::Support,
        "Corroborates",
        "Corroborated by",
    ),
    rel(
        "provides_evidence",
        Family::Support,
        "Provides evidence for",
        "Evidence from",
    ),
    rel("asserts", Family::Support, "Asserts", "Asserted by"),
    rel("enables", Family::Support, "Enables", "Enabled by"),
    // Contradiction / challenge
    rel(
        "contradicts",
        Family::Contradiction,
        "Contradicts",
        "Contradicted by",
    ),
    rel("refutes", Family::Contradiction, "Refutes", "Refuted by"),
    rel(
        "challenges",
        Family::Contradiction,
        "Challenges",
        "Challenged by",
    ),
    // Hierarchical
    rel(
        "decomposes_to",
        Family::Hierarchy,
        "Decomposes into",
        "Part of",
    ),
    rel("refines", Family::Hierarchy, "Refines", "Refined by"),
    rel(
        "specializes",
        Family::Hierarchy,
        "Specializes",
        "Specialized by",
    ),
    // Argument continuation
    rel(
        "continues_argument",
        Family::Argument,
        "Continues into",
        "Continues from",
    ),
    rel(
        "elaborates",
        Family::Argument,
        "Elaborates",
        "Elaborated by",
    ),
    // Equivalence / variants
    rel("same_as", Family::Equivalence, "Same as", "Same as"),
    rel(
        "equivalent_to",
        Family::Equivalence,
        "Equivalent to",
        "Equivalent to",
    ),
    rel(
        "analogous",
        Family::Equivalence,
        "Analogous to",
        "Analogous to",
    ),
    rel(
        "variant_of",
        Family::Equivalence,
        "Variant of",
        "Has variant",
    ),
    rel(
        "definitional_variant_of",
        Family::Equivalence,
        "Definitional variant of",
        "Has definitional variant",
    ),
    // Lineage / temporal
    rel("supersedes", Family::Lineage, "Supersedes", "Superseded by"),
    rel("derived_from", Family::Lineage, "Derived from", "Source of"),
    // Generic / cross-reference
    rel(
        "relates_to",
        Family::Reference,
        "Relates to",
        "Related from",
    ),
];

/// Spelling variants that are the same relationship once case-folded.
const ALIASES: &[(&str, &str)] = &[("derives_from", "derived_from")];

/// Case-fold, normalise separators and merge aliases: `SUPPORTS` →
/// `supports`, `Derives-From` → `derived_from`.
pub fn fold(raw: &str) -> String {
    let folded = raw.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == folded)
        .map(|(_, canonical)| (*canonical).to_string())
        .unwrap_or(folded)
}

fn lookup(key: &str) -> Option<(usize, &'static Rel)> {
    RELATIONSHIPS.iter().enumerate().find(|(_, r)| r.key == key)
}

/// A neighbour, ready to render as a link (or plain text for entity types
/// that have no page).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Neighbour {
    pub id: Uuid,
    pub entity_type: String,
    pub text: String,
    /// `None` for entity types without a page (paper, trace, …).
    pub href: Option<String>,
    pub truth_value: Option<f64>,
    pub pignistic_prob: Option<f64>,
    /// `Some(false)` for a superseded claim.
    pub is_current: Option<bool>,
}

/// One heading: a canonical relationship in one direction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RelGroup {
    /// Canonical (folded) relationship.
    pub relationship: String,
    pub direction: EdgeDirection,
    /// `Supports →` / `← Supported by`.
    pub heading: String,
    pub neighbours: Vec<Neighbour>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FamilyGroup {
    pub family: Family,
    pub title: String,
    pub groups: Vec<RelGroup>,
}

impl FamilyGroup {
    pub fn slug(&self) -> &'static str {
        self.family.slug()
    }
}

/// Every outlink of a claim, grouped for display.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Outlinks {
    pub families: Vec<FamilyGroup>,
    /// Edges upstream returned (after its degree cap).
    pub shown_edges: usize,
    /// `/ego`'s `total_edges`: edges before the degree cap, counted inside
    /// the viewer-filtered read, so it never counts neighbours this viewer
    /// may not see.
    pub total_edges: u64,
    /// `/ego`'s `truncated`: the degree cap cut edges. Never inferred from
    /// the counts — see [`group_outlinks`].
    pub truncated: bool,
    /// The graph view of the same neighbourhood.
    pub graph_url: String,
}

impl Outlinks {
    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }
}

/// The heading for `relationship` (already folded) seen from the centre.
pub fn heading(relationship: &str, direction: EdgeDirection) -> String {
    let (out, inbound) = match lookup(relationship) {
        Some((_, r)) => (r.out.to_string(), r.inbound.to_string()),
        None => {
            let plain = relationship.replace('_', " ");
            (plain.clone(), plain)
        }
    };
    match direction {
        EdgeDirection::In => format!("← {inbound}"),
        _ => format!("{out} →"),
    }
}

/// Group an ego response's edges by family, then by (relationship,
/// direction). Families, relationships and directions come out in display
/// order (allowlist order, `Other` last and alphabetical, outgoing before
/// incoming); neighbours keep upstream's newest-first order, de-duplicated.
pub fn group_outlinks(ego: &EgoResponse, links: &Links) -> Outlinks {
    let center = ego.center.id;
    // (family, relationship order, relationship key, direction rank) → group
    let mut groups: Vec<((Family, usize, String, u8), RelGroup)> = Vec::new();
    let mut shown_edges = 0usize;

    for edge in &ego.edges {
        let direction = match edge.direction {
            EdgeDirection::Unknown if edge.target_id == center && edge.source_id != center => {
                EdgeDirection::In
            }
            EdgeDirection::Unknown => EdgeDirection::Out,
            d => d,
        };
        let (neighbour_id, edge_type) = match direction {
            EdgeDirection::In => (edge.source_id, edge.source_type.as_str()),
            _ => (edge.target_id, edge.target_type.as_str()),
        };
        let key = fold(&edge.relationship);
        let (family, order) = match lookup(&key) {
            Some((i, r)) => (r.family, i),
            None => (Family::Other, usize::MAX),
        };
        let dir_rank = u8::from(direction == EdgeDirection::In);
        let sort_key = (family, order, key.clone(), dir_rank);

        // Upstream hydrates every endpoint it returns — a claim the viewer
        // may not read is dropped along with its edges. An id that reaches
        // here with no node is therefore one we are not entitled to name:
        // drop the edge rather than synthesise "claim <short-id>" from it.
        let Some(node) = ego
            .nodes
            .iter()
            .chain(std::iter::once(&ego.center))
            .find(|n| n.id == neighbour_id)
        else {
            continue;
        };
        let neighbour = neighbour(neighbour_id, edge_type, node, links);
        shown_edges += 1;

        match groups.iter_mut().find(|(k, _)| *k == sort_key) {
            Some((_, g)) => {
                if !g.neighbours.iter().any(|n| n.id == neighbour.id) {
                    g.neighbours.push(neighbour);
                }
            }
            None => groups.push((
                sort_key,
                RelGroup {
                    heading: heading(&key, direction),
                    relationship: key,
                    direction,
                    neighbours: vec![neighbour],
                },
            )),
        }
    }

    groups.sort_by(|(a, _), (b, _)| a.cmp(b));
    let mut families: Vec<FamilyGroup> = Vec::new();
    for ((family, ..), group) in groups {
        match families.last_mut() {
            Some(f) if f.family == family => f.groups.push(group),
            _ => families.push(FamilyGroup {
                family,
                title: family.title().to_string(),
                groups: vec![group],
            }),
        }
    }

    // Truncation is upstream's to declare. Inferring it from
    // `total_edges > edges.len()` also fires when the missing edges are ones
    // the viewer may not see, which puts a dead "explore the rest" link on
    // the page (the graph view reads the same `/ego` route) and tells the
    // viewer exactly how many neighbours are hidden from them. `/ego` counts
    // `total_edges` inside its viewer-filtered read and its `truncated` means
    // degree-cap truncation, so both are taken as given; the
    // `.max(shown_edges)` fixup that papered over the mismatch goes with them.
    Outlinks {
        families,
        shown_edges,
        total_edges: ego.total_edges,
        truncated: ego.truncated,
        graph_url: links.claim_graph(center),
    }
}

fn neighbour(id: Uuid, edge_type: &str, node: &EgoNode, links: &Links) -> Neighbour {
    let entity_type = if node.entity_type.trim().is_empty() {
        edge_type
    } else {
        node.entity_type.trim()
    }
    .to_ascii_lowercase();
    let label = Some(node.label.trim())
        .filter(|l| !l.is_empty() && !l.eq_ignore_ascii_case(&entity_type))
        .map(str::to_string)
        .or_else(|| {
            node.content
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_string)
        });
    let text = match label {
        Some(l) => truncate_chars(&super::vocab::one_line(&l), NEIGHBOUR_TEXT_CHARS),
        None => format!(
            "{} {}",
            if entity_type.is_empty() {
                "entity"
            } else {
                &entity_type
            },
            short_id(id)
        ),
    };
    Neighbour {
        id,
        href: links.entity(&entity_type, id),
        entity_type,
        text,
        truth_value: node.truth_value,
        pignistic_prob: node.pignistic_prob,
        is_current: node.is_current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::EgoEdge;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn node(n: u128, t: &str, label: &str) -> EgoNode {
        EgoNode {
            id: id(n),
            entity_type: t.into(),
            label: label.into(),
            content: (t == "claim").then(|| label.to_string()),
            truth_value: None,
            pignistic_prob: None,
            labels: vec![],
            is_current: None,
        }
    }

    fn edge(source: u128, target: u128, rel: &str, dir: &str) -> EgoEdge {
        serde_json::from_value(serde_json::json!({
            "id": id(1000 + source * 10 + target), "source_id": id(source), "target_id": id(target),
            "source_type": "claim", "target_type": "claim",
            "relationship": rel, "direction": dir
        }))
        .unwrap()
    }

    fn links() -> Links {
        Links::new("https://explorer.example.com", "/explorer")
    }

    #[test]
    fn folding_merges_case_and_aliases() {
        assert_eq!(fold("SUPPORTS"), "supports");
        assert_eq!(fold(" Derives-From "), "derived_from");
        assert_eq!(fold("DERIVED_FROM"), "derived_from");
        assert_eq!(fold("same_source"), "same_source");
        assert_eq!(heading("supports", EdgeDirection::Out), "Supports →");
        assert_eq!(heading("supports", EdgeDirection::In), "← Supported by");
        assert_eq!(heading("same_source", EdgeDirection::In), "← same source");
    }

    #[test]
    fn edges_group_by_family_relationship_and_direction() {
        let ego = EgoResponse {
            center: node(1, "claim", "centre"),
            nodes: vec![
                node(2, "claim", "two"),
                node(3, "claim", "three"),
                node(4, "paper", "paper"),
                node(5, "claim", "five"),
            ],
            edges: vec![
                edge(1, 2, "SUPPORTS", "out"),
                edge(1, 2, "supports", "out"), // duplicate after folding
                edge(3, 1, "supports", "in"),
                edge(5, 1, "CONTRADICTS", "in"),
                edge(1, 5, "same_source", "out"),
                edge(1, 3, "derives_from", "sideways"), // direction from ids
            ],
            total_edges: 9,
            truncated: true,
        };
        let o = group_outlinks(&ego, &links());
        let titles: Vec<_> = o.families.iter().map(|f| f.family).collect();
        assert_eq!(
            titles,
            [
                Family::Support,
                Family::Contradiction,
                Family::Lineage,
                Family::Other
            ]
        );
        let support = &o.families[0].groups;
        assert_eq!(support[0].heading, "Supports →");
        assert_eq!(support[0].neighbours.len(), 1, "folded duplicates merge");
        assert_eq!(support[1].heading, "← Supported by");
        assert_eq!(support[1].neighbours[0].id, id(3));
        assert_eq!(o.families[1].groups[0].heading, "← Contradicted by");
        assert_eq!(o.families[2].groups[0].heading, "Derived from →");
        assert_eq!(o.families[3].groups[0].heading, "same source →");
        assert_eq!((o.shown_edges, o.total_edges, o.truncated), (6, 9, true));
        assert_eq!(o.graph_url, format!("/explorer/claim/{}/graph", id(1)));
    }

    #[test]
    fn neighbours_link_by_entity_type_and_fall_back_to_text() {
        let mut paper_edge = edge(4, 1, "asserts", "in");
        paper_edge.source_type = "paper".into();
        let mut agent_edge = edge(1, 6, "ATTRIBUTED_TO", "out");
        agent_edge.target_type = "agent".into();
        let ego = EgoResponse {
            center: node(1, "claim", "c"),
            // `paper` is hydrated, `agent` is one of upstream's unhydrated
            // nodes (label == entity_type, no content).
            nodes: vec![node(4, "paper", "paper"), node(6, "agent", "agent")],
            edges: vec![paper_edge, agent_edge],
            total_edges: 2,
            truncated: false,
        };
        let o = group_outlinks(&ego, &links());
        let all: Vec<&Neighbour> = o
            .families
            .iter()
            .flat_map(|f| f.groups.iter().flat_map(|g| g.neighbours.iter()))
            .collect();
        let paper = all.iter().find(|n| n.id == id(4)).unwrap();
        assert_eq!(paper.href, None, "papers have no page");
        assert_eq!(paper.text, format!("paper {}", short_id(id(4))));
        let agent = all.iter().find(|n| n.id == id(6)).unwrap();
        assert_eq!(
            agent.href.as_deref(),
            Some(format!("/explorer/agent/{}", id(6)).as_str())
        );
        assert!(!o.truncated);
    }

    /// A claim the viewer may not read is absent from `nodes` (`68b8a8b1`).
    /// An edge naming one must be dropped, not rendered as a linked
    /// "claim <short-id>" — that fallback was the last path by which an
    /// invisible claim's uuid could reach a page.
    #[test]
    fn edges_whose_neighbour_is_absent_are_dropped() {
        let ego = EgoResponse {
            center: node(1, "claim", "centre"),
            nodes: vec![node(2, "claim", "two")],
            edges: vec![edge(1, 2, "supports", "out"), edge(1, 7, "refines", "out")],
            total_edges: 2,
            truncated: false,
        };
        let o = group_outlinks(&ego, &links());
        let all: Vec<&Neighbour> = o
            .families
            .iter()
            .flat_map(|f| f.groups.iter().flat_map(|g| g.neighbours.iter()))
            .collect();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, id(2));
        assert_eq!(o.shown_edges, 1, "the dropped edge is not counted as shown");
        let rendered = format!("{o:?}");
        assert!(
            !rendered.contains(&id(7).to_string()),
            "the absent claim's id must not reach the page: {rendered}"
        );
    }

    /// `/ego` counts `total_edges` inside its viewer-filtered read and sets
    /// `truncated` only for its degree cap. A response where the two simply
    /// disagree (fewer edges than `total_edges`, `truncated: false`) must not
    /// raise the truncation notice: that link is dead — the graph view reads
    /// the same `/ego` — and the count would disclose how many neighbours the
    /// viewer may not see.
    #[test]
    fn a_short_edge_list_alone_is_not_truncation() {
        let ego = EgoResponse {
            center: node(1, "claim", "centre"),
            nodes: vec![node(2, "claim", "two")],
            edges: vec![edge(1, 2, "supports", "out")],
            total_edges: 9,
            truncated: false,
        };
        let o = group_outlinks(&ego, &links());
        assert!(
            !o.truncated,
            "truncation is upstream's to declare, never inferred from the counts"
        );
        assert_eq!(o.shown_edges, 1);
        assert_eq!(
            o.total_edges, 9,
            "upstream's total is reported verbatim, not raised to the shown count"
        );

        // And the cap flag alone is enough, even when the counts agree.
        let ego = EgoResponse {
            truncated: true,
            total_edges: 1,
            ..ego
        };
        assert!(group_outlinks(&ego, &links()).truncated);
    }
}
