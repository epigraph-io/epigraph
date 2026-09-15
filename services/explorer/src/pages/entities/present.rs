//! Pure presentation for the entities pages: formatting, query parsing,
//! duplicate detection in version histories, and the provenance-chain
//! layout. No I/O.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use url::form_urlencoded;
use uuid::Uuid;

use crate::links::Links;
use crate::upstream::entities::ClaimVersion;
use crate::upstream::{truncate_chars, ChainNode, ProvenanceChainResponse, REDACTED};

/// What a redacted claim reads as on these pages.
pub const HIDDEN_TEXT: &str = "Content hidden. You do not have access to this claim's text.";
/// `?max_depth=` on the provenance page when absent or unparseable
/// (the MCP tool's default, plan §2.1).
pub const DEFAULT_PROVENANCE_DEPTH: u32 = 4;

// ---- formatting ----------------------------------------------------------------

/// A probability-like number to two places, or an em dash.
pub fn fmt_prob(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{x:.2}"),
        _ => "—".into(),
    }
}

/// An upstream timestamp as `YYYY-MM-DD HH:MM UTC`. Upstream mixes `Z` and
/// `+00:00`; anything unparseable is shown as sent (cut to 40 chars).
pub fn fmt_time(raw: Option<&str>) -> String {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return "—".into();
    };
    match DateTime::parse_from_rfc3339(raw) {
        Ok(t) => t
            .with_timezone(&Utc)
            .format("%Y-%m-%d %H:%M UTC")
            .to_string(),
        Err(_) => truncate_chars(raw, 40),
    }
}

/// First 8 hex digits of a UUID, for compact references.
pub fn short_id(id: Uuid) -> String {
    let s = id.simple().to_string();
    s[..8].to_string()
}

/// Claim text ready for a template: cut on a char boundary, with redaction
/// made explicit so templates can style it (`.claim-text--redacted`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimText {
    pub text: String,
    pub redacted: bool,
    /// True when the text was cut to fit.
    pub cut: bool,
}

pub fn claim_text(content: &str, max_chars: usize) -> ClaimText {
    let trimmed = content.trim();
    if trimmed == REDACTED {
        return ClaimText {
            text: HIDDEN_TEXT.into(),
            redacted: true,
            cut: false,
        };
    }
    if trimmed.is_empty() {
        return ClaimText {
            text: "(no text recorded)".into(),
            redacted: false,
            cut: false,
        };
    }
    let text = truncate_chars(trimmed, max_chars);
    let cut = text.len() != trimmed.len();
    ClaimText {
        text,
        redacted: false,
        cut,
    }
}

// ---- query parsing ---------------------------------------------------------------

/// The last value of `key` in a raw query string. Hand-parsed rather than
/// `Query<T>` so a repeated or odd parameter can never turn into a 400.
pub fn query_param(raw: Option<&str>, key: &str) -> Option<String> {
    form_urlencoded::parse(raw.unwrap_or("").as_bytes())
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .last()
}

/// `?max_depth=` → `lo..=hi`; anything unparseable is `default`. A wide
/// integer is parsed first so `-3` and `300` clamp instead of failing.
pub fn parse_depth(raw: Option<&str>, default: u32, (lo, hi): (u32, u32)) -> u32 {
    match raw.and_then(|s| s.trim().parse::<i64>().ok()) {
        Some(d) => d.clamp(i64::from(lo), i64::from(hi)) as u32,
        None => default.clamp(lo, hi),
    }
}

// ---- history -----------------------------------------------------------------------

/// For each version, the index of the version it is a duplicate of, when it
/// was (by inference) reached through `mark_duplicate` rather than a real
/// supersession.
///
/// `mark_duplicate` writes `dup.supersedes = canonical` and retires the
/// duplicate, so `/history` lists the duplicate as a *later* version that is
/// not current (claims-endpoints §7). A real supersession always leaves a
/// newer version behind. So a later version is a duplicate of its
/// predecessor when it is not current and either the predecessor is still
/// current, or nothing supersedes it (it is the last version and has no
/// `superseded_by`).
pub fn duplicate_of(versions: &[ClaimVersion]) -> Vec<Option<usize>> {
    versions
        .iter()
        .enumerate()
        .map(|(i, v)| {
            if i == 0 || v.is_current {
                return None;
            }
            let prev_current = versions[i - 1].is_current;
            let dead_end = i + 1 == versions.len() && v.superseded_by.is_none();
            (prev_current || dead_end).then_some(i - 1)
        })
        .collect()
}

// ---- provenance chain --------------------------------------------------------------

/// A compact, linked mention of a claim in the chain.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeRef {
    pub url: String,
    pub label: String,
    pub redacted: bool,
}

/// One edge, read from the node it is listed under.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainLink {
    /// "supports", "superseded by", … (`{node} {phrase} {other}`).
    pub phrase: String,
    pub other: NodeRef,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainNodeView {
    pub id: Uuid,
    pub url: String,
    pub text: ClaimText,
    /// `is_current == false`: a superseded ancestor.
    pub superseded: bool,
    pub truth: String,
    pub labels: Vec<String>,
    pub in_cycle: bool,
    pub links: Vec<ChainLink>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainLevel {
    pub depth: u32,
    pub title: String,
    pub nodes: Vec<ChainNodeView>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainLayout {
    /// Depth 0 (the root) first.
    pub levels: Vec<ChainLevel>,
    /// Each cycle as a closed walk (the first node repeated at the end).
    pub cycles: Vec<Vec<NodeRef>>,
    /// Nodes other than the root.
    pub ancestor_count: usize,
}

/// Longest claim text shown per chain node.
const CHAIN_TEXT_CHARS: usize = 400;
/// Longest claim text in a [`NodeRef`].
const REF_TEXT_CHARS: usize = 90;
/// Labels shown per chain node.
const CHAIN_LABELS: usize = 6;

fn is_hidden(n: &ChainNode) -> bool {
    n.redacted || n.content.trim() == REDACTED
}

/// Group the chain by depth and attach every edge to exactly one node.
///
/// Upstream stores evidence relationships ancestor → descendant and
/// `supersedes` new → old, and sends edges in arbitrary order. Each edge is
/// listed under its *upstream* end — the deeper endpoint (ties go to the
/// source) — and phrased from that node: "A supports B", "O superseded by
/// N". So the root (depth 0) shows no edges of its own and every ancestor
/// says how it feeds the claims below it.
pub fn layout_chain(chain: &ProvenanceChainResponse, links: &Links) -> ChainLayout {
    let by_id: HashMap<Uuid, &ChainNode> = chain.nodes.iter().map(|n| (n.id, n)).collect();
    let in_cycle: HashSet<Uuid> = chain.cycles.iter().flatten().copied().collect();

    let node_ref = |id: Uuid| -> NodeRef {
        match by_id.get(&id) {
            Some(n) if is_hidden(n) => NodeRef {
                url: links.claim(id),
                label: format!("Hidden claim {}", short_id(id)),
                redacted: true,
            },
            Some(n) if !n.content.trim().is_empty() => NodeRef {
                url: links.claim(id),
                label: truncate_chars(n.content.trim(), REF_TEXT_CHARS),
                redacted: false,
            },
            _ => NodeRef {
                url: links.claim(id),
                label: format!("Claim {}", short_id(id)),
                redacted: false,
            },
        }
    };

    let mut edge_links: HashMap<Uuid, Vec<ChainLink>> = HashMap::new();
    for e in &chain.edges {
        let depth = |id: Uuid| by_id.get(&id).map(|n| n.depth);
        let holder_is_source = match (depth(e.source), depth(e.target)) {
            (Some(s), Some(t)) => s >= t,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => continue,
        };
        let (holder, other) = if holder_is_source {
            (e.source, e.target)
        } else {
            (e.target, e.source)
        };
        edge_links.entry(holder).or_default().push(ChainLink {
            phrase: relationship_phrase(&e.relationship, holder_is_source),
            other: node_ref(other),
        });
    }
    for v in edge_links.values_mut() {
        v.sort_by(|a, b| {
            (a.phrase.as_str(), a.other.label.as_str())
                .cmp(&(b.phrase.as_str(), b.other.label.as_str()))
        });
        v.dedup();
    }

    // Upstream order is topological with the root last; reversed, each level
    // reads from the claims nearest the root outwards.
    let mut levels: BTreeMap<u32, Vec<ChainNodeView>> = BTreeMap::new();
    for n in chain.nodes.iter().rev() {
        let depth = if n.id == chain.root { 0 } else { n.depth };
        let text = if is_hidden(n) {
            claim_text(REDACTED, CHAIN_TEXT_CHARS)
        } else {
            claim_text(&n.content, CHAIN_TEXT_CHARS)
        };
        levels.entry(depth).or_default().push(ChainNodeView {
            id: n.id,
            url: links.claim(n.id),
            text,
            superseded: n.is_current == Some(false),
            truth: fmt_prob(n.truth_value),
            labels: n
                .labels
                .iter()
                .take(CHAIN_LABELS)
                .map(|l| truncate_chars(l, 60))
                .collect(),
            in_cycle: in_cycle.contains(&n.id),
            links: edge_links.remove(&n.id).unwrap_or_default(),
        });
    }

    let cycles = chain
        .cycles
        .iter()
        .filter(|c| !c.is_empty())
        .map(|c| {
            let mut walk: Vec<NodeRef> = c.iter().map(|id| node_ref(*id)).collect();
            if c.len() > 1 && c.first() != c.last() {
                walk.push(node_ref(c[0]));
            }
            walk
        })
        .collect();

    ChainLayout {
        levels: levels
            .into_iter()
            .map(|(depth, nodes)| ChainLevel {
                depth,
                title: match depth {
                    0 => "This claim".to_string(),
                    1 => "Direct sources · depth 1".to_string(),
                    d => format!("Depth {d}"),
                },
                nodes,
            })
            .collect(),
        cycles,
        ancestor_count: chain.nodes.iter().filter(|n| n.id != chain.root).count(),
    }
}

/// How an edge reads from the node it is listed under. `from_source`: that
/// node is the edge's stored source ("A supports B"); otherwise it is the
/// target and the phrase is passive ("O superseded by N").
pub fn relationship_phrase(relationship: &str, from_source: bool) -> String {
    let key = relationship.trim().to_ascii_lowercase();
    let human = truncate_chars(&key.replace('_', " "), 40);
    if from_source {
        return if human.is_empty() {
            "linked to".into()
        } else {
            human
        };
    }
    match key.as_str() {
        "supersedes" => "superseded by".into(),
        "supports" => "supported by".into(),
        "corroborates" => "corroborated by".into(),
        "elaborates" => "elaborated by".into(),
        "decomposes_to" => "part of".into(),
        "" => "linked from".into(),
        _ => format!("target of {human} from"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{ChainEdge, ChainNode};

    fn uid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn links() -> Links {
        Links::new("https://explorer.example.com", "/explorer")
    }

    #[test]
    fn numbers_and_times() {
        assert_eq!(fmt_prob(Some(0.456)), "0.46");
        assert_eq!(fmt_prob(None), "—");
        assert_eq!(fmt_prob(Some(f64::NAN)), "—");
        assert_eq!(
            fmt_time(Some("2026-01-02T03:04:05Z")),
            "2026-01-02 03:04 UTC"
        );
        assert_eq!(
            fmt_time(Some("2026-01-02T05:04:05+02:00")),
            "2026-01-02 03:04 UTC"
        );
        assert_eq!(fmt_time(Some("yesterday")), "yesterday");
        assert_eq!(fmt_time(None), "—");
        assert_eq!(
            short_id(uid(0xabcdef12_0000_0000_0000_000000000000)),
            "abcdef12"
        );
    }

    #[test]
    fn claim_text_redacts_and_cuts_on_chars() {
        let t = claim_text("[REDACTED]", 10);
        assert!(t.redacted && t.text == HIDDEN_TEXT);
        let t = claim_text("μμμμμ", 3);
        assert_eq!(t.text, "μμμ…");
        assert!(t.cut);
        let t = claim_text("  short ", 10);
        assert_eq!(t.text, "short");
        assert!(!t.cut);
    }

    #[test]
    fn query_params_clamp_and_never_fail() {
        assert_eq!(
            query_param(Some("page=2&page=3"), "page").as_deref(),
            Some("3")
        );
        assert_eq!(query_param(None, "page"), None);
        assert_eq!(parse_depth(Some("300"), 4, (1, 8)), 8);
        assert_eq!(parse_depth(Some("-3"), 4, (1, 8)), 1);
        assert_eq!(parse_depth(Some("x"), 4, (1, 8)), 4);
        assert_eq!(parse_depth(None, 4, (1, 8)), 4);
    }

    fn version(n: u32, current: bool, superseded_by: Option<Uuid>) -> ClaimVersion {
        ClaimVersion {
            claim_id: uid(u128::from(n)),
            content: format!("v{n}"),
            truth_value: None,
            version: n,
            is_current: current,
            created_at: None,
            superseded_by,
        }
    }

    #[test]
    fn duplicates_are_inferred_from_retirement_shape() {
        // Plain supersession: v1 → v2 (current).
        let v = [version(1, false, Some(uid(2))), version(2, true, None)];
        assert_eq!(duplicate_of(&v), [None, None]);

        // mark_duplicate: the canonical stays current, the dup follows it.
        let v = [version(1, true, None), version(2, false, None)];
        assert_eq!(duplicate_of(&v), [None, Some(0)]);

        // Canonical later superseded elsewhere; the walk picked the dup.
        let v = [version(1, false, Some(uid(2))), version(2, false, None)];
        assert_eq!(duplicate_of(&v), [None, Some(0)]);

        // Middle version retired by a real supersession is not a duplicate.
        let v = [
            version(1, false, Some(uid(2))),
            version(2, false, Some(uid(3))),
            version(3, true, None),
        ];
        assert_eq!(duplicate_of(&v), [None, None, None]);
        assert!(duplicate_of(&[]).is_empty());
    }

    fn node(n: u128, depth: u32, content: &str) -> ChainNode {
        ChainNode {
            id: uid(n),
            content: content.into(),
            truth_value: Some(0.5),
            labels: vec![],
            is_current: Some(true),
            depth,
            redacted: false,
        }
    }

    fn edge(s: u128, t: u128, rel: &str) -> ChainEdge {
        ChainEdge {
            source: uid(s),
            target: uid(t),
            relationship: rel.into(),
        }
    }

    #[test]
    fn chain_levels_edges_cycles_and_redaction() {
        let mut old = node(3, 1, "old version");
        old.is_current = Some(false);
        let mut hidden = node(4, 2, "[REDACTED]");
        hidden.redacted = true;
        let chain = ProvenanceChainResponse {
            root: uid(1),
            // Evidence first, root last.
            nodes: vec![
                hidden,
                node(2, 1, "evidence claim"),
                old,
                node(1, 0, "root"),
            ],
            edges: vec![
                edge(2, 1, "supports"),
                edge(1, 3, "SUPERSEDES"),
                edge(4, 2, "decomposes_to"),
                edge(2, 4, "corroborates"),
            ],
            truncated: false,
            cycles: vec![vec![uid(2), uid(4)]],
        };
        let l = layout_chain(&chain, &links());
        assert_eq!(l.ancestor_count, 3);
        assert_eq!(
            l.levels.iter().map(|x| x.depth).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(l.levels[0].nodes.len(), 1);
        assert!(l.levels[0].nodes[0].links.is_empty(), "root lists no edges");

        let lvl1 = &l.levels[1].nodes;
        let ev = lvl1.iter().find(|n| n.id == uid(2)).unwrap();
        assert_eq!(ev.links.len(), 1);
        assert_eq!(ev.links[0].phrase, "supports");
        assert_eq!(ev.links[0].other.label, "root");
        assert!(ev.in_cycle);

        let old = lvl1.iter().find(|n| n.id == uid(3)).unwrap();
        assert!(old.superseded);
        assert_eq!(old.links[0].phrase, "superseded by");

        let hidden = &l.levels[2].nodes[0];
        assert!(hidden.text.redacted);
        assert!(!hidden.text.text.contains("REDACTED"));
        // The deeper end holds both edges between 2 and 4.
        let phrases: Vec<_> = hidden.links.iter().map(|x| x.phrase.as_str()).collect();
        assert_eq!(phrases, ["corroborated by", "decomposes to"]);

        assert_eq!(l.cycles.len(), 1);
        let walk: Vec<_> = l.cycles[0].iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            walk,
            ["evidence claim", "Hidden claim 00000000", "evidence claim"]
        );
        assert!(l.cycles[0][1].redacted);
    }

    #[test]
    fn chain_edges_to_unknown_nodes_still_link() {
        let chain = ProvenanceChainResponse {
            root: uid(1),
            nodes: vec![node(1, 0, "root")],
            edges: vec![edge(9, 1, "supports"), edge(8, 7, "supports")],
            truncated: true,
            cycles: vec![],
        };
        let l = layout_chain(&chain, &links());
        // Edge 9 → 1: only the target is known, so it is listed on the root.
        let root = &l.levels[0].nodes[0];
        assert_eq!(root.links.len(), 1);
        assert_eq!(root.links[0].phrase, "supported by");
        assert!(root.links[0].other.label.starts_with("Claim "));
        assert_eq!(l.ancestor_count, 0);
        assert_eq!(
            relationship_phrase("RELATES_TO", false),
            "target of relates to from"
        );
        assert_eq!(relationship_phrase("", true), "linked to");
    }
}
