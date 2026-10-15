//! `/bff/graph/ego/:id`, `/bff/themes`, `/bff/communities`,
//! `/bff/neighborhood/:id` (plan §3.4). OWNED BY THE GRAPH AREA.
//!
//! The two graph routes answer one canvas-ready shape ([`CanvasGraph`]) that
//! `static/graph.js` renders and merges without knowing which upstream
//! route produced it:
//!
//! ```text
//! { "center": uuid|null,
//!   "nodes": [{ id, entity_type, label, content, truth_value, pignistic_prob,
//!               labels, is_current, is_center, frame_id, atom_count,
//!               kind, href, expand_href, graph_href }],
//!   "edges": [{ id, source, target, relationship, family, directed, strength }],
//!   "total_edges": n, "truncated": bool, "hidden_nodes": n, … }
//! ```
//!
//! Every URL in it is built here from [`Links`] (base-path aware), so the
//! JS never assembles one. A claim the viewer may not read is absent from
//! the upstream payload entirely (`68b8a8b1`), so no node here needs
//! blanking. The overviews are cached for 60 s per viewer
//! ([`RequestAuth::cache_key`]); upstream visibility differs per viewer, so
//! one viewer's cached body is never served to another.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{RequestAuth, SignedIn};
use crate::error::{not_found_as, AppError};
use crate::links::Links;
use crate::state::AppState;
use crate::upstream::graph::{
    CommunitiesOverview, CompoundGroup, NeighborhoodExpand, NeighborhoodMode, ThemesOverview,
    WeightedEdge,
};
use crate::upstream::{truncate_chars, EgoNode, EgoResponse, DEFAULT_EGO_DEGREE, MAX_EGO_DEGREE};

/// Most nodes a canvas payload carries (plan §3.6); graph.js enforces the
/// same cap across merges.
pub const VISIBLE_NODE_CAP: usize = 150;
/// Per-viewer cache lifetime of `/bff/themes` and `/bff/communities`.
pub const OVERVIEW_TTL: Duration = Duration::from_secs(60);
/// Most themes / supernodes an overview returns (upstream is unbounded).
pub const OVERVIEW_ITEM_CAP: usize = 500;
/// Most cluster edges an overview returns.
pub const OVERVIEW_EDGE_CAP: usize = 2000;
/// Node labels, cut on a char boundary (matches the ego route's 160).
pub const LABEL_CHARS: usize = 160;
/// Claim text carried for the canvas side panel.
pub const CONTENT_CHARS: usize = 1000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/bff/graph/ego/{id}", get(ego))
        .route("/bff/themes", get(themes))
        .route("/bff/communities", get(communities))
        .route("/bff/neighborhood/{id}", get(neighborhood))
}

// ---- canvas shape -----------------------------------------------------------------

/// A graph as `static/graph.js` consumes it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CanvasGraph {
    /// The ego centre; `None` for a neighbourhood.
    pub center: Option<Uuid>,
    pub nodes: Vec<CanvasNode>,
    pub edges: Vec<CanvasEdge>,
    /// Distinct upstream edges before any cap (ego: before the degree cap).
    pub total_edges: u64,
    /// Upstream or the BFF left something out.
    pub truncated: bool,
    /// Nodes dropped by [`VISIBLE_NODE_CAP`].
    pub hidden_nodes: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CanvasNode {
    pub id: Uuid,
    pub entity_type: String,
    /// One line, ≤ [`LABEL_CHARS`].
    pub label: String,
    /// Claim text for the side panel, ≤ [`CONTENT_CHARS`].
    pub content: Option<String>,
    pub truth_value: Option<f64>,
    pub pignistic_prob: Option<f64>,
    pub labels: Vec<String>,
    pub is_current: Option<bool>,
    pub is_center: bool,
    /// Hue key for the canvas (neighbourhood nodes only).
    pub frame_id: Option<Uuid>,
    /// Radius key for the canvas (compound neighbourhood nodes only).
    pub atom_count: Option<i64>,
    /// `compound` / `standalone` / `atom` for neighbourhood nodes.
    pub kind: Option<String>,
    /// The node's page, if its entity type has one.
    pub href: Option<String>,
    /// `/bff/graph/ego/:id`. Every node upstream returns is one the viewer
    /// may read, so every claim node gets one.
    pub expand_href: Option<String>,
    /// `/claim/:id/graph`.
    pub graph_href: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CanvasEdge {
    /// Upstream edge id, or `source|target|relationship` when there is none.
    pub id: String,
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
    /// `support`, `refute` or `structural` (see [`relationship_family`]).
    pub family: &'static str,
    /// Draw an arrowhead at `target`.
    pub directed: bool,
    pub strength: Option<f64>,
}

/// Edge style family for a raw upstream relationship (case-folded; `-` and
/// spaces read as `_`). Mirrors the support and refute groups of the
/// kernel's `GRAPH_VIEW_RELATIONSHIPS` (`routes/graph.rs:29-66`); every
/// other relationship is drawn as structural.
pub fn relationship_family(relationship: &str) -> &'static str {
    let r = relationship
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    match r.as_str() {
        "supports" | "corroborates" | "provides_evidence" | "asserts" | "enables" => "support",
        "refutes" | "contradicts" | "challenges" => "refute",
        _ => "structural",
    }
}

/// Whitespace collapsed to single spaces, then cut to `max` chars.
pub fn one_line(s: &str, max: usize) -> String {
    let joined = s.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&joined, max)
}

impl CanvasNode {
    /// A claim node from an expand payload, where `label` is the claim text
    /// itself.
    pub fn from_claim_label(id: Uuid, label: &str, links: &Links) -> Self {
        CanvasNode {
            id,
            entity_type: "claim".into(),
            label: non_empty_line(label).unwrap_or_else(|| id.to_string()),
            content: Some(truncate_chars(label.trim(), CONTENT_CHARS)),
            truth_value: None,
            pignistic_prob: None,
            labels: Vec::new(),
            is_current: None,
            is_center: false,
            frame_id: None,
            atom_count: None,
            kind: None,
            href: Some(links.claim(id)),
            expand_href: Some(links.bff_graph_ego(id, None)),
            graph_href: Some(links.claim_graph(id)),
        }
    }
}

fn non_empty_line(s: &str) -> Option<String> {
    let line = one_line(s, LABEL_CHARS);
    (!line.is_empty()).then_some(line)
}

fn ego_node(n: EgoNode, is_center: bool, links: &Links) -> CanvasNode {
    let is_claim = n.entity_type.eq_ignore_ascii_case("claim");
    let label = non_empty_line(&n.label)
        .or_else(|| n.content.as_deref().and_then(non_empty_line))
        .or_else(|| non_empty_line(&n.entity_type))
        .unwrap_or_else(|| n.id.to_string());
    CanvasNode {
        id: n.id,
        href: links.entity(&n.entity_type, n.id),
        expand_href: is_claim.then(|| links.bff_graph_ego(n.id, None)),
        graph_href: is_claim.then(|| links.claim_graph(n.id)),
        entity_type: n.entity_type,
        label,
        content: n
            .content
            .as_deref()
            .map(|c| truncate_chars(c.trim(), CONTENT_CHARS)),
        truth_value: n.truth_value,
        pignistic_prob: n.pignistic_prob,
        labels: n.labels,
        is_current: n.is_current,
        is_center,
        frame_id: None,
        atom_count: None,
        kind: None,
    }
}

/// Keep the first [`VISIBLE_NODE_CAP`] distinct nodes and the edges whose
/// endpoints both survive, de-duplicated by id. Returns the graph with
/// `hidden_nodes` set; the caller sets `center` and `truncated`.
fn cap_graph(
    nodes: Vec<CanvasNode>,
    edges: Vec<CanvasEdge>,
) -> (Vec<CanvasNode>, Vec<CanvasEdge>, usize) {
    let mut seen = HashSet::new();
    let mut kept: Vec<CanvasNode> = nodes.into_iter().filter(|n| seen.insert(n.id)).collect();
    let hidden = kept.len().saturating_sub(VISIBLE_NODE_CAP);
    kept.truncate(VISIBLE_NODE_CAP);

    let ids: HashSet<Uuid> = kept.iter().map(|n| n.id).collect();
    let mut edge_ids = HashSet::new();
    let edges = edges
        .into_iter()
        .filter(|e| ids.contains(&e.source) && ids.contains(&e.target))
        .filter(|e| edge_ids.insert(e.id.clone()))
        .collect();
    (kept, edges, hidden)
}

/// `/claims/:id/ego` → canvas. The centre is always the first node. A
/// centre the viewer may not read is a 404 upstream, so it never gets here.
pub fn canvas_from_ego(ego: EgoResponse, links: &Links) -> CanvasGraph {
    let center_id = ego.center.id;
    let center = ego_node(ego.center, true, links);

    let mut nodes = Vec::with_capacity(ego.nodes.len() + 1);
    nodes.push(center);
    nodes.extend(
        ego.nodes
            .into_iter()
            .filter(|n| n.id != center_id)
            .map(|n| ego_node(n, false, links)),
    );
    let edges: Vec<CanvasEdge> = ego
        .edges
        .into_iter()
        .map(|e| CanvasEdge {
            id: e.id.to_string(),
            source: e.source_id,
            target: e.target_id,
            family: relationship_family(&e.relationship),
            relationship: e.relationship,
            directed: true,
            strength: None,
        })
        .collect();
    let (nodes, edges, hidden_nodes) = cap_graph(nodes, edges);
    CanvasGraph {
        center: Some(center_id),
        nodes,
        edges,
        total_edges: ego.total_edges,
        truncated: ego.truncated || hidden_nodes > 0,
        hidden_nodes,
    }
}

impl CanvasEdge {
    /// An edge without an upstream id, keyed `source|target|relationship`.
    /// Undirected edges are always drawn as structural.
    pub fn keyed(
        source: Uuid,
        target: Uuid,
        relationship: String,
        directed: bool,
        strength: Option<f64>,
    ) -> Self {
        CanvasEdge {
            id: format!("{source}|{target}|{relationship}"),
            source,
            target,
            family: if directed {
                relationship_family(&relationship)
            } else {
                "structural"
            },
            relationship,
            directed,
            strength,
        }
    }
}

/// A compound group of an atomic neighbourhood.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GroupItem {
    pub compound_id: Uuid,
    pub label: String,
    pub member_count: usize,
    pub href: String,
}

fn group_item(g: CompoundGroup, links: &Links) -> GroupItem {
    GroupItem {
        compound_id: g.compound_id,
        label: non_empty_line(&g.label).unwrap_or_else(|| g.compound_id.to_string()),
        member_count: g.member_atom_ids.len(),
        href: links.claim(g.compound_id),
    }
}

/// `/graph/neighborhoods/:id/expand` → canvas plus the atomic groups. The
/// three compound edge arrays are merged into one list and de-duplicated
/// (upstream `direct_edges` has no DISTINCT).
pub fn canvas_from_neighborhood(
    n: NeighborhoodExpand,
    links: &Links,
) -> (CanvasGraph, Vec<GroupItem>) {
    let (nodes, edges, upstream_truncated, groups) =
        match n {
            NeighborhoodExpand::Compound(c) => {
                let nodes = c
                    .nodes
                    .into_iter()
                    .map(|n| {
                        let mut node = CanvasNode::from_claim_label(n.id, &n.label, links);
                        node.kind = Some(n.kind).filter(|k| !k.is_empty());
                        node.atom_count = (n.atom_count > 0).then_some(n.atom_count);
                        node.pignistic_prob = n.pignistic_prob;
                        node.frame_id = n.frame_id;
                        node
                    })
                    .collect::<Vec<_>>();
                let mut edges = Vec::new();
                edges.extend(c.induced_edges.into_iter().map(|e| {
                    CanvasEdge::keyed(e.source, e.target, e.relationship, true, e.strength)
                }));
                edges.extend(
                    c.direct_edges
                        .into_iter()
                        .map(|e| CanvasEdge::keyed(e.source, e.target, e.relationship, true, None)),
                );
                edges.extend(
                    c.structural_edges
                        .into_iter()
                        .map(|e| CanvasEdge::keyed(e.source, e.target, e.kind, false, None)),
                );
                (nodes, edges, c.truncated, Vec::new())
            }
            NeighborhoodExpand::Atomic(a) => {
                let nodes = a
                    .nodes
                    .into_iter()
                    .map(|n| {
                        let mut node = CanvasNode::from_claim_label(n.id, &n.label, links);
                        node.kind = Some("atom".into());
                        node.pignistic_prob = n.pignistic_prob;
                        node.frame_id = n.frame_id;
                        node
                    })
                    .collect::<Vec<_>>();
                let edges = a
                    .edges
                    .into_iter()
                    .map(|e| CanvasEdge::keyed(e.source, e.target, e.relationship, true, None))
                    .collect::<Vec<_>>();
                let groups = a
                    .compound_groups
                    .into_iter()
                    .take(VISIBLE_NODE_CAP)
                    .map(|g| group_item(g, links))
                    .collect();
                (nodes, edges, a.truncated, groups)
            }
        };
    let total_edges = edges
        .iter()
        .map(|e| e.id.as_str())
        .collect::<HashSet<_>>()
        .len() as u64;
    let (nodes, edges, hidden_nodes) = cap_graph(nodes, edges);
    (
        CanvasGraph {
            center: None,
            nodes,
            edges,
            total_edges,
            truncated: upstream_truncated || hidden_nodes > 0,
            hidden_nodes,
        },
        groups,
    )
}

// ---- overview shapes --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ThemesBody {
    pub themes: Vec<ThemeItem>,
    /// Themes upstream returned, before [`OVERVIEW_ITEM_CAP`].
    pub total: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ThemeItem {
    pub id: Uuid,
    pub label: String,
    pub claim_count: i64,
    pub href: String,
}

pub fn themes_body(o: ThemesOverview, links: &Links) -> ThemesBody {
    let total = o.themes.len();
    let themes = o
        .themes
        .into_iter()
        .take(OVERVIEW_ITEM_CAP)
        .map(|t| ThemeItem {
            href: links.theme(t.id),
            label: non_empty_line(&t.label).unwrap_or_else(|| t.id.to_string()),
            id: t.id,
            claim_count: t.claim_count,
        })
        .collect();
    ThemesBody {
        themes,
        total,
        truncated: total > OVERVIEW_ITEM_CAP,
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CommunitiesBody {
    pub run_id: Option<Uuid>,
    pub generated_at: Option<DateTime<Utc>>,
    pub degraded: bool,
    /// `"no_clusters_computed"` when clustering has never run.
    pub status: Option<String>,
    pub supernodes: Vec<SupernodeItem>,
    /// Only edges between returned supernodes, ≤ [`OVERVIEW_EDGE_CAP`].
    pub cluster_edges: Vec<WeightedEdge>,
    /// Supernodes upstream returned, before [`OVERVIEW_ITEM_CAP`].
    pub total: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SupernodeItem {
    pub cluster_id: Uuid,
    pub label: String,
    pub size: i64,
    pub mean_betp: Option<f64>,
    pub dominant_type: Option<String>,
    pub dominant_frame_id: Option<Uuid>,
    pub href: String,
    pub frame_href: Option<String>,
}

pub fn communities_body(o: CommunitiesOverview, links: &Links) -> CommunitiesBody {
    let total = o.supernodes.len();
    let supernodes: Vec<SupernodeItem> = o
        .supernodes
        .into_iter()
        .take(OVERVIEW_ITEM_CAP)
        .map(|s| SupernodeItem {
            href: links.community(s.cluster_id),
            frame_href: s.dominant_frame_id.map(|f| links.frame(f)),
            label: non_empty_line(&s.label).unwrap_or_else(|| s.cluster_id.to_string()),
            cluster_id: s.cluster_id,
            size: s.size,
            mean_betp: s.mean_betp,
            dominant_type: s.dominant_type,
            dominant_frame_id: s.dominant_frame_id,
        })
        .collect();
    let ids: HashSet<Uuid> = supernodes.iter().map(|s| s.cluster_id).collect();
    let edges_total = o.cluster_edges.len();
    let cluster_edges: Vec<WeightedEdge> = o
        .cluster_edges
        .into_iter()
        .filter(|e| ids.contains(&e.a) && ids.contains(&e.b))
        .take(OVERVIEW_EDGE_CAP)
        .collect();
    CommunitiesBody {
        run_id: o.run_id,
        generated_at: o.generated_at,
        degraded: o.degraded,
        status: o.status,
        truncated: total > OVERVIEW_ITEM_CAP || cluster_edges.len() < edges_total,
        supernodes,
        cluster_edges,
        total,
    }
}

// ---- handlers ---------------------------------------------------------------------

/// Graph JSON is per viewer: never let a shared or browser cache keep it.
fn private_json<T: Serialize>(body: T) -> Response {
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    resp
}

/// A path id; a malformed one is simply "not found" (JSON 404).
fn parse_id(raw: &str, what: &'static str) -> Result<Uuid, AppError> {
    Uuid::parse_str(raw.trim()).map_err(|_| AppError::NotFound(what.into()))
}

/// `?max_degree=`: lenient — non-numbers get the default, numbers are
/// clamped to `1..=MAX_EGO_DEGREE` (plan §3.5).
pub fn parse_max_degree(raw: Option<&str>) -> u32 {
    raw.and_then(|s| s.trim().parse::<i64>().ok())
        .map(|d| d.clamp(1, i64::from(MAX_EGO_DEGREE)) as u32)
        .unwrap_or(DEFAULT_EGO_DEGREE)
}

#[derive(Deserialize)]
struct EgoParams {
    max_degree: Option<String>,
}

#[derive(Serialize)]
struct EgoBody {
    #[serde(flatten)]
    graph: CanvasGraph,
    max_degree: u32,
}

async fn ego(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    Query(q): Query<EgoParams>,
) -> Result<Response, AppError> {
    let id = parse_id(&raw, "claim")?;
    let max_degree = parse_max_degree(q.max_degree.as_deref());
    let ego = user
        .api(&state)
        .ego(id, max_degree, None)
        .await
        .map_err(not_found_as("claim"))?;
    Ok(private_json(EgoBody {
        graph: canvas_from_ego(ego, &state.links),
        max_degree,
    }))
}

fn overview_key(what: &str, auth: &RequestAuth) -> String {
    format!("graph:{what}:{}", auth.cache_key())
}

async fn themes(State(state): State<AppState>, user: SignedIn) -> Result<Response, AppError> {
    let key = overview_key("themes", &user.auth);
    if let Some(hit) = state.cache.get::<ThemesBody>(&key) {
        return Ok(private_json(&*hit));
    }
    let body = themes_body(user.api(&state).themes_overview().await?, &state.links);
    state
        .cache
        .insert(key, Arc::new(body.clone()), OVERVIEW_TTL);
    Ok(private_json(body))
}

async fn communities(State(state): State<AppState>, user: SignedIn) -> Result<Response, AppError> {
    let key = overview_key("communities", &user.auth);
    if let Some(hit) = state.cache.get::<CommunitiesBody>(&key) {
        return Ok(private_json(&*hit));
    }
    let body = communities_body(user.api(&state).communities_overview().await?, &state.links);
    state
        .cache
        .insert(key, Arc::new(body.clone()), OVERVIEW_TTL);
    Ok(private_json(body))
}

#[derive(Deserialize)]
struct ModeParams {
    mode: Option<String>,
}

#[derive(Serialize)]
struct NeighborhoodBody {
    neighborhood_id: Uuid,
    mode: NeighborhoodMode,
    #[serde(flatten)]
    graph: CanvasGraph,
    compound_groups: Vec<GroupItem>,
}

async fn neighborhood(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    Query(q): Query<ModeParams>,
) -> Result<Response, AppError> {
    let id = parse_id(&raw, "neighbourhood")?;
    let requested = NeighborhoodMode::parse(q.mode.as_deref());
    let expand = user
        .api(&state)
        .neighborhood_expand(id, requested)
        .await
        .map_err(not_found_as("neighbourhood"))?;
    let mode = expand.mode();
    let neighborhood_id = expand.neighborhood_id();
    let (graph, compound_groups) = canvas_from_neighborhood(expand, &state.links);
    Ok(private_json(NeighborhoodBody {
        neighborhood_id,
        mode,
        graph,
        compound_groups,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn links() -> Links {
        Links::new("https://explorer.example.com", "/explorer")
    }

    fn uuid(n: u8) -> Uuid {
        Uuid::from_u128(u128::from(n))
    }

    #[test]
    fn families() {
        assert_eq!(relationship_family("SUPPORTS"), "support");
        assert_eq!(relationship_family("corroborates"), "support");
        assert_eq!(relationship_family("provides-evidence"), "support");
        assert_eq!(relationship_family("CONTRADICTS"), "refute");
        assert_eq!(relationship_family(" challenges "), "refute");
        assert_eq!(relationship_family("decomposes_to"), "structural");
        assert_eq!(relationship_family("RELATES_TO"), "structural");
        assert_eq!(relationship_family(""), "structural");
    }

    #[test]
    fn degree_parsing_clamps_and_defaults() {
        assert_eq!(parse_max_degree(None), DEFAULT_EGO_DEGREE);
        assert_eq!(parse_max_degree(Some("abc")), DEFAULT_EGO_DEGREE);
        assert_eq!(parse_max_degree(Some("500")), MAX_EGO_DEGREE);
        assert_eq!(parse_max_degree(Some("-3")), 1);
        assert_eq!(parse_max_degree(Some(" 12 ")), 12);
    }

    #[test]
    fn one_line_collapses_and_cuts_on_chars() {
        assert_eq!(one_line("a\n\n b\tc", 10), "a b c");
        assert_eq!(one_line("μμμμ", 2), "μμ…");
    }

    fn ego_json() -> serde_json::Value {
        json!({
            "center": {"id": uuid(1), "entity_type": "claim", "label": "Centre\nclaim",
                       "content": "Centre claim", "truth_value": 0.7, "pignistic_prob": 0.8,
                       "labels": ["x"], "is_current": true},
            "nodes": [
                {"id": uuid(2), "entity_type": "claim", "label": "Second", "content": "Second claim",
                 "truth_value": 0.2, "labels": ["private"], "is_current": true},
                {"id": uuid(3), "entity_type": "paper", "label": "paper"},
                {"id": uuid(4), "entity_type": "Agent", "label": "Ada"},
                {"id": uuid(4), "entity_type": "Agent", "label": "Ada again"}
            ],
            "edges": [
                {"id": uuid(10), "source_id": uuid(1), "target_id": uuid(2),
                 "source_type": "claim", "target_type": "claim",
                 "relationship": "SUPPORTS", "direction": "out"},
                {"id": uuid(11), "source_id": uuid(3), "target_id": uuid(1),
                 "source_type": "paper", "target_type": "claim",
                 "relationship": "asserts", "direction": "in"},
                {"id": uuid(11), "source_id": uuid(3), "target_id": uuid(1),
                 "source_type": "paper", "target_type": "claim",
                 "relationship": "asserts", "direction": "in"},
                {"id": uuid(12), "source_id": uuid(1), "target_id": uuid(99),
                 "relationship": "refutes", "direction": "out"}
            ],
            "total_edges": 57,
            "truncated": true
        })
    }

    #[test]
    fn ego_canvas_maps_links_and_dedupes() {
        let ego: EgoResponse = serde_json::from_value(ego_json()).unwrap();
        let g = canvas_from_ego(ego, &links());
        assert_eq!(g.center, Some(uuid(1)));
        assert_eq!(g.total_edges, 57);
        assert!(g.truncated);
        assert_eq!(g.hidden_nodes, 0);

        let ids: Vec<Uuid> = g.nodes.iter().map(|n| n.id).collect();
        assert_eq!(
            ids,
            [uuid(1), uuid(2), uuid(3), uuid(4)],
            "centre first, deduped"
        );

        let c = &g.nodes[0];
        assert!(c.is_center);
        assert_eq!(c.label, "Centre claim");
        assert_eq!(c.href.as_deref(), Some(&*links().claim(uuid(1))));
        assert_eq!(
            c.expand_href.as_deref(),
            Some(&*links().bff_graph_ego(uuid(1), None))
        );
        assert_eq!(
            c.graph_href.as_deref(),
            Some(&*links().claim_graph(uuid(1)))
        );

        let second = &g.nodes[1];
        assert_eq!(second.label, "Second");
        assert_eq!(second.content.as_deref(), Some("Second claim"));
        assert_eq!(second.truth_value, Some(0.2));
        assert_eq!(
            second.expand_href.as_deref(),
            Some(&*links().bff_graph_ego(uuid(2), None))
        );
        assert_eq!(second.href.as_deref(), Some(&*links().claim(uuid(2))));

        let paper = &g.nodes[2];
        assert!(paper.href.is_none(), "papers have no page");
        assert!(paper.expand_href.is_none(), "only claims have an ego");
        assert_eq!(g.nodes[3].href.as_deref(), Some(&*links().agent(uuid(4))));
        assert_eq!(g.nodes[3].label, "Ada");

        // Duplicate edge dropped; the edge to a node upstream did not send too.
        assert_eq!(g.edges.len(), 2);
        assert_eq!(g.edges[0].family, "support");
        assert_eq!(g.edges[1].source, uuid(3));
        assert_eq!(g.edges[1].target, uuid(1));
        assert!(g.edges.iter().all(|e| e.directed));
    }

    #[test]
    fn node_cap_keeps_the_centre_and_counts_the_rest() {
        let nodes: Vec<_> = (0..200u32)
            .map(|i| {
                json!({"id": Uuid::from_u128(1000 + u128::from(i)),
                            "entity_type": "claim", "label": format!("n{i}")})
            })
            .collect();
        let ego: EgoResponse = serde_json::from_value(json!({
            "center": {"id": uuid(1), "entity_type": "claim", "label": "c"},
            "nodes": nodes, "edges": [], "total_edges": 200, "truncated": false
        }))
        .unwrap();
        let g = canvas_from_ego(ego, &links());
        assert_eq!(g.nodes.len(), VISIBLE_NODE_CAP);
        assert_eq!(g.hidden_nodes, 51);
        assert!(g.truncated);
        assert_eq!(g.nodes[0].id, uuid(1));
    }

    #[test]
    fn compound_neighbourhood_merges_three_edge_arrays() {
        let n: NeighborhoodExpand = serde_json::from_value(json!({
            "neighborhood_id": uuid(50), "truncated": false,
            "nodes": [
                {"id": uuid(1), "label": "Compound one", "kind": "compound", "atom_count": 4,
                 "pignistic_prob": 0.9, "frame_id": uuid(70)},
                {"id": uuid(2), "label": "Standalone claim", "kind": "standalone", "atom_count": 0,
                 "pignistic_prob": 0.1, "frame_id": uuid(71)}
            ],
            "induced_edges": [{"source": uuid(1), "target": uuid(2), "relationship": "supports",
                               "strength": 0.5, "atom_edge_count": 2}],
            "direct_edges": [
                {"source": uuid(1), "target": uuid(2), "relationship": "supports"},
                {"source": uuid(2), "target": uuid(1), "relationship": "CONTRADICTS"},
                {"source": uuid(2), "target": uuid(1), "relationship": "CONTRADICTS"}
            ],
            "structural_edges": [{"source": uuid(1), "target": uuid(2), "kind": "shared_atom",
                                  "atom_count": 1}]
        }))
        .unwrap();
        let (g, groups) = canvas_from_neighborhood(n, &links());
        assert!(groups.is_empty());
        assert_eq!(g.center, None);
        assert_eq!(g.nodes[0].atom_count, Some(4));
        assert_eq!(g.nodes[0].frame_id, Some(uuid(70)));
        assert_eq!(g.nodes[0].kind.as_deref(), Some("compound"));
        assert_eq!(g.nodes[1].label, "Standalone claim");
        assert_eq!(g.nodes[1].pignistic_prob, Some(0.1));
        assert_eq!(g.nodes[1].frame_id, Some(uuid(71)));
        assert_eq!(g.nodes[1].atom_count, None);

        // induced+direct `supports` share a key; the CONTRADICTS duplicate collapses.
        assert_eq!(g.total_edges, 3);
        assert_eq!(g.edges.len(), 3);
        let structural = g
            .edges
            .iter()
            .find(|e| e.relationship == "shared_atom")
            .unwrap();
        assert!(!structural.directed);
        assert_eq!(structural.family, "structural");
        assert!(g
            .edges
            .iter()
            .any(|e| e.family == "refute" && e.source == uuid(2)));
        assert_eq!(g.edges[0].strength, Some(0.5));
    }

    #[test]
    fn atomic_neighbourhood_carries_groups() {
        let n: NeighborhoodExpand = serde_json::from_value(json!({
            "neighborhood_id": uuid(50), "truncated": true,
            "nodes": [{"id": uuid(1), "label": "Atom", "compound_id": uuid(9),
                       "pignistic_prob": 0.4, "frame_id": null}],
            "edges": [{"source": uuid(1), "target": uuid(1), "relationship": "elaborates"}],
            "compound_groups": [{"compound_id": uuid(9), "label": "Parent\nclaim",
                                 "member_atom_ids": [uuid(1), uuid(2)]}]
        }))
        .unwrap();
        let (g, groups) = canvas_from_neighborhood(n, &links());
        assert!(g.truncated, "upstream truncation is carried");
        assert_eq!(g.nodes[0].kind.as_deref(), Some("atom"));
        assert_eq!(g.nodes[0].atom_count, None);
        assert_eq!(groups[0].label, "Parent claim");
        assert_eq!(groups[0].member_count, 2);
        assert_eq!(groups[0].href, links().claim(uuid(9)));
    }

    #[test]
    fn overview_bodies_cap_and_link() {
        let themes: Vec<_> = (0..(OVERVIEW_ITEM_CAP as u32 + 3))
            .map(|i| {
                json!({"id": Uuid::from_u128(u128::from(i) + 1), "label": format!("t{i}"),
                            "claim_count": 1})
            })
            .collect();
        let body = themes_body(
            serde_json::from_value(json!({ "themes": themes })).unwrap(),
            &links(),
        );
        assert_eq!(body.themes.len(), OVERVIEW_ITEM_CAP);
        assert_eq!(body.total, OVERVIEW_ITEM_CAP + 3);
        assert!(body.truncated);
        assert_eq!(body.themes[0].href, links().theme(uuid(1)));

        let body = communities_body(
            serde_json::from_value(json!({
                "run_id": uuid(40), "generated_at": null, "degraded": false,
                "supernodes": [{"cluster_id": uuid(1), "label": "cluster-1", "size": 3,
                                "dominant_frame_id": uuid(8)}],
                "cluster_edges": [{"a": uuid(1), "b": uuid(2), "weight": 4}]
            }))
            .unwrap(),
            &links(),
        );
        assert_eq!(body.supernodes[0].href, links().community(uuid(1)));
        assert_eq!(body.supernodes[0].frame_href, Some(links().frame(uuid(8))));
        assert!(
            body.cluster_edges.is_empty(),
            "edge to an unreturned supernode"
        );
        assert!(body.truncated);
    }
}
