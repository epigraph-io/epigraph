//! `/claim/:id/graph`, `/theme/:id`, `/community/:id`, `/neighborhood/:id`
//! (plan §3.4). OWNED BY THE GRAPH AREA.
//!
//! - `/claim/:id/graph` is the canvas shell. `static/graph.js` fetches
//!   `/bff/graph/ego/:id` (named in a `data-` attribute; CSP forbids inline
//!   script); the same ego data is rendered server-side as a `<noscript>`
//!   list.
//! - `/theme/:id`, `/community/:id` and `/neighborhood/:id` are NOT
//!   permalinks: every clustering run mints new ids. Each shows a notice and,
//!   when the viewer arrived from a claim (`?claim=<uuid>`), a button that
//!   copies that claim's URL instead. An upstream 404 — or theme expand's
//!   synthetic placeholder — renders "view expired — clustering has re-run".

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use url::form_urlencoded;
use uuid::Uuid;

use crate::auth::{PageCtx, SignedIn};
use crate::bff::graph::{
    canvas_from_ego, canvas_from_neighborhood, one_line, parse_max_degree, CanvasEdge, CanvasGraph,
    CanvasNode, GroupItem, LABEL_CHARS, VISIBLE_NODE_CAP,
};
use crate::error::{not_found_as, AppError};
use crate::links::Links;
use crate::state::AppState;
use crate::upstream::graph::{clamp_expand_budget, NeighborhoodMode};
use crate::upstream::{degrade, Degraded, PlacementResponse, UpstreamError};
use crate::view::render;

/// Most edge rows a server-rendered list shows.
pub const EDGE_ROWS_CAP: usize = 300;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/claim/{id}/graph", get(claim_graph))
        .route("/theme/{id}", get(theme))
        .route("/community/{id}", get(community))
        .route("/neighborhood/{id}", get(neighborhood))
}

// ---- shared pieces ----------------------------------------------------------------

/// Query parameters these pages accept. All are parsed leniently: a bad
/// value is ignored rather than failing the page.
#[derive(Debug, Default, Deserialize)]
struct ViewParams {
    /// The claim the viewer came from; the share button copies its URL.
    claim: Option<String>,
    /// `/neighborhood/:id` only: `compound` (default) or `atomic`.
    mode: Option<String>,
    /// `/theme/:id` and `/community/:id`: expand budget.
    budget: Option<String>,
    /// `/claim/:id/graph`: ego degree cap.
    max_degree: Option<String>,
}

impl ViewParams {
    fn claim(&self) -> Option<Uuid> {
        self.claim
            .as_deref()
            .and_then(|s| Uuid::parse_str(s.trim()).ok())
    }

    fn budget(&self) -> u32 {
        clamp_expand_budget(self.budget.as_deref().and_then(|s| s.trim().parse().ok()))
    }
}

/// A malformed path id reads as "not found", not a generic 400.
fn parse_id(raw: &str, what: &'static str) -> Result<Uuid, AppError> {
    Uuid::parse_str(raw.trim()).map_err(|_| AppError::NotFound(what.into()))
}

/// `href` plus `?claim=<id>` when the centre claim is known, so the share
/// button survives navigation between non-permalink views.
fn with_claim(href: String, claim: Option<Uuid>) -> String {
    match claim {
        Some(c) => {
            let sep = if href.contains('?') { '&' } else { '?' };
            let qs = form_urlencoded::Serializer::new(String::new())
                .append_pair("claim", &c.to_string())
                .finish();
            format!("{href}{sep}{qs}")
        }
        None => href,
    }
}

/// The share target of a non-permalink view: the centre claim.
pub struct Share {
    /// Absolute URL (what the button copies).
    pub url: String,
    /// Browser path (what the fallback link points at).
    pub href: String,
}

fn share_for(claim: Option<Uuid>, links: &Links) -> Option<Share> {
    claim.map(|c| {
        let href = links.claim(c);
        Share {
            url: links.absolute(&href),
            href,
        }
    })
}

/// What `templates/graph/_canvas.html` needs. graph.js reads these from
/// `data-` attributes.
pub struct CanvasShell {
    /// `/bff/…` URL of the initial payload.
    pub source: String,
    /// Centre node id, or empty.
    pub center: String,
    /// Accessible name of the SVG.
    pub label: String,
    pub node_cap: usize,
    /// Link shown when the canvas cannot load.
    pub fallback_href: String,
}

/// Two decimals, or an em dash.
fn fmt_num(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{x:.2}"),
        _ => "—".into(),
    }
}

/// A server-rendered edge row.
pub struct EdgeRow {
    pub source: String,
    pub source_href: Option<String>,
    pub relationship: String,
    /// `support` / `refute` / `structural`, for the row's class.
    pub family: &'static str,
    pub target: String,
    pub target_href: Option<String>,
}

/// Edge rows over a canvas graph, looked up by node id.
fn edge_rows(graph: &CanvasGraph) -> Vec<EdgeRow> {
    let node = |id: Uuid| graph.nodes.iter().find(|n| n.id == id);
    graph
        .edges
        .iter()
        .take(EDGE_ROWS_CAP)
        .map(|e| {
            let (s, t) = (node(e.source), node(e.target));
            EdgeRow {
                source: s.map_or_else(|| e.source.to_string(), |n| n.label.clone()),
                source_href: s.and_then(|n| n.href.clone()),
                relationship: e.relationship.clone(),
                family: e.family,
                target: t.map_or_else(|| e.target.to_string(), |n| n.label.clone()),
                target_href: t.and_then(|n| n.href.clone()),
            }
        })
        .collect()
}

/// The "view expired" state: 404 when upstream no longer knows the id,
/// 200 when it answered with a placeholder.
fn with_status(status: StatusCode, html: Html<String>) -> Response {
    (status, html).into_response()
}

// ---- /claim/:id/graph ---------------------------------------------------------------

/// One neighbour of the centre in the `<noscript>` list.
pub struct NeighbourRow {
    pub relationship: String,
    pub family: &'static str,
    /// The centre is the edge's source.
    pub outgoing: bool,
    pub label: String,
    pub entity_type: String,
    pub href: Option<String>,
    pub redacted: bool,
}

/// Where the claim sits in the latest clustering run (all optional).
pub struct PlacementLinks {
    pub theme: Option<String>,
    pub community: Option<String>,
    pub neighborhood: Option<String>,
    pub run_completed_at: Option<String>,
}

impl PlacementLinks {
    fn from_response(p: PlacementResponse, links: &Links) -> Self {
        let claim = Some(p.claim_id);
        PlacementLinks {
            theme: p.theme_id.map(|t| with_claim(links.theme(t), claim)),
            community: p.cluster_id.map(|c| with_claim(links.community(c), claim)),
            neighborhood: p
                .neighborhood_id
                .map(|n| with_claim(links.neighborhood(n, None), claim)),
            run_completed_at: p
                .run_completed_at
                .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.theme.is_none() && self.community.is_none() && self.neighborhood.is_none()
    }
}

#[derive(askama::Template)]
#[template(path = "graph/claim_graph.html")]
struct ClaimGraphPage {
    ctx: PageCtx,
    title: String,
    redacted: bool,
    claim_href: String,
    canvas: CanvasShell,
    neighbours: Vec<NeighbourRow>,
    total_edges: u64,
    shown_edges: usize,
    truncated: bool,
    placement: Degraded<PlacementLinks>,
}

async fn claim_graph(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    Query(q): Query<ViewParams>,
) -> Result<Html<String>, AppError> {
    let id = parse_id(&raw, "claim")?;
    let links = &state.links;
    let max_degree = parse_max_degree(q.max_degree.as_deref());
    let api = user.api(&state);
    // Placement is ids only (no claim text), so it can run alongside.
    let (ego, placement) = tokio::join!(api.ego(id, max_degree, None), api.placement(id));
    let graph = canvas_from_ego(ego.map_err(not_found_as("claim"))?, links);
    let placement = degrade(placement)?.map(|p| PlacementLinks::from_response(p, links));

    let center = &graph.nodes[0];
    let neighbours = graph
        .edges
        .iter()
        .filter_map(|e| {
            let outgoing = e.source == id;
            let other = if outgoing { e.target } else { e.source };
            let n = graph.nodes.iter().find(|n| n.id == other)?;
            Some(NeighbourRow {
                relationship: e.relationship.clone(),
                family: e.family,
                outgoing,
                label: n.label.clone(),
                entity_type: n.entity_type.clone(),
                href: n.href.clone(),
                redacted: n.redacted,
            })
        })
        .collect::<Vec<_>>();

    let source = if q.max_degree.is_some() {
        links.bff_graph_ego(id, Some(max_degree))
    } else {
        links.bff_graph_ego(id, None)
    };
    let page = ClaimGraphPage {
        title: center.label.clone(),
        redacted: center.redacted,
        claim_href: links.claim(id),
        canvas: CanvasShell {
            source,
            center: id.to_string(),
            label: format!(
                "Graph of the claim and its {} nearest connections",
                graph.edges.len()
            ),
            node_cap: VISIBLE_NODE_CAP,
            fallback_href: links.claim(id),
        },
        total_edges: graph.total_edges,
        shown_edges: graph.edges.len(),
        truncated: graph.truncated,
        neighbours,
        placement,
        ctx: user.ctx,
    };
    render(&page)
}

// ---- /theme/:id -------------------------------------------------------------------

/// A neighbourhood supernode of a theme.
pub struct NeighbourhoodRow {
    pub href: String,
    pub name: String,
    pub size: i64,
    pub mean_betp: String,
    pub frame_href: Option<String>,
}

/// An undirected weighted edge between two neighbourhoods.
pub struct WeightRow {
    pub a: String,
    pub a_href: Option<String>,
    pub b: String,
    pub b_href: Option<String>,
    pub weight: String,
}

/// Upstream labels are a frame UUID string or `neighborhood-N`.
fn neighbourhood_name(label: &str, id: Uuid) -> String {
    match Uuid::parse_str(label.trim()) {
        Ok(frame) => {
            let s = frame.simple().to_string();
            format!("Frame {}", &s[..8])
        }
        Err(_) => {
            let line = one_line(label, LABEL_CHARS);
            if line.is_empty() {
                id.to_string()
            } else {
                line
            }
        }
    }
}

#[derive(askama::Template)]
#[template(path = "graph/theme.html")]
struct ThemePage {
    ctx: PageCtx,
    theme_id: Uuid,
    expired: bool,
    rows: Vec<NeighbourhoodRow>,
    edges: Vec<WeightRow>,
    /// Upstream always says `truncated: false`; a full page may still be cut.
    maybe_more: bool,
    share: Option<Share>,
    what: &'static str,
}

async fn theme(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    Query(q): Query<ViewParams>,
) -> Result<Response, AppError> {
    let id = parse_id(&raw, "theme")?;
    let links = &state.links;
    let claim = q.claim();
    let budget = q.budget();
    let mut page = ThemePage {
        theme_id: id,
        expired: false,
        rows: Vec::new(),
        edges: Vec::new(),
        maybe_more: false,
        share: share_for(claim, links),
        what: "theme",
        ctx: user.ctx.clone(),
    };
    let expand = match user.api(&state).theme_expand(id, budget).await {
        Ok(e) => e,
        Err(UpstreamError::NotFound { .. }) => {
            page.expired = true;
            return Ok(with_status(StatusCode::NOT_FOUND, render(&page)?));
        }
        Err(e) => return Err(e.into()),
    };
    if expand.is_synthetic() {
        page.expired = true;
        return Ok(with_status(StatusCode::OK, render(&page)?));
    }

    let real: Vec<_> = expand
        .neighborhoods
        .into_iter()
        .filter(|n| !n.is_synthetic())
        .collect();
    page.maybe_more = real.len() as u32 >= budget;
    let name_of = |nid: Uuid| {
        real.iter()
            .find(|n| n.id == nid)
            .map(|n| neighbourhood_name(&n.label, n.id))
    };
    page.edges = expand
        .neighborhood_edges
        .iter()
        .take(EDGE_ROWS_CAP)
        .map(|e| WeightRow {
            a: name_of(e.a).unwrap_or_else(|| e.a.to_string()),
            a_href: name_of(e.a).map(|_| with_claim(links.neighborhood(e.a, None), claim)),
            b: name_of(e.b).unwrap_or_else(|| e.b.to_string()),
            b_href: name_of(e.b).map(|_| with_claim(links.neighborhood(e.b, None), claim)),
            weight: fmt_num(Some(e.weight)),
        })
        .collect();
    page.rows = real
        .iter()
        .map(|n| NeighbourhoodRow {
            href: with_claim(links.neighborhood(n.id, None), claim),
            name: neighbourhood_name(&n.label, n.id),
            size: n.size,
            mean_betp: fmt_num(n.mean_betp),
            frame_href: n.dominant_frame_id.map(|f| links.frame(f)),
        })
        .collect();
    Ok(with_status(StatusCode::OK, render(&page)?))
}

// ---- /community/:id ---------------------------------------------------------------

/// A claim in a community (cluster).
pub struct ClaimRow {
    pub href: String,
    pub label: String,
    pub redacted: bool,
    pub betp: String,
}

#[derive(askama::Template)]
#[template(path = "graph/community.html")]
struct CommunityPage {
    ctx: PageCtx,
    cluster_id: Uuid,
    expired: bool,
    total_size: i64,
    claims: Vec<ClaimRow>,
    edges: Vec<EdgeRow>,
    more_edges: usize,
    filtered_edge_count: i64,
    truncated: bool,
    share: Option<Share>,
    what: &'static str,
}

async fn community(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    Query(q): Query<ViewParams>,
) -> Result<Response, AppError> {
    let id = parse_id(&raw, "community")?;
    let links = &state.links;
    let mut page = CommunityPage {
        cluster_id: id,
        expired: false,
        total_size: 0,
        claims: Vec::new(),
        edges: Vec::new(),
        more_edges: 0,
        filtered_edge_count: 0,
        truncated: false,
        share: share_for(q.claim(), links),
        what: "community",
        ctx: user.ctx.clone(),
    };
    let expand = match user.api(&state).community_expand(id, q.budget()).await {
        Ok(e) => e,
        Err(UpstreamError::NotFound { .. }) => {
            page.expired = true;
            return Ok(with_status(StatusCode::NOT_FOUND, render(&page)?));
        }
        Err(e) => return Err(e.into()),
    };

    // Reuse the canvas mapping for labels, redaction and links.
    let graph = CanvasGraph {
        center: None,
        nodes: expand
            .nodes
            .iter()
            .map(|n| CanvasNode::from_claim_label(n.id, &n.label, links))
            .collect(),
        edges: expand
            .edges
            .iter()
            .map(|e| CanvasEdge::keyed(e.source, e.target, e.relationship.clone(), true, None))
            .collect(),
        total_edges: expand.edges.len() as u64,
        truncated: expand.truncated,
        hidden_nodes: 0,
    };
    page.claims = expand
        .nodes
        .iter()
        .zip(&graph.nodes)
        .map(|(raw, n)| ClaimRow {
            href: links.claim(n.id),
            label: n.label.clone(),
            redacted: n.redacted,
            betp: if n.redacted {
                fmt_num(None)
            } else {
                fmt_num(raw.pignistic_prob)
            },
        })
        .collect();
    page.edges = edge_rows(&graph);
    page.more_edges = graph.edges.len().saturating_sub(page.edges.len());
    page.total_size = expand.total_size;
    page.filtered_edge_count = expand.filtered_edge_count;
    page.truncated = expand.truncated || expand.total_size > expand.nodes.len() as i64;
    Ok(with_status(StatusCode::OK, render(&page)?))
}

// ---- /neighborhood/:id ------------------------------------------------------------

#[derive(askama::Template)]
#[template(path = "graph/neighborhood.html")]
struct NeighborhoodPage {
    ctx: PageCtx,
    neighborhood_id: Uuid,
    expired: bool,
    atomic: bool,
    compound_href: String,
    atomic_href: String,
    canvas: CanvasShell,
    nodes: Vec<ClaimRow>,
    edges: Vec<EdgeRow>,
    groups: Vec<GroupItem>,
    hidden_nodes: usize,
    share: Option<Share>,
    what: &'static str,
}

async fn neighborhood(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    Query(q): Query<ViewParams>,
) -> Result<Response, AppError> {
    let id = parse_id(&raw, "neighbourhood")?;
    let links = &state.links;
    let claim = q.claim();
    let mode = NeighborhoodMode::parse(q.mode.as_deref());
    let mut page = NeighborhoodPage {
        neighborhood_id: id,
        expired: false,
        atomic: mode == NeighborhoodMode::Atomic,
        compound_href: with_claim(links.neighborhood(id, Some("compound")), claim),
        atomic_href: with_claim(links.neighborhood(id, Some("atomic")), claim),
        canvas: CanvasShell {
            source: links.bff_neighborhood(id, Some(mode.as_str())),
            center: String::new(),
            label: format!("Graph of this neighbourhood ({} view)", mode.as_str()),
            node_cap: VISIBLE_NODE_CAP,
            fallback_href: links.home(),
        },
        nodes: Vec::new(),
        edges: Vec::new(),
        groups: Vec::new(),
        hidden_nodes: 0,
        share: share_for(claim, links),
        what: "neighbourhood",
        ctx: user.ctx.clone(),
    };
    let expand = match user.api(&state).neighborhood_expand(id, mode).await {
        Ok(e) => e,
        Err(UpstreamError::NotFound { .. }) => {
            page.expired = true;
            return Ok(with_status(StatusCode::NOT_FOUND, render(&page)?));
        }
        Err(e) => return Err(e.into()),
    };
    // Upstream falls through to compound for anything but `atomic`; trust
    // the shape it sent over the mode we asked for.
    page.atomic = expand.mode() == NeighborhoodMode::Atomic;
    let (graph, groups) = canvas_from_neighborhood(expand, links);
    page.nodes = graph
        .nodes
        .iter()
        .map(|n| ClaimRow {
            href: links.claim(n.id),
            label: n.label.clone(),
            redacted: n.redacted,
            betp: fmt_num(n.pignistic_prob),
        })
        .collect();
    page.edges = edge_rows(&graph);
    page.groups = groups;
    page.hidden_nodes = graph.hidden_nodes;
    Ok(with_status(StatusCode::OK, render(&page)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links() -> Links {
        Links::new("https://explorer.example.com", "/explorer")
    }

    #[test]
    fn claim_param_is_carried_and_encoded() {
        let c = Uuid::from_u128(7);
        let l = links();
        assert_eq!(
            with_claim(l.theme(Uuid::from_u128(1)), Some(c)),
            format!("{}?claim={c}", l.theme(Uuid::from_u128(1)))
        );
        assert_eq!(
            with_claim(l.neighborhood(Uuid::from_u128(1), Some("atomic")), Some(c)),
            format!(
                "{}&claim={c}",
                l.neighborhood(Uuid::from_u128(1), Some("atomic"))
            )
        );
        assert_eq!(with_claim("/x".into(), None), "/x");
    }

    #[test]
    fn view_params_are_lenient() {
        let q = ViewParams {
            claim: Some("not-a-uuid".into()),
            budget: Some("9999".into()),
            ..Default::default()
        };
        assert_eq!(q.claim(), None);
        assert_eq!(q.budget(), crate::upstream::graph::MAX_EXPAND_BUDGET);
        let q = ViewParams {
            budget: Some("x".into()),
            ..Default::default()
        };
        assert_eq!(q.budget(), crate::upstream::graph::DEFAULT_EXPAND_BUDGET);
    }

    #[test]
    fn share_is_the_absolute_claim_url() {
        let c = Uuid::from_u128(7);
        let s = share_for(Some(c), &links()).unwrap();
        assert_eq!(s.href, format!("/explorer/claim/{c}"));
        assert_eq!(
            s.url,
            format!("https://explorer.example.com/explorer/claim/{c}")
        );
        assert!(share_for(None, &links()).is_none());
    }

    #[test]
    fn neighbourhood_names() {
        let id = Uuid::from_u128(3);
        assert_eq!(
            neighbourhood_name("0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10", id),
            "Frame 0b9a5a4e"
        );
        assert_eq!(neighbourhood_name("neighborhood-4", id), "neighborhood-4");
        assert_eq!(neighbourhood_name("  ", id), id.to_string());
    }

    #[test]
    fn numbers() {
        assert_eq!(fmt_num(Some(0.756)), "0.76");
        assert_eq!(fmt_num(None), "—");
        assert_eq!(fmt_num(Some(f64::NAN)), "—");
    }
}
