//! Upstream DTOs and typed calls for the Atlas (Topics view, phase P3a).
//! OWNED BY THE ATLAS AREA.
//!
//! The kernel routes these types decode, each read with the viewer's own
//! bearer (never a service token):
//!
//! - `POST /api/v1/claims/batch-get`: up to 100 ids, each readable one with
//!   its `GET /claims/:id` body plus `is_current`; `not_found` holds the rest
//!   ("absent or not readable", one answer) and `remaining` the ids a size cap
//!   left unclassified.
//! - `GET /api/v1/claims/:id/context`: the claim's ring (paper, section,
//!   parents, parts, siblings, edges), each list first-page or one list in
//!   page mode. No belief column anywhere.
//! - `GET /api/v1/graph/themes/layout` and `GET /api/v1/graph/links`: the
//!   shared map positions, the viewer's visible regions and themes, the public
//!   bundle counts between them, and the per-viewer drill-down list.
//!
//! Discipline (as `upstream/types.rs`): every field that is not guaranteed
//! present is `Option` or `#[serde(default)]`, unknown fields are ignored,
//! and every field is `pub` so that no unread field trips `dead_code`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Api, ClaimResponse, UpstreamError};

/// Most ids one batch-get call may carry (the kernel refuses more).
pub const BATCH_GET_MAX_IDS: usize = 100;
/// Page-size range of the context, layout and links routes.
pub const ATLAS_PAGE_RANGE: (u32, u32) = (1, 200);

fn clamp_page(limit: u32) -> u32 {
    limit.clamp(ATLAS_PAGE_RANGE.0, ATLAS_PAGE_RANGE.1)
}

// ---- POST /api/v1/claims/batch-get --------------------------------------------

#[derive(Serialize)]
struct BatchGetBody<'a> {
    /// `Uuid` serialises hyphenated, which the kernel parses.
    ids: &'a [Uuid],
}

/// One readable claim: the `GET /claims/:id` body plus its retirement state.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct BatchGetClaim {
    #[serde(flatten)]
    pub claim: ClaimResponse,
    #[serde(default)]
    pub is_current: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct BatchGetResponse {
    #[serde(default)]
    pub claims: Vec<BatchGetClaim>,
    /// Absent or not readable by this viewer: one answer for both.
    #[serde(default)]
    pub not_found: Vec<Uuid>,
    /// Not classified because of the response size cap; resubmit them.
    #[serde(default)]
    pub remaining: Vec<Uuid>,
}

// ---- GET /api/v1/claims/:id/context -------------------------------------------

/// A claim node of the context ring. `content` is clipped upstream (1,500
/// chars) and flagged.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ContextNode {
    pub id: Uuid,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub content_truncated: bool,
    #[serde(default)]
    pub truth_value: Option<f64>,
    #[serde(default)]
    pub is_current: Option<bool>,
    #[serde(default)]
    pub level: Option<i64>,
    #[serde(default)]
    pub theme_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ContextPaper {
    pub id: Uuid,
    #[serde(default)]
    pub doi: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub truncated: bool,
}

/// One page of a ring list. `total` is counted inside the viewer predicate.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ContextList<T> {
    #[serde(default = "Vec::new")]
    pub items: Vec<T>,
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SiblingList {
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    #[serde(flatten)]
    pub list: ContextList<ContextNode>,
}

/// An edge of the centre claim. A row without a `neighbor` fails to decode
/// as a whole, so nothing is ever fabricated for a hidden endpoint.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ContextEdge {
    pub edge_id: Uuid,
    #[serde(default)]
    pub relationship: String,
    /// `outgoing` or `incoming`, relative to the centre.
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub strength: Option<f64>,
    pub neighbor: ContextNode,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RelCount {
    #[serde(default)]
    pub relationship: String,
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub count: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EdgeList {
    #[serde(flatten)]
    pub list: ContextList<ContextEdge>,
    #[serde(default)]
    pub by_relationship: Vec<RelCount>,
}

/// `GET /claims/:id/context`. Every list is optional because page mode
/// omits all but one. `papers` (P3b) is deliberately not a field.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ClaimContext {
    pub claim: ContextNode,
    #[serde(default)]
    pub paper: Option<ContextPaper>,
    #[serde(default)]
    pub section: Option<ContextNode>,
    #[serde(default)]
    pub parents: Option<ContextList<ContextNode>>,
    #[serde(default)]
    pub parts: Option<ContextList<ContextNode>>,
    #[serde(default)]
    pub siblings: Option<SiblingList>,
    #[serde(default)]
    pub edges: Option<EdgeList>,
}

/// The lists page mode can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextListName {
    Parents,
    Parts,
    Siblings,
    Edges,
}

impl ContextListName {
    pub fn as_str(self) -> &'static str {
        match self {
            ContextListName::Parents => "parents",
            ContextListName::Parts => "parts",
            ContextListName::Siblings => "siblings",
            ContextListName::Edges => "edges",
        }
    }

    /// `None` for anything else, `papers` included (P3b).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "parents" => Some(ContextListName::Parents),
            "parts" => Some(ContextListName::Parts),
            "siblings" => Some(ContextListName::Siblings),
            "edges" => Some(ContextListName::Edges),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct ContextPageQuery<'a> {
    list: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
}

// ---- GET /api/v1/graph/themes/layout -------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LayoutRun {
    pub run_id: Uuid,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub algo: String,
    #[serde(default)]
    pub cluster_run_id: Option<Uuid>,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub extent: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LayoutRegion {
    pub id: Uuid,
    #[serde(default)]
    pub label: String,
    pub x: f64,
    pub y: f64,
    pub r: f64,
    #[serde(default)]
    pub theme_ids: Vec<Uuid>,
    #[serde(default)]
    pub theme_count: i64,
    #[serde(default)]
    pub member_count: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LayoutTheme {
    pub id: Uuid,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub region_id: Option<Uuid>,
    /// `shared` (a public position) or `viewer` (the client places it).
    #[serde(default)]
    pub placement: Option<String>,
    #[serde(default)]
    pub x: Option<f64>,
    #[serde(default)]
    pub y: Option<f64>,
    #[serde(default)]
    pub member_count: i64,
}

/// A bundle: shared public counts over a pair the viewer can see.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LayoutLink {
    /// `region`, `theme` or `theme_region`.
    #[serde(default)]
    pub kind: String,
    pub a: Uuid,
    pub b: Uuid,
    #[serde(default)]
    pub counts: BTreeMap<String, i64>,
    #[serde(default)]
    pub total: i64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct LayoutNext {
    #[serde(default)]
    pub themes: Option<String>,
    #[serde(default)]
    pub links: Option<String>,
}

/// `GET /graph/themes/layout`: top level (`regions`), region level
/// (`region` + `themes`), or the no-run 200 (`run: null`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct ThemesLayout {
    #[serde(default)]
    pub run: Option<LayoutRun>,
    /// `no_layout_run` / `layout_invalidated` when `run` is null.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub relationships: Vec<String>,
    #[serde(default)]
    pub regions: Vec<LayoutRegion>,
    #[serde(default)]
    pub region: Option<LayoutRegion>,
    #[serde(default)]
    pub themes: Vec<LayoutTheme>,
    #[serde(default)]
    pub links: Vec<LayoutLink>,
    #[serde(default)]
    pub unplaced_theme_count: i64,
    #[serde(default)]
    pub next: LayoutNext,
}

/// Query of `GET /graph/themes/layout`. `limit` is clamped to `1..=200`.
#[derive(Serialize, Default, Clone, Copy)]
pub struct LayoutQuery<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<Uuid>,
    /// A region uuid or `unplaced`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rel: Option<&'a str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub include_structure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub themes_after: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links_after: Option<&'a str>,
    pub limit: u32,
}

// ---- GET /api/v1/graph/links ---------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LinkSide {
    pub id: Uuid,
    /// `theme` or `region`.
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LinkEnd {
    pub id: Uuid,
    /// Claim content cut to 160 chars upstream.
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub truth_value: Option<f64>,
    #[serde(default)]
    pub theme_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LinkItem {
    pub edge_id: Uuid,
    #[serde(default)]
    pub relationship: String,
    #[serde(default)]
    pub strength: Option<f64>,
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    pub source: LinkEnd,
    pub target: LinkEnd,
}

/// `GET /graph/links`. `from`/`to` are optional because the
/// `layout_invalidated` 200 may carry only its status; the BFF echoes its
/// own validated parameters instead. `counts` come on the first page only;
/// `total` on every page.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct GraphLinks {
    #[serde(default)]
    pub from: Option<LinkSide>,
    #[serde(default)]
    pub to: Option<LinkSide>,
    #[serde(default)]
    pub run_id: Option<Uuid>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub relationships: Vec<String>,
    #[serde(default)]
    pub counts: Option<BTreeMap<String, i64>>,
    #[serde(default)]
    pub total: Option<i64>,
    #[serde(default)]
    pub items: Vec<LinkItem>,
    #[serde(default)]
    pub next: Option<String>,
}

/// Query of `GET /graph/links`. `limit` is clamped to `1..=200`.
#[derive(Serialize, Clone, Copy)]
pub struct LinksQuery<'a> {
    pub from: Uuid,
    pub to: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rel: Option<&'a str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub include_structure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<&'a str>,
    pub limit: u32,
}

// ---- typed calls ----------------------------------------------------------------

impl Api<'_> {
    /// `POST /api/v1/claims/batch-get`. Callers chunk to at most
    /// [`BATCH_GET_MAX_IDS`]; an empty `ids` returns an empty answer without
    /// a call.
    pub async fn claims_batch_get(&self, ids: &[Uuid]) -> Result<BatchGetResponse, UpstreamError> {
        debug_assert!(ids.len() <= BATCH_GET_MAX_IDS, "chunk batch-get ids");
        if ids.is_empty() {
            return Ok(BatchGetResponse::default());
        }
        self.post("/api/v1/claims/batch-get", &BatchGetBody { ids })
            .await
    }

    /// `GET /api/v1/claims/:id/context` (full mode: the first page of every
    /// list).
    pub async fn claim_context(&self, id: Uuid) -> Result<ClaimContext, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}/context")).await
    }

    /// `GET /api/v1/claims/:id/context?list=&after=&limit=` (page mode: the
    /// centre plus one list). `limit` is clamped to `1..=200`.
    pub async fn claim_context_page(
        &self,
        id: Uuid,
        list: ContextListName,
        after: Option<&str>,
        limit: Option<u32>,
    ) -> Result<ClaimContext, UpstreamError> {
        let q = ContextPageQuery {
            list: list.as_str(),
            after,
            limit: limit.map(clamp_page),
        };
        self.get_query(&format!("/api/v1/claims/{id}/context"), &q)
            .await
    }

    /// `GET /api/v1/graph/themes/layout`.
    pub async fn themes_layout(&self, q: &LayoutQuery<'_>) -> Result<ThemesLayout, UpstreamError> {
        let q = LayoutQuery {
            limit: clamp_page(q.limit),
            ..*q
        };
        self.get_query("/api/v1/graph/themes/layout", &q).await
    }

    /// `GET /api/v1/graph/links`.
    pub async fn graph_links(&self, q: &LinksQuery<'_>) -> Result<GraphLinks, UpstreamError> {
        let q = LinksQuery {
            limit: clamp_page(q.limit),
            ..*q
        };
        self.get_query("/api/v1/graph/links", &q).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "00000000-0000-0000-0000-00000000000a";
    const B: &str = "00000000-0000-0000-0000-00000000000b";
    const C: &str = "00000000-0000-0000-0000-00000000000c";

    fn as_json<T: Serialize>(q: &T) -> serde_json::Value {
        serde_json::to_value(q).unwrap()
    }

    /// Cross-lane contract pin for the U3/U4/U5 routes, one payload per
    /// shape exactly as the kernel designs state them.
    #[test]
    fn kernel_routes_serialize_into_these_dtos_atlas() {
        // U3: `labels` omitted (empty), `trace_id: null`, `is_current` added.
        let b: BatchGetResponse = serde_json::from_value(json!({
            "claims": [{
                "id": A, "content": "Water boils.", "truth_value": 0.62,
                "agent_id": B, "trace_id": null,
                "created_at": "2026-11-01T00:00:00Z", "updated_at": "2026-11-01T00:00:00Z",
                "is_current": true
            }],
            "not_found": [B],
            "remaining": [C]
        }))
        .unwrap();
        assert_eq!(b.claims[0].claim.id.to_string(), A);
        assert!(b.claims[0].claim.labels.is_empty() && b.claims[0].claim.trace_id.is_none());
        assert_eq!(b.claims[0].is_current, Some(true));
        assert_eq!((b.not_found.len(), b.remaining.len()), (1, 1));

        // U4 full mode.
        let node = json!({"id": B, "content": "Methods", "content_truncated": false,
                          "truth_value": 0.5, "is_current": true, "level": 1, "theme_id": null});
        let full: ClaimContext = serde_json::from_value(json!({
            "claim": {"id": A, "content": "c", "content_truncated": true, "truth_value": 0.72,
                      "is_current": true, "level": 2, "theme_id": C},
            "paper": {"id": C, "doi": "10.1234/x", "title": null, "truncated": false},
            "papers": {"items": [{"id": C, "doi": "10.1234/x", "title": null, "truncated": false}],
                       "total": 1, "next_cursor": null},
            "section": node,
            "parents": {"items": [node], "total": 1, "next_cursor": null},
            "parts": {"items": [node], "total": 12, "next_cursor": "k1.1.ab"},
            "siblings": {"parent_id": B, "items": [node], "total": 7, "next_cursor": null},
            "edges": {
                "items": [{"edge_id": C, "relationship": "refutes", "direction": "incoming",
                           "strength": 0.8, "neighbor": node}],
                "total": 9,
                "by_relationship": [{"relationship": "refutes", "direction": "incoming", "count": 1}],
                "next_cursor": "k1.1730700000000000.3f2c"
            }
        }))
        .unwrap();
        assert!(full.claim.content_truncated);
        assert_eq!(full.parts.as_ref().unwrap().total, 12);
        assert_eq!(
            full.siblings
                .as_ref()
                .unwrap()
                .parent_id
                .unwrap()
                .to_string(),
            B
        );
        let edges = full.edges.as_ref().unwrap();
        assert_eq!(edges.list.items[0].direction, "incoming");
        assert_eq!(edges.by_relationship[0].count, 1);
        assert_eq!(
            edges.list.next_cursor.as_deref(),
            Some("k1.1730700000000000.3f2c")
        );

        // U4 page mode: only `claim` and the one list; `level` and
        // `strength` omitted.
        let page: ClaimContext = serde_json::from_value(json!({
            "claim": {"id": A, "content": "c", "content_truncated": false, "truth_value": null,
                      "is_current": true, "theme_id": null},
            "edges": {"items": [{"edge_id": C, "relationship": "cites", "direction": "outgoing",
                                 "neighbor": {"id": B, "content": "n", "content_truncated": false,
                                              "truth_value": 0.1, "is_current": false, "theme_id": null}}],
                      "total": 1, "by_relationship": [], "next_cursor": null}
        }))
        .unwrap();
        assert!(page.parts.is_none() && page.paper.is_none() && page.section.is_none());
        assert!(page.edges.unwrap().list.items[0].strength.is_none());

        // U5 top level.
        let top: ThemesLayout = serde_json::from_value(json!({
            "run": {"run_id": A, "completed_at": "2026-11-01T00:00:00Z", "algo": "pca2-ward-v1",
                    "cluster_run_id": null, "stale": false, "extent": 1000.0},
            "status": null,
            "relationships": ["supports", "cites"],
            "regions": [{"id": B, "label": "R", "x": -412.3, "y": 88.1, "r": 151.0,
                         "theme_ids": [C], "theme_count": 14, "member_count": 3120}],
            "links": [{"kind": "region", "a": B, "b": C,
                       "counts": {"supports": 40, "contradicts": 6}, "total": 46}],
            "unplaced_theme_count": 2,
            "next": {"themes": null, "links": null}
        }))
        .unwrap();
        assert_eq!(top.regions[0].theme_count, 14);
        assert_eq!(top.links[0].counts["contradicts"], 6);
        assert_eq!(top.run.as_ref().unwrap().extent, Some(1000.0));

        // U5 region level.
        let region: ThemesLayout = serde_json::from_value(json!({
            "run": {"run_id": A, "completed_at": "2026-11-01T00:00:00Z", "algo": "pca2-ward-v1",
                    "cluster_run_id": B, "stale": true, "extent": 1000.0},
            "status": null, "relationships": ["supports"],
            "region": {"id": B, "label": "R", "x": 1.0, "y": 2.0, "r": 3.0,
                       "theme_count": 2, "member_count": 9},
            "themes": [
                {"id": C, "label": "T", "region_id": B, "placement": "shared",
                 "x": -398.0, "y": 120.5, "member_count": 811},
                {"id": A, "label": "Mine", "region_id": B, "placement": "viewer",
                 "x": null, "y": null, "member_count": 12}
            ],
            "links": [
                {"kind": "theme", "a": C, "b": A, "counts": {"supports": 5}, "total": 5},
                {"kind": "theme_region", "a": C, "b": B, "counts": {"cites": 2}, "total": 2}
            ],
            "next": {"themes": "lt2.3.abc", "links": "ll1.5.1.ab.cd"}
        }))
        .unwrap();
        assert!(region.region.as_ref().unwrap().theme_ids.is_empty());
        assert_eq!(region.themes[1].x, None);
        assert_eq!(region.next.themes.as_deref(), Some("lt2.3.abc"));

        // U5 unplaced.
        let unplaced: ThemesLayout = serde_json::from_value(json!({
            "run": {"run_id": A, "algo": "pca2-ward-v1", "stale": false, "extent": 1000.0},
            "status": null, "relationships": [], "region": null,
            "themes": [{"id": C, "label": "T", "region_id": null, "placement": null,
                        "x": null, "y": null, "member_count": 3}],
            "links": [], "next": {"themes": null, "links": null}
        }))
        .unwrap();
        assert!(unplaced.region.is_none() && unplaced.themes[0].region_id.is_none());

        // U5 no-run 200.
        let none: ThemesLayout = serde_json::from_value(json!({
            "run": null, "status": "no_layout_run", "regions": [], "links": [],
            "unplaced_theme_count": 0, "next": {"themes": null, "links": null}
        }))
        .unwrap();
        assert!(none.run.is_none());
        assert_eq!(none.status.as_deref(), Some("no_layout_run"));

        // U5 `/graph/links` page.
        let links: GraphLinks = serde_json::from_value(json!({
            "from": {"id": A, "kind": "theme"}, "to": {"id": B, "kind": "region"},
            "run_id": C, "relationships": ["supports"],
            "counts": {"supports": 3, "contradicts": 1}, "total": 4,
            "items": [{"edge_id": C, "relationship": "supports", "strength": 0.8,
                       "direction": "from_to", "created_at": "2026-11-01T00:00:00Z",
                       "source": {"id": A, "label": "s", "truth_value": 0.72, "theme_id": A},
                       "target": {"id": B, "label": "t", "truth_value": 0.41, "theme_id": B}}],
            "next": "gl2.s.3fe999999999999a.1730700000000000.ab"
        }))
        .unwrap();
        assert_eq!(links.total, Some(4));
        assert_eq!(links.items[0].source.truth_value, Some(0.72));

        // `layout_invalidated` with sides, and status-only.
        let inv: GraphLinks = serde_json::from_value(json!({
            "from": {"id": A, "kind": "theme"}, "to": {"id": B, "kind": "region"},
            "status": "layout_invalidated", "items": []
        }))
        .unwrap();
        assert_eq!(inv.status.as_deref(), Some("layout_invalidated"));
        let bare: GraphLinks =
            serde_json::from_value(json!({"status": "layout_invalidated"})).unwrap();
        assert!(bare.from.is_none() && bare.to.is_none() && bare.items.is_empty());
    }

    /// A kernel without the theme filter ignores `theme_id` and answers with
    /// global hits; the call must refuse that answer.
    #[test]
    fn theme_search_scope_is_checked() {
        use crate::upstream::core::{check_theme_scope, SemanticSearchResponse};
        let t: Uuid = A.parse().unwrap();
        let bare: SemanticSearchResponse =
            serde_json::from_value(json!({"results": [], "total": 0, "query_time_ms": 1})).unwrap();
        assert!(matches!(
            check_theme_scope(Some(t), bare.clone()),
            Err(UpstreamError::Decode(_))
        ));
        assert!(
            check_theme_scope(None, bare).is_ok(),
            "unpinned: no scope needed"
        );
        let scoped: SemanticSearchResponse = serde_json::from_value(json!({
            "results": [], "total": 0, "query_time_ms": 1,
            "theme_scope": {"theme_id": A, "member_count": 3, "rank_by": "theme_core"},
            "next_cursor": "o:100", "truncated": false
        }))
        .unwrap();
        assert_eq!(scoped.next_cursor.as_deref(), Some("o:100"));
        assert!(check_theme_scope(Some(t), scoped.clone()).is_ok());
        let other: Uuid = B.parse().unwrap();
        assert!(
            check_theme_scope(Some(other), scoped).is_err(),
            "an answer for another theme"
        );
    }

    #[test]
    fn query_serialisation_omits_defaults() {
        let q = LayoutQuery {
            limit: 200,
            ..Default::default()
        };
        assert_eq!(as_json(&q), json!({"limit": 200}));
        let q = LayoutQuery {
            region_id: Some("unplaced"),
            rel: Some("supports,cites"),
            include_structure: true,
            limit: 50,
            ..Default::default()
        };
        assert_eq!(
            as_json(&q),
            json!({"region_id": "unplaced", "rel": "supports,cites",
                   "include_structure": true, "limit": 50})
        );
        let a: Uuid = A.parse().unwrap();
        let l = LinksQuery {
            from: a,
            to: a,
            run_id: None,
            rel: None,
            include_structure: false,
            after: Some("gl2.x"),
            limit: 9,
        };
        assert_eq!(
            as_json(&l),
            json!({"from": A, "to": A, "after": "gl2.x", "limit": 9})
        );
        assert_eq!(clamp_page(0), 1);
        assert_eq!(clamp_page(999), 200);
        assert_eq!(ContextListName::parse("papers"), None);
        assert_eq!(
            ContextListName::parse("siblings").map(ContextListName::as_str),
            Some("siblings")
        );
    }
}
