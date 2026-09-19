//! Upstream DTOs and typed calls for the graph area (theme / community /
//! neighbourhood overviews and expands). OWNED BY THE GRAPH AREA.
//!
//! Field names are copied from the mapping reports
//! (`graph-entity-endpoints.md` §1-3, `search-overview-endpoints.md` §4-5).
//! Traps these types encode:
//!
//! - Every route here is on the upstream *protected* router: a bearer is
//!   required, and every error body is `text/plain` (`(StatusCode, String)`),
//!   which [`super::UpstreamError`] already carries as the message.
//! - Theme expand returns neighbourhood *supernodes*, not claims, and a
//!   synthetic entry (`label == "synthetic"`, `size == 0`, `id == theme_id`)
//!   when the latest run has no neighbourhoods for the theme
//!   ([`ThemeExpand::is_synthetic`]).
//! - Neighbourhood expand is `#[serde(untagged)]` upstream with no mode
//!   field; [`NeighborhoodExpand`] tells the two shapes apart by the array
//!   only each one carries (`compound_groups` / `induced_edges`).
//! - Labels are raw claim content, never truncated upstream, and — since the
//!   §2.6 sweep — redacted per viewer: `graph::expand` (community) and
//!   `graph_neighborhood::expand` (both response modes) substitute
//!   [`super::REDACTED`] for labels the requester may not read. The one
//!   exception is `graph/themes/:id/expand`, whose `NeighborhoodOut.label` is
//!   a frame UUID or `"neighborhood-N"`, never claim content.
//! - `budget` has no upper cap upstream; the BFF clamps it
//!   ([`clamp_expand_budget`]).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Api, UpstreamError};

/// `budget` sent to theme/community expand when the viewer gives none.
pub const DEFAULT_EXPAND_BUDGET: u32 = 100;
/// BFF-side cap on theme/community expand `budget` (plan §3.5). Matches the
/// canvas's visible node cap, so a page never asks for more than it shows.
pub const MAX_EXPAND_BUDGET: u32 = 150;

/// Clamp a viewer-supplied expand budget to `1..=MAX_EXPAND_BUDGET`; `None`
/// means [`DEFAULT_EXPAND_BUDGET`].
pub fn clamp_expand_budget(budget: Option<i64>) -> u32 {
    match budget {
        Some(b) => b.clamp(1, i64::from(MAX_EXPAND_BUDGET)) as u32,
        None => DEFAULT_EXPAND_BUDGET,
    }
}

// ---- GET /api/v1/graph/themes/overview (graph.rs:389-407) -------------------

/// Every theme, ordered `claim_count DESC, label ASC`. Unpaginated upstream.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ThemesOverview {
    #[serde(default)]
    pub themes: Vec<ThemeSummary>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ThemeSummary {
    pub id: Uuid,
    #[serde(default)]
    pub label: String,
    /// Denormalised counter, refreshed only by a recompute.
    #[serde(default)]
    pub claim_count: i64,
}

// ---- GET /api/v1/graph/communities/overview (graph.rs:92-231) ---------------

/// The latest cluster run's Louvain graph clusters (not the perspective
/// `communities` of `/api/v1/communities`). Both arrays are unbounded.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CommunitiesOverview {
    #[serde(default)]
    pub run_id: Option<Uuid>,
    #[serde(default)]
    pub generated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub degraded: bool,
    /// `"no_clusters_computed"` when no run exists; omitted otherwise.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub supernodes: Vec<Supernode>,
    #[serde(default)]
    pub cluster_edges: Vec<WeightedEdge>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Supernode {
    pub cluster_id: Uuid,
    /// `cluster-N` or a frame UUID string.
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub mean_betp: Option<f64>,
    #[serde(default)]
    pub dominant_type: Option<String>,
    #[serde(default)]
    pub dominant_frame_id: Option<Uuid>,
}

/// An undirected weighted edge between two supernodes (`a < b`). The
/// weight is `i32` for cluster edges and `f64` for neighbourhood edges; both
/// decode as `f64`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct WeightedEdge {
    pub a: Uuid,
    pub b: Uuid,
    #[serde(default)]
    pub weight: f64,
}

// ---- GET /api/v1/graph/communities/:id/expand (graph.rs:126-156, 242) --------

/// One cluster's claims (by allowlisted degree) and the induced subgraph.
/// 404 (text/plain `"no completed run"` / `"cluster not in latest run"`)
/// once clustering has re-run.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CommunityExpand {
    pub cluster_id: Uuid,
    /// `total_size > nodes.len()`.
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub total_size: i64,
    #[serde(default)]
    pub nodes: Vec<ExpandNode>,
    #[serde(default)]
    pub edges: Vec<ExpandEdge>,
    #[serde(default)]
    pub filtered_edge_count: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ExpandNode {
    pub id: Uuid,
    /// Full claim content, not truncated; [`super::REDACTED`] when the
    /// requester may not read it (`graph::expand`, §2.6 sweep).
    #[serde(default)]
    pub label: String,
    /// Always `"claim"` today.
    #[serde(default)]
    pub entity_type: Option<String>,
    #[serde(default)]
    pub pignistic_prob: Option<f64>,
    /// An arbitrary `claim_frames` row (nondeterministic between calls).
    #[serde(default)]
    pub frame_id: Option<Uuid>,
    #[serde(default)]
    pub cluster_id: Option<Uuid>,
    /// Always null today.
    #[serde(default)]
    pub conflict_k: Option<f64>,
}

/// A directed edge of the induced subgraph over the returned nodes.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ExpandEdge {
    pub source: Uuid,
    pub target: Uuid,
    #[serde(default)]
    pub relationship: String,
}

// ---- GET /api/v1/graph/themes/:id/expand (graph.rs:414-517) -----------------

/// A theme's neighbourhood supernodes and their undirected weighted edges.
/// NOT a claim graph. `truncated` is hard-coded `false` upstream even when
/// `budget` cut the list. 404 (text/plain `"theme not found"`) when the
/// theme id is gone.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ThemeExpand {
    pub theme_id: Uuid,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub neighborhoods: Vec<NeighborhoodSummary>,
    #[serde(default)]
    pub neighborhood_edges: Vec<WeightedEdge>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct NeighborhoodSummary {
    /// A neighbourhood id — except in the synthetic entry, where it is the
    /// theme id (following it to `/neighborhood/:id` 404s).
    pub id: Uuid,
    /// A frame UUID string, `neighborhood-N`, or `"synthetic"`.
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub mean_betp: Option<f64>,
    #[serde(default)]
    pub dominant_frame_id: Option<Uuid>,
}

impl NeighborhoodSummary {
    /// The placeholder upstream returns when the latest run has no
    /// neighbourhoods for the theme (plan §3.4 "Theme expand").
    pub fn is_synthetic(&self) -> bool {
        self.label == "synthetic" && self.size == 0
    }
}

impl ThemeExpand {
    /// True when the response is only the synthetic placeholder. Render
    /// "view expired" (plan §3.4). An empty list is not synthetic: upstream
    /// never sends one, and if it did "no neighbourhoods" is the honest page.
    pub fn is_synthetic(&self) -> bool {
        !self.neighborhoods.is_empty()
            && self
                .neighborhoods
                .iter()
                .all(NeighborhoodSummary::is_synthetic)
    }
}

// ---- GET /api/v1/graph/neighborhoods/:id/expand?mode= (graph_neighborhood.rs:36-124)

/// `mode=` for neighbourhood expand. Upstream silently treats anything but
/// `atomic` as compound; the BFF normalises the same way and always sends
/// the explicit value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NeighborhoodMode {
    #[default]
    Compound,
    Atomic,
}

impl NeighborhoodMode {
    /// `atomic` (any case, trimmed) → Atomic; anything else → Compound.
    pub fn parse(s: Option<&str>) -> Self {
        match s.map(str::trim) {
            Some(m) if m.eq_ignore_ascii_case("atomic") => NeighborhoodMode::Atomic,
            _ => NeighborhoodMode::Compound,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NeighborhoodMode::Compound => "compound",
            NeighborhoodMode::Atomic => "atomic",
        }
    }
}

/// Upstream's untagged response. Variant order matters: `Atomic` requires
/// `compound_groups` and `Compound` requires `induced_edges`, the one array
/// each shape always serialises and the other never has.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum NeighborhoodExpand {
    Atomic(AtomicNeighborhood),
    Compound(CompoundNeighborhood),
}

impl NeighborhoodExpand {
    pub fn mode(&self) -> NeighborhoodMode {
        match self {
            NeighborhoodExpand::Atomic(_) => NeighborhoodMode::Atomic,
            NeighborhoodExpand::Compound(_) => NeighborhoodMode::Compound,
        }
    }

    pub fn neighborhood_id(&self) -> Uuid {
        match self {
            NeighborhoodExpand::Atomic(a) => a.neighborhood_id,
            NeighborhoodExpand::Compound(c) => c.neighborhood_id,
        }
    }
}

/// Compound mode: the `decomposes_to` parents of the member atoms (usually
/// not members themselves) and three edge arrays. There is no `edges` key.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompoundNeighborhood {
    pub neighborhood_id: Uuid,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub nodes: Vec<CompoundNode>,
    /// Required: the discriminator against [`AtomicNeighborhood`].
    pub induced_edges: Vec<InducedEdge>,
    #[serde(default)]
    pub direct_edges: Vec<DirectEdge>,
    #[serde(default)]
    pub structural_edges: Vec<StructuralEdge>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompoundNode {
    pub id: Uuid,
    #[serde(default)]
    pub label: String,
    /// `"compound"` or `"standalone"`.
    #[serde(default)]
    pub kind: String,
    /// 0 for standalone nodes.
    #[serde(default)]
    pub atom_count: i64,
    #[serde(default)]
    pub pignistic_prob: Option<f64>,
    #[serde(default)]
    pub frame_id: Option<Uuid>,
}

/// Compound → compound, lifted from atom edges with `forward_strength > 0`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct InducedEdge {
    pub source: Uuid,
    pub target: Uuid,
    #[serde(default)]
    pub relationship: String,
    #[serde(default)]
    pub strength: Option<f64>,
    #[serde(default)]
    pub atom_edge_count: i64,
}

/// Unfiltered, not de-duplicated upstream (may include `decomposes_to`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DirectEdge {
    pub source: Uuid,
    pub target: Uuid,
    #[serde(default)]
    pub relationship: String,
}

/// Undirected (LEAST/GREATEST), and has `kind` instead of `relationship`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StructuralEdge {
    pub source: Uuid,
    pub target: Uuid,
    /// `"shared_atom"` or `"shared_ancestor"`.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub atom_count: i64,
}

/// Atomic mode: member atoms, their edges (no `decomposes_to`) and the
/// compound groups they belong to.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AtomicNeighborhood {
    pub neighborhood_id: Uuid,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub nodes: Vec<AtomicNode>,
    #[serde(default)]
    pub edges: Vec<ExpandEdge>,
    /// Required: the discriminator against [`CompoundNeighborhood`].
    pub compound_groups: Vec<CompoundGroup>,
}

/// No `atom_count` in atomic mode.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AtomicNode {
    pub id: Uuid,
    #[serde(default)]
    pub label: String,
    /// First parent (nondeterministic for multi-parent atoms).
    #[serde(default)]
    pub compound_id: Option<Uuid>,
    #[serde(default)]
    pub pignistic_prob: Option<f64>,
    #[serde(default)]
    pub frame_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompoundGroup {
    /// Generally not among the atomic `nodes`.
    pub compound_id: Uuid,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub member_atom_ids: Vec<Uuid>,
}

// ---- typed calls ----------------------------------------------------------------

#[derive(Serialize)]
struct Budget {
    budget: u32,
}

#[derive(Serialize)]
struct Mode {
    mode: NeighborhoodMode,
}

impl Api<'_> {
    /// `GET /api/v1/graph/themes/overview` (bearer required).
    pub async fn themes_overview(&self) -> Result<ThemesOverview, UpstreamError> {
        self.get("/api/v1/graph/themes/overview").await
    }

    /// `GET /api/v1/graph/communities/overview` (bearer required).
    pub async fn communities_overview(&self) -> Result<CommunitiesOverview, UpstreamError> {
        self.get("/api/v1/graph/communities/overview").await
    }

    /// `GET /api/v1/graph/themes/:id/expand?budget=`; `budget` is clamped
    /// to `1..=MAX_EXPAND_BUDGET`.
    pub async fn theme_expand(&self, id: Uuid, budget: u32) -> Result<ThemeExpand, UpstreamError> {
        let q = Budget {
            budget: budget.clamp(1, MAX_EXPAND_BUDGET),
        };
        self.get_query(&format!("/api/v1/graph/themes/{id}/expand"), &q)
            .await
    }

    /// `GET /api/v1/graph/communities/:id/expand?budget=`; `budget` is
    /// clamped to `1..=MAX_EXPAND_BUDGET`.
    pub async fn community_expand(
        &self,
        id: Uuid,
        budget: u32,
    ) -> Result<CommunityExpand, UpstreamError> {
        let q = Budget {
            budget: budget.clamp(1, MAX_EXPAND_BUDGET),
        };
        self.get_query(&format!("/api/v1/graph/communities/{id}/expand"), &q)
            .await
    }

    /// `GET /api/v1/graph/neighborhoods/:id/expand?mode=`. Upstream ignores
    /// `budget` and has no node cap here; callers cap what they render.
    pub async fn neighborhood_expand(
        &self,
        id: Uuid,
        mode: NeighborhoodMode,
    ) -> Result<NeighborhoodExpand, UpstreamError> {
        self.get_query(
            &format!("/api/v1/graph/neighborhoods/{id}/expand"),
            &Mode { mode },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T: &str = "00000000-0000-0000-0000-0000000000a1";
    const N1: &str = "00000000-0000-0000-0000-0000000000b1";
    const N2: &str = "00000000-0000-0000-0000-0000000000b2";

    #[test]
    fn budgets_clamp() {
        assert_eq!(clamp_expand_budget(None), DEFAULT_EXPAND_BUDGET);
        assert_eq!(clamp_expand_budget(Some(0)), 1);
        assert_eq!(clamp_expand_budget(Some(-7)), 1);
        assert_eq!(clamp_expand_budget(Some(10_000)), MAX_EXPAND_BUDGET);
        assert_eq!(clamp_expand_budget(Some(42)), 42);
    }

    #[test]
    fn mode_parsing_matches_upstream_fallthrough() {
        assert_eq!(NeighborhoodMode::parse(None), NeighborhoodMode::Compound);
        assert_eq!(
            NeighborhoodMode::parse(Some("Atomic ")),
            NeighborhoodMode::Atomic
        );
        assert_eq!(
            NeighborhoodMode::parse(Some("bogus")),
            NeighborhoodMode::Compound
        );
        assert_eq!(NeighborhoodMode::Atomic.as_str(), "atomic");
    }

    #[test]
    fn theme_expand_synthetic_detection() {
        let synthetic: ThemeExpand = serde_json::from_value(json!({
            "theme_id": T, "truncated": false,
            "neighborhoods": [{"id": T, "label": "synthetic", "size": 0,
                               "mean_betp": null, "dominant_frame_id": null}],
            "neighborhood_edges": []
        }))
        .unwrap();
        assert!(synthetic.is_synthetic());

        let real: ThemeExpand = serde_json::from_value(json!({
            "theme_id": T, "truncated": false,
            "neighborhoods": [
                {"id": N1, "label": "neighborhood-1", "size": 12, "mean_betp": 0.61,
                 "dominant_frame_id": null},
                {"id": N2, "label": "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10", "size": 3}
            ],
            "neighborhood_edges": [{"a": N1, "b": N2, "weight": 0.25}]
        }))
        .unwrap();
        assert!(!real.is_synthetic());

        let empty: ThemeExpand = serde_json::from_value(json!({"theme_id": T})).unwrap();
        assert!(!empty.is_synthetic(), "no entries is not the placeholder");
        assert_eq!(real.neighborhoods[1].mean_betp, None, "omitted → None");
        assert_eq!(real.neighborhood_edges[0].weight, 0.25);
    }

    #[test]
    fn communities_overview_tolerates_no_run() {
        let o: CommunitiesOverview = serde_json::from_value(json!({
            "run_id": null, "generated_at": null, "degraded": false,
            "status": "no_clusters_computed", "supernodes": [], "cluster_edges": []
        }))
        .unwrap();
        assert_eq!(o.status.as_deref(), Some("no_clusters_computed"));

        // `status` omitted and i32 weights once a run exists.
        let o: CommunitiesOverview = serde_json::from_value(json!({
            "run_id": T, "generated_at": "2026-09-01T00:00:00Z", "degraded": false,
            "supernodes": [{"cluster_id": N1, "label": "cluster-1", "size": 40,
                            "mean_betp": null, "dominant_type": null,
                            "dominant_frame_id": null}],
            "cluster_edges": [{"a": N1, "b": N2, "weight": 7}]
        }))
        .unwrap();
        assert!(o.status.is_none());
        assert_eq!(o.cluster_edges[0].weight, 7.0);
    }

    #[test]
    fn neighborhood_shapes_are_told_apart_without_a_mode_field() {
        let compound: NeighborhoodExpand = serde_json::from_value(json!({
            "neighborhood_id": N1, "truncated": false,
            "nodes": [{"id": N2, "label": "c", "kind": "compound", "atom_count": 3,
                       "pignistic_prob": null, "frame_id": null}],
            "induced_edges": [], "direct_edges": [],
            "structural_edges": [{"source": N1, "target": N2, "kind": "shared_atom",
                                  "atom_count": 1}]
        }))
        .unwrap();
        assert_eq!(compound.mode(), NeighborhoodMode::Compound);
        assert_eq!(compound.neighborhood_id().to_string(), N1);

        let atomic: NeighborhoodExpand = serde_json::from_value(json!({
            "neighborhood_id": N1, "truncated": false,
            "nodes": [{"id": N2, "label": "a", "compound_id": null,
                       "pignistic_prob": 0.5, "frame_id": null}],
            "edges": [{"source": N2, "target": N1, "relationship": "supports"}],
            "compound_groups": [{"compound_id": T, "label": "g", "member_atom_ids": [N2]}]
        }))
        .unwrap();
        assert_eq!(atomic.mode(), NeighborhoodMode::Atomic);

        let neither = serde_json::from_value::<NeighborhoodExpand>(json!({
            "neighborhood_id": N1, "nodes": []
        }));
        assert!(
            neither.is_err(),
            "a payload with neither array is a decode error"
        );
    }
}
