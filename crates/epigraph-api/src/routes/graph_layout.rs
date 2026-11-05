//! `GET /api/v1/graph/themes/layout` and `GET /api/v1/graph/links` — the
//! Atlas map's shared theme and region positions, and the claim pairs behind
//! one of its bundles (Atlas P3a; migration 197).
//!
//! # What is shared and what is the viewer's
//!
//! Positions (`x`, `y`, `r`), region labels and bundle counts come from the
//! latest layout run, which the operator CLI `atlas_layout` builds from PUBLIC
//! current claims and public in-force edges only. Everything else is decided
//! per viewer, inside the viewer predicate, on the caller's stamped connection:
//!
//! * a theme appears only if the caller can read one of its current members,
//!   and its `member_count` is the caller's own count;
//! * a region appears only if it holds such a theme; its `theme_count`,
//!   `member_count` and `theme_ids` are the caller's;
//! * a bundle sums the shared public counts only over theme pairs whose two
//!   themes the caller can see;
//! * a theme with no public member has no shared position. If the caller can
//!   read an embedded member of it, it is placed (`placement: "viewer"`, no
//!   `x`/`y`) in the region nearest the centroid of the members THIS caller
//!   can read, for this caller only; otherwise it is listed under
//!   `region_id=unplaced`.
//!
//! A run is served only while no public claim or edge has been narrowed since
//! its snapshot (migration 197's epoch). Otherwise the answer is a 200 with
//! `status: "layout_invalidated"` and no positions, and the client falls back
//! to packing themes by size.
//!
//! # Not cacheable across viewers
//!
//! Both routes answer `Cache-Control: private, no-store` and `Vary:
//! Authorization`, with no `ETag`: the body depends on the caller's principal
//! and groups, and a validator keyed on the run would answer 304 across a
//! membership change.
//!
//! # The drill-down reads live
//!
//! `/graph/links` reads the claim pairs between two themes, two regions'
//! shared themes, or a theme and a region, from `edges` and `claims` directly
//! through the viewer predicate, and counts them inside it. Items are ordered
//! by `properties.strength` (else `properties.confidence`) descending, nulls
//! last, then newest; when few edges carry a numeric strength the order is
//! effectively newest-first.
//!
//! A 404 is the same for an id that names nothing and for one whose members
//! the caller cannot read; the body echoes only the caller's own id. The sides
//! are decided in a fixed order (`from`, then `to`) and the first failing one
//! is echoed, whatever the other side is. The `layout_invalidated` 200 and the
//! overlap 400 (a theme inside the region it is paired with) come only after
//! both sides passed that check, so neither can reveal that a hidden theme or
//! region exists, or where a hidden theme sits.
//!
//! All SQL lives in `epigraph_db::AtlasLayoutRepository`.

use std::collections::BTreeMap;

use axum::{
    extract::{Query, State},
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use epigraph_db::repos::atlas_layout::{
    theme_sets_overlap, DetailPart, LayoutLinkCursor, LayoutLinkRow, LayoutRunRow, LinkPairCursor,
    LinkSideKind, ThemePageCursor, ThemePlacement, UnplacedCursor, VisibleRegionRow,
    VisibleThemeRow, ATLAS_DEFAULT_RELATIONSHIPS, ATLAS_LAYOUT_EXTENT, ATLAS_PAGE_MAX,
    ATLAS_STRUCTURE_RELATIONSHIPS,
};
use epigraph_db::AtlasLayoutRepository;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::routes::ego::clip_label;
use crate::state::AppState;

/// Default page size of `/graph/links`.
const LINKS_DEFAULT_LIMIT: i64 = 50;

/// Longest relationship name `rel=` accepts (the column is `varchar(100)`).
const MAX_RELATIONSHIP_LEN: usize = 100;

/// The relationship filter both routes share.
///
/// * `None` or blank: [`ATLAS_DEFAULT_RELATIONSHIPS`].
/// * `*` or `all`: `Ok(None)`, no filter.
/// * Otherwise a comma list, trimmed and lower-cased, empties dropped; each
///   name is 1..=100 of `[a-z0-9_-]`, anything else is `Err`.
///
/// `include_structure` adds [`ATLAS_STRUCTURE_RELATIONSHIPS`] to the set.
/// Order is kept and repeats are dropped.
///
/// # Errors
/// A name with any other character, or longer than 100.
pub fn resolve_atlas_relationships(
    rel: Option<&str>,
    include_structure: bool,
) -> Result<Option<Vec<String>>, String> {
    let raw = rel.map(str::trim).filter(|s| !s.is_empty());
    let mut out: Vec<String> = Vec::new();
    match raw {
        Some(s) if s == "*" || s.eq_ignore_ascii_case("all") => return Ok(None),
        Some(s) => {
            for name in s.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                let name = name.to_ascii_lowercase();
                let ok = name.len() <= MAX_RELATIONSHIP_LEN
                    && name.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
                    });
                if !ok {
                    return Err(format!("`rel` names an invalid relationship: {name:?}"));
                }
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        None => {}
    }
    if out.is_empty() {
        out = ATLAS_DEFAULT_RELATIONSHIPS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }
    if include_structure {
        for s in ATLAS_STRUCTURE_RELATIONSHIPS {
            if !out.iter().any(|o| o == s) {
                out.push((*s).to_string());
            }
        }
    }
    Ok(Some(out))
}

/// The relationship list a response echoes: the filter, or `["*"]`.
fn echo_relationships(rels: Option<&[String]>) -> Vec<String> {
    rels.map_or_else(|| vec!["*".to_string()], <[String]>::to_vec)
}

fn clamp_limit(limit: Option<i64>, default: i64) -> i64 {
    limit.unwrap_or(default).clamp(1, ATLAS_PAGE_MAX)
}

fn bad_request(message: impl Into<String>) -> ApiError {
    ApiError::BadRequest {
        message: message.into(),
    }
}

fn scoped_read_failed(e: impl std::fmt::Display, handler: &'static str) -> ApiError {
    tracing::error!(
        target: "tenancy.scoped_read",
        error = %e,
        handler = handler,
        "could not acquire a viewer-stamped connection"
    );
    ApiError::InternalError {
        message: "Failed to acquire a scoped connection".to_string(),
    }
}

/// A JSON body with the private, uncacheable headers both routes carry.
fn private_json<T: Serialize>(body: T) -> Response {
    (
        [
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            ),
            (header::VARY, HeaderValue::from_static("Authorization")),
        ],
        Json(body),
    )
        .into_response()
}

// ── /graph/themes/layout ─────────────────────────────────────────────────────

/// Query of `GET /api/v1/graph/themes/layout`. Typed, so a malformed value is
/// a 400 from the extractor.
#[derive(Debug, Deserialize)]
pub struct LayoutQuery {
    /// Default: the latest layout run.
    #[serde(default)]
    pub run_id: Option<Uuid>,
    /// A region of the run, or `unplaced`. Absent: the top level.
    #[serde(default)]
    pub region_id: Option<String>,
    /// Comma list, or `*` / `all`. Default: the epistemic set plus `cites`.
    #[serde(default)]
    pub rel: Option<String>,
    /// Add `decomposes_to` to the set.
    #[serde(default)]
    pub include_structure: Option<bool>,
    /// Next themes page (region level and `unplaced` only).
    #[serde(default)]
    pub themes_after: Option<String>,
    /// Next bundles page.
    #[serde(default)]
    pub links_after: Option<String>,
    /// Each list's page size, clamped to `1..=200`; default 200.
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct RunOut {
    pub run_id: Uuid,
    pub completed_at: DateTime<Utc>,
    pub algo: String,
    pub cluster_run_id: Option<Uuid>,
    pub stale: bool,
    pub extent: f64,
}

impl RunOut {
    fn of(run: &LayoutRunRow) -> Self {
        Self {
            run_id: run.id,
            completed_at: run.completed_at,
            algo: run.algo.clone(),
            cluster_run_id: run.cluster_run_id,
            stale: run.stale,
            extent: ATLAS_LAYOUT_EXTENT,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RegionOut {
    pub id: Uuid,
    pub label: String,
    pub x: f64,
    pub y: f64,
    pub r: f64,
    /// Top level only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme_ids: Option<Vec<Uuid>>,
    pub theme_count: i64,
    pub member_count: i64,
}

impl RegionOut {
    fn of(r: &VisibleRegionRow, with_ids: bool) -> Self {
        Self {
            id: r.id,
            label: clip_label(&r.label),
            x: r.x,
            y: r.y,
            r: r.r,
            theme_ids: with_ids.then(|| r.theme_ids.clone()),
            theme_count: r.theme_count,
            member_count: r.member_count,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ThemeOut {
    pub id: Uuid,
    pub label: String,
    pub region_id: Option<Uuid>,
    /// `"shared"` or `"viewer"`; `null` for a theme listed under
    /// `region_id=unplaced`, which has no position of either kind.
    pub placement: Option<&'static str>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub member_count: i64,
}

impl ThemeOut {
    fn of(t: &VisibleThemeRow) -> Self {
        Self {
            id: t.theme_id,
            label: clip_label(&t.label),
            region_id: t.region_id,
            placement: match t.placement {
                ThemePlacement::Unplaced => None,
                p => Some(p.as_str()),
            },
            x: t.x,
            y: t.y,
            member_count: t.member_count,
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LinkOut {
    pub kind: String,
    pub a: Uuid,
    pub b: Uuid,
    pub counts: BTreeMap<String, i64>,
    pub total: i64,
}

/// Fold per-relationship rows into one bundle per `(kind, a, b)`, in order.
fn fold_links(rows: &[LayoutLinkRow]) -> Vec<LinkOut> {
    let mut out: Vec<LinkOut> = Vec::new();
    for row in rows {
        let same = out
            .last()
            .is_some_and(|l| l.kind == row.kind && l.a == row.a && l.b == row.b);
        if !same {
            out.push(LinkOut {
                kind: row.kind.clone(),
                a: row.a,
                b: row.b,
                counts: BTreeMap::new(),
                total: row.total,
            });
        }
        if let Some(l) = out.last_mut() {
            *l.counts.entry(row.relationship.clone()).or_default() += row.link_count;
        }
    }
    out
}

#[derive(Debug, Default, Serialize)]
pub struct NextOut {
    pub themes: Option<String>,
    pub links: Option<String>,
}

/// The top level, and the no-run / invalidated answer at any level.
#[derive(Debug, Serialize)]
pub struct TopLevelResponse {
    pub run: Option<RunOut>,
    pub status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<Vec<String>>,
    pub regions: Vec<RegionOut>,
    pub links: Vec<LinkOut>,
    pub unplaced_theme_count: i64,
    pub next: NextOut,
}

impl TopLevelResponse {
    fn no_run(status: &'static str) -> Self {
        Self {
            run: None,
            status: Some(status),
            relationships: None,
            regions: Vec::new(),
            links: Vec::new(),
            unplaced_theme_count: 0,
            next: NextOut::default(),
        }
    }
}

/// A region page, or the unplaced list (`region: null`).
#[derive(Debug, Serialize)]
pub struct RegionLevelResponse {
    pub run: RunOut,
    pub status: Option<&'static str>,
    pub relationships: Vec<String>,
    pub region: Option<RegionOut>,
    pub themes: Vec<ThemeOut>,
    pub links: Vec<LinkOut>,
    pub next: NextOut,
}

enum Level {
    Top,
    Region(Uuid),
    Unplaced,
}

/// `GET /api/v1/graph/themes/layout`
pub async fn themes_layout(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Query(q): Query<LayoutQuery>,
) -> Result<Response, ApiError> {
    // 1. Validate everything before touching the database.
    let level = match q.region_id.as_deref().map(str::trim) {
        None => Level::Top,
        Some("unplaced") => Level::Unplaced,
        Some(s) => Level::Region(
            Uuid::try_parse(s)
                .map_err(|_| bad_request("`region_id` is not a uuid or `unplaced`"))?,
        ),
    };
    if q.themes_after.is_some() && q.links_after.is_some() {
        return Err(bad_request(
            "`themes_after` and `links_after` cannot be combined; page one list at a time",
        ));
    }
    if q.themes_after.is_some() && matches!(level, Level::Top) {
        return Err(bad_request(
            "`themes_after` pages a region's themes; give `region_id` with it",
        ));
    }
    if q.links_after.is_some() && matches!(level, Level::Unplaced) {
        return Err(bad_request("the unplaced list has no links to page"));
    }
    let links_after = match q.links_after.as_deref() {
        None => None,
        Some(t) => Some(
            LayoutLinkCursor::decode(t)
                .ok_or_else(|| bad_request("`links_after` is not a valid cursor"))?,
        ),
    };
    let themes_after_region = match (&level, q.themes_after.as_deref()) {
        (Level::Region(_), Some(t)) => Some(
            ThemePageCursor::decode(t)
                .ok_or_else(|| bad_request("`themes_after` is not a valid cursor"))?,
        ),
        _ => None,
    };
    let themes_after_unplaced = match (&level, q.themes_after.as_deref()) {
        (Level::Unplaced, Some(t)) => Some(
            UnplacedCursor::decode(t)
                .ok_or_else(|| bad_request("`themes_after` is not a valid cursor"))?,
        ),
        _ => None,
    };
    let limit = clamp_limit(q.limit, ATLAS_PAGE_MAX);
    let rels = resolve_atlas_relationships(q.rel.as_deref(), q.include_structure.unwrap_or(false))
        .map_err(bad_request)?;

    // 2. The caller's stamped connection.
    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| scoped_read_failed(e, "themes_layout"))?;

    // 3. The run.
    let run = AtlasLayoutRepository::run(&mut *read, q.run_id).await?;
    let Some(run) = run else {
        crate::routes::finish_scoped_read(read, "themes_layout").await?;
        if let Some(id) = q.run_id {
            return Err(ApiError::NotFound {
                entity: "Layout run".to_string(),
                id: id.to_string(),
            });
        }
        return Ok(private_json(TopLevelResponse::no_run("no_layout_run")));
    };
    if !run.current {
        crate::routes::finish_scoped_read(read, "themes_layout").await?;
        return Ok(private_json(TopLevelResponse::no_run("layout_invalidated")));
    }
    let relationships = echo_relationships(rels.as_deref());

    // 4. The level.
    match level {
        Level::Top => {
            let overview = AtlasLayoutRepository::overview(
                &mut read,
                &viewer,
                run.id,
                rels.as_deref(),
                links_after,
                limit,
            )
            .await?;
            crate::routes::finish_scoped_read(read, "themes_layout").await?;
            let regions = if links_after.is_some() {
                Vec::new()
            } else {
                overview
                    .regions
                    .iter()
                    .map(|r| RegionOut::of(r, true))
                    .collect()
            };
            Ok(private_json(TopLevelResponse {
                run: Some(RunOut::of(&run)),
                status: None,
                relationships: Some(relationships),
                regions,
                links: fold_links(&overview.links),
                unplaced_theme_count: overview.unplaced_theme_count,
                next: NextOut {
                    themes: None,
                    links: overview.next_links.map(|c| c.encode()),
                },
            }))
        }
        Level::Region(region_id) => {
            let part = match (themes_after_region, links_after) {
                (Some(c), _) => DetailPart::ThemesAfter(c),
                (None, Some(c)) => DetailPart::LinksAfter(c),
                (None, None) => DetailPart::Both,
            };
            let detail = AtlasLayoutRepository::region_detail(
                &mut read,
                &viewer,
                run.id,
                region_id,
                rels.as_deref(),
                part,
                limit,
            )
            .await?;
            crate::routes::finish_scoped_read(read, "themes_layout").await?;
            let detail = detail.ok_or_else(|| ApiError::NotFound {
                entity: "Region".to_string(),
                id: region_id.to_string(),
            })?;
            Ok(private_json(RegionLevelResponse {
                run: RunOut::of(&run),
                status: None,
                relationships,
                region: Some(RegionOut::of(&detail.region, false)),
                themes: detail.themes.iter().map(ThemeOut::of).collect(),
                links: fold_links(&detail.links),
                next: NextOut {
                    themes: detail.next_themes.map(|c| c.encode()),
                    links: detail.next_links.map(|c| c.encode()),
                },
            }))
        }
        Level::Unplaced => {
            let page = AtlasLayoutRepository::unplaced_themes(
                &mut read,
                &viewer,
                run.id,
                themes_after_unplaced,
                limit,
            )
            .await?;
            crate::routes::finish_scoped_read(read, "themes_layout").await?;
            Ok(private_json(RegionLevelResponse {
                run: RunOut::of(&run),
                status: None,
                relationships,
                region: None,
                themes: page.themes.iter().map(ThemeOut::of).collect(),
                links: Vec::new(),
                next: NextOut {
                    themes: page.next.map(|c| c.encode()),
                    links: None,
                },
            }))
        }
    }
}

// ── /graph/links ─────────────────────────────────────────────────────────────

/// Query of `GET /api/v1/graph/links`.
#[derive(Debug, Deserialize)]
pub struct LinksQuery {
    /// A theme id, or a region id of the run.
    #[serde(default)]
    pub from: Option<Uuid>,
    #[serde(default)]
    pub to: Option<Uuid>,
    /// Resolves region ids; default the latest layout run.
    #[serde(default)]
    pub run_id: Option<Uuid>,
    #[serde(default)]
    pub rel: Option<String>,
    #[serde(default)]
    pub include_structure: Option<bool>,
    #[serde(default)]
    pub after: Option<String>,
    /// Clamped to `1..=200`; default 50.
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SideOut {
    pub id: Uuid,
    pub kind: &'static str,
}

#[derive(Debug, Serialize)]
pub struct LinkEndOut {
    pub id: Uuid,
    pub label: String,
    pub truth_value: f64,
    pub theme_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct LinkItemOut {
    pub edge_id: Uuid,
    pub relationship: String,
    pub strength: Option<f64>,
    /// Relative to `from`: `from_to` or `to_from`.
    pub direction: &'static str,
    pub created_at: DateTime<Utc>,
    pub source: LinkEndOut,
    pub target: LinkEndOut,
}

#[derive(Debug, Serialize)]
pub struct LinksResponse {
    pub from: SideOut,
    pub to: SideOut,
    pub run_id: Option<Uuid>,
    pub status: Option<&'static str>,
    pub relationships: Vec<String>,
    /// Per-relationship counts the caller may read, on the first page only.
    pub counts: Option<BTreeMap<String, i64>>,
    /// The sum of those counts, on every page; `null` when invalidated.
    pub total: Option<i64>,
    pub items: Vec<LinkItemOut>,
    pub next: Option<String>,
}

fn side_not_found(id: Uuid) -> ApiError {
    ApiError::NotFound {
        entity: "Theme or region".to_string(),
        id: id.to_string(),
    }
}

/// `GET /api/v1/graph/links`
pub async fn graph_links(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Query(q): Query<LinksQuery>,
) -> Result<Response, ApiError> {
    // 1. Validate.
    let (Some(from), Some(to)) = (q.from, q.to) else {
        return Err(bad_request("`from` and `to` are both required"));
    };
    if from == to {
        return Err(bad_request("`from` and `to` must differ"));
    }
    let after = match q.after.as_deref() {
        None => None,
        Some(t) => Some(
            LinkPairCursor::decode(t)
                .ok_or_else(|| bad_request("`after` is not a valid cursor"))?,
        ),
    };
    let limit = clamp_limit(q.limit, LINKS_DEFAULT_LIMIT);
    let rels = resolve_atlas_relationships(q.rel.as_deref(), q.include_structure.unwrap_or(false))
        .map_err(bad_request)?;
    let relationships = echo_relationships(rels.as_deref());

    // 2. The caller's stamped connection.
    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| scoped_read_failed(e, "graph_links"))?;

    // 3. The run (it resolves region ids). An unknown explicit run is the
    //    same 404 shape as every other 404 on this route.
    let run = AtlasLayoutRepository::run(&mut *read, q.run_id).await?;
    if run.is_none() {
        if let Some(id) = q.run_id {
            crate::routes::finish_scoped_read(read, "graph_links").await?;
            return Err(side_not_found(id));
        }
    }

    // 4. Both sides, in one statement.
    let (from_side, to_side) =
        AtlasLayoutRepository::resolve_sides(&mut *read, run.as_ref().map(|r| r.id), from, to)
            .await?;

    // 5. Each side, in a fixed order (`from`, then `to`), must name a theme
    //    or region AND hold a current member the caller can read. Both
    //    failures are the same 404, and the first failing side is the one
    //    echoed, so neither the echoed id nor the status says whether a side
    //    the caller cannot read exists. This runs before the
    //    `layout_invalidated` answer, which would otherwise be a 200 for a
    //    hidden theme and a 404 for a random id.
    let from_ok = match &from_side {
        Some(s) => {
            AtlasLayoutRepository::any_visible_member(&mut read, &viewer, &s.theme_ids).await?
        }
        None => false,
    };
    let Some(from_side) = from_side.filter(|_| from_ok) else {
        crate::routes::finish_scoped_read(read, "graph_links").await?;
        return Err(side_not_found(from));
    };
    let to_ok = match &to_side {
        Some(s) => {
            AtlasLayoutRepository::any_visible_member(&mut read, &viewer, &s.theme_ids).await?
        }
        None => false,
    };
    let Some(to_side) = to_side.filter(|_| to_ok) else {
        crate::routes::finish_scoped_read(read, "graph_links").await?;
        return Err(side_not_found(to));
    };

    // 6. A region side needs a current run.
    let any_region = from_side.kind == LinkSideKind::Region || to_side.kind == LinkSideKind::Region;
    let run_id = if any_region {
        run.as_ref().map(|r| r.id)
    } else {
        None
    };
    let side_out = |s: &epigraph_db::repos::atlas_layout::LinkSide| SideOut {
        id: s.id,
        kind: s.kind.as_str(),
    };
    if any_region && !run.as_ref().is_some_and(|r| r.current) {
        crate::routes::finish_scoped_read(read, "graph_links").await?;
        return Ok(private_json(LinksResponse {
            from: side_out(&from_side),
            to: side_out(&to_side),
            run_id,
            status: Some("layout_invalidated"),
            relationships,
            counts: None,
            total: None,
            items: Vec::new(),
            next: None,
        }));
    }

    // 7. Only now: a theme inside the region it is paired with.
    if theme_sets_overlap(&from_side.theme_ids, &to_side.theme_ids) {
        crate::routes::finish_scoped_read(read, "graph_links").await?;
        return Err(bad_request(
            "`from` and `to` overlap (a theme inside the region it is paired with); there are no \
             links between them to list",
        ));
    }

    // 8. The page and its counts, inside the viewer predicate.
    let page = AtlasLayoutRepository::links_between(
        &mut read,
        &viewer,
        &from_side.theme_ids,
        &to_side.theme_ids,
        rels.as_deref(),
        after,
        limit,
    )
    .await?;
    crate::routes::finish_scoped_read(read, "graph_links").await?;

    let total: i64 = page.counts.iter().map(|(_, n)| n).sum();
    let counts = after
        .is_none()
        .then(|| page.counts.iter().cloned().collect::<BTreeMap<_, _>>());
    let items = page
        .items
        .iter()
        .map(|i| LinkItemOut {
            edge_id: i.edge_id,
            relationship: i.relationship.clone(),
            strength: i.strength,
            direction: if i.from_is_source {
                "from_to"
            } else {
                "to_from"
            },
            created_at: i.created_at,
            source: LinkEndOut {
                id: i.source_id,
                label: clip_label(&i.source_content),
                truth_value: i.source_truth_value,
                theme_id: i.source_theme_id,
            },
            target: LinkEndOut {
                id: i.target_id,
                label: clip_label(&i.target_content),
                truth_value: i.target_truth_value,
                theme_id: i.target_theme_id,
            },
        })
        .collect();
    Ok(private_json(LinksResponse {
        from: side_out(&from_side),
        to: side_out(&to_side),
        run_id,
        status: None,
        relationships,
        counts,
        total: Some(total),
        items,
        next: page.next.map(|c| c.encode()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn theme_row(placement: ThemePlacement) -> VisibleThemeRow {
        VisibleThemeRow {
            theme_id: Uuid::nil(),
            label: "t".into(),
            region_id: None,
            placement,
            x: None,
            y: None,
            member_count: 1,
        }
    }

    #[test]
    fn an_unplaced_theme_serialises_placement_as_null() {
        let v = |p| serde_json::to_value(ThemeOut::of(&theme_row(p))).unwrap()["placement"].clone();
        assert_eq!(v(ThemePlacement::Shared), serde_json::json!("shared"));
        assert_eq!(v(ThemePlacement::Viewer), serde_json::json!("viewer"));
        assert_eq!(v(ThemePlacement::Unplaced), serde_json::Value::Null);
    }

    #[test]
    fn the_default_set_is_epistemic_plus_cites_and_structure_is_opt_in() {
        let d = resolve_atlas_relationships(None, false).unwrap().unwrap();
        assert_eq!(d, ATLAS_DEFAULT_RELATIONSHIPS);
        assert!(!d.iter().any(|r| r == "decomposes_to"));
        let s = resolve_atlas_relationships(Some("  "), true)
            .unwrap()
            .unwrap();
        assert_eq!(s.last().map(String::as_str), Some("decomposes_to"));
    }

    #[test]
    fn rel_replaces_lowercases_and_dedupes() {
        let r = resolve_atlas_relationships(Some("Supports, cites,,SUPPORTS"), false)
            .unwrap()
            .unwrap();
        assert_eq!(r, vec!["supports".to_string(), "cites".to_string()]);
        let r = resolve_atlas_relationships(Some("supports"), true)
            .unwrap()
            .unwrap();
        assert_eq!(r, vec!["supports".to_string(), "decomposes_to".to_string()]);
    }

    #[test]
    fn star_and_all_mean_no_filter() {
        assert_eq!(resolve_atlas_relationships(Some("*"), false), Ok(None));
        assert_eq!(resolve_atlas_relationships(Some("ALL"), true), Ok(None));
    }

    #[test]
    fn a_bad_name_is_refused() {
        assert!(resolve_atlas_relationships(Some("supports;drop"), false).is_err());
        assert!(resolve_atlas_relationships(Some(&"a".repeat(101)), false).is_err());
    }

    #[test]
    fn fold_links_groups_consecutive_rows() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let row = |rel: &str, n: i64| LayoutLinkRow {
            kind: "region".into(),
            a,
            b,
            relationship: rel.into(),
            link_count: n,
            total: 46,
        };
        let out = fold_links(&[row("contradicts", 6), row("supports", 40)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].total, 46);
        assert_eq!(out[0].counts["supports"], 40);
        assert_eq!(out[0].counts["contradicts"], 6);
    }
}
