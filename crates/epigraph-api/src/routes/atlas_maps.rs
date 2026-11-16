//! The per-team Atlas maps' nested levels (Atlas W10, backlog 083c97b9):
//!
//! | Route | What |
//! |---|---|
//! | `GET /api/v1/atlas/maps` | the maps the caller can see |
//! | `GET /api/v1/atlas/maps/:map/themes` | each theme's name, claim count and root level per hierarchy on that map |
//! | `GET /api/v1/atlas/maps/:map/:hierarchy/levels/:id` | one level document (contract `atlas_level` v1) |
//! | `GET /api/v1/atlas/maps/:map/:hierarchy/claims/:claim_id/leaf` | the leaf holding a claim (contract `atlas_claim_leaf` v1) |
//!
//! `:map` is `public` or a team group's id; `:hierarchy` is `meaning` or
//! `links`.
//!
//! # Precomputed rows only
//!
//! A level is the document the nightly stored (migration 210,
//! `atlas_map_levels`), read by `AtlasMapRepository::level_for_viewer` in one
//! indexed statement on the caller's stamped connection. Nothing is computed
//! here but the per-viewer filter below.
//!
//! # What a viewer gets
//!
//! * A team map's rows are its members' (row security), so a non-member's
//!   session finds none of them.
//! * A leaf is served through `LevelDocument::for_viewer`, given which of its
//!   nodes the caller's own session can read (claims and evidence through
//!   their row security, agents by existence): a member never sees a node, or
//!   an edge to one, that their session cannot read. A group level is served
//!   as stored.
//! * **Staleness.** A run is served while nothing LEFT its map's readable set
//!   since the build (`nothing_left`), even when something arrived (`current`
//!   false: the map is only incomplete until the next nightly). A run where a
//!   row left is refused. No epoch, counter or flag is in any body.
//!
//! # One not-found body
//!
//! Every refusal of a level is `NotFound { entity: "atlas_level", id }` with
//! the requested id: an unknown id, a non-member, a map or hierarchy segment
//! that names nothing, a run something left, a leaf with no claim left for
//! this viewer, and a stored document that is not v1 or does not describe the
//! map, hierarchy, level and run it is stored under (a builder fault, logged).
//! So nothing tells "exists, not yours" from "does not exist". The theme
//! route's refusals are `NotFound { entity: "atlas_map", id }`, the
//! claim-to-leaf route's `NotFound { entity: "atlas_claim_leaf", id }`.
//!
//! # Not cacheable across viewers
//!
//! Every answer is `Cache-Control: private, no-store` and `Vary:
//! Authorization`. The Explorer BFF adds its own validator per viewer.
//!
//! All SQL lives in `epigraph_db::{AtlasMapRepository, AtlasServeRepository}`.

use std::collections::BTreeMap;

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use epigraph_atlas_contract::{
    ClaimLeaf, Hierarchy, LevelDocument, MapScope, Node, CLAIM_LEAF_SCHEMA_VERSION, SCHEMA_VERSION,
};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, MapLevel};
use epigraph_db::repos::atlas_serve::ThemeRoot;
use epigraph_db::{AtlasMapRepository, AtlasServeRepository, Viewer};
use serde::Serialize;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::state::AppState;

/// The label of the public map in the map list.
pub const PUBLIC_MAP_LABEL: &str = "Public map";

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

fn level_not_found(id: Uuid) -> ApiError {
    ApiError::NotFound {
        entity: "atlas_level".to_string(),
        id: id.to_string(),
    }
}

fn map_not_found(segment: &str) -> ApiError {
    ApiError::NotFound {
        entity: "atlas_map".to_string(),
        id: segment.to_string(),
    }
}

fn claim_leaf_not_found(id: Uuid) -> ApiError {
    ApiError::NotFound {
        entity: "atlas_claim_leaf".to_string(),
        id: id.to_string(),
    }
}

/// `public` or a team group's id; anything else names no map.
pub fn parse_map(segment: &str) -> Option<AtlasMap> {
    if segment == "public" {
        return Some(AtlasMap::Public);
    }
    Uuid::try_parse(segment).ok().map(AtlasMap::Team)
}

/// `meaning` or `links`, exactly.
pub fn parse_hierarchy(segment: &str) -> Option<AtlasHierarchy> {
    match segment {
        "meaning" => Some(AtlasHierarchy::Meaning),
        "links" => Some(AtlasHierarchy::Links),
        _ => None,
    }
}

fn contract_hierarchy(h: AtlasHierarchy) -> Hierarchy {
    match h {
        AtlasHierarchy::Meaning => Hierarchy::Meaning,
        AtlasHierarchy::Links => Hierarchy::Links,
    }
}

fn contract_map(map: AtlasMap) -> (MapScope, Option<Uuid>) {
    match map {
        AtlasMap::Public => (MapScope::Public, None),
        AtlasMap::Team(g) => (MapScope::Team, Some(g)),
    }
}

/// The map's path segment: `public` or the team group's id.
fn map_segment(map: AtlasMap) -> String {
    match map {
        AtlasMap::Public => "public".to_string(),
        AtlasMap::Team(g) => g.to_string(),
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

/// The stored document of `level`, decoded, when it is a valid v1 document of
/// exactly the map, hierarchy, level, theme and run it is stored under.
/// Anything else is a builder fault: logged, and served as absent.
fn stored_document(
    level: &MapLevel,
    map: AtlasMap,
    hierarchy: AtlasHierarchy,
    id: Uuid,
) -> Option<LevelDocument> {
    let fault = |why: String| {
        tracing::error!(
            target: "atlas.serve",
            run_id = %level.run_id,
            group_id = %id,
            reason = %why,
            "stored Atlas level refused"
        );
    };
    if level.schema_version != SCHEMA_VERSION as i32 {
        fault(format!("schema_version {}", level.schema_version));
        return None;
    }
    let doc: LevelDocument = match serde_json::from_value(level.payload.clone()) {
        Ok(d) => d,
        Err(e) => {
            fault(format!("not a v1 level: {e}"));
            return None;
        }
    };
    if let Err(v) = doc.validate() {
        fault(format!("invalid: {v}"));
        return None;
    }
    let (scope, group, h, theme, run, level_id) = match &doc {
        LevelDocument::Group(g) => (
            g.map_scope,
            g.map_group_id,
            g.hierarchy,
            g.theme_id,
            g.run_id,
            g.level_id,
        ),
        LevelDocument::Leaf(l) => (
            l.map_scope,
            l.map_group_id,
            l.hierarchy,
            l.theme_id,
            l.run_id,
            l.level_id,
        ),
    };
    let want = contract_map(map);
    if (scope, group) != want
        || h != contract_hierarchy(hierarchy)
        || level_id != id
        || theme != level.theme_id
        || run != level.run_id
    {
        fault(format!(
            "describes map {scope:?} {group:?}, {h:?}, level {level_id}, theme {theme}, run {run}"
        ));
        return None;
    }
    Some(doc)
}

/// One level as `viewer` may see it, with its run id, or `None` for every
/// refusal (see the module documentation). Shared by the level and the
/// claim-to-leaf routes.
async fn served_level(
    conn: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    hierarchy: AtlasHierarchy,
    id: Uuid,
) -> Result<Option<(Uuid, LevelDocument)>, ApiError> {
    let Some(level) =
        AtlasMapRepository::level_for_viewer(conn, viewer, map, hierarchy, id).await?
    else {
        return Ok(None);
    };
    // Staleness: refuse a run something LEFT; serve one something only
    // arrived in (`current` is not consulted).
    if !level.nothing_left {
        return Ok(None);
    }
    let Some(doc) = stored_document(&level, map, hierarchy, id) else {
        return Ok(None);
    };
    let served = match &doc {
        LevelDocument::Group(_) => Some(doc),
        LevelDocument::Leaf(leaf) => {
            let (mut claims, mut evidence, mut agents) = (Vec::new(), Vec::new(), Vec::new());
            for n in &leaf.nodes {
                match n {
                    Node::Claim(c) => claims.push(c.id),
                    Node::Evidence(e) => evidence.push(e.id),
                    Node::Agent(a) => agents.push(a.id),
                }
            }
            let readable = AtlasServeRepository::readable_leaf_nodes(
                conn, viewer, &claims, &evidence, &agents,
            )
            .await?;
            doc.for_viewer(|n| readable.contains(&n))
        }
    };
    Ok(served.map(|d| (level.run_id, d)))
}

// ── GET /api/v1/atlas/maps ──────────────────────────────────────────────────

/// One map the caller can see.
#[derive(Debug, Serialize)]
pub struct MapEntry {
    /// `team` or `public`.
    pub scope: MapScope,
    /// The team group; `null` for the public map.
    pub group_id: Option<Uuid>,
    /// The path segment of the map's routes: `public` or the group id.
    pub map: String,
    /// The team group's display name, or "Public map".
    pub label: String,
    /// The run every level of the map is served from.
    pub run_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct MapsResponse {
    /// Team and community maps first (by label), then the public map.
    pub maps: Vec<MapEntry>,
}

/// `GET /api/v1/atlas/maps`: every map whose latest finished run the
/// caller's session can read and which nothing has left since its build.
pub async fn atlas_maps(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| scoped_read_failed(e, "atlas_maps"))?;
    let runs = AtlasServeRepository::served_runs(&mut read, &viewer).await?;
    crate::routes::finish_scoped_read(read, "atlas_maps").await?;
    let maps = runs
        .into_iter()
        .filter(|r| r.nothing_left)
        .map(|r| {
            let (scope, group_id) = contract_map(r.map);
            let label = match r.map {
                AtlasMap::Public => PUBLIC_MAP_LABEL.to_string(),
                AtlasMap::Team(g) => r
                    .label
                    .filter(|l| !l.trim().is_empty())
                    .unwrap_or_else(|| format!("Team {}", &g.simple().to_string()[..8])),
            };
            MapEntry {
                scope,
                group_id,
                map: map_segment(r.map),
                label,
                run_id: r.run_id,
            }
        })
        .collect();
    Ok(private_json(MapsResponse { maps }))
}

// ── GET /api/v1/atlas/maps/:map/themes ──────────────────────────────────────

/// A theme's root level in each hierarchy.
#[derive(Debug, Serialize)]
pub struct ThemeRoots {
    pub meaning: Uuid,
    pub links: Uuid,
}

/// One theme as a map draws it.
#[derive(Debug, Serialize)]
pub struct MapTheme {
    pub theme_id: Uuid,
    /// The theme's name on this map (its root level's name); `null` until named.
    pub label: Option<String>,
    /// Claims under the theme's root on this map, as stored.
    pub claim_count: u32,
    pub roots: ThemeRoots,
}

#[derive(Debug, Serialize)]
pub struct MapThemesResponse {
    pub scope: MapScope,
    pub group_id: Option<Uuid>,
    pub run_id: Uuid,
    /// Largest first, then by theme id.
    pub themes: Vec<MapTheme>,
}

/// Fold a run's root rows into one entry per theme. A theme with a root in
/// only one hierarchy takes the other root from that root's switch (the id
/// the document itself names), so the list always offers both; a theme whose
/// two roots would coincide, or with neither, is left out. The name and the
/// count come from the meaning root when there is one.
pub fn fold_theme_roots(rows: Vec<ThemeRoot>) -> Vec<MapTheme> {
    let mut by_theme: BTreeMap<Uuid, (Option<ThemeRoot>, Option<ThemeRoot>)> = BTreeMap::new();
    for r in rows {
        let slot = by_theme.entry(r.theme_id).or_default();
        match r.hierarchy {
            AtlasHierarchy::Meaning => slot.0 = Some(r),
            AtlasHierarchy::Links => slot.1 = Some(r),
        }
    }
    let mut out: Vec<MapTheme> = by_theme
        .into_iter()
        .filter_map(|(theme_id, (meaning, links))| {
            let (m, l) = match (&meaning, &links) {
                (Some(m), Some(l)) => (m.group_id, l.group_id),
                (Some(m), None) => (m.group_id, m.switch_level_id?),
                (None, Some(l)) => (l.switch_level_id?, l.group_id),
                (None, None) => return None,
            };
            if m == l {
                return None;
            }
            let first = meaning.as_ref().or(links.as_ref())?;
            Some(MapTheme {
                theme_id,
                label: first.name.clone().filter(|n| !n.is_empty()),
                claim_count: u32::try_from(first.claim_count.max(0)).unwrap_or(u32::MAX),
                roots: ThemeRoots {
                    meaning: m,
                    links: l,
                },
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.claim_count
            .cmp(&a.claim_count)
            .then(a.theme_id.cmp(&b.theme_id))
    });
    out
}

/// `GET /api/v1/atlas/maps/:map/themes`.
pub async fn atlas_map_themes(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(segment): Path<String>,
) -> Result<Response, ApiError> {
    let Some(map) = parse_map(&segment) else {
        return Err(map_not_found(&segment));
    };
    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| scoped_read_failed(e, "atlas_map_themes"))?;
    let run = AtlasServeRepository::served_run(&mut read, &viewer, map).await?;
    let Some(run) = run.filter(|r| r.nothing_left) else {
        crate::routes::finish_scoped_read(read, "atlas_map_themes").await?;
        return Err(map_not_found(&segment));
    };
    let rows = AtlasServeRepository::theme_roots(&mut read, &viewer, map, run.run_id).await?;
    crate::routes::finish_scoped_read(read, "atlas_map_themes").await?;
    let (scope, group_id) = contract_map(map);
    Ok(private_json(MapThemesResponse {
        scope,
        group_id,
        run_id: run.run_id,
        themes: fold_theme_roots(rows),
    }))
}

// ── GET /api/v1/atlas/maps/:map/:hierarchy/levels/:id ───────────────────────

/// `GET /api/v1/atlas/maps/:map/:hierarchy/levels/:id`: one v1 level document
/// as the caller may see it, or the one not-found body.
pub async fn atlas_level(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path((segment, hierarchy, id)): Path<(String, String, Uuid)>,
) -> Result<Response, ApiError> {
    let (Some(map), Some(hierarchy)) = (parse_map(&segment), parse_hierarchy(&hierarchy)) else {
        return Err(level_not_found(id));
    };
    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| scoped_read_failed(e, "atlas_level"))?;
    let served = served_level(&mut read, &viewer, map, hierarchy, id).await?;
    crate::routes::finish_scoped_read(read, "atlas_level").await?;
    match served {
        Some((_, doc)) => Ok(private_json(doc)),
        None => Err(level_not_found(id)),
    }
}

// ── GET /api/v1/atlas/maps/:map/:hierarchy/claims/:claim_id/leaf ────────────

/// `GET /api/v1/atlas/maps/:map/:hierarchy/claims/:claim_id/leaf`: the leaf
/// of the served run that holds a claim the caller can read, answered only
/// when the claim is still on that leaf after the caller's filter.
pub async fn atlas_claim_leaf(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path((segment, hierarchy, claim_id)): Path<(String, String, Uuid)>,
) -> Result<Response, ApiError> {
    let (Some(map), Some(hierarchy)) = (parse_map(&segment), parse_hierarchy(&hierarchy)) else {
        return Err(claim_leaf_not_found(claim_id));
    };
    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| scoped_read_failed(e, "atlas_claim_leaf"))?;
    let found = claim_leaf_in(&mut read, &viewer, map, hierarchy, claim_id).await?;
    crate::routes::finish_scoped_read(read, "atlas_claim_leaf").await?;
    let Some((theme_id, level_id)) = found else {
        return Err(claim_leaf_not_found(claim_id));
    };
    let (map_scope, map_group_id) = contract_map(map);
    Ok(private_json(ClaimLeaf {
        schema_version: CLAIM_LEAF_SCHEMA_VERSION,
        claim_id,
        map_scope,
        map_group_id,
        hierarchy: contract_hierarchy(hierarchy),
        theme_id,
        level_id,
    }))
}

/// `(theme id, leaf id)` of the leaf holding `claim_id` as `viewer` would be
/// served it, or `None`.
async fn claim_leaf_in(
    conn: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    hierarchy: AtlasHierarchy,
    claim_id: Uuid,
) -> Result<Option<(Uuid, Uuid)>, ApiError> {
    let Some(run) = AtlasServeRepository::served_run(conn, viewer, map).await? else {
        return Ok(None);
    };
    if !run.nothing_left {
        return Ok(None);
    }
    let leaves =
        AtlasServeRepository::leaves_of_claim(conn, viewer, map, run.run_id, hierarchy, claim_id)
            .await?;
    let &[(theme_id, leaf_id)] = leaves.as_slice() else {
        if leaves.len() > 1 {
            tracing::error!(
                target: "atlas.serve",
                run_id = %run.run_id,
                claim_id = %claim_id,
                "a claim is on two leaves of one run; refusing the lookup"
            );
        }
        return Ok(None);
    };
    let served = served_level(conn, viewer, map, hierarchy, leaf_id).await?;
    let holds = match &served {
        Some((run_id, LevelDocument::Leaf(l))) if *run_id == run.run_id => l
            .nodes
            .iter()
            .any(|n| matches!(n, Node::Claim(c) if c.id == claim_id)),
        _ => false,
    };
    Ok(holds.then_some((theme_id, leaf_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(
        theme: u128,
        h: AtlasHierarchy,
        group: u128,
        switch: Option<u128>,
        n: i64,
    ) -> ThemeRoot {
        ThemeRoot {
            theme_id: Uuid::from_u128(theme),
            hierarchy: h,
            group_id: Uuid::from_u128(group),
            name: Some(format!("theme {theme}")),
            switch_level_id: switch.map(Uuid::from_u128),
            claim_count: n,
        }
    }

    #[test]
    fn map_and_hierarchy_segments_are_exact() {
        assert_eq!(parse_map("public"), Some(AtlasMap::Public));
        let g = Uuid::from_u128(5);
        assert_eq!(parse_map(&g.to_string()), Some(AtlasMap::Team(g)));
        for bad in ["Public", "team", "", "public/"] {
            assert_eq!(parse_map(bad), None, "{bad}");
        }
        assert_eq!(parse_hierarchy("links"), Some(AtlasHierarchy::Links));
        assert_eq!(parse_hierarchy("Meaning"), None);
    }

    #[test]
    fn theme_roots_fold_to_both_hierarchies_largest_first() {
        use AtlasHierarchy::{Links, Meaning};
        let themes = fold_theme_roots(vec![
            root(1, Meaning, 10, Some(11), 5),
            root(1, Links, 11, Some(10), 5),
            // only a meaning root: links comes from its switch
            root(2, Meaning, 20, Some(21), 9),
            // only a links root
            root(3, Links, 31, Some(30), 1),
            // a meaning root with no switch and no links root: left out
            root(4, Meaning, 40, None, 7),
            // roots that coincide: left out
            root(5, Meaning, 50, Some(50), 3),
        ]);
        let got: Vec<(u128, u128, u128, u32)> = themes
            .iter()
            .map(|t| {
                (
                    t.theme_id.as_u128(),
                    t.roots.meaning.as_u128(),
                    t.roots.links.as_u128(),
                    t.claim_count,
                )
            })
            .collect();
        assert_eq!(got, vec![(2, 20, 21, 9), (1, 10, 11, 5), (3, 30, 31, 1)]);
    }
}
