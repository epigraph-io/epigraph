//! `GET /atlas`: the Atlas shell (Topics view, phase P3a). OWNED BY THE
//! ATLAS AREA.
//!
//! The page's one upstream input is the per-team map list (backlog W10): with
//! the viewer's own bearer it asks the kernel which maps the viewer can see
//! (`GET /api/v1/atlas/maps`) and, concurrently, each map's themes and root
//! levels, and renders them as `data-atlas-maps` (contract `atlas_maps` v1,
//! [`crate::atlas_maps`]), with each map's `level_url` under
//! `/bff/atlas/maps/<key>/` and the claim-to-leaf prefix in
//! `data-atlas-claim-leaf-url`. When the kernel lists no map, or any of those
//! calls fails, the attribute is left out and the Atlas behaves as before:
//! themes open onto their claim lists. Every other map item, label and count
//! still arrives through `/bff/atlas/*`, and `static/atlas.js` reports each
//! failed fetch inline.
//!
//! The map list is the page's only wait on the API, so it runs under one
//! budget, [`maps_page_budget`] (a third of the upstream timeout, at most
//! [`MAPS_PAGE_BUDGET_CAP`]), across both its stages. A slow or hung API
//! costs the shell that budget, not one upstream timeout per stage, and the
//! page then renders without the list.
//!
//! An anonymous visitor gets a 200 sign-in shell with a generic OG card, as
//! `/claim/:id` does: a redirect would unfurl as the login page, and would
//! lose the `#c-<id>` fragment, which `atlas.js` copies into the sign-in
//! link's `return_to`.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use askama::Template;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::Router;

use crate::atlas_maps::{AtlasMap, AtlasMapTheme, AtlasMaps, Roots, ATLAS_MAPS_SCHEMA_VERSION};
use crate::auth::{Caller, PageCtx, RequestAuth};
use crate::bff::atlas_nested::{CLAIM_LEAF_PREFIX, MAPS_PREFIX};
use crate::error::AppError;
use crate::links::Links;
use crate::pages::core::claim_view::{og_generic, Og};
use crate::state::AppState;
use crate::upstream::atlas_maps::KernelMap;
use crate::view::render;

pub fn routes() -> Router<AppState> {
    Router::new().route("/atlas", get(atlas))
}

/// Every URL `atlas.js` needs, built from [`crate::links::Links`] so the
/// base path is respected. The script never assembles a page URL itself.
#[derive(Debug, Clone)]
pub struct AtlasShell {
    pub layout_url: String,
    pub theme_claims_prefix: String,
    pub claim_prefix: String,
    pub links_url: String,
    pub search_url: String,
    pub resolve_prefix: String,
    pub themes_url: String,
    pub claim_page_prefix: String,
    pub login_url: String,
    pub atlas_url: String,
    pub home_url: String,
    pub search_page_url: String,
    /// `data-atlas-maps`, when the kernel lists at least one map.
    pub maps_json: Option<String>,
    /// `data-atlas-claim-leaf-url`: a claim's leaf is
    /// `<this><map key>/<hierarchy>/<claim id>` (contract `atlas_claim_leaf` v1).
    pub claim_leaf_url: String,
}

/// Most maps in the list (the `atlas_maps` v1 schema's cap).
pub const MAX_MAPS: usize = 64;
/// Most themes per map (the schema's cap).
pub const MAX_MAP_THEMES: usize = 4096;
/// Most characters in a map or theme label (the schema's cap).
pub const MAX_MAP_LABEL_CHARS: usize = 120;

fn clip_label(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    Some(t.chars().take(MAX_MAP_LABEL_CHARS).collect())
}

/// The longest the /atlas page waits for the map list, whatever the upstream
/// timeout.
pub const MAPS_PAGE_BUDGET_CAP: Duration = Duration::from_secs(3);

/// How long the /atlas page waits for the whole map list (the list, then
/// every map's themes) before it renders without it: a third of the
/// per-call upstream timeout, at most [`MAPS_PAGE_BUDGET_CAP`].
pub fn maps_page_budget(upstream_timeout: Duration) -> Duration {
    (upstream_timeout / 3).min(MAPS_PAGE_BUDGET_CAP)
}

/// [`atlas_maps_for`] under [`maps_page_budget`]: `None` when the budget runs
/// out, so a slow API delays the shell by the budget at most.
pub async fn atlas_maps_within_budget(state: &AppState, auth: &RequestAuth) -> Option<AtlasMaps> {
    let budget = maps_page_budget(state.upstream.timeout());
    let started = Instant::now();
    match tokio::time::timeout(budget, atlas_maps_for(state, auth)).await {
        Ok(maps) => maps,
        Err(_) => {
            tracing::warn!(
                budget_ms = budget.as_millis() as u64,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "the atlas map list ran past the page budget; serving the Atlas without it"
            );
            None
        }
    }
}

/// The map list for `auth`, as `data-atlas-maps` carries it, or `None` when
/// the kernel lists no map or a call fails (the Atlas then behaves as it did
/// before the nested levels). Maps keep the kernel's order (team maps, then
/// the public map); a map whose themes cannot be read is left out.
pub async fn atlas_maps_for(state: &AppState, auth: &RequestAuth) -> Option<AtlasMaps> {
    let api = state.api(auth);
    let listed = match api.atlas_maps().await {
        Ok(m) => m.maps,
        Err(e) => {
            tracing::info!(error = %e, "atlas map list unavailable; serving the Atlas without it");
            return None;
        }
    };
    let entries: Vec<(KernelMap, String)> = listed
        .iter()
        .filter_map(|m| Some((m.kernel_map()?, m.label.clone())))
        .take(MAX_MAPS)
        .collect();
    if entries.is_empty() {
        return None;
    }
    let themes =
        futures::future::join_all(entries.iter().map(|(m, _)| api.atlas_map_themes(*m))).await;
    let links: &Links = &state.links;
    let mut maps = Vec::new();
    let mut seen_maps = BTreeSet::new();
    for ((map, label), themes) in entries.into_iter().zip(themes) {
        let themes = match themes {
            Ok(t) if (t.scope, t.group_id) == map.scope() => t.themes,
            Ok(_) => {
                tracing::error!(?map, "the API answered a map's themes with another map");
                continue;
            }
            Err(e) => {
                tracing::info!(error = %e, ?map, "a map's themes are unavailable; leaving the map out");
                continue;
            }
        };
        if !seen_maps.insert(map) {
            continue;
        }
        let mut theme_ids = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let themes: Vec<AtlasMapTheme> = themes
            .into_iter()
            .filter(|t| {
                t.roots.meaning != t.roots.links
                    && !roots.contains(&t.roots.meaning)
                    && !roots.contains(&t.roots.links)
                    && theme_ids.insert(t.theme_id)
                    && roots.insert(t.roots.meaning)
                    && roots.insert(t.roots.links)
            })
            .take(MAX_MAP_THEMES)
            .map(|t| AtlasMapTheme {
                theme_id: t.theme_id,
                label: t.label.as_deref().and_then(clip_label),
                claim_count: t.claim_count,
                roots: Roots {
                    meaning: t.roots.meaning,
                    links: t.roots.links,
                },
            })
            .collect();
        let (scope, group_id) = map.scope();
        let key = map.key();
        maps.push(AtlasMap {
            level_url: links.path(&format!("{MAPS_PREFIX}{key}/")),
            key,
            scope,
            group_id,
            label: clip_label(&label).unwrap_or_else(|| match map {
                KernelMap::Public => "Public map".to_string(),
                KernelMap::Team(_) => "Team map".to_string(),
            }),
            themes,
        });
    }
    if maps.is_empty() {
        return None;
    }
    Some(AtlasMaps {
        schema_version: ATLAS_MAPS_SCHEMA_VERSION,
        maps,
    })
}

#[derive(Template)]
#[template(path = "atlas/atlas.html")]
struct AtlasPage {
    ctx: PageCtx,
    shell: AtlasShell,
}

#[derive(Template)]
#[template(path = "atlas/anon.html")]
struct AtlasAnonPage {
    ctx: PageCtx,
    og: Og,
}

/// The vendored d3 modules, in the dependency order `atlas.html` loads them
/// (`static/vendor/`).
pub const VENDOR_SCRIPTS: &[&str] = &[
    "vendor/d3-color.min.js",
    "vendor/d3-interpolate.min.js",
    "vendor/d3-ease.min.js",
    "vendor/d3-hierarchy.min.js",
    "vendor/d3-dispatch.min.js",
    "vendor/d3-timer.min.js",
    "vendor/d3-quadtree.min.js",
    "vendor/d3-force.min.js",
];

async fn atlas(State(state): State<AppState>, caller: Caller) -> Result<Html<String>, AppError> {
    let links = &state.links;
    if !caller.auth.is_signed_in() {
        let mut og = og_generic(links.absolute(&links.atlas()));
        og.title = "The EpiGraph Atlas".into();
        og.description =
            "Sign in to EpiGraph Explorer to explore the map of themes and claims.".into();
        return render(&AtlasAnonPage {
            ctx: caller.ctx,
            og,
        });
    }
    let shell = AtlasShell {
        layout_url: links.bff_atlas_layout(),
        theme_claims_prefix: links.bff_atlas_theme_claims_prefix(),
        claim_prefix: links.bff_atlas_claim_prefix(),
        links_url: links.bff_atlas_links(),
        search_url: links.bff_atlas_search(),
        resolve_prefix: links.bff_atlas_resolve_prefix(),
        themes_url: links.bff_themes(),
        claim_page_prefix: links.path("/claim/"),
        login_url: caller.ctx.login_url(),
        atlas_url: links.atlas(),
        home_url: links.home(),
        search_page_url: links.search_page(),
        maps_json: atlas_maps_within_budget(&state, &caller.auth)
            .await
            .map(|m| m.to_attr()),
        claim_leaf_url: links.path(CLAIM_LEAF_PREFIX),
    };
    render(&AtlasPage {
        ctx: caller.ctx,
        shell,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_map_list_budget_is_a_third_of_the_upstream_timeout_capped() {
        assert_eq!(
            maps_page_budget(Duration::from_millis(2_000)).as_millis(),
            666
        );
        assert_eq!(
            maps_page_budget(Duration::from_millis(8_000)).as_millis(),
            2_666
        );
        assert_eq!(
            maps_page_budget(Duration::from_secs(60)),
            MAPS_PAGE_BUDGET_CAP
        );
    }
}
