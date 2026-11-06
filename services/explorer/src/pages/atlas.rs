//! `GET /atlas`: the Atlas shell (Topics view, phase P3a). OWNED BY THE
//! ATLAS AREA.
//!
//! The page carries no upstream data and makes no upstream call: every map
//! item, label and count arrives through `/bff/atlas/*` with the viewer's
//! own bearer, so the shell renders even while the API is down and
//! `static/atlas.js` reports each failed fetch inline.
//!
//! An anonymous visitor gets a 200 sign-in shell with a generic OG card, as
//! `/claim/:id` does: a redirect would unfurl as the login page, and would
//! lose the `#c-<id>` fragment, which `atlas.js` copies into the sign-in
//! link's `return_to`.

use askama::Template;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::Router;

use crate::auth::{Caller, PageCtx};
use crate::error::AppError;
use crate::pages::core::claim_view::{og_generic, Og};
use crate::state::AppState;
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
    };
    render(&AtlasPage {
        ctx: caller.ctx,
        shell,
    })
}
