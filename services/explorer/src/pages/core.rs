//! `/`, `/search`, `/claim/:id` (plan §3.4). OWNED BY THE CORE AREA.
//!
//! The claim composition and the search runner live in submodules so
//! `/bff/claim/:id` and `/bff/search` (`crate::bff::core`) serve exactly
//! what the pages render.

pub mod claim_view;
pub mod relationships;
pub mod search_view;
pub mod vocab;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use uuid::Uuid;

use self::claim_view::{compose, og_for_claim, og_generic, ClaimView, EdgeEvidenceRow, Og};
use self::search_view::{Mode, RawSearchQuery, SearchOutcome, SearchParams};
use self::vocab::fmt_prob;
use crate::auth::{Caller, PageCtx, SignedIn};
use crate::error::AppError;
use crate::state::AppState;
use crate::upstream::Degraded;
use crate::view::{render, stub_page};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(landing))
        .route("/search", get(search))
        .route("/claim/{id}", get(claim))
}

/// A malformed claim id is a missing claim: 404, and no upstream call.
pub fn parse_claim_id(raw: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(raw.trim()).map_err(|_| AppError::NotFound("claim".into()))
}

// STUB: `/api/v1/stats` + theme/community overviews.
async fn landing(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "EpiGraph Explorer", "core")
}

// ---- /search ---------------------------------------------------------------------

#[derive(Template)]
#[template(path = "core/search.html")]
struct SearchPage {
    ctx: PageCtx,
    outcome: SearchOutcome,
    modes: [Mode; 3],
}

async fn search(
    State(state): State<AppState>,
    user: SignedIn,
    Query(raw): Query<RawSearchQuery>,
) -> Result<Html<String>, AppError> {
    let params = SearchParams::from_raw(&raw);
    let api = user.api(&state);
    let outcome = search_view::run(&api, &state.links, &params).await?;
    let mut ctx = user.ctx;
    ctx.search_query = params.q.clone();
    render(&SearchPage {
        ctx,
        outcome,
        modes: Mode::ALL,
    })
}

// ---- /claim/:id --------------------------------------------------------------------

#[derive(Template)]
#[template(path = "core/claim.html")]
struct ClaimPage {
    ctx: PageCtx,
    view: ClaimView,
    og: Og,
}

impl ClaimPage {
    /// DS belief rows, empty when the belief section is unavailable.
    fn belief_rows(&self) -> Vec<(&'static str, String)> {
        self.view
            .belief
            .get()
            .map(ClaimView::belief_rows)
            .unwrap_or_default()
    }

    fn betp(&self) -> Option<f64> {
        self.view
            .belief
            .get()
            .and_then(|b| b.pignistic_prob)
            .filter(|p| p.is_finite())
    }

    fn betp_display(&self) -> String {
        fmt_prob(self.betp())
    }

    fn truth(&self) -> Option<f64> {
        self.view.claim.truth_value.filter(|t| t.is_finite())
    }

    /// `(key, title, section)` for the two edge-based evidence lists.
    #[allow(clippy::type_complexity)]
    fn edge_sections(&self) -> [(&'static str, &'static str, &Degraded<Vec<EdgeEvidenceRow>>); 2] {
        [
            ("supporting", "Supporting evidence", &self.view.supporting),
            (
                "contradicting",
                "Contradicting evidence",
                &self.view.contradicting,
            ),
        ]
    }
}

/// Anonymous viewers: 200, a sign-in prompt and OG tags (plan §3.3). A
/// redirect would unfurl as the login page.
#[derive(Template)]
#[template(path = "core/claim_anon.html")]
struct ClaimAnonPage {
    ctx: PageCtx,
    id: Uuid,
    og: Og,
}

async fn claim(
    State(state): State<AppState>,
    caller: Caller,
    Path(raw): Path<String>,
) -> Result<Html<String>, AppError> {
    let id = parse_claim_id(&raw)?;
    let canonical = state.links.absolute(&state.links.claim(id));

    if !caller.auth.is_signed_in() {
        let og = anonymous_og(&state, &caller, id, canonical).await;
        return render(&ClaimAnonPage {
            ctx: caller.ctx,
            id,
            og,
        });
    }

    let api = caller.api(&state);
    let view = compose(&api, &state.links, id).await?;
    let og = if view.redacted {
        og_generic(canonical)
    } else {
        og_for_claim(&view.claim, view.belief.get(), canonical)
    };
    render(&ClaimPage {
        ctx: caller.ctx,
        view,
        og,
    })
}

/// The OG card for a sessionless request: claim text only when
/// `PUBLIC_UNFURL=true` and an anonymous upstream read is not redacted;
/// otherwise (or on any upstream failure) a generic card, with no upstream
/// call at all when unfurling is off.
async fn anonymous_og(state: &AppState, caller: &Caller, id: Uuid, canonical: String) -> Og {
    if !state.config.public_unfurl {
        return og_generic(canonical);
    }
    match caller.api(state).claim(id).await {
        Ok(c) if !c.is_redacted() => og_for_claim(&c, None, canonical),
        Ok(_) => og_generic(canonical),
        Err(e) => {
            tracing::debug!(error = %e, "anonymous unfurl read failed; generic card");
            og_generic(canonical)
        }
    }
}
