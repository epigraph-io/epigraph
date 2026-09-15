//! `/`, `/search`, `/claim/:id` (plan §3.4). OWNED BY THE CORE AREA.
//!
//! The claim composition and the search runner live in submodules so
//! `/bff/claim/:id` and `/bff/search` (`crate::bff::core`) serve exactly
//! what the pages render.

pub mod claim_view;
pub mod relationships;
pub mod search_view;
pub mod vocab;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use uuid::Uuid;

use self::claim_view::{compose, og_for_claim, og_generic, ClaimView, EdgeEvidenceRow, Og};
use self::search_view::{Mode, RawSearchQuery, SearchOutcome, SearchParams};
use self::vocab::{fmt_count, fmt_datetime, fmt_prob};
use crate::auth::{Caller, PageCtx, SignedIn};
use crate::error::AppError;
use crate::state::AppState;
use crate::upstream::core::{CommunitiesOverview, ThemesOverview};
use crate::upstream::{degrade, Degraded, StatsResponse, UpstreamError};
use crate::view::render;

/// Items shown per landing overview list (upstream sends every one).
pub const OVERVIEW_ITEMS: usize = 12;
/// How long landing data is cached per viewer (plan §3.4: 60 s overviews).
pub const LANDING_CACHE_TTL: Duration = Duration::from_secs(60);

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

// ---- / -------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct StatRow {
    pub label: &'static str,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct StatsView {
    pub rows: Vec<StatRow>,
    pub computed: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OverviewItem {
    pub href: String,
    pub label: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct OverviewList {
    pub items: Vec<OverviewItem>,
    /// Entries upstream returned (only the first [`OVERVIEW_ITEMS`] show).
    pub total: usize,
    /// Run status worth telling the reader ("no clustering yet", …).
    pub note: Option<String>,
}

#[derive(Template)]
#[template(path = "core/landing.html")]
struct LandingPage {
    ctx: PageCtx,
    stats: Degraded<StatsView>,
    themes: Degraded<OverviewList>,
    communities: Degraded<OverviewList>,
    modes: [Mode; 3],
}

async fn landing(State(state): State<AppState>, user: SignedIn) -> Result<Html<String>, AppError> {
    let api = user.api(&state);
    let who = user.auth.cache_key();
    let (stats, themes, communities) = tokio::join!(
        cached(&state, format!("core:landing:stats:{who}"), api.stats()),
        cached(
            &state,
            format!("core:landing:themes:{who}"),
            api.landing_themes()
        ),
        cached(
            &state,
            format!("core:landing:communities:{who}"),
            api.landing_communities()
        ),
    );
    let links = &state.links;
    render(&LandingPage {
        ctx: user.ctx,
        stats: degrade(stats)?.map(|s| stats_view(&s)),
        themes: degrade(themes)?.map(|t| themes_list(&t, links)),
        communities: degrade(communities)?.map(|c| communities_list(&c, links)),
        modes: Mode::ALL,
    })
}

/// Per-viewer TTL cache in front of an upstream call. Only successes are
/// cached; the key must carry `RequestAuth::cache_key` (redaction differs
/// per viewer). `call` is not polled on a hit.
async fn cached<T, F>(state: &AppState, key: String, call: F) -> Result<Arc<T>, UpstreamError>
where
    T: Send + Sync + 'static,
    F: Future<Output = Result<T, UpstreamError>>,
{
    if let Some(hit) = state.cache.get::<T>(&key) {
        return Ok(hit);
    }
    let value = Arc::new(call.await?);
    state
        .cache
        .insert(key, Arc::clone(&value), LANDING_CACHE_TTL);
    Ok(value)
}

fn stats_view(s: &StatsResponse) -> StatsView {
    let row = |label, n| StatRow {
        label,
        value: fmt_count(n),
    };
    StatsView {
        rows: vec![
            row("Claims", s.claims),
            row("Edges", s.edges),
            row("Evidence", s.evidence),
            row("Embeddings", s.embeddings),
            row("Agents", s.agents),
            row("Frames", s.frames),
            row("Workflows", s.workflows),
        ],
        computed: s.computed_at.as_ref().map(fmt_datetime),
    }
}

fn themes_list(t: &ThemesOverview, links: &crate::links::Links) -> OverviewList {
    // Upstream already orders by claim_count DESC, label ASC.
    OverviewList {
        items: t
            .themes
            .iter()
            .take(OVERVIEW_ITEMS)
            .map(|th| OverviewItem {
                href: links.theme(th.id),
                label: nonempty_label(&th.label, "Untitled theme"),
                detail: format!("{} claims", fmt_count(th.claim_count)),
            })
            .collect(),
        total: t.themes.len(),
        note: None,
    }
}

fn communities_list(c: &CommunitiesOverview, links: &crate::links::Links) -> OverviewList {
    let mut nodes: Vec<_> = c.supernodes.iter().collect();
    nodes.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.label.cmp(&b.label)));
    let note = if c.status.as_deref() == Some("no_clusters_computed") {
        Some("No clustering run has been computed yet.".to_string())
    } else if c.degraded {
        Some("The latest clustering run is marked degraded.".to_string())
    } else {
        None
    };
    OverviewList {
        items: nodes
            .into_iter()
            .take(OVERVIEW_ITEMS)
            .map(|n| {
                let mut detail = format!("{} claims", fmt_count(n.size));
                if n.mean_betp.is_some() {
                    detail.push_str(&format!(" · mean BetP {}", fmt_prob(n.mean_betp)));
                }
                OverviewItem {
                    href: links.community(n.cluster_id),
                    label: nonempty_label(&n.label, "Unnamed community"),
                    detail,
                }
            })
            .collect(),
        total: c.supernodes.len(),
        note,
    }
}

fn nonempty_label(label: &str, fallback: &str) -> String {
    let l = vocab::one_line(label);
    if l.is_empty() {
        fallback.to_string()
    } else {
        crate::upstream::truncate_chars(&l, 80)
    }
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
