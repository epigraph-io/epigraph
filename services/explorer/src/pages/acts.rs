//! `/acts`: the viewer's own admin acts (J7), read-only, linking a pending
//! act out to the API's own confirmation page.
//!
//! The listing exists only on an API with the elevation stack; the section
//! nav shows this page only when the capability probe has seen the route
//! (`upstream::capabilities`). Visited directly against an API without it,
//! the page says so instead of erroring.
//!
//! The Explorer never hosts, proxies or frames the passkey ceremony: a
//! pending act's link is the API's public origin (`EPIGRAPH_OAUTH_BASE_URL`)
//! joined with the path the API returned, opened in a new tab with no
//! referrer, and only when that path is exactly the act's own confirmation
//! page. The page itself is unframable (`security::UNFRAMABLE_ROUTES`). An
//! act's URL is a capability, so nothing here logs it.

use askama::Template;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};

use crate::auth::{PageCtx, SignedIn};
use crate::error::AppError;
use crate::state::AppState;
use crate::upstream::acts::{ListedAct, ACTS_LIMIT};
use crate::upstream::UpstreamError;
use crate::view::render;

pub fn routes() -> Router<AppState> {
    Router::new().route("/acts", get(acts))
}

/// One act as the page shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct ActRow {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub reason: String,
    pub status: &'static str,
    pub refusal: Option<String>,
    pub proposed: String,
    pub expires: String,
    /// Set only for a pending act whose path is its own confirmation page.
    pub confirm_url: Option<String>,
}

fn when(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M UTC").to_string()
}

pub fn act_row(act: &ListedAct, api_origin: &str, now: DateTime<Utc>) -> ActRow {
    let status = act.status(now);
    ActRow {
        id: act.id.to_string(),
        kind: act.kind.clone(),
        target: format!("{} {}", act.target_type, act.target_id),
        reason: act.reason.clone(),
        status: status.as_str(),
        refusal: act
            .refusal
            .clone()
            .filter(|r| !r.trim().is_empty() && act.outcome.as_deref() == Some("refused")),
        proposed: when(act.proposed_at),
        expires: when(act.expires_at),
        confirm_url: act.confirm_url(api_origin, now),
    }
}

/// The listing as shown.
#[derive(Debug, Clone, PartialEq)]
pub struct ActList {
    pub rows: Vec<ActRow>,
    /// The listing filled the page: older acts are not shown.
    pub capped: bool,
}

/// What the page shows.
#[derive(Debug, Clone, PartialEq)]
pub enum ActsView {
    /// The listing answered (possibly empty).
    Listed(ActList),
    /// The API has no admin-acts route (404/405).
    Absent,
    /// The route exists; this viewer may not use it (403).
    Forbidden,
    /// Any other failure, with a viewer-safe sentence.
    Unavailable(&'static str),
}

#[derive(Template)]
#[template(path = "acts.html")]
struct ActsPage {
    ctx: PageCtx,
    view: ActsView,
    limit: u32,
}

async fn acts(State(state): State<AppState>, user: SignedIn) -> Result<Html<String>, AppError> {
    let api = user.api(&state);
    let view = match api.admin_acts(ACTS_LIMIT).await {
        Ok(listing) => {
            let now = Utc::now();
            let origin = state.config.oauth_base_url.as_str();
            let capped = listing.acts.len() >= ACTS_LIMIT as usize;
            ActsView::Listed(ActList {
                rows: listing
                    .acts
                    .iter()
                    .map(|a| act_row(a, origin, now))
                    .collect(),
                capped,
            })
        }
        Err(UpstreamError::SessionExpired) => return Err(AppError::SessionExpired),
        Err(UpstreamError::NotFound { .. } | UpstreamError::Rejected { status: 405, .. }) => {
            ActsView::Absent
        }
        Err(UpstreamError::Forbidden { .. }) => ActsView::Forbidden,
        Err(e) => {
            tracing::warn!(error = %e, "admin acts listing failed");
            ActsView::Unavailable(e.user_message())
        }
    };
    render(&ActsPage {
        ctx: user.ctx,
        view,
        limit: ACTS_LIMIT,
    })
}
