//! `/recalls`: the signed-in caller's own recall history (backlog 39aad446),
//! read from `GET /api/v1/recall-events`.
//!
//! Each row is one recall the caller ran: its query text, when, which tool,
//! and the claims it returned, each linking to its claim page. The route
//! answers for the bearer's own rows only, so this page has no agent in its
//! path and cannot show anyone else's history.
//!
//! Paging follows the route's keyset cursor: "Older" carries the page's
//! `next_cursor` as `?after=`, and "Newest" goes back to the first page.
//! There is no "Previous": a keyset cursor only walks forward, and the
//! browser's back button already does the rest.

use askama::Template;
use axum::extract::{RawQuery, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use uuid::Uuid;

use crate::auth::{PageCtx, SignedIn};
use crate::error::AppError;
use crate::links::Links;
use crate::pages::entities::present::{fmt_time, query_param, short_id};
use crate::state::AppState;
use crate::upstream::recalls::{sane_cursor, RecallEventsPage};
use crate::upstream::{degrade, truncate_chars, Degraded};
use crate::view::render;

pub fn routes() -> Router<AppState> {
    Router::new().route("/recalls", get(recalls))
}

/// Recalls per page.
pub const RECALLS_PER_PAGE: u32 = 25;
/// Longest query text shown in a row.
const QUERY_TEXT_CHARS: usize = 500;
/// Returned claims linked per row before "and N more".
const CLAIM_LINKS_PER_ROW: usize = 20;

#[derive(Template)]
#[template(path = "recalls/history.html")]
struct RecallsPage {
    ctx: PageCtx,
    history: Degraded<RecallsView>,
}

struct RecallsView {
    rows: Vec<RecallRow>,
    /// True on a page reached through `?after=`.
    paged: bool,
    newest_url: String,
    older_url: Option<String>,
}

struct RecallRow {
    query: String,
    when: String,
    tool: String,
    claims: Vec<ClaimLink>,
    more_claims: usize,
}

struct ClaimLink {
    url: String,
    short: String,
}

fn recalls_view(page: &RecallEventsPage, paged: bool, links: &Links) -> RecallsView {
    let base = links.recalls();
    RecallsView {
        rows: page
            .items
            .iter()
            .map(|r| RecallRow {
                query: truncate_chars(r.query_text.trim(), QUERY_TEXT_CHARS),
                when: fmt_time(r.created_at.as_deref()),
                tool: truncate_chars(&r.tool, 60),
                claims: r
                    .returned_claim_ids
                    .iter()
                    .take(CLAIM_LINKS_PER_ROW)
                    .map(|&id: &Uuid| ClaimLink {
                        url: links.claim(id),
                        short: short_id(id),
                    })
                    .collect(),
                more_claims: r
                    .returned_claim_ids
                    .len()
                    .saturating_sub(CLAIM_LINKS_PER_ROW),
            })
            .collect(),
        paged,
        older_url: page
            .next_cursor
            .as_deref()
            .and_then(|c| sane_cursor(Some(c)))
            .map(|c| links.recalls_after(c)),
        newest_url: base,
    }
}

async fn recalls(
    State(state): State<AppState>,
    user: SignedIn,
    RawQuery(query): RawQuery,
) -> Result<Html<String>, AppError> {
    let after = query_param(query.as_deref(), "after");
    let after = sane_cursor(after.as_deref());
    let api = user.api(&state);
    let history = degrade(api.own_recall_events(after, RECALLS_PER_PAGE).await)?
        .map(|p| recalls_view(&p, after.is_some(), &state.links));
    render(&RecallsPage {
        history,
        ctx: user.ctx,
    })
}
