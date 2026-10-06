//! `/backlog?label=&page=`: open backlog items, newest first (J3), read-only.
//!
//! "Open" is the repo's own definition (`CLAUDE.md`, "Querying open
//! backlog"): current claims labelled `backlog` and not labelled `resolved`.
//! Upstream does the filtering and the ordering (`GET /claims/by-labels`
//! with `exclude_labels=resolved&current_only=true`, `ORDER BY created_at
//! DESC`); this page only asks for it and renders the rows in the order they
//! come. Resolving an item stays on MCP / the CLI.
//!
//! An empty list ("no open backlog items") and a failed one ("unavailable")
//! are different answers and render differently.

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::auth::{PageCtx, SignedIn};
use crate::error::AppError;
use crate::links::Links;
use crate::pages::core::search_view::{MAX_PAGE, PAGE_SIZE};
use crate::pages::core::vocab::{fmt_date, one_line};
use crate::state::AppState;
use crate::upstream::core::{LabelHit, BACKLOG_LABEL};
use crate::upstream::{degrade, truncate_chars, Degraded};
use crate::view::render;

/// Longest sub-label accepted.
pub const MAX_LABEL_CHARS: usize = 200;
/// Snippet length in the list.
const SNIPPET_CHARS: usize = 300;

pub fn routes() -> Router<AppState> {
    Router::new().route("/backlog", get(backlog))
}

/// The raw query string. Every field is a string so a malformed `page`
/// cannot turn into a 400 before the page renders.
#[derive(Debug, Default, Deserialize)]
pub struct RawBacklogQuery {
    pub label: Option<String>,
    pub page: Option<String>,
}

/// The optional sub-label: `Ok(None)` for no filter (unset, blank, or
/// `backlog` itself), `Ok(Some(label))` for one label, `Err(why)` for a
/// value the page will not send.
pub fn parse_sub_label(raw: Option<&str>) -> Result<Option<String>, &'static str> {
    let label = raw.unwrap_or("").trim();
    if label.is_empty() || label == BACKLOG_LABEL {
        return Ok(None);
    }
    if label.contains(',') {
        // Upstream ANDs a comma-separated list, so this would quietly be a
        // narrower filter than the one shown.
        return Err("Filter by one label at a time (no commas).");
    }
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err("That label is too long.");
    }
    Ok(Some(label.to_string()))
}

/// `1..=MAX_PAGE`; anything unparsable is page 1.
pub fn parse_page(raw: Option<&str>) -> u32 {
    raw.and_then(|p| p.trim().parse::<u32>().ok())
        .unwrap_or(1)
        .clamp(1, MAX_PAGE)
}

/// A label on a row, linking to the backlog filtered by it.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelLink {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BacklogRow {
    pub claim_url: String,
    /// Snippet (whitespace collapsed, char-boundary cut).
    pub text: String,
    pub created: Option<String>,
    /// The row's labels other than `backlog`, each a filter link.
    pub labels: Vec<LabelLink>,
}

fn row(h: LabelHit, links: &Links) -> BacklogRow {
    BacklogRow {
        claim_url: links.claim(h.id),
        text: truncate_chars(&one_line(&h.content), SNIPPET_CHARS),
        created: Some(fmt_date(&h.created_at)).filter(|d| !d.is_empty()),
        labels: h
            .labels
            .into_iter()
            .filter(|l| l != BACKLOG_LABEL && !l.trim().is_empty())
            .map(|l| LabelLink {
                url: links.backlog_page(Some(&l), None),
                name: l,
            })
            .collect(),
    }
}

#[derive(Template)]
#[template(path = "backlog.html")]
struct BacklogPage {
    ctx: PageCtx,
    /// The sub-label in force, if any.
    filter: Option<String>,
    page: u32,
    /// Why nothing was asked of upstream (a bad filter).
    problem: Option<String>,
    /// `None` when nothing was asked of upstream.
    rows: Option<Degraded<Vec<BacklogRow>>>,
    all_url: String,
    prev_url: Option<String>,
    next_url: Option<String>,
}

async fn backlog(
    State(state): State<AppState>,
    user: SignedIn,
    Query(raw): Query<RawBacklogQuery>,
) -> Result<Html<String>, AppError> {
    let links = &state.links;
    let page = parse_page(raw.page.as_deref());
    let (mut filter, mut problem, mut rows) = (None, None, None);
    let (mut prev_url, mut next_url) = (None, None);
    match parse_sub_label(raw.label.as_deref()) {
        Err(why) => problem = Some(why.to_string()),
        Ok(sub) => {
            let api = user.api(&state);
            let offset = u64::from(page - 1) * u64::from(PAGE_SIZE);
            let list = degrade(api.backlog_open(sub.as_deref(), PAGE_SIZE, offset).await)?
                .map(|v| v.into_iter().map(|h| row(h, links)).collect::<Vec<_>>());
            if page > 1 {
                prev_url = Some(links.backlog_page(sub.as_deref(), Some(page - 1)));
            }
            // Offset paging has no total upstream: offer the next page while
            // this one is full, as label search does.
            if list.get().is_some_and(|r| r.len() as u32 >= PAGE_SIZE) && page < MAX_PAGE {
                next_url = Some(links.backlog_page(sub.as_deref(), Some(page + 1)));
            }
            filter = sub;
            rows = Some(list);
        }
    }
    render(&BacklogPage {
        ctx: user.ctx,
        filter,
        page,
        problem,
        rows,
        all_url: links.backlog(),
        prev_url,
        next_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_label_is_one_trimmed_label_and_backlog_is_no_filter() {
        assert_eq!(parse_sub_label(None), Ok(None));
        assert_eq!(parse_sub_label(Some("   ")), Ok(None));
        assert_eq!(parse_sub_label(Some(" backlog ")), Ok(None));
        assert_eq!(parse_sub_label(Some(" bug ")), Ok(Some("bug".into())));
        assert!(parse_sub_label(Some("bug,ui")).is_err());
        assert!(parse_sub_label(Some(&"x".repeat(MAX_LABEL_CHARS + 1))).is_err());
        assert_eq!(
            parse_sub_label(Some(&"é".repeat(MAX_LABEL_CHARS))),
            Ok(Some("é".repeat(MAX_LABEL_CHARS))),
            "the cap counts characters, not bytes"
        );
    }

    #[test]
    fn page_is_clamped_and_garbage_is_page_one() {
        assert_eq!(parse_page(None), 1);
        assert_eq!(parse_page(Some("x")), 1);
        assert_eq!(parse_page(Some("0")), 1);
        assert_eq!(parse_page(Some(" 3 ")), 3);
        assert_eq!(parse_page(Some("999999")), MAX_PAGE);
    }
}
