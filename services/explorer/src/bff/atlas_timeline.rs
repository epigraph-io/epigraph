//! `/bff/atlas/timeline`: the Atlas Timeline view (phase P3c), one theme's
//! claims in filing order with the links among them. OWNED BY THE ATLAS AREA.
//!
//! | Route | Upstream |
//! |---|---|
//! | `timeline?theme_id=&from=&to=&after=&limit=` | `GET /claims?theme_id=&created_after=&created_before=&sort_by=created_at&sort_order=asc&is_current=true&include_links=true` (backlog ea26d7aa) |
//!
//! The rules of `bff::atlas` hold: [`SignedIn`] and the viewer's own bearer,
//! `private, no-store` with no ETag, colour from `truth_value` alone (never
//! sorted, compared or folded here), at most [`ATLAS_ITEM_CAP`] items per
//! array. On top of them:
//!
//! - `theme_id` is required: a lane is a theme. `from` and `to` are an RFC
//!   3339 instant or a `YYYY-MM-DD` day (its UTC midnight), `from` before `to`.
//! - A link is kept only when both its ends are claims of the page (a
//!   second-line drop rule; the API already promises it) and its
//!   relationship is a plain lower-case name.
//! - An API without the theme filter or the links (it refused `theme_id`, or
//!   answered without `links`) is a 503 with [`TIMELINE_UNSUPPORTED`], never
//!   an unfiltered page drawn as the theme's.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::SignedIn;
use crate::bff::atlas::{
    atlas_err, bad, claim_key, finish, finite, label_of, opaque_cursor, parse_limit,
    parse_uuid_param, present, theme_directory, theme_ref, ThemeRef, ATLAS_ITEM_CAP, MAX_REL_CHARS,
    STALE_LINK,
};
use crate::error::AppError;
use crate::links::Links;
use crate::state::AppState;
use crate::upstream::atlas_timeline::{ClaimsPage, PageClaim, TimelineQuery, CLAIMS_PAGE_RANGE};
use crate::upstream::UpstreamError;

/// Claims per page when the client does not say (the API's most).
pub const TIMELINE_DEFAULT: u32 = 100;

/// Shown when the API predates the timeline filters.
pub const TIMELINE_UNSUPPORTED: &str = "This EpiGraph API cannot list a theme's claims by \
     date yet. The map and claim pages still work.";

pub fn routes() -> Router<AppState> {
    Router::new().route("/bff/atlas/timeline", get(timeline))
}

#[derive(Deserialize, Default)]
struct TimelineParams {
    theme_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    after: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct ClaimOut {
    id: Uuid,
    key: String,
    label: String,
    truth_value: Option<f64>,
    created_at: DateTime<Utc>,
    href: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct LinkOut {
    id: Uuid,
    source_id: Uuid,
    target_id: Uuid,
    relationship: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct TimelineBody {
    /// The theme asked for, labelled from the viewer's own directory.
    theme: ThemeRef,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    /// Oldest first.
    claims: Vec<ClaimOut>,
    /// Links whose two ends are both in `claims`.
    links: Vec<LinkOut>,
    /// More links exist among these claims than are listed.
    links_truncated: bool,
    /// Pass back as `after` for the next (later) page; `null` on the last.
    next: Option<String>,
}

/// An RFC 3339 instant, or a `YYYY-MM-DD` day read as its UTC midnight.
pub fn parse_instant(raw: Option<&str>, what: &str) -> Result<Option<DateTime<Utc>>, AppError> {
    let Some(s) = present(raw) else {
        return Ok(None);
    };
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(Some(t.with_timezone(&Utc)));
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|t| Some(t.and_utc()))
        .ok_or_else(|| bad(what))
}

/// A relationship name the page can show: `^[a-z_]{1,40}$` after lower-casing.
fn relationship(raw: &str) -> Option<String> {
    let r = raw.trim().to_ascii_lowercase();
    (!r.is_empty()
        && r.len() <= MAX_REL_CHARS
        && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
    .then_some(r)
}

fn claim_out(c: &PageClaim, links: &Links) -> ClaimOut {
    let label = label_of(&c.content);
    ClaimOut {
        id: c.id,
        key: claim_key(c.id),
        label: if label.is_empty() {
            c.id.to_string()
        } else {
            label
        },
        truth_value: finite(c.truth_value),
        created_at: c.created_at,
        href: links.claim(c.id),
    }
}

/// The page's claims (each once, at most [`ATLAS_ITEM_CAP`]) and the links
/// among them (at most [`ATLAS_ITEM_CAP`], `true` when any was cut).
fn shape(page: &ClaimsPage, links: &Links) -> (Vec<ClaimOut>, Vec<LinkOut>, bool) {
    let mut seen = HashSet::new();
    let claims: Vec<ClaimOut> = page
        .claims
        .iter()
        .filter(|c| seen.insert(c.id))
        .take(ATLAS_ITEM_CAP)
        .map(|c| claim_out(c, links))
        .collect();
    let on_page: HashSet<Uuid> = claims.iter().map(|c| c.id).collect();
    let mut kept: Vec<LinkOut> = page
        .links
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|l| l.source_id != l.target_id)
        .filter(|l| on_page.contains(&l.source_id) && on_page.contains(&l.target_id))
        .filter_map(|l| {
            Some(LinkOut {
                id: l.id,
                source_id: l.source_id,
                target_id: l.target_id,
                relationship: relationship(&l.relationship)?,
            })
        })
        .collect();
    let cut = kept.len() > ATLAS_ITEM_CAP;
    kept.truncate(ATLAS_ITEM_CAP);
    (claims, kept, cut || page.links_truncated.unwrap_or(false))
}

async fn timeline(
    State(state): State<AppState>,
    user: SignedIn,
    Query(p): Query<TimelineParams>,
) -> Result<Response, AppError> {
    let theme_id =
        parse_uuid_param(p.theme_id.as_deref(), "theme_id")?.ok_or_else(|| bad("theme_id"))?;
    let from = parse_instant(p.from.as_deref(), "from")?;
    let to = parse_instant(p.to.as_deref(), "to")?;
    if let (Some(f), Some(t)) = (from, to) {
        if f >= t {
            return Err(AppError::BadRequest(
                "Pick a start date before the end date.".into(),
            ));
        }
    }
    let after = opaque_cursor(p.after.as_deref(), "after")?;
    let limit = parse_limit(p.limit.as_deref(), TIMELINE_DEFAULT, CLAIMS_PAGE_RANGE.1)?;

    let api = user.api(&state);
    let q = TimelineQuery {
        theme_id,
        created_after: from,
        created_before: to,
        after,
        limit,
    };
    let (res, dir) = tokio::join!(api.claims_timeline(&q), theme_directory(&state, &user));
    let page = res.map_err(|e| match e {
        UpstreamError::Rejected { status: 400, .. } if after.is_some() => {
            AppError::BadRequest(STALE_LINK.into())
        }
        // Our own parameters are checked above, so a 400 here is an API that
        // refuses the theme filter (the in-memory arm) or the links.
        UpstreamError::Rejected { status: 400, .. } => {
            AppError::Degraded(TIMELINE_UNSUPPORTED.into())
        }
        other => atlas_err(other),
    })?;
    if page.links.is_none() {
        tracing::warn!(%theme_id, "GET /claims answered without links: an API from before the timeline filters");
        return Err(AppError::Degraded(TIMELINE_UNSUPPORTED.into()));
    }
    let dir = dir?;
    let (claims, links, links_truncated) = shape(&page, &state.links);
    finish(&TimelineBody {
        theme: theme_ref(&dir, Some(theme_id)).unwrap_or(ThemeRef {
            id: theme_id,
            label: None,
        }),
        from,
        to,
        claims,
        links,
        links_truncated,
        next: page
            .next_cursor
            .filter(|c| opaque_cursor(Some(c), "after").ok().flatten().is_some()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_are_rfc3339_or_a_day() {
        assert_eq!(parse_instant(None, "from").unwrap(), None);
        assert_eq!(parse_instant(Some(" "), "from").unwrap(), None);
        assert_eq!(
            parse_instant(Some("2026-03-01"), "from")
                .unwrap()
                .unwrap()
                .to_rfc3339(),
            "2026-03-01T00:00:00+00:00"
        );
        assert_eq!(
            parse_instant(Some("2026-03-01T10:00:00+02:00"), "from")
                .unwrap()
                .unwrap()
                .to_rfc3339(),
            "2026-03-01T08:00:00+00:00"
        );
        for bad in ["yesterday", "2026-13-01", "2026-03-01 10:00", "1700000000"] {
            assert!(parse_instant(Some(bad), "from").is_err(), "{bad}");
        }
    }

    #[test]
    fn relationships_are_plain_lower_case_names() {
        assert_eq!(relationship("SUPPORTS").as_deref(), Some("supports"));
        assert_eq!(
            relationship("decomposes_to").as_deref(),
            Some("decomposes_to")
        );
        for bad in ["", "sup ports", "<b>", "x".repeat(41).as_str()] {
            assert_eq!(relationship(bad), None, "{bad}");
        }
    }
}
