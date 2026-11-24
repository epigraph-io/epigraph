//! `/bff/atlas/sources`: the Atlas Sources view (phase P3b), who said what
//! across the viewer's corpus or one theme. OWNED BY THE ATLAS AREA.
//!
//! | Route | Upstream |
//! |---|---|
//! | `sources?theme_id=&kind=&after=&limit=` | `GET /sources/overview` (backlog da4a8bc1) |
//!
//! The rules of `bff::atlas` hold: [`SignedIn`] and the viewer's own bearer,
//! `private, no-store` with no ETag, no belief figure, at most
//! [`ATLAS_ITEM_CAP`] items per array. On top of them:
//!
//! - A source is passed through by kind (`paper`, `agent`, `web`); a kind this
//!   build does not know is dropped, never guessed at.
//! - Text is clipped to one line; a DOI is linked only when it parses as one
//!   (`doi_href`); a web domain that is not a plain host name is dropped.
//! - Counts are the API's per-viewer counts, never summed: there is no total.
//! - An API that predates the overview route is a 503 with
//!   [`SOURCES_UNSUPPORTED`]; the API timing a corpus-wide page out is a 503
//!   with [`SOURCES_NARROW`].

use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::SignedIn;
use crate::bff::atlas::{
    atlas_err, bad, clip, finish, label_of, opaque_cursor, parse_limit, parse_uuid_param, present,
    theme_directory, theme_ref, ThemeRef, ATLAS_ITEM_CAP, PAPER_DOI_CHARS, PAPER_TITLE_CHARS,
    STALE_LINK,
};
use crate::bff::graph::one_line;
use crate::error::AppError;
use crate::links::Links;
use crate::pages::core::vocab::doi_url;
use crate::state::AppState;
use crate::upstream::atlas_sources::{
    SourceAuthor, SourceEntry, SourcesQuery, SOURCES_PAGE_RANGE, SOURCE_KINDS,
};
use crate::upstream::UpstreamError;

/// Sources per page when the client does not say.
pub const SOURCES_DEFAULT: u32 = 50;
/// Most authors listed per paper (the kernel lists at most 10).
pub const SOURCE_AUTHORS_CAP: usize = 10;
/// Longest web domain kept (a DNS name's limit).
const DOMAIN_CHARS: usize = 253;

/// Shown when the API predates `GET /sources/overview`.
pub const SOURCES_UNSUPPORTED: &str = "This EpiGraph API cannot list sources yet. \
     The map and claim pages still work.";
/// Shown when the API timed a page out.
pub const SOURCES_NARROW: &str =
    "Listing every source took too long. Pick a theme to list its sources.";

pub fn routes() -> Router<AppState> {
    Router::new().route("/bff/atlas/sources", get(sources))
}

#[derive(Deserialize, Default)]
struct SourcesParams {
    theme_id: Option<String>,
    kind: Option<String>,
    after: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct AuthorOut {
    id: Uuid,
    name: Option<String>,
    /// An ingester's word awaiting the person's countersignature.
    pending_countersign: bool,
}

/// One source, tagged by `kind`.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SourceOut {
    Paper {
        id: Uuid,
        doi: Option<String>,
        doi_href: Option<String>,
        title: Option<String>,
        authors: Vec<AuthorOut>,
        authors_truncated: bool,
        claim_count: i64,
    },
    Agent {
        id: Uuid,
        name: Option<String>,
        href: String,
        claim_count: i64,
    },
    Web {
        domain: String,
        claim_count: i64,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct SourcesBody {
    /// The theme asked for, labelled from the viewer's own directory.
    theme: Option<ThemeRef>,
    kind: Option<&'static str>,
    sources: Vec<SourceOut>,
    /// Pass back as `after` for the next page; `null` on the last.
    next: Option<String>,
}

/// `kind`: one of [`SOURCE_KINDS`], lower-cased; blank is absent.
fn parse_kind(raw: Option<&str>) -> Result<Option<&'static str>, AppError> {
    match present(raw) {
        None => Ok(None),
        Some(k) => SOURCE_KINDS
            .iter()
            .find(|x| x.eq_ignore_ascii_case(k))
            .map(|x| Some(*x))
            .ok_or_else(|| bad("kind")),
    }
}

/// A plain host name: letters, digits, `-` and `.`, with a dot, at most 253
/// characters. Anything else is not drawn.
pub fn plain_domain(raw: &str) -> Option<String> {
    let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !d.is_empty()
        && d.len() <= DOMAIN_CHARS
        && d.contains('.')
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    ok.then_some(d)
}

fn name_of(raw: Option<&str>) -> Option<String> {
    raw.map(label_of).filter(|s| !s.is_empty())
}

fn author_out(a: &SourceAuthor) -> AuthorOut {
    AuthorOut {
        id: a.id,
        name: name_of(a.display_name.as_deref()),
        pending_countersign: a.pending_countersign,
    }
}

fn source_out(s: &SourceEntry, links: &Links) -> Option<SourceOut> {
    Some(match s {
        SourceEntry::Paper {
            id,
            doi,
            title,
            authors,
            authors_truncated,
            claim_count,
        } => {
            let doi = doi
                .as_deref()
                .map(|d| clip(d.trim(), PAPER_DOI_CHARS).0)
                .filter(|d| !d.is_empty());
            SourceOut::Paper {
                id: *id,
                doi_href: doi.as_deref().and_then(doi_url),
                doi,
                title: title
                    .as_deref()
                    .map(|t| one_line(t, PAPER_TITLE_CHARS))
                    .filter(|t| !t.is_empty()),
                authors: authors
                    .iter()
                    .take(SOURCE_AUTHORS_CAP)
                    .map(author_out)
                    .collect(),
                authors_truncated: *authors_truncated || authors.len() > SOURCE_AUTHORS_CAP,
                claim_count: (*claim_count).max(0),
            }
        }
        SourceEntry::Agent {
            id,
            display_name,
            claim_count,
        } => SourceOut::Agent {
            id: *id,
            name: name_of(display_name.as_deref()),
            href: links.agent(*id),
            claim_count: (*claim_count).max(0),
        },
        SourceEntry::Web {
            domain,
            claim_count,
        } => SourceOut::Web {
            domain: plain_domain(domain)?,
            claim_count: (*claim_count).max(0),
        },
        SourceEntry::Unknown => return None,
    })
}

async fn sources(
    State(state): State<AppState>,
    user: SignedIn,
    Query(p): Query<SourcesParams>,
) -> Result<Response, AppError> {
    let theme_id = parse_uuid_param(p.theme_id.as_deref(), "theme_id")?;
    let kind = parse_kind(p.kind.as_deref())?;
    let after = opaque_cursor(p.after.as_deref(), "after")?;
    let limit = parse_limit(p.limit.as_deref(), SOURCES_DEFAULT, SOURCES_PAGE_RANGE.1)?;

    let api = user.api(&state);
    let q = SourcesQuery {
        theme_id,
        kind,
        after,
        limit,
    };
    let (res, dir) = tokio::join!(api.sources_overview(&q), async {
        match theme_id {
            Some(_) => theme_directory(&state, &user).await.map(Some),
            None => Ok(None),
        }
    });
    let body = res.map_err(|e| match e {
        UpstreamError::Rejected { status: 400, .. } if after.is_some() => {
            AppError::BadRequest(STALE_LINK.into())
        }
        // No route: an API from before the overview (axum's bare 404, or
        // 405 where a wildcard GET claims the path).
        UpstreamError::NotFound { .. } | UpstreamError::Rejected { status: 405, .. } => {
            AppError::Degraded(SOURCES_UNSUPPORTED.into())
        }
        UpstreamError::Server { status: 503, .. } => AppError::Degraded(SOURCES_NARROW.into()),
        other => atlas_err(other),
    })?;
    let dir = dir?;

    finish(&SourcesBody {
        theme: dir.and_then(|d| theme_ref(&d, theme_id)),
        kind,
        sources: body
            .sources
            .iter()
            .filter_map(|s| source_out(s, &state.links))
            .take(ATLAS_ITEM_CAP)
            .collect(),
        next: body
            .next_cursor
            .filter(|c| opaque_cursor(Some(c), "after").ok().flatten().is_some()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_the_three_the_api_filters_by() {
        assert_eq!(parse_kind(None).unwrap(), None);
        assert_eq!(parse_kind(Some(" ")).unwrap(), None);
        assert_eq!(parse_kind(Some("Paper")).unwrap(), Some("paper"));
        assert_eq!(parse_kind(Some("web")).unwrap(), Some("web"));
        assert!(parse_kind(Some("dataset")).is_err());
        assert!(parse_kind(Some("paper,web")).is_err());
    }

    #[test]
    fn only_plain_host_names_are_drawn() {
        assert_eq!(plain_domain("Example.ORG.").as_deref(), Some("example.org"));
        assert_eq!(
            plain_domain("sub-1.example.org").as_deref(),
            Some("sub-1.example.org")
        );
        for bad in [
            "",
            "localhost",
            "example..org",
            "-x.org",
            "x-.org",
            "exa mple.org",
            "example.org/path",
            "javascript:alert(1)",
            "ex\u{e4}mple.org",
        ] {
            assert_eq!(plain_domain(bad), None, "{bad}");
        }
        assert_eq!(plain_domain(&format!("{}.org", "a".repeat(64))), None);
    }
}
