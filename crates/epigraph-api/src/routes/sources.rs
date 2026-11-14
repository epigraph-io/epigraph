//! `GET /api/v1/sources/overview`: who said what, across the corpus or one
//! theme (backlog da4a8bc1).
//!
//! Before this route a client asked `/agents/:id/claims` per agent and
//! `/claims/by-labels?labels=doi:X` per paper, and could not list the sources
//! of a theme at all. This answers it in one cursor-paged read:
//!
//! ```text
//! GET /api/v1/sources/overview?theme_id=&kind=&after=&limit=
//! {
//!   "sources": [
//!     {"kind": "paper", "id": "…", "doi": "10.…", "title": "…",
//!      "authors": [{"id": "…", "display_name": "…", "pending_countersign": false}],
//!      "authors_truncated": false, "claim_count": 12},
//!     {"kind": "agent", "id": "…", "display_name": "…", "claim_count": 4},
//!     {"kind": "web", "domain": "example.org", "claim_count": 2}
//!   ],
//!   "next_cursor": null
//! }
//! ```
//!
//! `sources` is grouped by kind (`paper`, then `agent`, then `web`), and
//! within a kind ordered by `claim_count` descending. What each kind counts,
//! and the cursor's stability, are in `epigraph_db::repos::sources`.
//!
//! # What a viewer cannot read is not counted
//!
//! There is no redaction pass. Every statement splices the caller's viewer
//! into `claims`, `edges` and `evidence`, on the caller's stamped connection,
//! so `claim_count` is the number of current claims the caller could list one
//! at a time, and a source with no such claim is absent. There is no `total`:
//! the only numbers served are those per-source counts.
//!
//! # Parameters
//!
//! * `theme_id`: only claims with `claims.theme_id` equal to it.
//! * `kind`: `paper`, `agent` or `web`; only that kind.
//! * `limit`: 1..=200, default 50.
//! * `after`: the previous page's `next_cursor`, with the same `theme_id` and
//!   `kind`.
//!
//! An empty value (`?theme_id=&kind=`) is the parameter left out. A value that
//! does not parse is a 400.
//!
//! All SQL lives in `epigraph_db` (`SourceOverviewRepository::page`).

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{extract::State, Json};

#[cfg(feature = "db")]
use crate::middleware::bearer::ViewerExtractor;
#[cfg(feature = "db")]
use axum::extract::Query;
#[cfg(feature = "db")]
use epigraph_db::{
    SourceCursor, SourceDetail, SourceKind, SourceOverviewRepository, SOURCES_PAGE_DEFAULT,
    SOURCES_PAGE_MAX,
};
#[cfg(feature = "db")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "db")]
use uuid::Uuid;

/// Query of `GET /api/v1/sources/overview`. Strings, so an empty value reads
/// as absent and a bad one is refused by name.
#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct SourcesOverviewQuery {
    #[serde(default)]
    pub theme_id: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

/// One listed author of a paper source.
#[cfg(feature = "db")]
#[derive(Debug, Serialize)]
pub struct SourceAuthorOut {
    pub id: Uuid,
    pub display_name: Option<String>,
    /// An ingester's word awaiting the person's countersignature.
    pub pending_countersign: bool,
}

/// One source, tagged by `kind`.
#[cfg(feature = "db")]
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceOut {
    Paper {
        id: Uuid,
        doi: String,
        title: Option<String>,
        authors: Vec<SourceAuthorOut>,
        authors_truncated: bool,
        claim_count: i64,
    },
    Agent {
        id: Uuid,
        display_name: Option<String>,
        claim_count: i64,
    },
    Web {
        domain: String,
        claim_count: i64,
    },
}

/// Response body.
#[cfg(feature = "db")]
#[derive(Debug, Serialize)]
pub struct SourcesOverviewResponse {
    pub sources: Vec<SourceOut>,
    /// `null` on the last page; otherwise pass it back as `after`.
    pub next_cursor: Option<String>,
}

/// A parameter's value, with an empty or blank one read as absent.
#[cfg(feature = "db")]
fn present(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

#[cfg(feature = "db")]
fn bad_param(field: &str, reason: &str) -> ApiError {
    ApiError::ValidationError {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}

/// `GET /api/v1/sources/overview`
///
/// The sources of the current claims the caller may read, grouped by kind,
/// each with the caller's own claim count, one page at a time.
#[cfg(feature = "db")]
pub async fn sources_overview(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Query(q): Query<SourcesOverviewQuery>,
) -> Result<Json<SourcesOverviewResponse>, ApiError> {
    // Validate everything before touching the database.
    let theme_id = match present(q.theme_id.as_deref()) {
        None => None,
        Some(s) => Some(Uuid::parse_str(s).map_err(|_| bad_param("theme_id", "not a UUID"))?),
    };
    let kind = match present(q.kind.as_deref()) {
        None => None,
        Some(s) => Some(
            SourceKind::parse(s)
                .ok_or_else(|| bad_param("kind", "expected `paper`, `agent` or `web`"))?,
        ),
    };
    let after = match present(q.after.as_deref()) {
        None => None,
        Some(s) => {
            Some(SourceCursor::decode(s).ok_or_else(|| bad_param("after", "not a valid cursor"))?)
        }
    };
    if let (Some(k), Some(c)) = (kind, after.as_ref()) {
        if c.kind != k {
            return Err(bad_param(
                "after",
                "the cursor is from a page of another `kind`",
            ));
        }
    }
    let limit = match present(q.limit.as_deref()) {
        None => SOURCES_PAGE_DEFAULT,
        Some(s) => s
            .parse::<i64>()
            .map_err(|_| bad_param("limit", "not an integer"))?
            .clamp(1, SOURCES_PAGE_MAX),
    };

    // The caller's stamped connection: every statement of the page runs under
    // the session GUCs migration 077's policies read.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "sources_overview",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let page =
        SourceOverviewRepository::page(&mut read, &viewer, theme_id, kind, after.as_ref(), limit)
            .await?;

    crate::routes::finish_scoped_read(read, "sources_overview").await?;

    let sources = page
        .sources
        .into_iter()
        .map(|s| {
            let claim_count = s.claim_count;
            match s.detail {
                SourceDetail::Paper {
                    id,
                    doi,
                    title,
                    authors,
                    authors_truncated,
                } => SourceOut::Paper {
                    id,
                    doi,
                    title,
                    authors: authors
                        .into_iter()
                        .map(|a| SourceAuthorOut {
                            id: a.agent_id,
                            display_name: a.display_name,
                            pending_countersign: a.pending_countersign,
                        })
                        .collect(),
                    authors_truncated,
                    claim_count,
                },
                SourceDetail::Agent { id, display_name } => SourceOut::Agent {
                    id,
                    display_name,
                    claim_count,
                },
                SourceDetail::Web { domain } => SourceOut::Web {
                    domain,
                    claim_count,
                },
            }
        })
        .collect();

    Ok(Json(SourcesOverviewResponse {
        sources,
        next_cursor: page.next.map(|c| c.encode()),
    }))
}

/// Sources overview (placeholder - no database)
#[cfg(not(feature = "db"))]
pub async fn sources_overview(
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Sources overview requires database".to_string(),
    })
}
