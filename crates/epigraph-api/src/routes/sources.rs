//! `GET /api/v1/sources/overview`: who said what across a scope.
//!
//! The caller's readable, current claims (optionally one theme's), grouped
//! by source kind, each source with the number of those claims it stated:
//! a `paper` (its ingest-written assertions; with its document key, title and
//! one ingest's authors), a `web` host (the claims' evidence `source_url`), or
//! the filing `agent` of a claim no readable paper asserts. The grouping and
//! its visibility rules are `epigraph_db::repos::sources`'s module doc.
//!
//! Every statement runs on ONE viewer-stamped connection, so every count is
//! the caller's own. Ordered by `(claim_count DESC, kind, key)` and paged by
//! an opaque cursor: pass a page's `next_cursor` back as `after`.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::state::AppState;

/// Default page size.
pub const DEFAULT_SOURCES_LIMIT: i64 = 50;

/// Most authors listed per paper source.
pub const MAX_SOURCE_PAPER_AUTHORS: i64 = 10;

/// Query parameters of `GET /api/v1/sources/overview`.
#[derive(Debug, Deserialize)]
pub struct SourcesOverviewParams {
    /// Only claims in this theme.
    #[serde(default)]
    pub theme_id: Option<Uuid>,
    /// Only these kinds, comma-separated: `paper`, `web`, `agent`.
    #[serde(default)]
    pub kind: Option<String>,
    /// The previous page's `next_cursor`.
    #[serde(default)]
    pub after: Option<String>,
    /// Page size (default 50, at most 200).
    #[serde(default)]
    pub limit: Option<i64>,
}

/// One author of a paper source.
#[derive(Debug, Serialize)]
pub struct SourceAuthor {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub position: Option<i64>,
}

/// The paper behind a `paper` source.
#[derive(Debug, Serialize)]
pub struct SourcePaper {
    pub id: Uuid,
    /// The document key (`papers.doi`).
    pub doi: Option<String>,
    pub title: Option<String>,
    /// ONE ingest's authors (the paper's first ingest the caller can read,
    /// `authors_ingested_by`), in position order, not awaiting
    /// countersignature.
    pub authors: Vec<SourceAuthor>,
    /// Authors that ingest named without speaking for them, awaiting their
    /// countersignature, in position order. Never under `authors`.
    ///
    /// Listed rather than dropped because both lists come from ONE bounded
    /// window of at most 10 authorship rows (as on `GET /api/v1/papers`): a
    /// filter applied after the bound could leave `authors` empty with
    /// `authors_truncated` set while every row of the window was pending.
    pub pending_authors: Vec<SourceAuthor>,
    /// More than 10 authorship rows (both lists together) exist.
    pub authors_truncated: bool,
    pub authors_ingested_by: Option<Uuid>,
}

/// The agent behind an `agent` source.
#[derive(Debug, Serialize)]
pub struct SourceAgent {
    pub id: Uuid,
    pub display_name: Option<String>,
}

/// One source.
#[derive(Debug, Serialize)]
pub struct SourceItem {
    /// `paper`, `web` or `agent`.
    pub kind: String,
    /// The paper id, the host, or the agent id.
    pub key: String,
    /// The caller's readable current claims this source stated. CURRENT
    /// only, since the overview describes a scope as it stands; a paper's
    /// `claim_count` on `GET /api/v1/papers` also counts its superseded
    /// claims, so the two can differ for one paper.
    pub claim_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paper: Option<SourcePaper>,
    /// For a `web` source: the host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<SourceAgent>,
}

/// `GET /api/v1/sources/overview`'s response.
#[derive(Debug, Serialize)]
pub struct SourcesOverviewResponse {
    pub sources: Vec<SourceItem>,
    /// Pass back as `after` for the next page; `null` on the last page.
    pub next_cursor: Option<String>,
    pub theme_id: Option<Uuid>,
}

/// The sources of the caller's readable current claims, grouped by kind,
/// with the caller's counts (module doc).
///
/// The answer to a failed overview read: a 503 when the statement ran past
/// [`epigraph_db::SOURCES_OVERVIEW_STATEMENT_TIMEOUT`] (`57014
/// query_canceled`), telling the caller to narrow by `theme_id`, else an
/// opaque 500. Either way the driver's error is logged, never answered.
#[must_use]
pub fn overview_read_failed(e: &epigraph_db::DbError) -> ApiError {
    tracing::error!(
        target: "tenancy.scoped_read",
        error = %e,
        handler = "sources_overview",
        "sources overview read failed"
    );
    let canceled = matches!(
        e,
        epigraph_db::DbError::QueryFailed { source }
            if source
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref()
                == Some("57014")
    );
    if canceled {
        ApiError::ServiceUnavailable {
            service: "sources overview (the read ran past its time bound; narrow it with \
                      theme_id)"
                .to_string(),
        }
    } else {
        ApiError::InternalError {
            message: "Failed to read the sources overview".to_string(),
        }
    }
}

/// # Errors
/// 400 for an unknown `kind` or a malformed `after`; 503 when the grouping
/// ran past its time bound; 500 when a read fails.
pub async fn sources_overview(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<SourcesOverviewParams>,
) -> Result<Json<SourcesOverviewResponse>, ApiError> {
    let kinds: Option<Vec<String>> = match params.kind.as_deref() {
        None | Some("") => None,
        Some(list) => {
            let mut out = Vec::new();
            for k in list.split(',').map(str::trim).filter(|k| !k.is_empty()) {
                if !epigraph_db::SOURCE_KINDS.contains(&k) {
                    return Err(ApiError::ValidationError {
                        field: "kind".to_string(),
                        reason: format!(
                            "unknown source kind '{k}'; one of: {}",
                            epigraph_db::SOURCE_KINDS.join(", ")
                        ),
                    });
                }
                out.push(k.to_string());
            }
            Some(out)
        }
    };
    let after = match params.after.as_deref() {
        None | Some("") => None,
        Some(token) => Some(epigraph_db::SourcesCursor::decode(token).ok_or_else(|| {
            ApiError::ValidationError {
                field: "after".to_string(),
                reason: "malformed `after` cursor; pass back a page's `next_cursor` unchanged"
                    .to_string(),
            }
        })?),
    };
    let limit = params
        .limit
        .unwrap_or(DEFAULT_SOURCES_LIMIT)
        .clamp(1, epigraph_db::MAX_SOURCES_PAGE);

    let failed = |e: epigraph_db::DbError| overview_read_failed(&e);
    let mut read = state.read_as(&viewer).await.map_err(failed)?;
    let (rows, more) = epigraph_db::SourcesRepository::overview(
        &mut read,
        &viewer,
        &epigraph_db::SourcesQuery {
            theme_id: params.theme_id,
            kinds: kinds.as_deref(),
            after,
            limit,
        },
        epigraph_db::SOURCES_OVERVIEW_STATEMENT_TIMEOUT,
    )
    .await
    .map_err(failed)?;

    // The listed papers' authors: one ingest's, in one bounded read.
    let paper_ids: Vec<Uuid> = rows
        .iter()
        .filter(|r| r.kind == "paper")
        .filter_map(|r| r.key.parse().ok())
        .collect();
    let firsts =
        epigraph_db::PaperRepository::first_ingest_principals(&mut *read, &viewer, &paper_ids)
            .await
            .map_err(failed)?;
    let writers: Vec<(Uuid, Uuid, i32)> = firsts
        .iter()
        .map(|(paper, p)| (*paper, p.ingested_by, 0))
        .collect();
    let mut authors = epigraph_db::PaperRepository::list_authors_bounded(
        &mut *read,
        &viewer,
        &paper_ids,
        MAX_SOURCE_PAPER_AUTHORS,
        &writers,
        &[],
    )
    .await
    .map_err(failed)?;

    crate::routes::finish_scoped_read(read, "sources_overview").await?;

    let next_cursor = if more {
        rows.last().map(|r| {
            epigraph_db::SourcesCursor {
                claim_count: r.claim_count,
                kind: r.kind.clone(),
                key: r.key.clone(),
            }
            .encode()
        })
    } else {
        None
    };
    let sources = rows
        .into_iter()
        .map(|r| {
            let id: Option<Uuid> = r.key.parse().ok();
            let paper = (r.kind == "paper").then(|| {
                let id = id.unwrap_or_default();
                let (listed, authors_truncated) = authors.remove(&id).unwrap_or_default();
                let mut plain = Vec::new();
                let mut pending = Vec::new();
                for (a, _) in listed {
                    let item = SourceAuthor {
                        id: a.agent_id,
                        display_name: a.display_name,
                        position: a.position,
                    };
                    if a.pending_countersign {
                        pending.push(item);
                    } else {
                        plain.push(item);
                    }
                }
                SourcePaper {
                    id,
                    doi: r.doi.clone(),
                    title: r.title.clone(),
                    authors: plain,
                    pending_authors: pending,
                    authors_truncated,
                    authors_ingested_by: firsts.get(&id).map(|p| p.ingested_by),
                }
            });
            let agent = (r.kind == "agent").then(|| SourceAgent {
                id: id.unwrap_or_default(),
                display_name: r.display_name.clone(),
            });
            let domain = (r.kind == "web").then(|| r.key.clone());
            SourceItem {
                kind: r.kind,
                key: r.key,
                claim_count: r.claim_count,
                paper,
                domain,
                agent,
            }
        })
        .collect();

    Ok(Json(SourcesOverviewResponse {
        sources,
        next_cursor,
        theme_id: params.theme_id,
    }))
}
