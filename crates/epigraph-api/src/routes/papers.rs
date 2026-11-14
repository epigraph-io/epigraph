//! Papers CRUD endpoints
//!
//! Provides REST endpoints for the `papers` table (migration 030).
//! Papers track research paper sources linked to claims via `asserts` edges.
//!
//! - `POST /api/v1/papers` — Create or upsert a paper by DOI
//! - `GET  /api/v1/papers` — List papers with optional `?doi=` filter
//!
//! # Tenancy: the listing reads as the caller; the writer does not
//!
//! `GET /api/v1/papers` returns, beside each `papers` row, the paper's
//! authors, its claim count and its ingestion block, and every one of those
//! depends on who asks: an assertion, a claim or an ingest record the caller
//! cannot read is neither counted nor listed. So `list_papers` takes a
//! [`ViewerExtractor`](crate::middleware::bearer::ViewerExtractor) and runs
//! every statement, the `papers` page included, on ONE viewer-stamped
//! connection ([`AppState::read_as`]); the enrichment reads live in the repo
//! layer (`PaperRepository::{count_readable_claims_of_papers,
//! first_ingest_principals, list_authors_bounded}`,
//! `AuthoredByRepository::for_papers_ingestions`), where the visibility
//! markers apply. `ViewerExtractor` refuses a token with no agent id (401);
//! every token the server issues carries one (`oauth::token::principal_agent_id`).
//!
//! `create_paper` is unchanged and still runs on the raw pool: its two writes
//! (`UPDATE papers`, `INSERT ... RETURNING`) cannot run on `read_as`, which is
//! read-only by construction (`routes/belief.rs`'s module doc says why a write
//! routed through it is a silent rollback), and `papers` carries no row
//! security. `epigraph-db/tests/no_unscoped_pool.rs` counts its 4 sites.

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request to create (or upsert) a paper
#[derive(Deserialize)]
pub struct CreatePaperRequest {
    /// DOI (required, unique key)
    pub doi: String,
    /// Paper title
    #[serde(default)]
    pub title: Option<String>,
    /// Journal name
    #[serde(default)]
    pub journal: Option<String>,
    /// Publication year (stored as integer for easy filtering)
    #[serde(default)]
    pub year: Option<i32>,
}

/// Paper response
#[derive(Serialize, Debug)]
pub struct PaperResponse {
    pub id: Uuid,
    pub doi: String,
    pub title: Option<String>,
    pub journal: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Query parameters for paper listing
#[derive(Deserialize, Debug)]
pub struct PaperListParams {
    /// Filter by DOI: any spelling of one document key (`https://doi.org/…`,
    /// `doi:…` or bare) matches the same paper
    #[serde(default)]
    pub doi: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// An agent, as `GET /api/v1/agents/:id` names it.
#[derive(Serialize, Debug, Clone)]
pub struct PaperAgentRef {
    pub id: Uuid,
    pub display_name: Option<String>,
}

/// One author of a listed paper, from its `authored` edge.
#[derive(Serialize, Debug, Clone)]
pub struct PaperAuthorItem {
    pub id: Uuid,
    pub display_name: Option<String>,
    /// The extraction's author index, when recorded.
    pub position: Option<i64>,
    /// `"author"` unless the edge records another role.
    pub role: String,
    pub affiliations: Vec<String>,
    /// On a pending author only: the ingester that named them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub named_by: Option<Uuid>,
}

/// The prompt snapshot an ingesting agent ran (never the prompt text).
#[derive(Serialize, Debug, Clone)]
pub struct PaperPromptSnapshot {
    pub snapshot_id: Uuid,
    pub model: String,
    pub prompt_hash: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

/// One ingest of a listed paper.
#[derive(Serialize, Debug, Clone)]
pub struct PaperIngestionItem {
    /// The ingesting agent.
    pub ingested_by: PaperAgentRef,
    /// The human that agent was bound to at `ingested_at`, for every reader.
    pub human: Option<PaperAgentRef>,
    /// The snapshot it ran then; `null` unless the caller is in the
    /// snapshot's audience (the agent's human and admins), and when none was
    /// active.
    pub prompt_snapshot: Option<PaperPromptSnapshot>,
    /// The ingest's earliest readable record of the paper.
    pub ingested_at: chrono::DateTime<chrono::Utc>,
    pub tool: Option<String>,
    pub pipeline: Option<String>,
    /// The record was derived after the fact by the legacy ingest-marker
    /// backfill, not written by the ingest itself.
    pub derived: bool,
}

/// One paper of `GET /api/v1/papers`: the row, and what the caller may read
/// of its provenance.
#[derive(Serialize, Debug)]
pub struct PaperListItem {
    #[serde(flatten)]
    pub paper: PaperResponse,
    /// ONE ingest's authors (the paper's first ingest readable by the
    /// caller, `authors_ingested_by`), in position order: one ingest's
    /// author list is never mixed with another's. At most 50, with
    /// `authors_truncated`.
    pub authors: Vec<PaperAuthorItem>,
    /// Authors that ingest named without speaking for them, awaiting their
    /// countersignature. Never listed under `authors`.
    pub pending_authors: Vec<PaperAuthorItem>,
    pub authors_truncated: bool,
    /// Whose ingest the author lists are; `null` when no ingest of the paper
    /// is readable.
    pub authors_ingested_by: Option<Uuid>,
    /// The claims any ingest of the paper asserts, each once, whose
    /// assertion is in force and readable and which the caller can read.
    pub claim_count: i64,
    /// Every readable ingest of the paper, oldest first, at most 10.
    pub ingestions: Vec<PaperIngestionItem>,
    pub ingestions_truncated: bool,
}

/// Paginated paper response
#[derive(Serialize, Debug)]
pub struct PaginatedPaperResponse {
    pub items: Vec<PaperListItem>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Create or upsert a paper
///
/// POST /api/v1/papers
///
/// Inserts a new paper under the canonical document key
/// (`epigraph_db::repos::paper::canonical_document_key`), or returns the
/// existing one found under any spelling of that key, filling title/journal
/// only where the stored value is NULL (an existing value is never
/// overwritten; backlog 62ce37ca).
#[cfg(feature = "db")]
pub async fn create_paper(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreatePaperRequest>,
) -> Result<Json<PaperResponse>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    if request.doi.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "doi".to_string(),
            reason: "DOI cannot be empty".to_string(),
        });
    }

    use sqlx::Row;

    // One document key per paper, shared with the MCP ingestion tools
    // (backlog 90756d26): `https://doi.org/10.x/y`, `doi:10.x/y` and `10.x/y`
    // are one paper. A new row is stored under the canonical (bare) key; an
    // existing row is found under any of its spellings, canonical first, so a
    // row an older writer keyed on the resolver URL is reused rather than
    // twinned.
    let doi = epigraph_db::repos::paper::canonical_document_key(&request.doi);
    let spellings = epigraph_db::repos::paper::document_key_spellings(&request.doi);

    // Check for existing paper first
    let existing: Option<_> = sqlx::query(
        "SELECT id, doi, title, journal, created_at FROM papers \
         WHERE doi = ANY($1) ORDER BY array_position($1, doi) LIMIT 1",
    )
    .bind(&spellings)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to query paper: {e}"),
    })?;

    let row = if let Some(existing_row) = existing {
        // Paper exists — fill title/journal only where the stored value is
        // NULL, then re-fetch. By id: the row found may be keyed on a legacy
        // spelling. Fill-only, not overwrite (backlog 62ce37ca): `papers` is
        // one global row per document with no row security, so overwriting
        // let any `claims:write` caller naming an existing DOI rewrite that
        // paper's title for every reader. Same rule as
        // `PaperRepository::get_or_create`.
        let existing_id: Uuid = existing_row.get("id");
        if request.title.is_some() || request.journal.is_some() {
            sqlx::query(
                r#"UPDATE papers
                   SET title   = COALESCE(title, $2),
                       journal = COALESCE(journal, $3)
                   WHERE id = $1"#,
            )
            .bind(existing_id)
            .bind(&request.title)
            .bind(&request.journal)
            .execute(&state.db_pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to update paper: {e}"),
            })?;
            // Re-fetch updated row
            sqlx::query("SELECT id, doi, title, journal, created_at FROM papers WHERE id = $1")
                .bind(existing_id)
                .fetch_one(&state.db_pool)
                .await
                .map_err(|e| ApiError::DatabaseError {
                    message: format!("Failed to re-fetch paper: {e}"),
                })?
        } else {
            existing_row
        }
    } else {
        // New paper — insert under the canonical key. `ON CONFLICT`: every
        // spelling now maps to that one key, so a concurrent POST of the same
        // new document under another spelling collides here; the loser gets
        // the winner's row instead of a unique violation (a 500).
        sqlx::query(
            r#"INSERT INTO papers (doi, title, journal)
               VALUES ($1, $2, $3)
               ON CONFLICT (doi) DO UPDATE SET
                   title   = COALESCE(papers.title, EXCLUDED.title),
                   journal = COALESCE(papers.journal, EXCLUDED.journal)
               RETURNING id, doi, title, journal, created_at"#,
        )
        .bind(&doi)
        .bind(&request.title)
        .bind(&request.journal)
        .fetch_one(&state.db_pool)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to insert paper: {e}"),
        })?
    };

    Ok(Json(PaperResponse {
        id: row.get("id"),
        doi: row.get("doi"),
        title: row.get("title"),
        journal: row.get("journal"),
        created_at: row.get("created_at"),
    }))
}

/// Create a paper (placeholder - no database)
#[cfg(not(feature = "db"))]
pub async fn create_paper(
    State(_state): State<AppState>,
    Json(_request): Json<CreatePaperRequest>,
) -> Result<Json<PaperResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Papers require database".to_string(),
    })
}

/// List papers with optional DOI filter
///
/// GET /api/v1/papers?doi=10.1234/example&limit=20&offset=0
///
/// Each item carries the paper's authors, claim count and ingestions as the
/// caller's viewer sees them ([`PaperListItem`]). Every statement runs on one
/// viewer-stamped connection (module doc).
#[cfg(feature = "db")]
pub async fn list_papers(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<PaperListParams>,
) -> Result<Json<PaginatedPaperResponse>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    use sqlx::Row;

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "list_papers",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let (rows, total): (Vec<sqlx::postgres::PgRow>, i64) = if let Some(ref doi) = params.doi {
        // DOI lookup under every spelling of the document key (the same
        // normalizer the writer and the MCP tools use), canonical first.
        let spellings = epigraph_db::repos::paper::document_key_spellings(doi);
        let rows = sqlx::query(
            "SELECT id, doi, title, journal, created_at FROM papers \
             WHERE doi = ANY($1) ORDER BY array_position($1, doi) LIMIT $2 OFFSET $3",
        )
        .bind(&spellings)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *read)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query papers: {e}"),
        })?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM papers WHERE doi = ANY($1)")
            .bind(&spellings)
            .fetch_one(&mut *read)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to count papers: {e}"),
            })?;
        (rows, total)
    } else {
        let rows = sqlx::query(
            "SELECT id, doi, title, journal, created_at FROM papers \
             ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *read)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query papers: {e}"),
        })?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM papers")
            .fetch_one(&mut *read)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to count papers: {e}"),
            })?;
        (rows, total)
    };

    let papers: Vec<PaperResponse> = rows
        .iter()
        .map(|r| PaperResponse {
            id: r.get("id"),
            doi: r.get("doi"),
            title: r.get("title"),
            journal: r.get("journal"),
            created_at: r.get("created_at"),
        })
        .collect();
    let ids: Vec<Uuid> = papers.iter().map(|p| p.id).collect();

    let enrich = |e: epigraph_db::DbError| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "list_papers",
            "paper provenance read failed"
        );
        ApiError::InternalError {
            message: "Failed to read paper provenance".to_string(),
        }
    };
    let counts =
        epigraph_db::PaperRepository::count_readable_claims_of_papers(&mut *read, &viewer, &ids)
            .await
            .map_err(enrich)?;
    let firsts = epigraph_db::PaperRepository::first_ingest_principals(&mut *read, &viewer, &ids)
        .await
        .map_err(enrich)?;
    let writers: Vec<(Uuid, Uuid, i32)> = firsts
        .iter()
        .map(|(paper, p)| (*paper, p.ingested_by, 0))
        .collect();
    let mut authors = epigraph_db::PaperRepository::list_authors_bounded(
        &mut *read,
        &viewer,
        &ids,
        i64::try_from(epigraph_db::authored_by::MAX_PAPER_AUTHORS).unwrap_or(i64::MAX),
        &writers,
        &[],
    )
    .await
    .map_err(enrich)?;
    let mut ingestions = epigraph_db::AuthoredByRepository::for_papers_ingestions(
        &mut read,
        &viewer,
        &ids,
        epigraph_db::PROMPT_SNAPSHOT_AUDIENCE,
    )
    .await
    .map_err(enrich)?;

    crate::routes::finish_scoped_read(read, "list_papers").await?;

    let agent_ref = |a: epigraph_db::AuthorRef| PaperAgentRef {
        id: a.id,
        display_name: a.display_name,
    };
    let items = papers
        .into_iter()
        .map(|paper| {
            let id = paper.id;
            let (listed, authors_truncated) = authors.remove(&id).unwrap_or_default();
            let mut plain = Vec::new();
            let mut pending = Vec::new();
            for (a, _) in listed {
                let item = PaperAuthorItem {
                    id: a.agent_id,
                    display_name: a.display_name,
                    position: a.position,
                    role: a.role,
                    affiliations: a.affiliations,
                    named_by: if a.pending_countersign {
                        a.written_by
                    } else {
                        None
                    },
                };
                if a.pending_countersign {
                    pending.push(item);
                } else {
                    plain.push(item);
                }
            }
            let block = ingestions.remove(&id).unwrap_or_default();
            PaperListItem {
                paper,
                authors: plain,
                pending_authors: pending,
                authors_truncated,
                authors_ingested_by: firsts.get(&id).map(|p| p.ingested_by),
                claim_count: counts.get(&id).copied().unwrap_or(0),
                ingestions: block
                    .ingestions
                    .into_iter()
                    .map(|i| PaperIngestionItem {
                        ingested_by: agent_ref(i.ingested_by),
                        human: i.human.map(agent_ref),
                        prompt_snapshot: i.prompt_snapshot.map(|s| PaperPromptSnapshot {
                            snapshot_id: s.snapshot_id,
                            model: s.model,
                            prompt_hash: s.prompt_hash,
                            started_at: s.started_at,
                        }),
                        ingested_at: i.ingested_at,
                        tool: i.tool,
                        pipeline: i.pipeline,
                        derived: i.derived,
                    })
                    .collect(),
                ingestions_truncated: block.truncated,
            }
        })
        .collect();

    Ok(Json(PaginatedPaperResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// List papers (placeholder - no database)
#[cfg(not(feature = "db"))]
pub async fn list_papers(
    State(_state): State<AppState>,
    Query(_params): Query<PaperListParams>,
) -> Result<Json<PaginatedPaperResponse>, ApiError> {
    Ok(Json(PaginatedPaperResponse {
        items: vec![],
        total: 0,
        limit: 20,
        offset: 0,
    }))
}
