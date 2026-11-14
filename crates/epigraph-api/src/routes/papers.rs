//! Papers CRUD endpoints
//!
//! Provides REST endpoints for the `papers` table (migration 030).
//! Papers track research paper sources linked to claims via `asserts` edges.
//!
//! - `POST /api/v1/papers` — Create or upsert a paper by DOI
//! - `GET  /api/v1/papers` — List papers with optional `?doi=` filter
//!
//! # Tenancy: shard 4 measured this file and converted NOTHING
//!
//! That is the result of the measurement, not an omission from it.
//!
//! `epigraph-db/tests/no_unscoped_pool.rs` records 8 sites here, and the recon
//! that sized conversion shard 4 classified all 8 as reads. Re-measured against
//! the tree and the schema, neither half of that holds, and the register keeps
//! its row at 8:
//!
//! * **Two of the eight are writes** (`create_paper`'s `UPDATE papers` and its
//!   `INSERT ... RETURNING`, the latter issued as a `fetch_one` so a needle
//!   looking for `execute` misses it). `read_as` is read-only by construction;
//!   see `routes/belief.rs`'s module doc for why routing a write through it is a
//!   silent rollback rather than a compile error.
//! * **Neither handler holds a `Viewer`**, so all eight sites would need an
//!   extractor added to BOTH `#[cfg]` arms before any of them could be
//!   converted. Both routes already sit on the authenticated router, so that is
//!   not an anonymous-access change — but `ViewerExtractor` additionally refuses
//!   a token that carries no agent id, which IS a callable behaviour change and
//!   needs its own evidence.
//! * **Converting the remaining six would have moved `HIGH_WATER` by 6 and
//!   changed no row this endpoint returns.** That is the operational
//!   conclusion of a schema measurement taken at migration head 092; the
//!   measurement itself is registered as `F-SHARD4-A3` and is not restated
//!   here. The ratchet counts these sites because its needle is textual.
//!
//! So converting this file would have cost a real behaviour change and bought
//! a counter movement — the exact trade the ratchet's own module doc warns a
//! shard against ("check the CONTROL before the counter").
//!
//! `F-SHARD4-A3` needs an operator decision and this batch is not positioned to
//! make it. Analysis held outside this repository.

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
    /// Who wrote the paper and how much of it is in the graph, as the caller
    /// may read it. Present on `GET /api/v1/papers`; absent from the upsert's
    /// response, which reads nothing but the registry row.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub listing: Option<PaperListing>,
}

/// The claim-derived part of a paper in `GET /api/v1/papers` (backlog
/// fe75ef36): the fields MCP `query_paper` returns and this route did not.
///
/// Everything here is read on the caller's stamped connection through the same
/// `PaperRepository` functions `query_paper` uses, so the two surfaces agree
/// and neither counts nor lists a row the caller may not read.
#[derive(Serialize, Debug)]
pub struct PaperListing {
    /// The paper's authors, in the order the extraction recorded them: the
    /// author list of the paper's FIRST ingest (an ingest's authors go with
    /// that ingest's claims, never another's; see `query_paper`). At most
    /// [`MAX_LISTED_AUTHORS`].
    pub authors: Vec<PaperAuthorView>,
    /// More than [`MAX_LISTED_AUTHORS`] authors exist for that ingest.
    pub authors_truncated: bool,
    /// Claims of this paper the caller may read: the larger of the claims
    /// linked by an `asserts` edge and the claims labelled `doi:<doi>` (a
    /// partial ingest has the label before the edge), as in `query_paper`.
    pub claim_count: i64,
    /// Each ingest of the paper the caller may read, oldest first, at most
    /// [`MAX_LISTED_INGESTS`].
    pub ingests: Vec<PaperIngestView>,
    /// More than [`MAX_LISTED_INGESTS`] ingests exist.
    pub ingests_truncated: bool,
}

/// One author of a paper.
#[derive(Serialize, Debug)]
pub struct PaperAuthorView {
    pub agent_id: Uuid,
    /// The author's display name; empty when the agent has none.
    pub name: String,
    /// The extraction's index of the author, when it recorded one.
    pub position: Option<i64>,
    /// `"author"` unless the ingest recorded another role.
    pub role: String,
    pub affiliations: Vec<String>,
    /// The authorship is an ingester's word awaiting the person's
    /// countersignature: show it as pending, not as a plain author.
    pub pending_countersign: bool,
}

/// One ingest of a paper: the principal whose document ingest wrote it, with
/// the human it acted for and the model it ran (backlog b7354adc, owner
/// ruling A5), so a reader can show "ingested by <human> using <model> on
/// <date>".
///
/// `agent`, `human` and `prompt_snapshot` are the parts
/// `GET /api/v1/claims/:id` gives a claim's filer in `authored_by`, read by
/// the same repo code (`epigraph_db::AuthoredByRepository`) for the pair
/// (this principal, `ingested_at`), each under the caller's viewer:
///
/// * `agent`: every reader of the ingest;
/// * `human`: every reader of the ingest; the human the agent was bound to at
///   `ingested_at` (its binding record), `null` when it was bound to nobody
///   then and on a human's own ingest (`agent` is that human);
/// * `prompt_snapshot`: the audience `epigraph_db::PROMPT_SNAPSHOT_AUDIENCE`
///   names (ruled: the agent's linked human and admins), otherwise `null`,
///   exactly as when no snapshot was recorded. Never any prompt text.
#[derive(Serialize, Debug)]
pub struct PaperIngestView {
    /// The ingesting agent's id (the same id as `agent.id`).
    pub ingested_by: Uuid,
    /// The principal's oldest ingest-written edge on the paper that the
    /// caller may read (the same instant as `ingested_at`).
    pub first_written_at: chrono::DateTime<chrono::Utc>,
    /// The ingesting agent.
    pub agent: crate::routes::claims::AuthorRefView,
    /// The human the agent was bound to at `ingested_at`.
    pub human: Option<crate::routes::claims::AuthorRefView>,
    /// The prompt snapshot (model, identity prompt hash, start) the agent was
    /// running at `ingested_at`, for a caller the snapshot gate admits.
    pub prompt_snapshot: Option<crate::routes::claims::PromptSnapshotView>,
    /// When the paper was ingested by this principal: `first_written_at`.
    pub ingested_at: chrono::DateTime<chrono::Utc>,
    /// Always `true`: nothing records an ingest's human or model when it
    /// runs, so this entry is DERIVED from the paper's first ingest activity
    /// (the principal's oldest readable ingest-written edge, and the binding
    /// and snapshot history at that instant). A recorded entry, when ingests
    /// start writing one, will say `false`.
    pub derived: bool,
}

/// Most authors listed per paper.
pub const MAX_LISTED_AUTHORS: i64 = 100;
/// Most ingests listed per paper.
pub const MAX_LISTED_INGESTS: i64 = 10;

/// Read the claim-derived listing of each paper in `papers` on `read`, the
/// caller's stamped connection.
#[cfg(feature = "db")]
async fn paper_listings(
    read: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    papers: &[(Uuid, String)],
) -> Result<Vec<PaperListing>, ApiError> {
    use epigraph_db::repos::paper::PaperRepository;
    let db = |e: epigraph_db::DbError| ApiError::DatabaseError {
        message: format!("Failed to read a paper's listing: {e}"),
    };
    let mut out = Vec::with_capacity(papers.len());
    for (paper_id, doi) in papers {
        let asserted = PaperRepository::count_asserted_claims(&mut *read, viewer, *paper_id)
            .await
            .map_err(db)?;
        let labelled = PaperRepository::count_claims_by_doi_label(&mut *read, viewer, doi)
            .await
            .map_err(db)?;
        // Each ingest the caller may read, with its agent, the human it was
        // bound to and the snapshot it ran at its first write: the claim
        // read's own repo code and snapshot gate, for (principal, instant).
        let mut principals = epigraph_db::AuthoredByRepository::for_paper_ingests(
            &mut *read,
            viewer,
            *paper_id,
            MAX_LISTED_INGESTS + 1,
            epigraph_db::PROMPT_SNAPSHOT_AUDIENCE,
        )
        .await
        .map_err(db)?;
        let ingests_truncated =
            principals.len() > usize::try_from(MAX_LISTED_INGESTS).unwrap_or(usize::MAX);
        principals.truncate(usize::try_from(MAX_LISTED_INGESTS).unwrap_or(usize::MAX));
        let (authors, authors_truncated) = match principals.first() {
            None => (Vec::new(), false),
            Some(first) => {
                let mut rows = PaperRepository::list_authors_by(
                    &mut *read,
                    viewer,
                    *paper_id,
                    first.ingested_by.agent.id,
                    MAX_LISTED_AUTHORS + 1,
                )
                .await
                .map_err(db)?;
                let truncated =
                    rows.len() > usize::try_from(MAX_LISTED_AUTHORS).unwrap_or(usize::MAX);
                rows.truncate(usize::try_from(MAX_LISTED_AUTHORS).unwrap_or(usize::MAX));
                (rows, truncated)
            }
        };
        out.push(PaperListing {
            authors: authors
                .into_iter()
                .map(|a| PaperAuthorView {
                    agent_id: a.agent_id,
                    name: a.display_name.unwrap_or_default(),
                    position: a.position,
                    role: a.role,
                    affiliations: a.affiliations,
                    pending_countersign: a.pending_countersign,
                })
                .collect(),
            authors_truncated,
            claim_count: asserted.max(labelled),
            ingests: principals
                .into_iter()
                .map(|p| {
                    let by = crate::routes::claims::FilerView::from(p.ingested_by);
                    PaperIngestView {
                        ingested_by: by.agent.id,
                        first_written_at: p.first_written_at,
                        agent: by.agent,
                        human: by.human,
                        prompt_snapshot: by.prompt_snapshot,
                        ingested_at: p.first_written_at,
                        derived: true,
                    }
                })
                .collect(),
            ingests_truncated,
        });
    }
    Ok(out)
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

/// Paginated paper response
#[derive(Serialize, Debug)]
pub struct PaginatedPaperResponse {
    pub items: Vec<PaperResponse>,
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
/// existing one found under any spelling of that key, updating title/journal
/// when provided.
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
        // Paper exists — update title/journal if new values provided, then
        // re-fetch. By id: the row found may be keyed on a legacy spelling.
        let existing_id: Uuid = existing_row.get("id");
        if request.title.is_some() || request.journal.is_some() {
            sqlx::query(
                r#"UPDATE papers
                   SET title   = COALESCE($2, title),
                       journal = COALESCE($3, journal)
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
                   title   = COALESCE(EXCLUDED.title, papers.title),
                   journal = COALESCE(EXCLUDED.journal, papers.journal)
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
        listing: None,
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
/// Each item carries its authors, its claim count and its ingests
/// ([`PaperListing`]) as the caller may read them; each ingest names its
/// agent, that agent's human and, for a caller the prompt-history gate admits,
/// the model it ran ([`PaperIngestView`]). The registry row itself
/// (`papers` has no row security: it is keyed on the document) is read from
/// the pool; everything derived from claims and edges is read on the caller's
/// stamped connection.
#[cfg(feature = "db")]
pub async fn list_papers(
    State(state): State<AppState>,
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    Query(params): Query<PaperListParams>,
) -> Result<Json<PaginatedPaperResponse>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    use sqlx::Row;

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
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query papers: {e}"),
        })?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM papers WHERE doi = ANY($1)")
            .bind(&spellings)
            .fetch_one(&state.db_pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to count papers: {e}"),
            })?;
        (rows, total)
    } else {
        // Full list
        let rows = sqlx::query(
            "SELECT id, doi, title, journal, created_at FROM papers ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query papers: {e}"),
        })?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM papers")
            .fetch_one(&state.db_pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to count papers: {e}"),
            })?;
        (rows, total)
    };

    let keys: Vec<(Uuid, String)> = rows.iter().map(|r| (r.get("id"), r.get("doi"))).collect();
    let listings = if keys.is_empty() {
        Vec::new()
    } else {
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
        paper_listings(&mut read, &viewer, &keys).await?
    };

    let items = rows
        .iter()
        .zip(listings)
        .map(|(r, listing)| PaperResponse {
            id: r.get("id"),
            doi: r.get("doi"),
            title: r.get("title"),
            journal: r.get("journal"),
            created_at: r.get("created_at"),
            listing: Some(listing),
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
