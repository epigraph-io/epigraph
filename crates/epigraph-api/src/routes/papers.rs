//! Papers CRUD endpoints
//!
//! Provides REST endpoints for the `papers` table (migration 030).
//! Papers track research paper sources linked to claims via `asserts` edges.
//!
//! - `POST /api/v1/papers` — Create or upsert a paper by DOI
//! - `GET  /api/v1/papers` — List papers with optional `?doi=` filter
//!
//! # Tenancy
//!
//! Since migration 246 a `papers` row carries the tenancy of the ingest that
//! wrote it, under FORCEd row security (a team's or agent's private ingest
//! writes a row only its group reads).
//!
//! `list_papers` takes a `ViewerExtractor` (its items carry per-viewer
//! authors, claim counts and ingests) and runs every statement, the paper rows
//! included, on the caller's stamped connection, whose row security admits
//! only the papers the caller may read.
//!
//! `create_paper` takes a `ViewerExtractor` too and registers a PUBLIC row
//! owned by the caller's home group, written and read back on the caller's
//! stamped transaction (`AppState::begin_claim_write`); the one pool site left
//! (`epigraph-db/tests/no_unscoped_pool.rs`) is the home-group resolution.

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
/// Registers a PUBLIC paper under the canonical document key
/// (`epigraph_db::repos::paper::canonical_document_key`), or returns the
/// existing public row of that document found under any spelling of the key,
/// filling title/journal only where the stored value is NULL (an existing
/// value is never overwritten; backlog 62ce37ca). A team's or agent's private
/// copy of the document (a non-public ingest's row, migration 246) is neither
/// returned nor touched. An empty DOI, or a placeholder such as `"unknown"`
/// ([`epigraph_core::domain::evidence::is_placeholder_id`]), is refused with
/// 400 and writes nothing.
///
/// The row is owned by the caller's home group, and written on a transaction
/// stamped from the caller (`AppState::begin_claim_write`): since migration
/// 246 `papers` has row security, and an unstamped write carries no writable
/// group. A request with no `ViewerExtractor` principal is refused.
#[cfg(feature = "db")]
pub async fn create_paper(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    Json(request): Json<CreatePaperRequest>,
) -> Result<Json<PaperResponse>, ApiError> {
    // Enforce scope unconditionally: a request with no AuthContext is refused
    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;

    if request.doi.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "doi".to_string(),
            reason: "DOI cannot be empty".to_string(),
        });
    }
    // A placeholder ("unknown", "n/a", ...) means "this document has no DOI";
    // it is not an identity. Keyed on it, every caller posting one got the
    // same row and unrelated documents collapsed onto one paper node
    // (backlog 8ef80a04). Same test, and same first sentence, as the MCP
    // ingestion tools' refusal.
    if epigraph_core::domain::evidence::is_placeholder_id(&request.doi) {
        return Err(ApiError::ValidationError {
            field: "doi".to_string(),
            reason: format!(
                "{:?} is a placeholder, not a document identity. A document with no DOI \
                 needs a stable key of its own (for example a `urn:epigraph:doc:*` key).",
                request.doi
            ),
        });
    }

    let principal = viewer.principal().ok_or_else(|| ApiError::Unauthorized {
        reason: "a paper must be registered by a principal".into(),
    })?;
    // The caller's home group owns the row (the same owner rule as a claim the
    // caller writes); the row is public, as every row this route wrote before
    // migration 246 was.
    let home =
        epigraph_db::ClaimRepository::default_decl_for_author_pool(&state.db_pool, principal)
            .await?
            .owner_group_bind()
            .ok_or_else(|| ApiError::InternalError {
                message: "the caller's home group did not resolve".to_string(),
            })?;
    let decl = epigraph_core::TenancyDecl::public(home);

    // One document key per paper, shared with the MCP ingestion tools
    // (backlog 90756d26): `https://doi.org/10.x/y`, `doi:10.x/y` and `10.x/y`
    // are one paper. `get_or_create` stores a new row under the canonical
    // (bare) key and finds an existing one under any of its spellings, so a
    // row an older writer keyed on the resolver URL is reused rather than
    // twinned; a concurrent POST of the same new document under another
    // spelling waits on the insert and gets the winner's row.
    let mut tx = state.begin_claim_write(&viewer, "create_paper").await?;
    let id = epigraph_db::PaperRepository::get_or_create(
        &mut tx,
        &request.doi,
        request.title.as_deref(),
        request.journal.as_deref(),
        decl,
    )
    .await
    .map_err(|e| {
        if e.is_write_authority_refusal() {
            ApiError::from(e)
        } else {
            ApiError::DatabaseError {
                message: format!("Failed to register paper: {e}"),
            }
        }
    })?;
    let row = epigraph_db::PaperRepository::registered_row(&mut *tx, id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to re-fetch paper: {e}"),
        })?;
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit paper: {e}"),
    })?;

    Ok(Json(PaperResponse {
        id: row.id,
        doi: row.doi,
        title: row.title,
        journal: row.journal,
        created_at: row.created_at,
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
/// the model it ran ([`PaperIngestView`]). Every read, the registry rows
/// included, runs on the caller's one stamped connection, so the page is one
/// snapshot under `SessionGucMode::Transaction`. Since migration 246 a
/// `papers` row carries the tenancy of the ingest that wrote it: the registry
/// statements carry the viewer's predicate as well as the row security that
/// admits the same rows, so a non-member's list and count omit a group's
/// private copy. The full list is ordered `created_at DESC, id DESC`, so
/// `offset` paging is stable across papers registered in the same instant.
#[cfg(feature = "db")]
pub async fn list_papers(
    State(state): State<AppState>,
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
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
        // normalizer and lookup the writer and the MCP tools use), canonical
        // first; a case-variant legacy key only when no exact spelling is
        // stored (backlog f3a3ca54).
        let spellings = epigraph_db::repos::paper::document_key_spellings(doi);
        // Scoped like the full list below (the viewer's predicate on top of
        // the row security that admits the same rows), in both arms and the
        // exact-spelling gate of the shared lookup.
        let matched = epigraph_db::repos::paper::document_key_rows_in_sql(
            "id, doi, title, journal, created_at",
            1,
            "$4::bool OR visibility = 'public' OR owner_group_id = ANY($5::uuid[])",
        );
        let rows = sqlx::query(&format!(
            "SELECT id, doi, title, journal, created_at FROM ({matched}) AS m \
             ORDER BY array_position($1::text[], m.doi), m.doi \
             LIMIT $2 OFFSET $3"
        ))
        .bind(&spellings)
        .bind(limit)
        .bind(offset)
        .bind(viewer.bypass_bind())
        .bind(viewer.group_bind().unwrap_or(&[]))
        .fetch_all(&mut *read)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query papers: {e}"),
        })?;

        let counted = epigraph_db::repos::paper::document_key_rows_in_sql(
            "id",
            1,
            "$2::bool OR visibility = 'public' OR owner_group_id = ANY($3::uuid[])",
        );
        let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM ({counted}) AS m"))
            .bind(&spellings)
            .bind(viewer.bypass_bind())
            .bind(viewer.group_bind().unwrap_or(&[]))
            .fetch_one(&mut *read)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to count papers: {e}"),
            })?;
        (rows, total)
    } else {
        // Full list
        let rows = sqlx::query(
            "SELECT id, doi, title, journal, created_at FROM papers \
             WHERE ($3::bool OR visibility = 'public' OR owner_group_id = ANY($4::uuid[])) \
             ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .bind(viewer.bypass_bind())
        .bind(viewer.group_bind().unwrap_or(&[]))
        .fetch_all(&mut *read)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query papers: {e}"),
        })?;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM papers \
             WHERE ($1::bool OR visibility = 'public' OR owner_group_id = ANY($2::uuid[]))",
        )
        .bind(viewer.bypass_bind())
        .bind(viewer.group_bind().unwrap_or(&[]))
        .fetch_one(&mut *read)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to count papers: {e}"),
        })?;
        (rows, total)
    };

    let keys: Vec<(Uuid, String)> = rows.iter().map(|r| (r.get("id"), r.get("doi"))).collect();
    let listings = paper_listings(&mut read, &viewer, &keys).await?;
    crate::routes::finish_scoped_read(read, "list_papers").await?;

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
