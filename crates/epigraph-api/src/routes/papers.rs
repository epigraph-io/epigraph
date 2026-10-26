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
#[cfg(feature = "db")]
pub async fn list_papers(
    State(state): State<AppState>,
    Query(params): Query<PaperListParams>,
) -> Result<Json<PaginatedPaperResponse>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    use sqlx::Row;

    if let Some(ref doi) = params.doi {
        // DOI lookup under every spelling of the document key (the same
        // normalizer the writer and the MCP tools use), canonical first.
        let spellings = epigraph_db::repos::paper::document_key_spellings(doi);
        let rows: Vec<_> = sqlx::query(
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

        let items = rows
            .iter()
            .map(|r| PaperResponse {
                id: r.get("id"),
                doi: r.get("doi"),
                title: r.get("title"),
                journal: r.get("journal"),
                created_at: r.get("created_at"),
            })
            .collect();

        Ok(Json(PaginatedPaperResponse {
            items,
            total,
            limit,
            offset,
        }))
    } else {
        // Full list
        let rows: Vec<_> = sqlx::query(
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

        let items = rows
            .iter()
            .map(|r| PaperResponse {
                id: r.get("id"),
                doi: r.get("doi"),
                title: r.get("title"),
                journal: r.get("journal"),
                created_at: r.get("created_at"),
            })
            .collect();

        Ok(Json(PaginatedPaperResponse {
            items,
            total,
            limit,
            offset,
        }))
    }
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
