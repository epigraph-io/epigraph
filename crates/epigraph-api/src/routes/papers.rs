//! Papers CRUD endpoints
//!
//! Provides REST endpoints for the `papers` table (migration 030).
//! Papers track research paper sources linked to claims via `asserts` edges.
//!
//! - `POST /api/v1/papers` — Create or upsert a paper by DOI
//! - `GET  /api/v1/papers` — List papers with optional `?doi=` filter

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
    /// Filter by exact DOI
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
/// Inserts a new paper or returns the existing one if the DOI already exists.
/// Uses `ON CONFLICT (doi) DO UPDATE` to upsert title/journal when provided.
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
    let row = sqlx::query(
        r#"
        INSERT INTO papers (doi, title, journal)
        VALUES ($1, $2, $3)
        ON CONFLICT (doi) DO UPDATE
            SET title   = COALESCE(EXCLUDED.title, papers.title),
                journal = COALESCE(EXCLUDED.journal, papers.journal)
        RETURNING id, doi, title, journal, created_at
        "#,
    )
    .bind(&request.doi)
    .bind(&request.title)
    .bind(&request.journal)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to upsert paper: {e}"),
    })?;

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
        // Exact DOI lookup
        let rows: Vec<_> = sqlx::query(
            "SELECT id, doi, title, journal, created_at FROM papers WHERE doi = $1 LIMIT $2 OFFSET $3",
        )
        .bind(doi)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query papers: {e}"),
        })?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM papers WHERE doi = $1")
            .bind(doi)
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
