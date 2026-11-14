//! `GET /api/v1/claims/:id/context` — the document context of one claim:
//! the paper that asserts it, its section, its structural parents and parts,
//! its sibling claims, and its epistemic edges in both directions, each node
//! carrying `theme_id`.
//!
//! The body is built by `epigraph_engine::claim_context`, which MCP
//! `claim_context` calls too (backlog `0720d208`), so the two surfaces return
//! one shape; that module documents the visibility, counting, primary-chain
//! and body-size rules. This file is the HTTP half: query parsing, the
//! viewer-stamped connection, and the 404 for a root the viewer cannot read,
//! byte-identical to the 404 for a uuid that names nothing.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use epigraph_engine::claim_context::{load, validate, ContextBody};
use serde::Deserialize;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ContextQuery {
    /// Page mode: return the root plus only this list.
    #[serde(default)]
    pub list: Option<String>,
    /// The `next_cursor` of that list's previous page. Requires `list`.
    #[serde(default)]
    pub after: Option<String>,
    /// Page size for `list`, clamped to `[1, 200]`. Requires `list`. `u32`
    /// as on `/ego`: a value in range is clamped; anything else is axum's
    /// plain-text 400, which runs before the handler body.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `GET /api/v1/claims/:id/context`
pub async fn claim_context(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<ContextQuery>,
) -> Result<Json<ContextBody>, ApiError> {
    let mode = validate(
        params.list.as_deref(),
        params.after.as_deref(),
        params.limit,
    )
    .map_err(|message| ApiError::BadRequest { message })?;

    // One viewer-stamped connection for every statement, so the root check,
    // the lists and their totals describe the same corpus.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "claim_context",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let Some(body) = load(&mut read, &viewer, claim_id, mode).await? else {
        return Err(ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        });
    };

    crate::routes::finish_scoped_read(read, "claim_context").await?;
    Ok(Json(body))
}
