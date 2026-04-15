//! Agent span endpoints for OTel-compatible tracing.
//!
//! - `POST /api/v1/spans`           — Open a new span
//! - `PUT  /api/v1/spans/:id/close` — Close a span (set status, edges)
//! - `GET  /api/v1/spans`           — List spans by trace_id

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateSpanRequest {
    pub trace_id: String,
    pub parent_span_id: Option<String>,
    pub span_name: String,
    #[serde(default = "default_span_kind")]
    pub span_kind: String,
    pub agent_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    #[serde(default)]
    pub attributes: serde_json::Value,
}

fn default_span_kind() -> String {
    "INTERNAL".to_string()
}

#[derive(Debug, Serialize)]
pub struct CreateSpanResponse {
    pub id: Uuid,
    pub span_id: String,
    pub trace_id: String,
    pub started_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CloseSpanRequest {
    #[serde(default = "default_status")]
    pub status: String,
    pub status_message: Option<String>,
    #[serde(default)]
    pub attributes: Option<serde_json::Value>,
    #[serde(default)]
    pub generated_ids: Vec<Uuid>,
    #[serde(default)]
    pub consumed_ids: Vec<Uuid>,
}

fn default_status() -> String {
    "OK".to_string()
}

#[derive(Debug, Serialize)]
pub struct SpanResponse {
    pub id: Uuid,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub span_name: String,
    pub span_kind: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub duration_ms: Option<f64>,
    pub status: String,
    pub status_message: Option<String>,
    pub agent_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub attributes: serde_json::Value,
    pub generated_ids: Vec<Uuid>,
    pub consumed_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct ListSpansQuery {
    pub trace_id: String,
}

// =============================================================================
// HELPERS
// =============================================================================

fn span_row_to_response(row: epigraph_db::repos::SpanRow) -> SpanResponse {
    SpanResponse {
        id: row.id,
        trace_id: row.trace_id,
        span_id: row.span_id,
        parent_span_id: row.parent_span_id,
        span_name: row.span_name,
        span_kind: row.span_kind,
        started_at: row.started_at.to_rfc3339(),
        ended_at: row.ended_at.map(|t| t.to_rfc3339()),
        duration_ms: row.duration_ms,
        status: row.status,
        status_message: row.status_message,
        agent_id: row.agent_id,
        user_id: row.user_id,
        session_id: row.session_id,
        attributes: row.attributes,
        generated_ids: row.generated_ids,
        consumed_ids: row.consumed_ids,
    }
}

/// Generate a random 16-char hex string (64-bit span ID).
fn random_span_id() -> String {
    let bytes: [u8; 8] = rand::random();
    hex::encode(bytes)
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Open a new span.
///
/// `POST /api/v1/spans`
#[cfg(feature = "db")]
pub async fn create_span(
    State(state): State<AppState>,
    Json(req): Json<CreateSpanRequest>,
) -> Result<(StatusCode, Json<CreateSpanResponse>), ApiError> {
    let span_id = random_span_id();

    let row = epigraph_db::repos::SpanRepository::insert(
        &state.db_pool,
        &req.trace_id,
        &span_id,
        req.parent_span_id.as_deref(),
        &req.span_name,
        &req.span_kind,
        req.agent_id,
        req.user_id,
        req.session_id,
        &req.attributes,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create span: {e}"),
    })?;

    // If this is a root span (no parent) and agent_id is set,
    // create an attributed_to edge: agent → span
    if req.parent_span_id.is_none() {
        if let Some(agent_id) = req.agent_id {
            let _ = epigraph_db::repos::EdgeRepository::create(
                &state.db_pool,
                agent_id,
                "agent",
                row.id,
                "span",
                "attributed_to",
                Some(serde_json::json!({"context": "agent_session_root_span"})),
                None,
                None,
            )
            .await;
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(CreateSpanResponse {
            id: row.id,
            span_id,
            trace_id: req.trace_id,
            started_at: row.started_at.to_rfc3339(),
        }),
    ))
}

/// Close a span.
///
/// `PUT /api/v1/spans/:id/close`
#[cfg(feature = "db")]
pub async fn close_span(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<CloseSpanRequest>,
) -> Result<Json<SpanResponse>, ApiError> {
    let row = epigraph_db::repos::SpanRepository::close(
        &state.db_pool,
        id,
        &req.status,
        req.status_message.as_deref(),
        req.attributes.as_ref(),
        &req.generated_ids,
        &req.consumed_ids,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to close span: {e}"),
    })?;

    // Auto-create edges for generated_ids: span --generated--> claim
    for claim_id in &row.generated_ids {
        let _ = epigraph_db::repos::EdgeRepository::create(
            &state.db_pool,
            row.id,
            "span",
            *claim_id,
            "claim",
            "generated",
            Some(serde_json::json!({"context": "span_generated_claim"})),
            None,
            None,
        )
        .await;
    }

    // Auto-create edges for consumed_ids: span --uses_evidence--> claim
    for claim_id in &row.consumed_ids {
        let _ = epigraph_db::repos::EdgeRepository::create(
            &state.db_pool,
            row.id,
            "span",
            *claim_id,
            "claim",
            "uses_evidence",
            Some(serde_json::json!({"context": "span_consumed_claim"})),
            None,
            None,
        )
        .await;
    }

    Ok(Json(span_row_to_response(row)))
}

/// List spans for a trace (waterfall view).
///
/// `GET /api/v1/spans?trace_id=...`
#[cfg(feature = "db")]
pub async fn list_spans(
    State(state): State<AppState>,
    Query(params): Query<ListSpansQuery>,
) -> Result<Json<Vec<SpanResponse>>, ApiError> {
    let rows = epigraph_db::repos::SpanRepository::list_by_trace(&state.db_pool, &params.trace_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to list spans: {e}"),
        })?;

    Ok(Json(rows.into_iter().map(span_row_to_response).collect()))
}

// =============================================================================
// STUBS (no-db feature)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn create_span() -> (StatusCode, &'static str) {
    (StatusCode::NOT_IMPLEMENTED, "spans require db feature")
}

#[cfg(not(feature = "db"))]
pub async fn close_span() -> (StatusCode, &'static str) {
    (StatusCode::NOT_IMPLEMENTED, "spans require db feature")
}

#[cfg(not(feature = "db"))]
pub async fn list_spans() -> (StatusCode, &'static str) {
    (StatusCode::NOT_IMPLEMENTED, "spans require db feature")
}
