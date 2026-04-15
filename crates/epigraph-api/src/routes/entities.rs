//! Entity and triple REST endpoints for NER/RDF knowledge graph operations
//!
//! ## Write endpoints (protected, require auth)
//! - `POST /api/v1/entities` — Upsert a named entity
//! - `POST /api/v1/entity-mentions/batch` — Batch insert entity mentions
//! - `POST /api/v1/triples/batch` — Batch insert RDF-style triples
//!
//! ## Read endpoints (public)
//! - `POST /api/v1/triples/query` — Query triples with optional filters
//! - `GET /api/v1/entities/:id/neighborhood` — Get all triples for an entity

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

#[cfg(feature = "db")]
use axum::extract::Path;
#[cfg(feature = "db")]
use epigraph_db::{EntityRepository, TripleRepository};

// =============================================================================
// Request / Response types
// =============================================================================

/// Request to upsert a named entity
#[derive(Deserialize)]
pub struct CreateEntityRequest {
    pub canonical_name: String,
    pub type_top: String,
    pub type_sub: Option<String>,
    pub properties: Option<serde_json::Value>,
}

/// An entity mention to insert as part of a batch
#[derive(Deserialize)]
pub struct BatchMentionItem {
    pub entity_id: Uuid,
    pub claim_id: Uuid,
    pub surface_form: String,
    pub mention_role: String,
    pub confidence: f64,
    pub extractor: String,
    pub span_start: Option<i32>,
    pub span_end: Option<i32>,
}

/// Request to batch-insert entity mentions
#[derive(Deserialize)]
pub struct BatchMentionsRequest {
    pub mentions: Vec<BatchMentionItem>,
}

/// An RDF-style triple to insert as part of a batch
#[derive(Deserialize)]
pub struct BatchTripleItem {
    pub claim_id: Uuid,
    pub subject_id: Uuid,
    pub predicate: String,
    pub object_id: Option<Uuid>,
    pub object_literal: Option<String>,
    pub confidence: f64,
    pub extractor: String,
    pub properties: Option<serde_json::Value>,
}

/// Request to batch-insert triples
#[derive(Deserialize)]
pub struct BatchTriplesRequest {
    pub triples: Vec<BatchTripleItem>,
}

/// Query parameters for filtering triples
#[derive(Deserialize)]
pub struct QueryTriplesRequest {
    pub subject_name: Option<String>,
    pub subject_type: Option<String>,
    pub predicate: Option<String>,
    pub object_name: Option<String>,
    pub object_type: Option<String>,
    pub min_confidence: Option<f64>,
    pub limit: Option<i64>,
}

/// Response for a single entity
#[derive(Serialize)]
pub struct EntityResponse {
    pub id: Uuid,
    pub canonical_name: String,
    pub type_top: String,
    pub type_sub: Option<String>,
    pub is_canonical: bool,
    pub created_at: String,
}

/// Response carrying a list of inserted UUIDs
#[derive(Serialize)]
pub struct BatchIdsResponse {
    pub ids: Vec<Uuid>,
    pub count: usize,
}

// =============================================================================
// Write handlers
// =============================================================================

/// POST /api/v1/entities — upsert an entity
#[cfg(feature = "db")]
pub async fn create_entity(
    State(state): State<AppState>,
    Json(req): Json<CreateEntityRequest>,
) -> Result<Json<EntityResponse>, ApiError> {
    let properties = req
        .properties
        .unwrap_or(serde_json::Value::Object(Default::default()));
    let row = EntityRepository::upsert(
        &state.db_pool,
        &req.canonical_name,
        &req.type_top,
        req.type_sub.as_deref(),
        None, // no embedding at creation time via REST
        properties,
    )
    .await?;

    Ok(Json(EntityResponse {
        id: row.id,
        canonical_name: row.canonical_name,
        type_top: row.type_top,
        type_sub: row.type_sub,
        is_canonical: row.is_canonical,
        created_at: row.created_at.to_rfc3339(),
    }))
}

#[cfg(not(feature = "db"))]
pub async fn create_entity(
    State(_state): State<AppState>,
    Json(_req): Json<CreateEntityRequest>,
) -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_IMPLEMENTED
}

/// POST /api/v1/entity-mentions/batch — batch insert entity mentions
#[cfg(feature = "db")]
pub async fn batch_create_mentions(
    State(state): State<AppState>,
    Json(req): Json<BatchMentionsRequest>,
) -> Result<Json<BatchIdsResponse>, ApiError> {
    let data = req
        .mentions
        .into_iter()
        .map(|m| {
            (
                m.entity_id,
                m.claim_id,
                m.surface_form,
                m.mention_role,
                m.confidence,
                m.extractor,
                m.span_start,
                m.span_end,
            )
        })
        .collect();

    let ids = TripleRepository::batch_create_mentions(&state.db_pool, data).await?;
    let count = ids.len();
    Ok(Json(BatchIdsResponse { ids, count }))
}

#[cfg(not(feature = "db"))]
pub async fn batch_create_mentions(
    State(_state): State<AppState>,
    Json(_req): Json<BatchMentionsRequest>,
) -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_IMPLEMENTED
}

/// POST /api/v1/triples/batch — batch insert RDF-style triples
#[cfg(feature = "db")]
pub async fn batch_create_triples(
    State(state): State<AppState>,
    Json(req): Json<BatchTriplesRequest>,
) -> Result<Json<BatchIdsResponse>, ApiError> {
    let data = req
        .triples
        .into_iter()
        .map(|t| {
            (
                t.claim_id,
                t.subject_id,
                t.predicate,
                t.object_id,
                t.object_literal,
                t.confidence,
                t.extractor,
                t.properties
                    .unwrap_or(serde_json::Value::Object(Default::default())),
            )
        })
        .collect();

    let ids = TripleRepository::batch_create_triples(&state.db_pool, data).await?;
    let count = ids.len();
    Ok(Json(BatchIdsResponse { ids, count }))
}

#[cfg(not(feature = "db"))]
pub async fn batch_create_triples(
    State(_state): State<AppState>,
    Json(_req): Json<BatchTriplesRequest>,
) -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_IMPLEMENTED
}

// =============================================================================
// Read handlers
// =============================================================================

/// POST /api/v1/triples/query — query triples with optional filters
///
/// Entity names are resolved to UUIDs server-side via `EntityRepository::find_by_name_and_type`.
/// Returns an empty list when a named entity does not exist (rather than an error), so that
/// callers can distinguish "no entity found" from "entity found but no triples."
#[cfg(feature = "db")]
pub async fn query_triples(
    State(state): State<AppState>,
    Json(req): Json<QueryTriplesRequest>,
) -> Result<Json<Vec<epigraph_db::TripleRow>>, ApiError> {
    // Resolve optional subject name → UUID
    let subject_id = if let (Some(name), Some(type_top)) =
        (req.subject_name.as_deref(), req.subject_type.as_deref())
    {
        EntityRepository::find_by_name_and_type(&state.db_pool, name, type_top)
            .await?
            .map(|e| e.id)
    } else {
        None
    };

    // Resolve optional object name → UUID
    let object_id = if let (Some(name), Some(type_top)) =
        (req.object_name.as_deref(), req.object_type.as_deref())
    {
        EntityRepository::find_by_name_and_type(&state.db_pool, name, type_top)
            .await?
            .map(|e| e.id)
    } else {
        None
    };

    let min_confidence = req.min_confidence.unwrap_or(0.0);
    let limit = req.limit.unwrap_or(50).min(500);

    let rows = TripleRepository::query(
        &state.db_pool,
        subject_id,
        req.predicate.as_deref(),
        object_id,
        min_confidence,
        limit,
    )
    .await?;

    Ok(Json(rows))
}

#[cfg(not(feature = "db"))]
pub async fn query_triples(
    State(_state): State<AppState>,
    Json(_req): Json<QueryTriplesRequest>,
) -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_IMPLEMENTED
}

/// GET /api/v1/entities/:id/neighborhood — all triples for an entity
///
/// Follows the canonical chain: if the entity at `id` has been merged into
/// another entity, this endpoint returns the neighborhood of the survivor.
#[cfg(feature = "db")]
pub async fn entity_neighborhood(
    State(state): State<AppState>,
    Path(entity_id): Path<Uuid>,
) -> Result<Json<Vec<epigraph_db::TripleRow>>, ApiError> {
    // Resolve to canonical entity (follow merged_into chain one hop)
    let entity = EntityRepository::get(&state.db_pool, entity_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Entity".to_string(),
            id: entity_id.to_string(),
        })?;

    // If this entity has been merged into another, use the survivor's ID
    let canonical_id = entity.merged_into.unwrap_or(entity.id);

    let rows = TripleRepository::entity_neighborhood(&state.db_pool, canonical_id, 200).await?;
    Ok(Json(rows))
}

#[cfg(not(feature = "db"))]
pub async fn entity_neighborhood(
    State(_state): State<AppState>,
    Path(_entity_id): Path<Uuid>,
) -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_IMPLEMENTED
}
