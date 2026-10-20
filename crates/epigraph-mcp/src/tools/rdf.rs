//! MCP tools for querying the RDF triple layer.
//!
//! **Stub — not in production use.** The `triples` table exists in the schema but is not
//! populated by any current write path. These tools are wired up and correct, but return
//! empty results against a live graph. Retained for potential future use when an RDF
//! extraction or materialization pass is introduced.
//!
//! Because of that, every response carries `index_populated`
//! ([`TripleRepository::index_populated`]): whether any triple is visible to the
//! caller. `false` means an empty answer is not evidence that the corpus lacks
//! the fact.

use rmcp::model::*;
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{EntityRepository, TripleRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn query_triples(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: QueryTriplesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    // Entities are keyed by `(canonical_name, type_top)`. A name without a type
    // cannot be resolved without guessing one, so it is refused.
    if params.subject.is_some() && params.subject_type.is_none() {
        return Err(invalid_params(
            "subject_type is required when subject is given (entities are keyed by name and type)",
        ));
    }
    if params.object.is_some() && params.object_type.is_none() {
        return Err(invalid_params(
            "object_type is required when object is given (entities are keyed by name and type)",
        ));
    }

    let index_populated = TripleRepository::index_populated(&server.pool, viewer)
        .await
        .map_err(internal_error)?;

    // A name that resolves to no entity means no triple can match. It must not
    // become a `None` filter, which the repo reads as "any subject/object".
    let mut unresolved: Vec<&str> = Vec::new();

    let subject_id = match (params.subject.as_deref(), params.subject_type.as_deref()) {
        (Some(name), Some(type_top)) => {
            let id = EntityRepository::find_by_name_and_type(&server.pool, name, type_top)
                .await
                .map_err(internal_error)?
                .map(|e| e.id);
            if id.is_none() {
                unresolved.push("subject");
            }
            id
        }
        _ => None,
    };

    let object_id = match (params.object.as_deref(), params.object_type.as_deref()) {
        (Some(name), Some(type_top)) => {
            let id = EntityRepository::find_by_name_and_type(&server.pool, name, type_top)
                .await
                .map_err(internal_error)?
                .map(|e| e.id);
            if id.is_none() {
                unresolved.push("object");
            }
            id
        }
        _ => None,
    };

    if !unresolved.is_empty() {
        return success_json(&serde_json::json!({
            "count": 0,
            "index_populated": index_populated,
            "unresolved": unresolved,
            "triples": [],
        }));
    }

    let min_confidence = params.min_confidence.unwrap_or(0.0);
    let triples = TripleRepository::query(
        &server.pool,
        viewer,
        subject_id,
        params.predicate.as_deref(),
        object_id,
        min_confidence,
        limit,
    )
    .await
    .map_err(internal_error)?;

    success_json(&serde_json::json!({
        "count": triples.len(),
        "index_populated": index_populated,
        "unresolved": unresolved,
        "triples": triples,
    }))
}

pub async fn entity_neighborhood(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: EntityNeighborhoodParams,
) -> Result<CallToolResult, McpError> {
    let index_populated = TripleRepository::index_populated(&server.pool, viewer)
        .await
        .map_err(internal_error)?;

    // Try UUID first, then name lookup
    let entity = if let Ok(uuid) = params.entity.parse::<Uuid>() {
        EntityRepository::get(&server.pool, uuid)
            .await
            .map_err(internal_error)?
    } else {
        let type_top = params.entity_type.as_deref().unwrap_or("Material");
        EntityRepository::find_by_name_and_type(&server.pool, &params.entity, type_top)
            .await
            .map_err(internal_error)?
    };

    let entity = entity.ok_or_else(|| {
        let mut message = format!("Entity '{}' not found", params.entity);
        if !index_populated {
            message.push_str(
                " (the triple/entity index is empty: no pipeline populates it, so this \
                 miss is not evidence that the corpus lacks the entity)",
            );
        }
        McpError {
            code: rmcp::model::ErrorCode::INVALID_PARAMS,
            message: std::borrow::Cow::Owned(message),
            data: None,
        }
    })?;

    let canonical_id = if entity.is_canonical {
        entity.id
    } else {
        entity.merged_into.unwrap_or(entity.id)
    };

    let triples = TripleRepository::entity_neighborhood(&server.pool, viewer, canonical_id, 100)
        .await
        .map_err(internal_error)?;

    success_json(&serde_json::json!({
        "entity_id": canonical_id,
        "canonical_name": entity.canonical_name,
        "type_top": entity.type_top,
        "index_populated": index_populated,
        "triple_count": triples.len(),
        "triples": triples,
    }))
}

pub async fn search_triples(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SearchTriplesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    // On an empty index the answer is known without embedding the query.
    let index_populated = TripleRepository::index_populated(&server.pool, viewer)
        .await
        .map_err(internal_error)?;
    if !index_populated {
        return success_json(&serde_json::json!({
            "count": 0,
            "index_populated": false,
            "query": params.query,
            "triples": [],
        }));
    }

    // Path B: Embedding fallback — find claims, then look up their triples
    let claim_results = server
        .embedder
        .search(viewer, &params.query, limit)
        .await
        .map_err(internal_error)?;

    let mut triples = Vec::new();
    for (claim_id, _similarity) in &claim_results {
        let claim_triples = TripleRepository::get_by_claim(&server.pool, viewer, *claim_id)
            .await
            .map_err(internal_error)?;
        triples.extend(claim_triples);
    }
    triples.truncate(limit as usize);

    success_json(&serde_json::json!({
        "count": triples.len(),
        "index_populated": true,
        "query": params.query,
        "triples": triples,
    }))
}
