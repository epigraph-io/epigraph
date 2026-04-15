//! MCP tools for querying the RDF triple layer.

use rmcp::model::*;
use uuid::Uuid;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{EntityRepository, TripleRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn query_triples(
    server: &EpiGraphMcpFull,
    params: QueryTriplesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let subject_id = if let Some(ref name) = params.subject {
        let type_top = params.subject_type.as_deref().unwrap_or("Material");
        EntityRepository::find_by_name_and_type(&server.pool, name, type_top)
            .await
            .map_err(internal_error)?
            .map(|e| e.id)
    } else {
        None
    };

    let object_id = if let Some(ref name) = params.object {
        let type_top = params.object_type.as_deref().unwrap_or("Material");
        EntityRepository::find_by_name_and_type(&server.pool, name, type_top)
            .await
            .map_err(internal_error)?
            .map(|e| e.id)
    } else {
        None
    };

    let triples = TripleRepository::query(
        &server.pool,
        subject_id,
        params.predicate.as_deref(),
        object_id,
        0.5,
        limit,
    )
    .await
    .map_err(internal_error)?;

    success_json(&serde_json::json!({
        "count": triples.len(),
        "triples": triples,
    }))
}

pub async fn entity_neighborhood(
    server: &EpiGraphMcpFull,
    params: EntityNeighborhoodParams,
) -> Result<CallToolResult, McpError> {
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

    let entity = entity.ok_or_else(|| McpError {
        code: rmcp::model::ErrorCode::INVALID_PARAMS,
        message: std::borrow::Cow::Owned(format!("Entity '{}' not found", params.entity)),
        data: None,
    })?;

    let canonical_id = if entity.is_canonical {
        entity.id
    } else {
        entity.merged_into.unwrap_or(entity.id)
    };

    let triples = TripleRepository::entity_neighborhood(&server.pool, canonical_id, 100)
        .await
        .map_err(internal_error)?;

    success_json(&serde_json::json!({
        "entity_id": canonical_id,
        "canonical_name": entity.canonical_name,
        "type_top": entity.type_top,
        "triple_count": triples.len(),
        "triples": triples,
    }))
}

pub async fn search_triples(
    server: &EpiGraphMcpFull,
    params: SearchTriplesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    // Path B: Embedding fallback — find claims, then look up their triples
    let claim_results = server
        .embedder
        .search(&params.query, limit)
        .await
        .map_err(internal_error)?;

    let mut triples = Vec::new();
    for (claim_id, _similarity) in &claim_results {
        let claim_triples = TripleRepository::get_by_claim(&server.pool, *claim_id)
            .await
            .map_err(internal_error)?;
        triples.extend(claim_triples);
    }
    triples.truncate(limit as usize);

    success_json(&serde_json::json!({
        "count": triples.len(),
        "query": params.query,
        "triples": triples,
    }))
}
