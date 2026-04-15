//! Method lookup endpoint for external tooling.

#[cfg(feature = "db")]
use axum::{
    extract::{Path, State},
    Json,
};
#[cfg(feature = "db")]
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

/// GET /api/v1/methods/:id — Method details with evidence strength.
#[cfg(feature = "db")]
pub async fn get_method(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let method = epigraph_db::MethodRepository::get(&state.db_pool, id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("{e}"),
        })?
        .ok_or(ApiError::NotFound {
            entity: "method".into(),
            id: id.to_string(),
        })?;

    let evidence = epigraph_db::MethodRepository::get_evidence_strength(&state.db_pool, id)
        .await
        .ok();

    Ok(Json(serde_json::json!({
        "id": method.id,
        "name": method.name,
        "canonical_name": method.canonical_name,
        "technique_type": method.technique_type,
        "measures": method.measures,
        "typical_conditions": method.typical_conditions,
        "limitations": method.limitations,
        "source_claim_ids": method.source_claim_ids,
        "evidence": evidence.map(|e| serde_json::json!({
            "avg_belief": e.avg_belief,
            "claim_count": e.claim_count,
            "source_count": e.source_count,
        })),
    })))
}
