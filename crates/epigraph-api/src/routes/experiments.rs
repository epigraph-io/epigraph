//! Experiment design endpoints.
//!
//! ## Endpoints
//!
//! - `POST /api/v1/experiments/hypothesize`  - Evaluate a scientific hypothesis
//! - `POST /api/v1/methods`                  - Add a characterization/synthesis method
//! - `GET  /api/v1/methods/search`           - Search methods by embedding similarity
//! - `GET  /api/v1/methods/:id/gaps`         - Method gap analysis for a hypothesis
//! - `POST /api/v1/experiments/design`        - Design an experiment protocol

#[cfg(feature = "db")]
use axum::{
    extract::{Query, State},
    Json,
};
#[cfg(feature = "db")]
use serde::Deserialize;
#[cfg(feature = "db")]
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

// ── Request / Response types ──

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct HypothesizeRequest {
    pub statement: String,
    pub search_radius: Option<f64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct AddMethodRequest {
    pub name: String,
    pub technique_type: String,
    pub measures: Option<String>,
    pub resolution: Option<String>,
    pub limitations: Option<Vec<String>>,
    pub required_equipment: Option<Vec<String>>,
    pub conditions: Option<serde_json::Value>,
    pub capabilities: Option<Vec<String>>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct FindMethodsQuery {
    pub query: String,
    pub technique_type: Option<String>,
    pub limit: Option<i64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct MethodGapQuery {
    pub hypothesis_id: Uuid,
    pub required_capabilities: Option<Vec<String>>,
    pub max_paper_age_years: Option<i32>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct DesignExperimentRequest {
    pub hypothesis_id: Uuid,
    pub method_ids: Vec<Uuid>,
    pub constraints: Option<String>,
}

// ── Handlers ──

/// POST /api/v1/experiments/hypothesize - Evaluate a scientific hypothesis.
///
/// Searches for similar claims, computes prior belief from neighborhood.
#[cfg(feature = "db")]
pub async fn hypothesize(
    State(state): State<AppState>,
    Json(request): Json<HypothesizeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;

    let search_radius = request.search_radius.unwrap_or(0.3);

    // Embed the hypothesis
    let embedding =
        embedder
            .generate(&request.statement)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to embed hypothesis: {e}"),
            })?;

    // Find similar claims
    let similar: Vec<SimilarClaimRow> = sqlx::query_as(
        "SELECT id, content, truth_value, belief, plausibility, \
                1 - (embedding <=> $1::vector) AS similarity \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND 1 - (embedding <=> $1::vector) >= $2 \
         ORDER BY similarity DESC \
         LIMIT 50",
    )
    .bind(format_embedding(&embedding))
    .bind(search_radius)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to search similar claims: {e}"),
    })?;

    // Compute prior belief from neighborhood (similarity-weighted average)
    let (weighted_sum, weight_total) = similar.iter().fold((0.0, 0.0), |(ws, wt), row| {
        let truth = row.truth_value.unwrap_or(0.5);
        let sim = row.similarity.unwrap_or(0.0);
        (ws + truth * sim, wt + sim)
    });
    let prior_belief = if weight_total > 0.0 {
        weighted_sum / weight_total
    } else {
        0.5
    };

    // Classify epistemic status
    let status = if similar.is_empty() {
        "understudied"
    } else if similar.len() >= 10 && prior_belief > 0.7 {
        "established"
    } else if similar.iter().any(|s| {
        let t = s.truth_value.unwrap_or(0.5);
        (t - prior_belief).abs() > 0.3
    }) {
        "contested"
    } else {
        "moderate_evidence"
    };

    let similar_json: Vec<serde_json::Value> = similar
        .iter()
        .take(20)
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "content": s.content.chars().take(200).collect::<String>(),
                "similarity": s.similarity,
                "truth_value": s.truth_value,
                "belief": s.belief,
                "plausibility": s.plausibility,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "prior_belief": prior_belief,
        "similar_claims": similar_json,
        "similar_count": similar.len(),
        "epistemic_status": status,
    })))
}

/// POST /api/v1/methods - Add a characterization/synthesis method.
#[cfg(feature = "db")]
pub async fn add_method(
    State(state): State<AppState>,
    Json(request): Json<AddMethodRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let canonical_name = request.name.to_lowercase().replace(' ', "_");

    // Generate embedding for the method
    let embed_text = if let Some(ref measures) = request.measures {
        format!("{} — {measures}", request.name)
    } else {
        request.name.clone()
    };

    let embedding = if let Some(embedder) = state.embedding_service() {
        embedder.generate(&embed_text).await.ok()
    } else {
        None
    };

    let method = epigraph_db::MethodRecord {
        name: request.name.clone(),
        canonical_name: canonical_name.clone(),
        technique_type: request.technique_type.clone(),
        measures: request.measures.clone(),
        resolution: request.resolution.clone(),
        sensitivity: None,
        limitations: request.limitations.clone().unwrap_or_default(),
        required_equipment: request.required_equipment.clone().unwrap_or_default(),
        typical_conditions: request.conditions.clone(),
        source_claim_ids: Vec::new(),
        properties: serde_json::json!({}),
        embedding,
    };

    let method_id = epigraph_db::MethodRepository::insert(&state.db_pool, &method)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to insert method: {e}"),
        })?;

    // Link capabilities
    let mut caps_linked = 0;
    if let Some(ref capabilities) = request.capabilities {
        for cap in capabilities {
            let _ = epigraph_db::MethodRepository::link_capability(
                &state.db_pool,
                method_id,
                cap,
                1,
                0,
            )
            .await;
            caps_linked += 1;
        }
    }

    Ok(Json(serde_json::json!({
        "method_id": method_id,
        "canonical_name": canonical_name,
        "capabilities_linked": caps_linked,
        "embedded": method.embedding.is_some(),
    })))
}

/// GET /api/v1/methods/search - Search methods by embedding similarity.
#[cfg(feature = "db")]
pub async fn find_methods(
    State(state): State<AppState>,
    Query(params): Query<FindMethodsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;

    let limit = params.limit.unwrap_or(10).clamp(1, 50);

    let query_vec =
        embedder
            .generate(&params.query)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to embed query: {e}"),
            })?;

    let methods = epigraph_db::MethodRepository::find_by_embedding(
        &state.db_pool,
        &query_vec,
        params.technique_type.as_deref(),
        limit,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to search methods: {e}"),
    })?;

    let mut results = Vec::new();
    for m in &methods {
        let capabilities = epigraph_db::MethodRepository::get_capabilities(&state.db_pool, m.id)
            .await
            .unwrap_or_default();

        results.push(serde_json::json!({
            "id": m.id,
            "name": m.name,
            "canonical_name": m.canonical_name,
            "technique_type": m.technique_type,
            "measures": m.measures,
            "resolution": m.resolution,
            "similarity": m.similarity,
            "capabilities": capabilities.iter().map(|c| serde_json::json!({
                "capability": c.capability,
                "specificity": c.specificity,
                "evidence_count": c.evidence_count,
            })).collect::<Vec<_>>(),
        }));
    }

    Ok(Json(serde_json::json!({
        "methods": results,
        "total": results.len(),
    })))
}

/// GET /api/v1/methods/:id/gaps - Method gap analysis for a hypothesis.
#[cfg(feature = "db")]
pub async fn method_gap_analysis(
    State(state): State<AppState>,
    Query(params): Query<MethodGapQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let max_age = params.max_paper_age_years.unwrap_or(5);
    let current_year = chrono::Utc::now().year();

    let capabilities = params.required_capabilities.clone().unwrap_or_default();

    if capabilities.is_empty() {
        return Ok(Json(serde_json::json!({
            "hypothesis_id": params.hypothesis_id,
            "required_capabilities": [],
            "summary": {
                "total_capabilities": 0,
                "covered": 0,
                "gaps": 0,
                "stale": 0,
            },
        })));
    }

    let mut cap_results = Vec::new();
    let mut covered = 0;
    let mut gaps = 0;
    let mut stale = 0;

    for cap in &capabilities {
        let methods =
            epigraph_db::MethodRepository::get_methods_for_capability(&state.db_pool, cap)
                .await
                .unwrap_or_default();

        if methods.is_empty() {
            gaps += 1;
            cap_results.push(serde_json::json!({
                "capability": cap,
                "methods_found": [],
                "gap_flags": ["no_method"],
            }));
            continue;
        }

        let mut method_infos = Vec::new();
        let mut cap_flags: Vec<String> = Vec::new();

        for m in &methods {
            let evidence =
                epigraph_db::MethodRepository::get_evidence_strength(&state.db_pool, m.method_id)
                    .await
                    .ok();

            let papers =
                epigraph_db::MethodRepository::get_source_papers(&state.db_pool, m.method_id)
                    .await
                    .unwrap_or_default();

            let newest_year = papers.iter().filter_map(|p| p.pub_year).max();
            let is_stale = newest_year.is_some_and(|y| current_year - y > max_age);
            let is_single_source = papers.len() <= 1;

            let status = if is_stale {
                stale += 1;
                cap_flags.push("stale".into());
                "stale"
            } else if is_single_source {
                cap_flags.push("single_source".into());
                "single_source"
            } else {
                "adequate"
            };

            method_infos.push(serde_json::json!({
                "method_id": m.method_id,
                "name": m.name,
                "evidence_strength": evidence.as_ref().map(|e| e.avg_belief).unwrap_or(0.0),
                "newest_source_year": newest_year,
                "source_count": papers.len(),
                "status": status,
            }));
        }

        if cap_flags.is_empty() {
            covered += 1;
        }

        cap_results.push(serde_json::json!({
            "capability": cap,
            "methods_found": method_infos,
            "gap_flags": cap_flags,
        }));
    }

    Ok(Json(serde_json::json!({
        "hypothesis_id": params.hypothesis_id,
        "required_capabilities": cap_results,
        "summary": {
            "total_capabilities": capabilities.len(),
            "covered": covered,
            "gaps": gaps,
            "stale": stale,
        },
    })))
}

/// POST /api/v1/experiments/design - Design an experiment protocol from methods.
#[cfg(feature = "db")]
pub async fn design_experiment(
    State(state): State<AppState>,
    Json(request): Json<DesignExperimentRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Load methods
    let mut protocol = Vec::new();
    let mut _all_equipment: Vec<String> = Vec::new();
    let mut critical_gaps = Vec::new();

    for (i, method_id) in request.method_ids.iter().enumerate() {
        let method = epigraph_db::MethodRepository::get(&state.db_pool, *method_id)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to load method {method_id}: {e}"),
            })?
            .ok_or(ApiError::NotFound {
                entity: "method".into(),
                id: method_id.to_string(),
            })?;

        let evidence =
            epigraph_db::MethodRepository::get_evidence_strength(&state.db_pool, *method_id)
                .await
                .ok();

        // Flag methods with no published evidence
        if evidence.as_ref().is_none_or(|e| e.source_count == 0) {
            critical_gaps.push(format!("{}: no published evidence", method.name));
        }

        // Classify phase based on technique type
        let phase = match method.technique_type.as_str() {
            "fabrication" | "synthesis" => "preparation",
            "characterization" | "spectroscopy" | "analytical" => "characterization",
            _ => "execution",
        };

        protocol.push(serde_json::json!({
            "phase": phase,
            "step_number": i + 1,
            "method_id": method_id,
            "method_name": method.name,
            "technique_type": method.technique_type,
            "measures": method.measures,
            "limitations": method.limitations,
        }));

        // Collect equipment
        // Note: required_equipment is on MethodRecord, not MethodSearchResult
        // We'd need to query it separately or add to the get() return type.
    }

    Ok(Json(serde_json::json!({
        "hypothesis_id": request.hypothesis_id,
        "protocol": protocol,
        "critical_gaps": critical_gaps,
        "constraints": request.constraints,
    })))
}

// ── Internal helpers ──

#[cfg(feature = "db")]
use chrono::Datelike;

#[cfg(feature = "db")]
fn format_embedding(embedding: &[f32]) -> String {
    format!(
        "[{}]",
        embedding
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

// ── Internal types ──

#[cfg(feature = "db")]
#[derive(sqlx::FromRow)]
struct SimilarClaimRow {
    id: Uuid,
    content: String,
    truth_value: Option<f64>,
    belief: Option<f64>,
    plausibility: Option<f64>,
    similarity: Option<f64>,
}
