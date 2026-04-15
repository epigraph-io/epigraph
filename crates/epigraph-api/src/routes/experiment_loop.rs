//! Experiment lifecycle endpoints.
//!
//! - POST /api/v1/experiments — Create experiment for hypothesis
//! - POST /api/v1/experiments/:id/start — Set status to running
//! - POST /api/v1/experiments/:id/results — Submit results with measurements
//! - POST /api/v1/experiments/:eid/results/:rid/measurements — Add more measurements
//! - POST /api/v1/experiments/:eid/results/:rid/analyze — Trigger analysis

#[cfg(feature = "db")]
use axum::{
    extract::{Path, State},
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

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct CreateExperimentRequest {
    pub hypothesis_id: Uuid,
    pub agent_id: Uuid,
    pub method_ids: Option<Vec<Uuid>>,
    pub protocol: Option<String>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct SubmitResultsRequest {
    pub data_source: String,
    pub measurements: Vec<serde_json::Value>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct AddMeasurementsRequest {
    pub measurements: Vec<serde_json::Value>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    pub agent_id: Uuid,
    pub direction: String,
    pub scope_limitations: Vec<serde_json::Value>,
    /// Expected value under hypothesis — effect_size = |measured - expected|.
    /// If omitted, raw measurement value is used (assumes expected = 0).
    pub expected_value: Option<f64>,
}

/// POST /api/v1/experiments
#[cfg(feature = "db")]
pub async fn create_experiment(
    State(state): State<AppState>,
    Json(req): Json<CreateExperimentRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = epigraph_db::ExperimentRepository::create(
        &state.db_pool,
        req.hypothesis_id,
        req.agent_id,
        req.method_ids.as_deref(),
        req.protocol.as_deref(),
        None,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("{e}"),
    })?;

    // Create tests_hypothesis edge
    sqlx::query(
        r#"
        INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
        VALUES ($1, 'experiment', $2, 'claim', 'tests_hypothesis', '{}')
        "#,
    )
    .bind(id)
    .bind(req.hypothesis_id)
    .execute(&state.db_pool)
    .await
    .ok();

    Ok(Json(
        serde_json::json!({ "experiment_id": id, "status": "designed" }),
    ))
}

/// POST /api/v1/experiments/:id/start
#[cfg(feature = "db")]
pub async fn start_experiment(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    epigraph_db::ExperimentRepository::update_status(&state.db_pool, id, "running")
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("{e}"),
        })?;
    Ok(Json(
        serde_json::json!({ "experiment_id": id, "status": "running" }),
    ))
}

/// POST /api/v1/experiments/:id/results
#[cfg(feature = "db")]
pub async fn submit_results(
    State(state): State<AppState>,
    Path(experiment_id): Path<Uuid>,
    Json(req): Json<SubmitResultsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let measurements_json =
        serde_json::to_value(&req.measurements).map_err(|e| ApiError::BadRequest {
            message: format!("Invalid measurements: {e}"),
        })?;

    let count = req.measurements.len() as i32;

    let result_id = epigraph_db::ExperimentResultRepository::create(
        &state.db_pool,
        experiment_id,
        &req.data_source,
        &measurements_json,
        count,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("{e}"),
    })?;

    // Create result_of edge
    sqlx::query(
        r#"
        INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
        VALUES ($1, 'experiment_result', $2, 'experiment', 'result_of', $3)
        "#,
    )
    .bind(result_id)
    .bind(experiment_id)
    .bind(serde_json::json!({"data_source": req.data_source}))
    .execute(&state.db_pool)
    .await
    .ok();

    // Update experiment status to collecting
    epigraph_db::ExperimentRepository::update_status(&state.db_pool, experiment_id, "collecting")
        .await
        .ok();

    Ok(Json(serde_json::json!({
        "result_id": result_id,
        "measurement_count": count,
    })))
}

/// POST /api/v1/experiments/:eid/results/:rid/measurements
#[cfg(feature = "db")]
pub async fn add_measurements(
    State(state): State<AppState>,
    Path((_, result_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<AddMeasurementsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let new_json = serde_json::to_value(&req.measurements).map_err(|e| ApiError::BadRequest {
        message: format!("{e}"),
    })?;
    let new_count = req.measurements.len() as i32;

    // For v1, store raw measurements and let analysis compute effective error
    let effective_err = serde_json::json!(null);

    epigraph_db::ExperimentResultRepository::add_measurements(
        &state.db_pool,
        result_id,
        &new_json,
        new_count,
        &effective_err,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("{e}"),
    })?;

    // Get updated count
    let result = epigraph_db::ExperimentResultRepository::get(&state.db_pool, result_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("{e}"),
        })?
        .ok_or(ApiError::NotFound {
            entity: "result".into(),
            id: result_id.to_string(),
        })?;

    Ok(Json(serde_json::json!({
        "result_id": result_id,
        "total_measurements": result.measurement_count,
    })))
}

/// POST /api/v1/experiments/:eid/results/:rid/analyze
///
/// Creates an analysis node, computes error-derived mass function,
/// submits to hypothesis_assessment frame, creates provides_evidence edge
/// (which triggers shared_evidence factor if multi-hypothesis).
#[cfg(feature = "db")]
pub async fn analyze_result(
    State(state): State<AppState>,
    Path((experiment_id, result_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<AnalyzeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use epigraph_engine::{build_error_mass, ErrorBudget, EvidenceDirection, ScopeLimitation};

    // Load result
    let result = epigraph_db::ExperimentResultRepository::get(&state.db_pool, result_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("{e}"),
        })?
        .ok_or(ApiError::NotFound {
            entity: "result".into(),
            id: result_id.to_string(),
        })?;

    // Load experiment to get hypothesis_id
    let experiment = epigraph_db::ExperimentRepository::get(&state.db_pool, experiment_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("{e}"),
        })?
        .ok_or(ApiError::NotFound {
            entity: "experiment".into(),
            id: experiment_id.to_string(),
        })?;

    // ── Circularity guard ──
    // Reject if the hypothesis claim itself lacks grounded evidence AND
    // the measurements reference claim truth values (not raw experimental data).
    // A hypothesis cannot provide evidence for itself through claim-to-claim propagation.
    //
    // Check: does the experiment's data_source reference claims that are either
    // (a) the hypothesis itself, or (b) ungrounded (no paper/evidence/analysis provenance)?
    let empty_vec = vec![];
    let raw_measurements = result.raw_measurements.as_array().unwrap_or(&empty_vec);
    let mut ungrounded_sources: Vec<String> = Vec::new();
    for m in raw_measurements {
        if let Some(source) = m.get("source").and_then(|s| s.as_str()) {
            // Check if any measurement source references a claim by UUID
            if let Ok(source_claim_id) = source.parse::<Uuid>() {
                // Reject self-reference
                if source_claim_id == experiment.hypothesis_id {
                    return Err(ApiError::BadRequest {
                        message: "Circularity rejected: measurement source references the hypothesis itself. \
                                  A hypothesis cannot provide evidence for itself.".into(),
                    });
                }
                // Check if source claim is grounded
                let grounded = epigraph_db::ClaimRepository::has_grounded_evidence(
                    &state.db_pool,
                    source_claim_id,
                )
                .await
                .unwrap_or(false);
                if !grounded {
                    ungrounded_sources.push(source.to_string());
                }
            }
        }
    }
    if !ungrounded_sources.is_empty() {
        return Err(ApiError::BadRequest {
            message: format!(
                "Evidence rejected: {} measurement source(s) lack grounded evidence \
                 (no paper, experimental data, or analysis provenance). \
                 Claim-to-claim propagation is not sufficient evidence. \
                 Ungrounded sources: {:?}",
                ungrounded_sources.len(),
                ungrounded_sources,
            ),
        });
    }

    // Compute aggregate error from measurements (reuse raw_measurements parsed above)
    let expected = req.expected_value.unwrap_or(0.0);
    let (random_err, systematic_err, effect_size) = aggregate_errors(raw_measurements, expected);

    // Update experiment status to 'analyzing'
    epigraph_db::ExperimentRepository::update_status(&state.db_pool, experiment_id, "analyzing")
        .await
        .ok();

    // Build scope limitations
    let scope_lims: Vec<ScopeLimitation> = req
        .scope_limitations
        .iter()
        .filter_map(|s| {
            s.get("type").and_then(|t| t.as_str()).map(|t| match t {
                "single_temperature_point" => ScopeLimitation::SingleTemperaturePoint,
                "single_material_system" => ScopeLimitation::SingleMaterialSystem,
                "non_standard_environment" => ScopeLimitation::NonStandardEnvironment,
                "small_sample_size" => ScopeLimitation::SmallSampleSize,
                "proxy_measurement" => ScopeLimitation::ProxyMeasurement,
                _ => ScopeLimitation::Custom(
                    s.get("weight").and_then(|w| w.as_f64()).unwrap_or(0.05),
                ),
            })
        })
        .collect();

    let direction = if req.direction == "supports" {
        EvidenceDirection::Supports
    } else {
        EvidenceDirection::Refutes
    };

    let budget = ErrorBudget {
        random_error: random_err,
        systematic_error: systematic_err,
        scope_limitations: scope_lims,
        effect_size,
        direction,
    };

    let mass_result = build_error_mass(&budget).map_err(|e| ApiError::InternalError {
        message: format!("Mass function error: {e}"),
    })?;

    // Create analysis node
    let analysis_id: (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO analyses (analysis_type, method_description, inference_path, agent_id, properties)
        VALUES ('automated', 'Error-derived mass function from experimental measurements',
                'novel', $1, $2)
        RETURNING id
        "#,
    )
    .bind(req.agent_id)
    .bind(serde_json::json!({
        "scope_limitations": req.scope_limitations,
        "error_budget": {
            "random_contribution": random_err,
            "systematic_contribution": systematic_err,
            "scope_penalty": mass_result.m_open_world,
            "m_supported": if direction == EvidenceDirection::Supports { mass_result.m_evidence } else { 0.0 },
            "m_unsupported": if direction == EvidenceDirection::Refutes { mass_result.m_evidence } else { 0.0 },
            "m_frame_ignorance": mass_result.m_frame_ignorance,
            "m_open_world": mass_result.m_open_world,
        },
        "supports_hypothesis": req.direction == "supports",
    }))
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError { message: format!("Failed to create analysis: {e}") })?;

    // Create analyzes edge (analysis → result)
    sqlx::query(
        r#"
        INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
        VALUES ($1, 'analysis', $2, 'experiment_result', 'analyzes', '{}')
        "#,
    )
    .bind(analysis_id.0)
    .bind(result_id)
    .execute(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create analyzes edge: {e}"),
    })?;

    // Create provides_evidence edge (analysis → hypothesis)
    // CRITICAL: This triggers the shared_evidence factor creation if multi-hypothesis.
    sqlx::query(
        r#"
        INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
        VALUES ($1, 'analysis', $2, 'claim', 'provides_evidence', $3)
        "#,
    )
    .bind(analysis_id.0)
    .bind(experiment.hypothesis_id)
    .bind(serde_json::json!({
        "direction": req.direction,
        "precision_ratio": mass_result.precision_ratio,
        "evidence_strength": mass_result.evidence_strength,
    }))
    .execute(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create provides_evidence edge: {e}"),
    })?;

    // Submit mass function to hypothesis_assessment frame
    let frame_id: (Uuid,) =
        sqlx::query_as("SELECT id FROM frames WHERE name = 'hypothesis_assessment'")
            .fetch_one(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("{e}"),
            })?;

    let masses_json = mass_result.mass_function.masses_to_json();
    epigraph_db::MassFunctionRepository::store(
        &state.db_pool,
        experiment.hypothesis_id,
        frame_id.0,
        Some(req.agent_id),
        &masses_json,
        None,
        Some("error_derived"),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("{e}"),
    })?;

    // Update statuses
    epigraph_db::ExperimentResultRepository::update_status(&state.db_pool, result_id, "complete")
        .await
        .ok();
    epigraph_db::ExperimentRepository::update_status(&state.db_pool, experiment_id, "complete")
        .await
        .ok();

    Ok(Json(serde_json::json!({
        "analysis_id": analysis_id.0,
        "hypothesis_id": experiment.hypothesis_id,
        "mass_function": {
            "precision_ratio": mass_result.precision_ratio,
            "evidence_strength": mass_result.evidence_strength,
            "m_evidence": mass_result.m_evidence,
            "m_frame_ignorance": mass_result.m_frame_ignorance,
            "m_open_world": mass_result.m_open_world,
        },
    })))
}

/// GET /api/v1/experiments?hypothesis_id=:id — List experiments for a hypothesis.
#[cfg(feature = "db")]
pub async fn list_experiments(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<ListExperimentsParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let experiments =
        epigraph_db::ExperimentRepository::get_for_hypothesis(&state.db_pool, params.hypothesis_id)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("{e}"),
            })?;

    let results: Vec<serde_json::Value> = experiments
        .iter()
        .map(|exp| {
            serde_json::json!({
                "id": exp.id,
                "hypothesis_id": exp.hypothesis_id,
                "status": exp.status,
                "method_ids": exp.method_ids,
                "created_at": exp.created_at.to_rfc3339(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "experiments": results })))
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct ListExperimentsParams {
    pub hypothesis_id: Uuid,
}

/// Aggregate errors from measurement array.
/// Returns (random_error, systematic_error, effect_size) as RMS across parameters.
#[cfg(feature = "db")]
fn aggregate_errors(measurements: &[serde_json::Value], expected_value: f64) -> (f64, f64, f64) {
    if measurements.is_empty() {
        return (0.0, 0.0, 0.0);
    }

    let mut random_sum_sq = 0.0;
    let mut systematic_sum_sq = 0.0;
    let mut effect_sum = 0.0;
    let mut count = 0.0;

    for m in measurements {
        let random = m
            .get("random_error")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let systematic = m
            .get("systematic_error")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let n_avg = m
            .get("n_averaged")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0)
            .max(1.0);
        let value = m.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);

        // Effective random error after averaging
        let effective_random = random / n_avg.sqrt();
        random_sum_sq += effective_random.powi(2);
        systematic_sum_sq += systematic.powi(2);
        // effect_size = distance between measurement and hypothesis prediction
        effect_sum += (value - expected_value).abs();
        count += 1.0;
    }

    let random_rms = (random_sum_sq / count).sqrt();
    let systematic_rms = (systematic_sum_sq / count).sqrt();
    let avg_effect = effect_sum / count;

    (random_rms, systematic_rms, avg_effect)
}
