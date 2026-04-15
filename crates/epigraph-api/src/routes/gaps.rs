//! Epistemic gap detection endpoints.
//!
//! ## Endpoints
//!
//! - `POST /api/v1/gaps/surface`    - Surface gaps as challenges
//! - `POST /api/v1/gaps/analysis`   - Run epistemic gap analysis

#[cfg(feature = "db")]
use axum::{extract::State, Json};
#[cfg(feature = "db")]
use serde::Deserialize;
#[cfg(feature = "db")]
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

// ── Request types ──

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct SurfaceGapsRequest {
    pub gap_analysis_id: Option<Uuid>,
    pub min_severity: Option<f64>,
    pub gaps: Option<Vec<GapInput>>,
}

#[cfg(feature = "db")]
#[derive(Debug, Clone, Deserialize)]
pub struct GapInput {
    pub gap_type: String,
    pub severity: f64,
    pub unconstrained_claim: String,
    pub nearest_graph_claim: Option<String>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct GapAnalysisRequest {
    pub question: String,
    pub min_gap_severity: Option<f64>,
}

// ── Handlers ──

/// POST /api/v1/gaps/surface - Surface gaps as challenges.
///
/// Takes gap entries (from a prior gap analysis or provided directly)
/// and creates challenge records for gaps above the severity threshold.
#[cfg(feature = "db")]
pub async fn surface_gaps(
    State(state): State<AppState>,
    Json(request): Json<SurfaceGapsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let min_severity = request.min_severity.unwrap_or(0.5);

    // Resolve gaps — either from stored analysis or from request body
    let gaps: Vec<GapInput> = if let Some(ref direct_gaps) = request.gaps {
        direct_gaps.clone()
    } else if let Some(analysis_id) = request.gap_analysis_id {
        // Load from stored gap analysis
        let analyses = epigraph_db::GapRepository::get_gap_analyses(&state.db_pool, None, 1)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to load gap analyses: {e}"),
            })?;

        let analysis =
            analyses
                .into_iter()
                .find(|a| a.id == analysis_id)
                .ok_or(ApiError::NotFound {
                    entity: "gap_analysis".into(),
                    id: analysis_id.to_string(),
                })?;

        // Parse stored gaps from JSON value
        let gap_array = analysis.gaps.as_array().unwrap_or(&Vec::new()).clone();
        gap_array
            .iter()
            .filter_map(|g| {
                Some(GapInput {
                    gap_type: g.get("gap_type")?.as_str()?.to_string(),
                    severity: g.get("severity")?.as_f64()?,
                    unconstrained_claim: g.get("unconstrained_claim")?.as_str()?.to_string(),
                    nearest_graph_claim: g
                        .get("nearest_graph_claim")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                })
            })
            .collect()
    } else {
        return Err(ApiError::BadRequest {
            message: "Either gap_analysis_id or gaps must be provided".into(),
        });
    };

    // Create challenges for gaps above threshold
    let mut challenge_ids = Vec::new();
    for gap in &gaps {
        if gap.severity < min_severity {
            continue;
        }

        let challenge_id = epigraph_db::ChallengeRepository::create(
            &state.db_pool,
            Uuid::nil(), // placeholder claim_id — gap doesn't target a specific claim
            None,
            &format!("gap_{}", gap.gap_type),
            &gap.unconstrained_claim,
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to create gap challenge: {e}"),
        })?;

        challenge_ids.push(challenge_id);

        // Emit event
        let _ = epigraph_db::EventRepository::insert(
            &state.db_pool,
            "gap.surfaced",
            None,
            &serde_json::json!({
                "challenge_id": challenge_id,
                "gap_type": gap.gap_type,
                "severity": gap.severity,
            }),
        )
        .await;
    }

    Ok(Json(serde_json::json!({
        "challenges_created": challenge_ids.len(),
        "challenge_ids": challenge_ids,
    })))
}

/// POST /api/v1/gaps/analysis - Run epistemic gap analysis.
///
/// Analyzes a question against the knowledge graph to identify gaps.
/// Compares graph-constrained claims with the question to find
/// structural absences, blind spots, and confidence divergences.
#[cfg(feature = "db")]
pub async fn gap_analysis(
    State(state): State<AppState>,
    Json(request): Json<GapAnalysisRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;

    let min_severity = request.min_gap_severity.unwrap_or(0.3);

    // Embed the question
    let query_vec =
        embedder
            .generate(&request.question)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to embed question: {e}"),
            })?;

    // Find relevant claims in the graph
    let graph_claims: Vec<GraphClaimRow> = sqlx::query_as(
        "SELECT id, content, truth_value, belief, plausibility, \
                1 - (embedding <=> $1::vector) AS similarity \
         FROM claims \
         WHERE embedding IS NOT NULL \
           AND 1 - (embedding <=> $1::vector) >= 0.3 \
         ORDER BY similarity DESC \
         LIMIT 20",
    )
    .bind(format_embedding(&query_vec))
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to search graph claims: {e}"),
    })?;

    // Analyze gaps — claims with low truth or high ignorance
    let mut gap_records = Vec::new();

    for claim in &graph_claims {
        let truth = claim.truth_value.unwrap_or(0.5);
        let belief = claim.belief.unwrap_or(truth);
        let plausibility = claim.plausibility.unwrap_or(truth);
        let ignorance = plausibility - belief;
        let similarity = claim.similarity.unwrap_or(0.0);

        // High ignorance = knowledge void
        if ignorance > 0.4 && similarity > 0.5 {
            let severity = ignorance * similarity;
            if severity >= min_severity {
                gap_records.push(epigraph_db::GapRecord {
                    gap_type: "confidence_divergence".into(),
                    severity,
                    unconstrained_claim: format!(
                        "High ignorance ({:.2}) on: {}",
                        ignorance,
                        claim.content.chars().take(100).collect::<String>()
                    ),
                    nearest_graph_claim: Some(claim.content.chars().take(200).collect()),
                    nearest_similarity: similarity,
                    graph_inference_path: None,
                    recommendation: "Gather more evidence to reduce ignorance".into(),
                });
            }
        }

        // Low truth despite relevance = potential blind spot
        if truth < 0.3 && similarity > 0.6 {
            let severity = (1.0 - truth) * similarity;
            if severity >= min_severity {
                gap_records.push(epigraph_db::GapRecord {
                    gap_type: "blind_spot".into(),
                    severity,
                    unconstrained_claim: format!(
                        "Low truth ({:.2}) on relevant claim: {}",
                        truth,
                        claim.content.chars().take(100).collect::<String>()
                    ),
                    nearest_graph_claim: Some(claim.content.chars().take(200).collect()),
                    nearest_similarity: similarity,
                    graph_inference_path: None,
                    recommendation: "Investigate low-truth claim for missing evidence".into(),
                });
            }
        }
    }

    // If few claims found, the area itself is a structural absence
    if graph_claims.len() < 3 {
        gap_records.push(epigraph_db::GapRecord {
            gap_type: "structural_absence".into(),
            severity: 0.9,
            unconstrained_claim: format!(
                "Only {} claims found for: {}",
                graph_claims.len(),
                request.question
            ),
            nearest_graph_claim: graph_claims
                .first()
                .map(|c| c.content.chars().take(200).collect()),
            nearest_similarity: graph_claims
                .first()
                .and_then(|c| c.similarity)
                .unwrap_or(0.0),
            graph_inference_path: None,
            recommendation: "This area lacks coverage — consider ingesting relevant sources".into(),
        });
    }

    // Persist gap analysis
    let analysis_id = epigraph_db::GapRepository::store_gap_analysis(
        &state.db_pool,
        &request.question,
        None,
        None,
        graph_claims.len() as i32,
        0, // no unconstrained analysis in REST version
        0,
        &gap_records,
        0,
        None,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to store gap analysis: {e}"),
    })?;

    let gaps_json: Vec<serde_json::Value> = gap_records
        .iter()
        .map(|g| {
            serde_json::json!({
                "gap_type": g.gap_type,
                "severity": g.severity,
                "unconstrained_claim": g.unconstrained_claim,
                "nearest_graph_claim": g.nearest_graph_claim,
                "nearest_similarity": g.nearest_similarity,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "question": request.question,
        "graph_claims_count": graph_claims.len(),
        "gaps": gaps_json,
        "gap_analysis_id": analysis_id,
    })))
}

// ── Internal helpers ──

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
struct GraphClaimRow {
    #[allow(dead_code)]
    id: Uuid,
    content: String,
    truth_value: Option<f64>,
    belief: Option<f64>,
    plausibility: Option<f64>,
    similarity: Option<f64>,
}
