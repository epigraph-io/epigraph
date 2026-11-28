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
///
/// # A stored analysis, and whose claims it names
///
/// `gap_analyses` has no tenancy, so any caller may name any analysis id. The
/// analysis is loaded BY that id, and each stored gap is surfaced only through
/// the claim id it names ([`epigraph_db::GapRecord::nearest_claim_id`]),
/// resolved with the CALLER's viewer on the transaction the challenge is
/// written on (`ChallengeRepository::admission_of`, as
/// `POST /claims/:id/challenge` does). A gap whose claim the caller cannot
/// read, or may not challenge, is skipped; a gap that names no claim (every
/// row stored before ids were) has nothing to target and is skipped too. The
/// response does not tell those apart. The challenge is filed against that
/// claim by the caller, and its text names the gap type and the claim id only:
/// any text a legacy row still stores is never copied.
///
/// Gaps given directly in the body are the caller's own text and are filed as
/// given.
#[cfg(feature = "db")]
pub async fn surface_gaps(
    // `claims:write`, checked before the body is parsed (backlog f00d75ab).
    _scope: crate::middleware::bearer::RequireScopeWrite,
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<SurfaceGapsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use epigraph_db::repos::challenge::ChallengeAdmission;

    let min_severity = request.min_severity.unwrap_or(0.5);
    let Some(caller) = viewer.principal() else {
        return Err(ApiError::Forbidden {
            reason: "surfacing a gap files a challenge, which needs an authenticated \
                     challenger"
                .to_string(),
        });
    };

    // ONE transaction stamped with the caller's viewer: the analysis lookup,
    // every readability check, every challenge and its event.
    let mut tx = state.write_as(&viewer, "surface_gaps").await?;

    // (gap_type, severity, target claim, explanation)
    let mut targets: Vec<(String, f64, Uuid, String)> = Vec::new();
    if let Some(ref direct_gaps) = request.gaps {
        // Caller-supplied text. These name no claim, so the target is the nil
        // placeholder this route has always used.
        for gap in direct_gaps {
            if gap.severity >= min_severity {
                targets.push((
                    gap.gap_type.clone(),
                    gap.severity,
                    Uuid::nil(),
                    gap.unconstrained_claim.clone(),
                ));
            }
        }
    } else if let Some(analysis_id) = request.gap_analysis_id {
        let analysis = epigraph_db::GapRepository::get_gap_analysis(&mut *tx, analysis_id)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to load gap analysis: {e}"),
            })?
            .ok_or(ApiError::NotFound {
                entity: "gap_analysis".into(),
                id: analysis_id.to_string(),
            })?;

        let stored: Vec<epigraph_db::GapRecord> = analysis
            .gaps
            .as_array()
            .map(|gaps| {
                gaps.iter()
                    .filter_map(|g| serde_json::from_value(g.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();

        for gap in stored {
            if gap.severity < min_severity {
                continue;
            }
            let Some(claim_id) = gap.nearest_claim_id else {
                continue;
            };
            let admission =
                epigraph_db::ChallengeRepository::admission_of(&mut *tx, &viewer, claim_id)
                    .await
                    .map_err(|e| ApiError::InternalError {
                        message: format!("Failed to read a gap's claim: {e}"),
                    })?;
            if !matches!(
                admission,
                Some(ChallengeAdmission::Insider | ChallengeAdmission::Outsider { .. })
            ) {
                continue;
            }
            let explanation = format!("gap_{}: claim {claim_id}", gap.gap_type);
            targets.push((gap.gap_type, gap.severity, claim_id, explanation));
        }
    } else {
        return Err(ApiError::BadRequest {
            message: "Either gap_analysis_id or gaps must be provided".into(),
        });
    }

    // Create challenges for gaps above threshold
    let mut challenge_ids = Vec::new();
    for (gap_type, severity, claim_id, explanation) in &targets {
        let challenge_id = epigraph_db::ChallengeRepository::create(
            &mut *tx,
            *claim_id,
            Some(caller),
            &format!("gap_{gap_type}"),
            explanation,
        )
        .await
        .map_err(|e| {
            if crate::errors::is_insufficient_privilege(&e) {
                tracing::warn!(
                    target: "tenancy.scoped_write",
                    handler = "surface_gaps",
                    claim = %claim_id,
                    error = %e,
                    "the database refused a gap challenge"
                );
                crate::errors::write_refused("challenge")
            } else {
                ApiError::InternalError {
                    message: format!("Failed to create gap challenge: {e}"),
                }
            }
        })?;

        challenge_ids.push(challenge_id);

        // The event rides the challenge's fate, SAVEPOINT-wrapped so a refused
        // event cannot abort the challenge. `claim_id` is load-bearing:
        // `EventRepository::list` (and the webhook fan-out) hide an event only
        // when a uuid in its payload names a claim the reader cannot see, so
        // without it a gap on a group-private claim would show every reader
        // its challenger, gap type and severity (as `claim.challenged` does).
        epigraph_db::EventRepository::publish_or_log_conn(
            &mut tx,
            "gap.surfaced",
            Some(caller),
            &serde_json::json!({
                "challenge_id": challenge_id,
                "claim_id": claim_id,
                "gap_type": gap_type,
                "severity": severity,
            }),
        )
        .await;
    }

    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the gap challenges: {e}"),
    })?;

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
///
/// # Viewer
///
/// PR-07 fixed the caller-supplied-probe-vector-over-the-whole-corpus leak in
/// `search.rs::semantic_search` and left it standing in this sibling, which ran
/// the same statement shape and returned up to 200 characters of each matching
/// claim in `nearest_graph_claim`. The handler took no auth argument at all, so
/// the only gate was the router's `bearer_auth_middleware`. Adding the
/// `ViewerExtractor` is a deliberate behaviour change: a bearer token that
/// resolves to no `agents.id` now 401s here.
///
/// The claim search runs on the caller's stamped connection, so the caller's
/// own group-private claims are analysed (an unstamped read on the application
/// role sees only public rows).
///
/// # What is stored, and what is answered
///
/// `gap_analyses` has no tenancy, and `surface_gaps` serves a stored analysis
/// to any caller who names its id. The stored [`epigraph_db::GapRecord`]s
/// therefore carry the claim id, gap type, severity and similarity, and text
/// built only from fixed templates and numbers; `nearest_graph_claim` is never
/// stored. The RESPONSE adds the statements back, because it goes to the
/// caller who just read them.
#[cfg(feature = "db")]
pub async fn gap_analysis(
    // `claims:write`, checked before the body is parsed (backlog f00d75ab).
    _scope: crate::middleware::bearer::RequireScopeWrite,
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
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

    // Find relevant VISIBLE claims in the graph, on the caller's stamped
    // connection. Same predicate, threshold, ordering and limit as the inline
    // statement this replaced.
    let mut read = super::open_scoped_read(&state, &viewer, "gap_analysis").await?;
    let graph_claims = epigraph_db::ClaimRepository::semantic_search_flat(
        &mut *read,
        &viewer,
        epigraph_db::FlatRanking::Query(&epigraph_db::pgvector_literal(&query_vec)),
        GAP_RELEVANCE_FLOOR,
        None,
        None,
        None,
        None,
        20,
        None,
        0,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to search graph claims: {e}"),
    })?;
    super::finish_scoped_read(read, "gap_analysis").await?;

    // Analyze gaps — claims with low truth or high ignorance. Each record is
    // paired with the statement of the claim it names, for the response only.
    let mut gaps: Vec<(epigraph_db::GapRecord, Option<&str>)> = Vec::new();

    for claim in &graph_claims {
        let truth = claim.truth_value;
        let belief = claim.belief.unwrap_or(truth);
        let plausibility = claim.plausibility.unwrap_or(truth);
        let ignorance = plausibility - belief;
        let similarity = claim.similarity;

        // High ignorance = knowledge void
        if ignorance > 0.4 && similarity > 0.5 {
            let severity = ignorance * similarity;
            if severity >= min_severity {
                gaps.push((
                    epigraph_db::GapRecord {
                        gap_type: "confidence_divergence".into(),
                        severity,
                        unconstrained_claim: format!(
                            "High ignorance ({ignorance:.2}) on claim {}",
                            claim.claim_id
                        ),
                        nearest_graph_claim: None,
                        nearest_claim_id: Some(claim.claim_id),
                        nearest_similarity: similarity,
                        graph_inference_path: None,
                        recommendation: "Gather more evidence to reduce ignorance".into(),
                    },
                    Some(claim.statement.as_str()),
                ));
            }
        }

        // Low truth despite relevance = potential blind spot
        if truth < 0.3 && similarity > 0.6 {
            let severity = (1.0 - truth) * similarity;
            if severity >= min_severity {
                gaps.push((
                    epigraph_db::GapRecord {
                        gap_type: "blind_spot".into(),
                        severity,
                        unconstrained_claim: format!(
                            "Low truth ({truth:.2}) on relevant claim {}",
                            claim.claim_id
                        ),
                        nearest_graph_claim: None,
                        nearest_claim_id: Some(claim.claim_id),
                        nearest_similarity: similarity,
                        graph_inference_path: None,
                        recommendation: "Investigate low-truth claim for missing evidence".into(),
                    },
                    Some(claim.statement.as_str()),
                ));
            }
        }
    }

    // If few claims found, the area itself is a structural absence. The
    // question is the caller's own text (and is stored in `question` anyway).
    if graph_claims.len() < 3 {
        let nearest = graph_claims.first();
        gaps.push((
            epigraph_db::GapRecord {
                gap_type: "structural_absence".into(),
                severity: 0.9,
                unconstrained_claim: format!(
                    "Only {} claims found for: {}",
                    graph_claims.len(),
                    request.question
                ),
                nearest_graph_claim: None,
                nearest_claim_id: nearest.map(|c| c.claim_id),
                nearest_similarity: nearest.map_or(0.0, |c| c.similarity),
                graph_inference_path: None,
                recommendation: "This area lacks coverage — consider ingesting relevant sources"
                    .into(),
            },
            nearest.map(|c| c.statement.as_str()),
        ));
    }

    let gap_records: Vec<epigraph_db::GapRecord> = gaps.iter().map(|(g, _)| g.clone()).collect();

    // Persist gap analysis: ids, scores and templates only (see above).
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

    // The caller's own view: the stored template, plus the statement of the
    // claim it names (which this caller just read).
    let gaps_json: Vec<serde_json::Value> = gaps
        .iter()
        .map(|(g, statement)| {
            let unconstrained = match statement {
                Some(text) if g.gap_type != "structural_absence" => format!(
                    "{}: {}",
                    g.unconstrained_claim,
                    text.chars().take(100).collect::<String>()
                ),
                _ => g.unconstrained_claim.clone(),
            };
            serde_json::json!({
                "gap_type": g.gap_type,
                "severity": g.severity,
                "unconstrained_claim": unconstrained,
                "nearest_graph_claim": statement.map(|t| t.chars().take(200).collect::<String>()),
                "nearest_claim_id": g.nearest_claim_id,
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

/// The similarity floor `gap_analysis` has always used, previously written as a
/// bare `0.3` inside the SQL literal.
#[cfg(feature = "db")]
const GAP_RELEVANCE_FLOOR: f64 = 0.3;

// ── Internal types ──
//
// `GraphClaimRow` was deleted with the inline corpus scan it decoded. Its
// replacement is `epigraph_db::SemanticFlatHit`, returned by the
// viewer-spliced `ClaimRepository::semantic_search_flat`.
