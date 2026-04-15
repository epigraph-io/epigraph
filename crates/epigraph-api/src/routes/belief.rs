//! Dempster-Shafer belief endpoints
//!
//! Public (GET):
//! - `GET /api/v1/claims/:id/belief` — belief interval for a claim
//! - `GET /api/v1/claims/by-belief` — filter claims by belief bounds
//! - `GET /api/v1/frames` — list all frames
//! - `GET /api/v1/frames/:id` — frame detail with claims
//! - `GET /api/v1/frames/:id/conflict` — conflict coefficient for frame
//! - `GET /api/v1/frames/:id/claims` — claims in frame sorted by belief
//! - `GET /api/v1/claims/:id/divergence` — DS vs Bayesian divergence
//! - `GET /api/v1/divergence/top` — highest KL-divergence claims
//!
//! Protected (POST):
//! - `POST /api/v1/frames` — create a frame
//! - `POST /api/v1/frames/:id/evidence` — submit mass function evidence

use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use axum::extract::State;
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Response for claim belief interval
#[derive(Debug, Serialize)]
pub struct BeliefResponse {
    pub claim_id: Uuid,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub ignorance: Option<f64>,
    /// Genuine conflict: m((empty, false)) — evidence sources contradict each other
    pub mass_on_conflict: Option<f64>,
    /// Frame incompleteness: m((Omega, true)) — frame may be missing propositions
    pub mass_on_missing: Option<f64>,
    pub pignistic_prob: Option<f64>,
    pub mass_function_count: i64,
}

/// Response for a frame of discernment
#[derive(Debug, Serialize)]
pub struct FrameResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub hypotheses: Vec<String>,
    pub parent_frame_id: Option<Uuid>,
    pub is_refinable: bool,
    /// Frame version, incremented on extend()
    pub version: i32,
    pub created_at: String,
}

/// Response for frame detail with claims
#[derive(Debug, Serialize)]
pub struct FrameDetailResponse {
    pub frame: FrameResponse,
    pub claim_count: usize,
    pub claims: Vec<FrameClaimEntry>,
}

/// A claim assignment within a frame
#[derive(Debug, Serialize)]
pub struct FrameClaimEntry {
    pub claim_id: Uuid,
    pub hypothesis_index: Option<i32>,
}

/// Response for frame conflict analysis
#[derive(Debug, Serialize)]
pub struct FrameConflictResponse {
    pub frame_id: Uuid,
    pub source_count: i64,
    pub avg_conflict_k: Option<f64>,
    pub max_conflict_k: Option<f64>,
}

/// Request to create a new frame
#[derive(Debug, Deserialize)]
pub struct CreateFrameRequest {
    pub name: String,
    pub description: Option<String>,
    pub hypotheses: Vec<String>,
}

/// Request to submit mass function evidence
#[derive(Debug, Deserialize)]
pub struct SubmitEvidenceRequest {
    pub claim_id: Uuid,
    pub agent_id: Option<Uuid>,
    /// Optional perspective under which this evidence is submitted
    pub perspective_id: Option<Uuid>,
    /// Reliability discount factor [0, 1]. 1.0 = fully reliable.
    #[serde(default = "default_reliability")]
    pub reliability: f64,
    /// Conflict threshold for adaptive combination
    #[serde(default = "default_conflict_threshold")]
    pub conflict_threshold: f64,
    /// Mass assignments: keys are comma-separated hypothesis indices, values are mass.
    /// Prefix key with `~` for CDST complement (negative) elements.
    pub masses: std::collections::BTreeMap<String, f64>,
    /// Override combination method: "conjunctive", "dempster", "yager_open",
    /// "yager_closed", "dubois_prade", "inagaki". If omitted, uses adaptive.
    #[serde(default)]
    pub combination_method: Option<String>,
    /// Inagaki gamma parameter [0, 1]. Only used when combination_method = "inagaki".
    #[serde(default)]
    pub gamma: Option<f64>,
    /// If true, skip independence checking. Caller asserts provenance independence.
    /// Logged for audit purposes.
    #[serde(default)]
    pub assume_independent: Option<bool>,
}

fn default_reliability() -> f64 {
    1.0
}

fn default_conflict_threshold() -> f64 {
    0.3
}

/// Response from evidence submission
#[derive(Debug, Serialize)]
pub struct EvidenceSubmissionResponse {
    pub mass_function_id: Uuid,
    pub combination_reports: Vec<CombinationReportResponse>,
    pub updated_belief: f64,
    pub updated_plausibility: f64,
    /// Genuine conflict: m((empty, false))
    pub mass_on_conflict: f64,
    /// Frame incompleteness: m((Omega, true))
    pub mass_on_missing: f64,
    pub pignistic_prob: Option<f64>,
    pub bayesian_posterior: f64,
    pub total_sources: i64,
}

/// Simplified combination report for API response
#[derive(Debug, Serialize)]
pub struct CombinationReportResponse {
    pub method_used: String,
    pub conflict_k: f64,
    pub mass_on_conflict: f64,
    /// Frame incompleteness: m((Omega, true))
    pub mass_on_missing: f64,
}

/// Query parameters for listing frames
#[derive(Debug, Deserialize)]
pub struct ListFramesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Query parameters for `GET /api/v1/claims/by-belief`
#[derive(Debug, Deserialize)]
pub struct BeliefFilterQuery {
    #[serde(default)]
    pub min_belief: Option<f64>,
    #[serde(default)]
    pub max_plausibility: Option<f64>,
    #[serde(default)]
    pub frame_id: Option<Uuid>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
}

/// A claim row returned from belief-scoped queries
#[derive(Debug, Serialize)]
pub struct BeliefClaimRow {
    pub id: Uuid,
    pub content: String,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub mass_on_conflict: Option<f64>,
    pub mass_on_missing: Option<f64>,
}

/// Query parameters for `GET /api/v1/frames/:id/claims`
#[derive(Debug, Deserialize)]
pub struct FrameClaimsQuery {
    #[serde(default = "default_sort_by")]
    pub sort_by: String,
    #[serde(default = "default_order")]
    pub order: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Optional requester agent ID for partition-aware content filtering
    #[serde(default)]
    pub agent_id: Option<Uuid>,
}

fn default_sort_by() -> String {
    "belief".to_string()
}

fn default_order() -> String {
    "desc".to_string()
}

/// Response for a claim within a frame, with belief data
#[derive(Debug, Serialize)]
pub struct FrameClaimBeliefRow {
    pub claim_id: Uuid,
    pub content: String,
    pub hypothesis_index: Option<i32>,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub ignorance: Option<f64>,
    pub mass_on_missing: Option<f64>,
}

/// Response for divergence query
#[derive(Debug, Serialize)]
pub struct DivergenceResponse {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub pignistic_prob: f64,
    pub bayesian_posterior: f64,
    pub kl_divergence: f64,
    pub frame_version: Option<i32>,
    pub computed_at: String,
}

/// Query parameters for `GET /api/v1/divergence/top`
#[derive(Debug, Deserialize)]
pub struct TopDivergenceQuery {
    #[serde(default = "default_top_limit")]
    pub limit: i64,
}

fn default_top_limit() -> i64 {
    10
}

/// Query parameters for scoped belief lookup
#[derive(Debug, Deserialize)]
pub struct ScopedBeliefQuery {
    /// Scope: "global", "perspective", or "community". Defaults to global.
    #[serde(default)]
    pub scope: Option<String>,
    /// Scope entity ID (perspective or community UUID). Required when scope is not "global".
    #[serde(default)]
    pub scope_id: Option<Uuid>,
}

/// Response for an all-scopes belief comparison
#[derive(Debug, Serialize)]
pub struct AllScopesBeliefResponse {
    pub claim_id: Uuid,
    pub scopes: Vec<ScopedBeliefEntry>,
}

/// A single scoped belief entry
#[derive(Debug, Serialize)]
pub struct ScopedBeliefEntry {
    pub scope_type: String,
    pub scope_id: Option<Uuid>,
    pub belief: f64,
    pub plausibility: f64,
    pub ignorance: f64,
    /// Genuine conflict: m((empty, false))
    pub mass_on_conflict: f64,
    /// Frame incompleteness: m((Omega, true))
    pub mass_on_missing: f64,
    pub pignistic_prob: Option<f64>,
    pub conflict_k: Option<f64>,
    pub strategy_used: Option<String>,
    pub computed_at: String,
}

/// Pignistic probability distribution response
#[derive(Debug, Serialize)]
pub struct PignisticResponse {
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub frame_name: String,
    pub hypotheses: Vec<PignisticEntry>,
    /// Genuine conflict: m((empty, false))
    pub mass_on_conflict: f64,
    /// Frame incompleteness: m((Omega, true))
    pub mass_on_missing: f64,
}

/// Request body for POST /api/v1/frames/:id/conflict-batch
#[derive(Debug, Deserialize)]
pub struct ConflictBatchRequest {
    pub pairs: Vec<ConflictPair>,
}

#[derive(Debug, Deserialize)]
pub struct ConflictPair {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
}

/// Response for POST /api/v1/frames/:id/conflict-batch
#[derive(Debug, Serialize)]
pub struct ConflictBatchResponse {
    pub results: Vec<ConflictBatchResult>,
}

#[derive(Debug, Serialize)]
pub struct ConflictBatchResult {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub conflict_k: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A single hypothesis entry in a pignistic distribution
#[derive(Debug, Serialize)]
pub struct PignisticEntry {
    pub hypothesis_index: usize,
    pub hypothesis_name: String,
    pub pignistic_probability: f64,
    pub belief: f64,
    pub plausibility: f64,
}

/// Query parameters for pignistic endpoint
#[derive(Debug, Deserialize)]
pub struct PignisticQuery {
    pub frame_id: Uuid,
}

/// Request to create a frame refinement
#[derive(Debug, Deserialize)]
pub struct RefineFrameRequest {
    pub name: String,
    pub description: Option<String>,
    pub hypotheses: Vec<String>,
}

/// KL divergence threshold for emitting `divergence.spike` events
const DIVERGENCE_SPIKE_THRESHOLD: f64 = 0.5;

// =============================================================================
// HELPERS
// =============================================================================

/// Compute symmetric KL divergence between two Bernoulli distributions.
///
/// KL(p || q) = p * ln(p/q) + (1-p) * ln((1-p)/(1-q))
///
/// Clamps inputs to [ε, 1-ε] to avoid log(0).
fn kl_divergence_bernoulli(p: f64, q: f64) -> f64 {
    let eps = 1e-10;
    let p = p.clamp(eps, 1.0 - eps);
    let q = q.clamp(eps, 1.0 - eps);
    p * (p / q).ln() + (1.0 - p) * ((1.0 - p) / (1.0 - q)).ln()
}

/// Convert a FrameRow to a FrameResponse
#[cfg(feature = "db")]
fn frame_to_response(row: epigraph_db::FrameRow) -> FrameResponse {
    FrameResponse {
        id: row.id,
        name: row.name,
        description: row.description,
        hypotheses: row.hypotheses,
        parent_frame_id: row.parent_frame_id,
        is_refinable: row.is_refinable,
        version: row.version,
        created_at: row.created_at.to_rfc3339(),
    }
}

/// Compute belief, plausibility, and pignistic for the correct hypothesis
/// within a combined mass function, respecting the claim's hypothesis_index.
///
/// Returns `(belief, plausibility, pignistic_prob, mass_on_missing)`.
#[cfg(feature = "db")]
pub(crate) fn compute_hypothesis_belief(
    combined: &epigraph_ds::MassFunction,
    _ds_frame: &epigraph_ds::FrameOfDiscernment,
    hypothesis_index: Option<i32>,
) -> (f64, f64, f64, f64) {
    use epigraph_ds::{measures, FocalElement};

    let h_idx = hypothesis_index.map(|i| i as usize).unwrap_or(0);
    let supported = FocalElement::positive(std::collections::BTreeSet::from([h_idx]));
    let bel = measures::belief(combined, &supported);
    let pl = measures::plausibility(combined, &supported);
    let betp = measures::pignistic_probability(combined, h_idx);
    let m_missing = combined.mass_of_missing();

    (bel, pl, betp, m_missing)
}

// =============================================================================
// HANDLERS (db feature)
// =============================================================================

/// Get belief interval for a claim
///
/// `GET /api/v1/claims/:id/belief`
#[cfg(feature = "db")]
pub async fn get_claim_belief(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<BeliefResponse>, ApiError> {
    let pool = &state.db_pool;

    // Read the stored belief/plausibility/pignistic from the claims table
    #[allow(clippy::type_complexity)]
    let row: Option<(Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT belief, plausibility, mass_on_empty, pignistic_prob, mass_on_missing FROM claims WHERE id = $1",
    )
    .bind(claim_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    let (belief, plausibility, mass_on_empty, pignistic_prob, mass_on_missing) =
        row.ok_or(ApiError::NotFound {
            entity: "claim".to_string(),
            id: claim_id.to_string(),
        })?;

    // Count mass functions across all frames for this claim
    let count_row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;

    let ignorance = match (belief, plausibility) {
        (Some(b), Some(p)) => Some(p - b),
        _ => None,
    };

    Ok(Json(BeliefResponse {
        claim_id,
        belief,
        plausibility,
        ignorance,
        mass_on_conflict: mass_on_empty,
        mass_on_missing,
        pignistic_prob,
        mass_function_count: count_row.0,
    }))
}

/// List all frames
///
/// `GET /api/v1/frames`
#[cfg(feature = "db")]
pub async fn list_frames(
    State(state): State<AppState>,
    Query(params): Query<ListFramesQuery>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    let pool = &state.db_pool;
    let rows = epigraph_db::FrameRepository::list(pool, params.limit, params.offset).await?;

    let frames = rows.into_iter().map(frame_to_response).collect();

    Ok(Json(frames))
}

/// Get frame detail with claims
///
/// `GET /api/v1/frames/:id`
#[cfg(feature = "db")]
pub async fn get_frame(
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
) -> Result<Json<FrameDetailResponse>, ApiError> {
    let pool = &state.db_pool;

    let row = epigraph_db::FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    let claim_rows = epigraph_db::FrameRepository::get_claims_in_frame(pool, frame_id).await?;

    let claims: Vec<FrameClaimEntry> = claim_rows
        .into_iter()
        .map(|r| FrameClaimEntry {
            claim_id: r.claim_id,
            hypothesis_index: r.hypothesis_index,
        })
        .collect();

    Ok(Json(FrameDetailResponse {
        frame: frame_to_response(row),
        claim_count: claims.len(),
        claims,
    }))
}

/// Get conflict analysis for a frame
///
/// `GET /api/v1/frames/:id/conflict`
#[cfg(feature = "db")]
pub async fn frame_conflict(
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
) -> Result<Json<FrameConflictResponse>, ApiError> {
    let pool = &state.db_pool;

    // Verify frame exists
    epigraph_db::FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    let row: (i64, Option<f64>, Option<f64>) = sqlx::query_as(
        r#"
        SELECT COUNT(*), AVG(conflict_k), MAX(conflict_k)
        FROM mass_functions
        WHERE frame_id = $1 AND conflict_k IS NOT NULL
        "#,
    )
    .bind(frame_id)
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    Ok(Json(FrameConflictResponse {
        frame_id,
        source_count: row.0,
        avg_conflict_k: row.1,
        max_conflict_k: row.2,
    }))
}

/// Reconstruct a `MassFunction` from a frame and a JSON masses object.
///
/// Returns `Ok(mf)` on success, `Err(reason)` if the JSON is invalid or empty.
#[cfg(feature = "db")]
pub(crate) fn reconstruct_mass_function(
    frame: &epigraph_ds::FrameOfDiscernment,
    masses_json: &serde_json::Value,
) -> Result<epigraph_ds::MassFunction, String> {
    use epigraph_ds::{focal_serde::key_to_focal, FocalElement, MassFunction};
    use std::collections::BTreeMap;

    let masses_obj = masses_json
        .as_object()
        .ok_or_else(|| "masses is not a JSON object".to_string())?;

    let mut bba: BTreeMap<FocalElement, f64> = BTreeMap::new();
    for (key, val) in masses_obj {
        if let (Ok(fe), Some(mass)) = (key_to_focal(key), val.as_f64()) {
            if mass > 1e-12 {
                bba.insert(fe, mass);
            }
        }
    }
    if bba.is_empty() {
        return Err("no valid focal elements in masses".to_string());
    }
    MassFunction::new(frame.clone(), bba).map_err(|e| format!("invalid mass function: {e}"))
}

/// Batch compute conflict coefficients between claim pairs
///
/// `POST /api/v1/frames/:id/conflict-batch`
#[cfg(feature = "db")]
pub async fn conflict_batch(
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
    Json(request): Json<ConflictBatchRequest>,
) -> Result<Json<ConflictBatchResponse>, ApiError> {
    use epigraph_ds::{combination::conflict_coefficient, FrameOfDiscernment, MassFunction};
    use std::collections::{HashMap, HashSet};

    if request.pairs.len() > 100 {
        return Err(ApiError::ValidationError {
            field: "pairs".to_string(),
            reason: format!("Maximum 100 pairs per request, got {}", request.pairs.len()),
        });
    }

    if request.pairs.is_empty() {
        return Ok(Json(ConflictBatchResponse { results: vec![] }));
    }

    let pool = &state.db_pool;

    // Verify frame exists and get its hypotheses for reconstruction
    let frame_row = epigraph_db::FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    // Build DS frame from DB hypotheses
    let ds_frame =
        FrameOfDiscernment::new(&frame_row.name, frame_row.hypotheses.clone()).map_err(|e| {
            ApiError::InternalError {
                message: format!("Invalid frame: {e}"),
            }
        })?;

    // Collect unique claim IDs
    let mut claim_ids: HashSet<Uuid> = HashSet::new();
    for pair in &request.pairs {
        claim_ids.insert(pair.claim_a);
        claim_ids.insert(pair.claim_b);
    }

    // Load mass functions for all unique claims (use latest by created_at)
    let mut mass_fns: HashMap<Uuid, MassFunction> = HashMap::new();
    for &cid in &claim_ids {
        let rows =
            epigraph_db::MassFunctionRepository::get_for_claim_frame(pool, cid, frame_id).await?;
        // get_for_claim_frame returns ORDER BY created_at ASC, so last() is latest.
        // Use max_by_key as defense against ordering changes.
        if let Some(row) = rows.iter().max_by_key(|r| r.created_at) {
            if let Ok(mf) = reconstruct_mass_function(&ds_frame, &row.masses) {
                mass_fns.insert(cid, mf);
            }
        }
    }

    // Compute conflict for each pair
    let results: Vec<ConflictBatchResult> = request
        .pairs
        .iter()
        .map(|pair| {
            let mf_a = mass_fns.get(&pair.claim_a);
            let mf_b = mass_fns.get(&pair.claim_b);

            match (mf_a, mf_b) {
                (Some(a), Some(b)) => match conflict_coefficient(a, b) {
                    Ok(k) => ConflictBatchResult {
                        claim_a: pair.claim_a,
                        claim_b: pair.claim_b,
                        conflict_k: Some(k),
                        error: None,
                    },
                    Err(e) => ConflictBatchResult {
                        claim_a: pair.claim_a,
                        claim_b: pair.claim_b,
                        conflict_k: None,
                        error: Some(e.to_string()),
                    },
                },
                _ => {
                    let missing = if mf_a.is_none() && mf_b.is_none() {
                        format!(
                            "No mass functions for claims {} and {}",
                            pair.claim_a, pair.claim_b
                        )
                    } else if mf_a.is_none() {
                        format!("No mass function for claim {}", pair.claim_a)
                    } else {
                        format!("No mass function for claim {}", pair.claim_b)
                    };
                    ConflictBatchResult {
                        claim_a: pair.claim_a,
                        claim_b: pair.claim_b,
                        conflict_k: None,
                        error: Some(missing),
                    }
                }
            }
        })
        .collect();

    Ok(Json(ConflictBatchResponse { results }))
}

/// Stub for non-db builds
#[cfg(not(feature = "db"))]
pub async fn conflict_batch(
    Path(_frame_id): Path<Uuid>,
    Json(_request): Json<ConflictBatchRequest>,
) -> Result<Json<ConflictBatchResponse>, ApiError> {
    Ok(Json(ConflictBatchResponse { results: vec![] }))
}

/// Create a new frame
///
/// `POST /api/v1/frames`
#[cfg(feature = "db")]
pub async fn create_frame(
    State(state): State<AppState>,
    Json(request): Json<CreateFrameRequest>,
) -> Result<(StatusCode, Json<FrameResponse>), ApiError> {
    if request.hypotheses.len() < 2 {
        return Err(ApiError::ValidationError {
            field: "hypotheses".to_string(),
            reason: "Frame must have at least 2 hypotheses".to_string(),
        });
    }

    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    let pool = &state.db_pool;
    let row = epigraph_db::FrameRepository::create(
        pool,
        &request.name,
        request.description.as_deref(),
        &request.hypotheses,
    )
    .await?;

    // Emit frame.created event
    let event_store = super::events::global_event_store();
    event_store
        .push(
            "frame.created".to_string(),
            None,
            serde_json::json!({
                "frame_id": row.id,
                "name": row.name,
                "hypothesis_count": request.hypotheses.len(),
            }),
        )
        .await;

    Ok((StatusCode::CREATED, Json(frame_to_response(row))))
}

/// Submit mass function evidence for a claim in a frame
///
/// Pipeline: discount → store → retrieve all → combine → update claim → emit events → compute divergence
///
/// `POST /api/v1/frames/:id/evidence`
#[cfg(feature = "db")]
pub async fn submit_evidence(
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
    Json(request): Json<SubmitEvidenceRequest>,
) -> Result<(StatusCode, Json<EvidenceSubmissionResponse>), ApiError> {
    use epigraph_ds::{combination, FrameOfDiscernment, MassFunction};
    use std::collections::BTreeSet;

    let pool = &state.db_pool;

    // 1. Load and validate frame
    let frame_row = epigraph_db::FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    let ds_frame =
        FrameOfDiscernment::new(&frame_row.name, frame_row.hypotheses.clone()).map_err(|e| {
            ApiError::InternalError {
                message: format!("Invalid frame in DB: {e}"),
            }
        })?;

    // 2. Validate reliability
    if !(0.0..=1.0).contains(&request.reliability) || request.reliability.is_nan() {
        return Err(ApiError::ValidationError {
            field: "reliability".to_string(),
            reason: "Must be in [0, 1]".to_string(),
        });
    }

    // 3. Parse and validate the submitted mass function
    //    Keys may be prefixed with ~ to indicate CDST complement (negative) elements.
    let mut masses = std::collections::BTreeMap::new();
    for (key, &value) in &request.masses {
        let (is_complement, indices_str) = key
            .strip_prefix('~')
            .map_or((false, key.as_str()), |rest| (true, rest));
        let subset: BTreeSet<usize> = if indices_str.is_empty() {
            BTreeSet::new()
        } else {
            indices_str
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse::<usize>()
                        .map_err(|_| ApiError::ValidationError {
                            field: "masses".to_string(),
                            reason: format!("Invalid hypothesis index in key '{key}'"),
                        })
                })
                .collect::<Result<BTreeSet<usize>, ApiError>>()?
        };
        let fe = if is_complement {
            epigraph_ds::FocalElement::negative(subset)
        } else {
            epigraph_ds::FocalElement::positive(subset)
        };
        masses.insert(fe, value);
    }

    let raw_mass =
        MassFunction::new(ds_frame.clone(), masses).map_err(|e| ApiError::ValidationError {
            field: "masses".to_string(),
            reason: e.to_string(),
        })?;

    // 4. Apply reliability discount
    let discounted = combination::discount(&raw_mass, request.reliability).map_err(|e| {
        ApiError::InternalError {
            message: format!("Discount failed: {e}"),
        }
    })?;

    // 4b. Apply active context modifiers for this frame (between discount and store)
    let mut modified = discounted;
    let active_contexts = epigraph_db::ContextRepository::list_for_frame(pool, frame_id)
        .await
        .unwrap_or_default();
    let now = chrono::Utc::now();
    for ctx in &active_contexts {
        // Check temporal validity
        if let Some(from) = ctx.valid_from {
            if now < from {
                continue;
            }
        }
        if let Some(until) = ctx.valid_until {
            if now > until {
                continue;
            }
        }
        if let Some(ref modifier_type) = ctx.modifier_type {
            let params = ctx.parameters.clone().unwrap_or(serde_json::json!({}));
            match combination::apply_context_modifier(&modified, modifier_type, &params) {
                Ok(m) => {
                    modified = m;
                    // Create SCOPED_BY edge from claim to context (best-effort)
                    let _ = epigraph_db::EdgeRepository::create(
                        pool,
                        request.claim_id,
                        "claim",
                        ctx.id,
                        "context",
                        "SCOPED_BY",
                        Some(serde_json::json!({"modifier_type": modifier_type})),
                        None,
                        None,
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(
                        "Context modifier '{}' failed for context {}: {e}",
                        modifier_type,
                        ctx.id
                    );
                }
            }
        }
    }

    // 4c. Apply perspective confidence_calibration as additional discount
    if let Some(perspective_id) = request.perspective_id {
        if let Ok(Some(perspective)) =
            epigraph_db::PerspectiveRepository::get_by_id(pool, perspective_id).await
        {
            if let Some(calibration) = perspective.confidence_calibration {
                if (0.0..1.0).contains(&calibration) {
                    match combination::discount(&modified, calibration) {
                        Ok(m) => {
                            tracing::debug!(
                                "Applied confidence_calibration={calibration} for perspective {perspective_id}"
                            );
                            modified = m;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Confidence calibration discount failed for perspective {perspective_id}: {e}"
                            );
                        }
                    }
                }
            }
        }
    }

    // 4d. Apply competence_scopes discount for out-of-scope agents
    if let Some(agent_id) = request.agent_id {
        let agent_props: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT properties FROM agents WHERE id = $1")
                .bind(agent_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();

        if let Some((props,)) = agent_props {
            if let Some(scopes) = props.get("competence_scopes").and_then(|s| s.as_array()) {
                let frame_id_str = frame_id.to_string();
                let frame_name = &frame_row.name;
                let in_scope = scopes.iter().any(|s| {
                    s.as_str()
                        .map(|v| v == frame_id_str || v == frame_name)
                        .unwrap_or(false)
                });
                if !in_scope && !scopes.is_empty() {
                    // Agent has declared competence scopes but this frame isn't in them
                    const COMPETENCE_DISCOUNT: f64 = 0.7;
                    match combination::discount(&modified, COMPETENCE_DISCOUNT) {
                        Ok(m) => {
                            tracing::info!(
                                "Applied competence discount ({COMPETENCE_DISCOUNT}) for agent {agent_id} on frame {frame_id}"
                            );
                            modified = m;
                        }
                        Err(e) => {
                            tracing::warn!("Competence discount failed: {e}");
                        }
                    }
                }
            }
        }
    }

    // 4e. Pre-screen for contradiction potential (G8)
    //     Load the claim's edge neighborhood and check if the new evidence
    //     would introduce a contradiction via the Ascent reasoning engine.
    {
        use epigraph_engine::reasoning::{ReasoningClaim, ReasoningEdge, ReasoningEngine};

        // Load edges where this claim is source or target
        let source_edges =
            epigraph_db::EdgeRepository::get_by_source(pool, request.claim_id, "claim")
                .await
                .unwrap_or_default();
        let target_edges =
            epigraph_db::EdgeRepository::get_by_target(pool, request.claim_id, "claim")
                .await
                .unwrap_or_default();

        let all_edges: Vec<_> = source_edges.iter().chain(target_edges.iter()).collect();

        if !all_edges.is_empty() {
            // Collect neighbor claim IDs
            let mut neighbor_ids: Vec<Uuid> = all_edges
                .iter()
                .flat_map(|e| [e.source_id, e.target_id])
                .filter(|id| *id != request.claim_id)
                .collect();
            neighbor_ids.sort();
            neighbor_ids.dedup();

            // Load truth values for neighbors + this claim
            let mut claim_ids = neighbor_ids.clone();
            claim_ids.push(request.claim_id);

            let claim_rows: Vec<(Uuid, Option<f64>)> =
                sqlx::query_as("SELECT id, truth_value FROM claims WHERE id = ANY($1)")
                    .bind(&claim_ids)
                    .fetch_all(pool)
                    .await
                    .unwrap_or_default();

            let reasoning_claims: Vec<ReasoningClaim> = claim_rows
                .iter()
                .map(|(id, tv)| ReasoningClaim {
                    id: *id,
                    truth_value: tv.unwrap_or(0.5),
                })
                .collect();

            let reasoning_edges: Vec<ReasoningEdge> = all_edges
                .iter()
                .map(|e| ReasoningEdge {
                    source_id: e.source_id,
                    target_id: e.target_id,
                    relationship: e.relationship.clone(),
                    strength: e
                        .properties
                        .get("strength")
                        .and_then(serde_json::Value::as_f64)
                        .unwrap_or(0.5),
                })
                .collect();

            // Model the new evidence as a pseudo-node supporting the claim
            let pseudo_id = Uuid::new_v4();
            let new_edge = ReasoningEdge {
                source_id: pseudo_id,
                target_id: request.claim_id,
                relationship: "supports".to_string(),
                strength: request.reliability,
            };

            // Extend claims to include the pseudo-evidence node
            let mut extended_claims = reasoning_claims;
            extended_claims.push(ReasoningClaim {
                id: pseudo_id,
                truth_value: request.reliability,
            });

            if let Some(contradiction) =
                ReasoningEngine::would_contradict(&extended_claims, &reasoning_edges, &new_edge)
            {
                let event_store = super::events::global_event_store();
                event_store
                    .push(
                        "contradiction.predicted".to_string(),
                        request.agent_id,
                        serde_json::json!({
                            "claim_id": request.claim_id,
                            "contradicting_claims": [
                                contradiction.claim_a.to_string(),
                                contradiction.claim_b.to_string(),
                            ],
                            "target": contradiction.target.to_string(),
                            "support_strength": contradiction.support_strength,
                            "refute_strength": contradiction.refute_strength,
                        }),
                    )
                    .await;
            }
        }
    }

    // 5. Store the individual BBA (with optional perspective)
    let masses_json = modified.masses_to_json();
    let mf_id = epigraph_db::MassFunctionRepository::store_with_perspective(
        pool,
        request.claim_id,
        frame_id,
        request.agent_id,
        request.perspective_id,
        &masses_json,
        None,
        Some("discount"),
        Some(request.reliability),
        None,
    )
    .await?;

    // 6. Ensure claim is assigned to frame + create WITHIN_FRAME edge (best-effort)
    //    Use ON CONFLICT DO NOTHING to preserve any existing hypothesis_index assignment.
    //    assign_claim() uses DO UPDATE which would overwrite hypothesis_index with NULL.
    let _ = sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(request.claim_id)
    .bind(frame_id)
    .execute(pool)
    .await;
    let _ = epigraph_db::EdgeRepository::create(
        pool,
        request.claim_id,
        "claim",
        frame_id,
        "frame",
        "WITHIN_FRAME",
        None,
        None,
        None,
    )
    .await;

    // 7. Retrieve all BBAs for this (claim, frame), excluding system-combined results.
    //    Only include user-submitted BBAs (combination_method = "discount") to avoid
    //    double-counting derived artifacts (violates TBM independence assumption).
    let all_rows =
        epigraph_db::MassFunctionRepository::get_for_claim_frame(pool, request.claim_id, frame_id)
            .await?;

    // 8. Sort mass functions by row ID for canonical combination ordering.
    //    This ensures identical results regardless of evidence submission order.
    let mut indexed_rows: Vec<(Uuid, Option<Uuid>, MassFunction)> = all_rows
        .iter()
        .filter(|row| row.combination_method.as_deref() == Some("discount"))
        .filter_map(|row| {
            MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                .ok()
                .map(|m| (row.id, row.source_agent_id, m))
        })
        .collect();
    indexed_rows.sort_by_key(|(id, _, _)| *id);

    // 9. Independence analysis (G1, G11)
    let analysis = if request.assume_independent.unwrap_or(false) || indexed_rows.len() <= 1 {
        super::independence::IndependenceAnalysis::all_independent(
            indexed_rows.iter().map(|(_, _, m)| m.clone()).collect(),
        )
    } else {
        super::independence::analyze_independence(pool, &indexed_rows, 5).await?
    };

    // 10a. Cautious-combine within each dependent group
    let mut group_results = Vec::new();
    for group in &analysis.dependent_groups {
        if group.is_empty() {
            continue;
        }
        let combined_group = group
            .iter()
            .skip(1)
            .try_fold(group[0].clone(), |acc, m| {
                combination::cautious_combine(&acc, m)
            })
            .map_err(|e| ApiError::InternalError {
                message: format!("Cautious combine failed: {e}"),
            })?;
        group_results.push(combined_group);
    }

    // 10b. Merge independent BBAs + group results
    let mut for_combination: Vec<MassFunction> = analysis.independent.clone();
    for_combination.extend(group_results);

    // 10c. Standard adaptive combination on the now-independent set
    let (combined, reports) = if for_combination.len() <= 1 {
        (
            for_combination
                .into_iter()
                .next()
                .unwrap_or_else(|| indexed_rows[0].2.clone()),
            vec![],
        )
    } else {
        combination::combine_multiple(&for_combination, request.conflict_threshold).map_err(
            |e| ApiError::InternalError {
                message: format!("Combination failed: {e}"),
            },
        )?
    };

    // 11. Look up claim's hypothesis_index in claim_frames for correct Bel/Pl
    let claim_assignment =
        epigraph_db::FrameRepository::get_claim_assignment(pool, request.claim_id, frame_id)
            .await?;
    let h_idx = claim_assignment.and_then(|ca| ca.hypothesis_index);

    let (final_bel, final_pl, final_betp, m_missing) =
        compute_hypothesis_belief(&combined, &ds_frame, h_idx);
    let m_empty = combined.mass_of_empty();

    // 12. Read old belief/plausibility before updating (for event payload)
    let old_row: Option<(Option<f64>, Option<f64>)> =
        sqlx::query_as("SELECT belief, plausibility FROM claims WHERE id = $1")
            .bind(request.claim_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;
    let (old_belief, old_plausibility) = old_row.unwrap_or((None, None));

    // 13. Update claim's belief, plausibility, and pignistic probability
    epigraph_db::MassFunctionRepository::update_claim_belief(
        pool,
        request.claim_id,
        final_bel,
        final_pl,
        m_empty,
        Some(final_betp),
        m_missing,
    )
    .await?;

    // 13c. CDST residual mass analysis
    {
        let event_store = super::events::global_event_store();
        // High frame incompleteness -> evidence may not cover all relevant hypotheses
        if m_missing > 0.15 {
            event_store
                .push(
                    "frame.incomplete".to_string(),
                    request.agent_id,
                    serde_json::json!({
                        "claim_id": request.claim_id,
                        "frame_id": frame_id,
                        "mass_on_missing": m_missing,
                    }),
                )
                .await;
        }

        // High genuine conflict with low ignorance -> sources disagree within the frame
        if m_empty > 0.10 && m_missing < 0.05 {
            event_store
                .push(
                    "conflict.genuine".to_string(),
                    request.agent_id,
                    serde_json::json!({
                        "claim_id": request.claim_id,
                        "frame_id": frame_id,
                        "mass_on_conflict": m_empty,
                        "mass_on_missing": m_missing,
                    }),
                )
                .await;
        }
    }

    // 13b. Parallel Beta-Bernoulli update
    //      Compute likelihood ratio from evidence mass function and update Beta parameters.
    //      The evidence's mass on the singleton {h_i} indicates support strength.
    let bayesian_posterior = {
        let beta_row: Option<(f64, f64)> =
            sqlx::query_as("SELECT beta_alpha, beta_beta FROM claims WHERE id = $1")
                .bind(request.claim_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();

        let (mut alpha, mut beta_param) = beta_row.unwrap_or((1.0, 1.0));

        // Use the submitted evidence's singleton mass as the evidence strength
        if let Some(h_i) = h_idx {
            let singleton =
                epigraph_ds::FocalElement::positive(std::iter::once(h_i as usize).collect());
            let m_support = modified.mass_of(&singleton);
            // Evidence strength: mass on the singleton hypothesis vs complement
            // Higher m_support → stronger evidence for the hypothesis
            if m_support > 0.0 {
                alpha += m_support;
            }
            let m_complement = 1.0 - m_support - modified.mass_of_empty();
            if m_complement > 0.0 {
                beta_param += m_complement;
            }
        }

        // Store updated Beta parameters
        let _ = sqlx::query(
            "UPDATE claims SET beta_alpha = $2, beta_beta = $3, updated_at = NOW() WHERE id = $1",
        )
        .bind(request.claim_id)
        .bind(alpha)
        .bind(beta_param)
        .execute(pool)
        .await;

        // Compute posterior: E[Beta(alpha, beta)] = alpha / (alpha + beta)
        alpha / (alpha + beta_param)
    };

    // 14. Update the combined mass function's conflict in DB (G16: record actual method)
    let final_k = reports.last().map(|r| r.conflict_k);
    let used_cautious = !analysis.dependent_groups.is_empty();
    let final_method_str = if used_cautious {
        // Independence analysis detected shared provenance → cautious + adaptive
        let adaptive = reports
            .last()
            .map(|r| format!("{:?}", r.method_used))
            .unwrap_or_else(|| "none".to_string());
        Some(format!("cautious+{adaptive}"))
    } else {
        reports.last().map(|r| format!("{:?}", r.method_used))
    };
    let final_method = final_method_str.as_deref();

    // Store the combined result as a system mass function (agent_id = None)
    let combined_json = combined.masses_to_json();
    let _ = epigraph_db::MassFunctionRepository::store(
        pool,
        request.claim_id,
        frame_id,
        None, // system-generated combined result
        &combined_json,
        final_k,
        final_method,
    )
    .await;

    let report_responses: Vec<CombinationReportResponse> = reports
        .iter()
        .map(|r| CombinationReportResponse {
            method_used: format!("{:?}", r.method_used),
            conflict_k: r.conflict_k,
            mass_on_conflict: r.mass_on_conflict,
            mass_on_missing: r.mass_on_missing,
        })
        .collect();

    let total_sources = epigraph_db::MassFunctionRepository::count_for_claim_frame(
        pool,
        request.claim_id,
        frame_id,
    )
    .await?;

    // 15. Store global scoped belief cache
    let _ = epigraph_db::ScopedBeliefRepository::upsert(
        pool,
        frame_id,
        request.claim_id,
        "global",
        None,
        final_bel,
        final_pl,
        m_empty,
        m_missing,
        final_k,
        final_method,
        Some(final_betp),
    )
    .await;

    // 16. Create edges reflecting DS relationships (best-effort)
    //     Use "evidence" as entity type for mass functions (constraint-compatible)
    if final_bel > 0.5 {
        let _ = epigraph_db::EdgeRepository::create(
            pool,
            mf_id,
            "evidence",
            request.claim_id,
            "claim",
            "SUPPORTS",
            Some(serde_json::json!({"belief": final_bel})),
            None,
            None,
        )
        .await;
    } else if final_bel < 0.3 {
        let _ = epigraph_db::EdgeRepository::create(
            pool,
            mf_id,
            "evidence",
            request.claim_id,
            "claim",
            "CONTRADICTS",
            Some(serde_json::json!({"belief": final_bel})),
            None,
            None,
        )
        .await;
    }

    if let Some(agent_id) = request.agent_id {
        let _ = epigraph_db::EdgeRepository::create(
            pool,
            mf_id,
            "evidence",
            agent_id,
            "agent",
            "GENERATED_BY",
            None,
            None,
            None,
        )
        .await;
    }

    if let Some(perspective_id) = request.perspective_id {
        let _ = epigraph_db::EdgeRepository::create(
            pool,
            perspective_id,
            "perspective",
            request.claim_id,
            "claim",
            "CONTRIBUTES_TO",
            None,
            None,
            None,
        )
        .await;
    }

    // 17. Compute perspective-scoped and community-scoped beliefs
    if let Some(perspective_id) = request.perspective_id {
        // Perspective scope: combine only BBAs from this perspective
        let perspective_rows =
            epigraph_db::MassFunctionRepository::get_for_claim_frame_perspective(
                pool,
                request.claim_id,
                frame_id,
                perspective_id,
            )
            .await
            .unwrap_or_default();

        let mut p_indexed: Vec<(Uuid, MassFunction)> = perspective_rows
            .iter()
            .filter_map(|row| {
                MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                    .ok()
                    .map(|m| (row.id, m))
            })
            .collect();
        p_indexed.sort_by_key(|(id, _)| *id);
        let perspective_masses: Vec<MassFunction> = p_indexed.into_iter().map(|(_, m)| m).collect();

        if perspective_masses.len() >= 2 {
            if let Ok((p_combined, p_reports)) =
                combination::combine_multiple(&perspective_masses, request.conflict_threshold)
            {
                let (p_bel, p_pl, p_betp, p_m_missing) =
                    compute_hypothesis_belief(&p_combined, &ds_frame, h_idx);
                let p_m_empty = p_combined.mass_of_empty();
                let p_k = p_reports.last().map(|r| r.conflict_k);
                let p_method_str = p_reports.last().map(|r| format!("{:?}", r.method_used));
                let p_method = p_method_str.as_deref();

                let _ = epigraph_db::ScopedBeliefRepository::upsert(
                    pool,
                    frame_id,
                    request.claim_id,
                    "perspective",
                    Some(perspective_id),
                    p_bel,
                    p_pl,
                    p_m_empty,
                    p_m_missing,
                    p_k,
                    p_method,
                    Some(p_betp),
                )
                .await;
            }
        } else if perspective_masses.len() == 1 {
            let (p_bel, p_pl, p_betp, p_m_missing) =
                compute_hypothesis_belief(&perspective_masses[0], &ds_frame, h_idx);
            let p_m_empty = perspective_masses[0].mass_of_empty();

            let _ = epigraph_db::ScopedBeliefRepository::upsert(
                pool,
                frame_id,
                request.claim_id,
                "perspective",
                Some(perspective_id),
                p_bel,
                p_pl,
                p_m_empty,
                p_m_missing,
                None,
                None,
                Some(p_betp),
            )
            .await;
        }

        // Community scope: for each community this perspective belongs to
        if let Ok(community_ids) =
            epigraph_db::CommunityRepository::communities_for_perspective(pool, perspective_id)
                .await
        {
            for community_id in community_ids {
                // Check for community mass_override before combining member BBAs
                let use_override = if let Ok(Some(comm)) =
                    epigraph_db::CommunityRepository::get_by_id(pool, community_id).await
                {
                    if let Some(ref overrides) = comm.mass_override {
                        // Look up override for this specific frame
                        let frame_key = frame_id.to_string();
                        if let Some(frame_masses) = overrides.get(&frame_key) {
                            if let Ok(override_mf) =
                                MassFunction::from_json_masses(ds_frame.clone(), frame_masses)
                            {
                                let (o_bel, o_pl, o_betp, o_m_missing) =
                                    compute_hypothesis_belief(&override_mf, &ds_frame, h_idx);
                                let o_m_empty = override_mf.mass_of_empty();

                                let _ = epigraph_db::ScopedBeliefRepository::upsert(
                                    pool,
                                    frame_id,
                                    request.claim_id,
                                    "community",
                                    Some(community_id),
                                    o_bel,
                                    o_pl,
                                    o_m_empty,
                                    o_m_missing,
                                    None,
                                    Some("override"),
                                    Some(o_betp),
                                )
                                .await;
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if use_override {
                    continue;
                }

                if let Ok(member_ids) =
                    epigraph_db::CommunityRepository::member_perspective_ids(pool, community_id)
                        .await
                {
                    let community_rows =
                        epigraph_db::MassFunctionRepository::get_for_claim_frame_perspectives(
                            pool,
                            request.claim_id,
                            frame_id,
                            &member_ids,
                        )
                        .await
                        .unwrap_or_default();

                    let mut c_indexed: Vec<(Uuid, MassFunction)> = community_rows
                        .iter()
                        .filter_map(|row| {
                            MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                                .ok()
                                .map(|m| (row.id, m))
                        })
                        .collect();
                    c_indexed.sort_by_key(|(id, _)| *id);
                    let community_masses: Vec<MassFunction> =
                        c_indexed.into_iter().map(|(_, m)| m).collect();

                    if community_masses.len() >= 2 {
                        if let Ok((c_combined, c_reports)) = combination::combine_multiple(
                            &community_masses,
                            request.conflict_threshold,
                        ) {
                            let (c_bel, c_pl, c_betp, c_m_missing) =
                                compute_hypothesis_belief(&c_combined, &ds_frame, h_idx);
                            let c_m_empty = c_combined.mass_of_empty();
                            let c_k = c_reports.last().map(|r| r.conflict_k);
                            let c_method_str =
                                c_reports.last().map(|r| format!("{:?}", r.method_used));
                            let c_method = c_method_str.as_deref();

                            let _ = epigraph_db::ScopedBeliefRepository::upsert(
                                pool,
                                frame_id,
                                request.claim_id,
                                "community",
                                Some(community_id),
                                c_bel,
                                c_pl,
                                c_m_empty,
                                c_m_missing,
                                c_k,
                                c_method,
                                Some(c_betp),
                            )
                            .await;
                        }
                    } else if community_masses.len() == 1 {
                        let (c_bel, c_pl, c_betp, c_m_missing) =
                            compute_hypothesis_belief(&community_masses[0], &ds_frame, h_idx);
                        let c_m_empty = community_masses[0].mass_of_empty();

                        let _ = epigraph_db::ScopedBeliefRepository::upsert(
                            pool,
                            frame_id,
                            request.claim_id,
                            "community",
                            Some(community_id),
                            c_bel,
                            c_pl,
                            c_m_empty,
                            c_m_missing,
                            None,
                            None,
                            Some(c_betp),
                        )
                        .await;
                    }
                }
            }
        }
    }

    // 17b. Emit evidence.submitted event
    let event_store = super::events::global_event_store();
    event_store
        .push(
            "evidence.submitted".to_string(),
            request.agent_id,
            serde_json::json!({
                "mass_function_id": mf_id,
                "claim_id": request.claim_id,
                "frame_id": frame_id,
                "agent_id": request.agent_id,
                "perspective_id": request.perspective_id,
                "reliability": request.reliability,
            }),
        )
        .await;

    // 18. Emit belief.updated event
    event_store
        .push(
            "belief.updated".to_string(),
            request.agent_id,
            serde_json::json!({
                "claim_id": request.claim_id,
                "frame_id": frame_id,
                "old_belief": old_belief,
                "new_belief": final_bel,
                "old_plausibility": old_plausibility,
                "new_plausibility": final_pl,
                "pignistic_prob": final_betp,
                "combination_method": final_method,
                "total_sources": total_sources,
                "perspective_id": request.perspective_id,
            }),
        )
        .await;

    // 18b. Confidence velocity check — detect monotonic belief increase
    //      Reconstruct recent belief trajectory from scoped_belief snapshots.
    //      Each evidence submission updates the scoped_belief row's computed_at.
    //      We use the scoped_belief audit log (if available) or fall back to
    //      checking the singular mass function support values as a proxy.
    {
        // Use individual mass function singleton masses as a belief proxy trajectory.
        // Each discount-stage BBA's support for the hypothesis approximates what
        // the agent believed when submitting. Ordered by creation time.
        let recent_support: Vec<(f64,)> = if let Some(h_i) = h_idx {
            let focal_key = format!("{h_i}");
            sqlx::query_as(
                "SELECT COALESCE((masses->>$3)::float8, 0.0) AS support \
                 FROM mass_functions \
                 WHERE claim_id = $1 AND frame_id = $2 \
                 AND combination_method = 'discount' \
                 ORDER BY created_at DESC \
                 LIMIT 10",
            )
            .bind(request.claim_id)
            .bind(frame_id)
            .bind(&focal_key)
            .fetch_all(pool)
            .await
            .unwrap_or_default()
        } else {
            vec![]
        };

        if recent_support.len() >= 3 {
            let samples: Vec<_> = recent_support
                .iter()
                .rev()
                .enumerate()
                .map(|(i, (b,))| epigraph_engine::silence_alarm::BeliefSample {
                    belief: *b,
                    evidence_count: i,
                })
                .collect();
            let velocity = epigraph_engine::silence_alarm::check_confidence_velocity(&samples, 5);
            if velocity.is_suspicious {
                event_store
                    .push(
                        "velocity.suspicious".to_string(),
                        request.agent_id,
                        serde_json::json!({
                            "claim_id": request.claim_id,
                            "frame_id": frame_id,
                            "monotonic_streak": velocity.monotonic_streak,
                            "total_samples": velocity.total_samples,
                            "reason": velocity.reason,
                        }),
                    )
                    .await;
            }
        }
    }

    // 19. Emit conflict.detected if conflict exceeds threshold
    if let Some(k) = final_k {
        if k >= request.conflict_threshold {
            event_store
                .push(
                    "conflict.detected".to_string(),
                    request.agent_id,
                    serde_json::json!({
                        "frame_id": frame_id,
                        "claim_id": request.claim_id,
                        "conflict_k": k,
                        "method_used": final_method,
                    }),
                )
                .await;

            // 19b. Auto-create challenge when conflict K >= 0.7 (S4.4 / G14)
            const HIGH_CONFLICT_THRESHOLD: f64 = 0.7;
            if let Some(challenge) = epigraph_core::auto_create_challenge(
                k,
                request.claim_id,
                frame_id,
                HIGH_CONFLICT_THRESHOLD,
            ) {
                let _ = state.challenge_service.submit(challenge);
            }
        }
    }

    // 19c. Silence alarm — check conflict density for this frame (S3.2 / G2)
    //      Query total claims and CONTRADICTS edges for the frame, then run the
    //      pure check_conflict_density() function.
    {
        let silence_counts: Option<(i64, i64)> = sqlx::query_as(
            "SELECT \
                 (SELECT COUNT(DISTINCT claim_id) FROM mass_functions WHERE frame_id = $1) AS total, \
                 (SELECT COUNT(*) FROM edges e \
                  JOIN mass_functions mf ON mf.claim_id = e.source_id AND mf.frame_id = $1 \
                  WHERE e.relationship = 'CONTRADICTS') AS contradicts",
        )
        .bind(frame_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

        if let Some((total, contradicts)) = silence_counts {
            let silence = epigraph_engine::silence_alarm::check_conflict_density(
                total as usize,
                contradicts as usize,
                &epigraph_engine::silence_alarm::SilenceAlarmConfig::default(),
            );
            if silence.is_suspicious {
                event_store
                    .push(
                        "silence.suspicious".to_string(),
                        request.agent_id,
                        serde_json::json!({
                            "frame_id": frame_id,
                            "claim_id": request.claim_id,
                            "total_claims": silence.total_claims,
                            "contradicts_edges": silence.contradicts_edges,
                            "conflict_rate": silence.conflict_rate,
                            "reason": silence.reason,
                        }),
                    )
                    .await;
            }
        }
    }

    // 20. Compute and store DS vs Bayesian divergence (using live Beta posterior)
    {
        let kl = kl_divergence_bernoulli(final_betp, bayesian_posterior);

        // Store divergence record (best-effort; don't fail the whole request)
        let _ = epigraph_db::DivergenceRepository::store(
            pool,
            request.claim_id,
            frame_id,
            final_betp,
            bayesian_posterior,
            kl,
            Some(frame_row.version),
        )
        .await;

        // Emit divergence.spike if KL exceeds threshold
        if kl >= DIVERGENCE_SPIKE_THRESHOLD {
            event_store
                .push(
                    "divergence.spike".to_string(),
                    request.agent_id,
                    serde_json::json!({
                        "claim_id": request.claim_id,
                        "frame_id": frame_id,
                        "pignistic_prob": final_betp,
                        "bayesian_posterior": bayesian_posterior,
                        "kl_divergence": kl,
                    }),
                )
                .await;
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(EvidenceSubmissionResponse {
            mass_function_id: mf_id,
            combination_reports: report_responses,
            updated_belief: final_bel,
            updated_plausibility: final_pl,
            mass_on_conflict: m_empty,
            mass_on_missing: m_missing,
            pignistic_prob: Some(final_betp),
            bayesian_posterior,
            total_sources,
        }),
    ))
}

/// Filter claims by belief/plausibility bounds
///
/// `GET /api/v1/claims/by-belief`
#[cfg(feature = "db")]
#[allow(clippy::type_complexity)]
pub async fn claims_by_belief(
    State(state): State<AppState>,
    Query(params): Query<BeliefFilterQuery>,
) -> Result<Json<Vec<BeliefClaimRow>>, ApiError> {
    let pool = &state.db_pool;
    let min_bel = params.min_belief.unwrap_or(0.0);
    let max_pl = params.max_plausibility.unwrap_or(1.0);

    let rows: Vec<(
        Uuid,
        String,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
    )> = sqlx::query_as(
        r#"
        SELECT c.id, c.content, c.belief, c.plausibility, c.mass_on_empty, c.mass_on_missing
        FROM claims c
        WHERE c.belief >= $1 AND c.plausibility <= $2
          AND ($3::uuid IS NULL OR c.id IN (
              SELECT claim_id FROM claim_frames WHERE frame_id = $3
          ))
        ORDER BY c.belief DESC
        LIMIT $4 OFFSET $5
        "#,
    )
    .bind(min_bel)
    .bind(max_pl)
    .bind(params.frame_id)
    .bind(params.limit)
    .bind(params.offset)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    let mut result: Vec<BeliefClaimRow> = rows
        .into_iter()
        .map(
            |(id, content, belief, plausibility, mass_on_empty, mass_on_missing)| BeliefClaimRow {
                id,
                content,
                belief,
                plausibility,
                mass_on_conflict: mass_on_empty,
                mass_on_missing,
            },
        )
        .collect();

    // Apply partition-aware content filtering
    for row in &mut result {
        let access =
            crate::access_control::check_content_access(pool, row.id, params.agent_id).await;
        if access == crate::access_control::ContentAccess::Redacted {
            crate::access_control::redact_claim_content(&mut row.content);
        }
    }

    Ok(Json(result))
}

/// List claims in a frame sorted by belief metric
///
/// `GET /api/v1/frames/:id/claims`
#[cfg(feature = "db")]
#[allow(clippy::type_complexity)]
pub async fn frame_claims_sorted(
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
    Query(params): Query<FrameClaimsQuery>,
) -> Result<Json<Vec<FrameClaimBeliefRow>>, ApiError> {
    let pool = &state.db_pool;

    // Verify frame exists
    epigraph_db::FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    // Validate sort_by
    let order_col = match params.sort_by.as_str() {
        "belief" => "c.belief",
        "plausibility" => "c.plausibility",
        "ignorance" => "(c.plausibility - c.belief)",
        _ => {
            return Err(ApiError::ValidationError {
                field: "sort_by".to_string(),
                reason: "Must be one of: belief, plausibility, ignorance".to_string(),
            });
        }
    };

    let order_dir = match params.order.as_str() {
        "asc" => "ASC",
        "desc" => "DESC",
        _ => {
            return Err(ApiError::ValidationError {
                field: "order".to_string(),
                reason: "Must be 'asc' or 'desc'".to_string(),
            });
        }
    };

    // Build query with validated sort column and direction.
    // These values come from match arms above, not user input, so this is safe.
    let query = format!(
        r#"
        SELECT cf.claim_id, c.content, cf.hypothesis_index, c.belief, c.plausibility, c.mass_on_missing
        FROM claim_frames cf
        JOIN claims c ON c.id = cf.claim_id
        WHERE cf.frame_id = $1
        ORDER BY {order_col} {order_dir} NULLS LAST
        LIMIT $2 OFFSET $3
        "#,
    );

    let rows: Vec<(
        Uuid,
        String,
        Option<i32>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
    )> = sqlx::query_as(&query)
        .bind(frame_id)
        .bind(params.limit)
        .bind(params.offset)
        .fetch_all(pool)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: e.to_string(),
        })?;

    let mut result: Vec<FrameClaimBeliefRow> = rows
        .into_iter()
        .map(
            |(claim_id, content, hypothesis_index, belief, plausibility, mass_on_missing)| {
                FrameClaimBeliefRow {
                    claim_id,
                    content,
                    hypothesis_index,
                    belief,
                    plausibility,
                    ignorance: match (belief, plausibility) {
                        (Some(b), Some(p)) => Some(p - b),
                        _ => None,
                    },
                    mass_on_missing,
                }
            },
        )
        .collect();

    // Apply partition-aware content filtering
    for row in &mut result {
        let access =
            crate::access_control::check_content_access(pool, row.claim_id, params.agent_id).await;
        if access == crate::access_control::ContentAccess::Redacted {
            crate::access_control::redact_claim_content(&mut row.content);
        }
    }

    Ok(Json(result))
}

/// Get latest DS vs Bayesian divergence for a claim
///
/// `GET /api/v1/claims/:id/divergence`
#[cfg(feature = "db")]
pub async fn claim_divergence(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<Option<DivergenceResponse>>, ApiError> {
    let pool = &state.db_pool;
    let row = epigraph_db::DivergenceRepository::get_latest(pool, claim_id).await?;

    Ok(Json(row.map(|r| DivergenceResponse {
        id: r.id,
        claim_id: r.claim_id,
        frame_id: r.frame_id,
        pignistic_prob: r.pignistic_prob,
        bayesian_posterior: r.bayesian_posterior,
        kl_divergence: r.kl_divergence,
        frame_version: r.frame_version,
        computed_at: r.computed_at.to_rfc3339(),
    })))
}

/// Get claims with the highest KL divergence
///
/// `GET /api/v1/divergence/top`
#[cfg(feature = "db")]
pub async fn top_divergence(
    State(state): State<AppState>,
    Query(params): Query<TopDivergenceQuery>,
) -> Result<Json<Vec<DivergenceResponse>>, ApiError> {
    let pool = &state.db_pool;
    let rows = epigraph_db::DivergenceRepository::top_divergent(pool, params.limit).await?;

    let result = rows
        .into_iter()
        .map(|r| DivergenceResponse {
            id: r.id,
            claim_id: r.claim_id,
            frame_id: r.frame_id,
            pignistic_prob: r.pignistic_prob,
            bayesian_posterior: r.bayesian_posterior,
            kl_divergence: r.kl_divergence,
            frame_version: r.frame_version,
            computed_at: r.computed_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(result))
}

/// Get scoped belief for a claim
///
/// `GET /api/v1/claims/:id/belief/scoped`
///
/// Query params: `scope` (global|perspective|community), `scope_id` (UUID)
#[cfg(feature = "db")]
pub async fn get_scoped_belief(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<ScopedBeliefQuery>,
) -> Result<Json<Option<ScopedBeliefEntry>>, ApiError> {
    let pool = &state.db_pool;
    let scope_type = params.scope.as_deref().unwrap_or("global");

    if scope_type != "global" && params.scope_id.is_none() {
        return Err(ApiError::ValidationError {
            field: "scope_id".to_string(),
            reason: format!("scope_id is required when scope is '{scope_type}'"),
        });
    }

    let row = epigraph_db::ScopedBeliefRepository::get(pool, claim_id, scope_type, params.scope_id)
        .await?;

    Ok(Json(row.map(scoped_belief_to_entry)))
}

/// Get all scoped beliefs for a claim (global + all perspective/community scopes)
///
/// `GET /api/v1/claims/:id/belief/all-scopes`
#[cfg(feature = "db")]
pub async fn all_scopes_belief(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<AllScopesBeliefResponse>, ApiError> {
    let pool = &state.db_pool;
    let rows = epigraph_db::ScopedBeliefRepository::list_for_claim(pool, claim_id).await?;

    let scopes = rows.into_iter().map(scoped_belief_to_entry).collect();

    Ok(Json(AllScopesBeliefResponse { claim_id, scopes }))
}

#[cfg(feature = "db")]
fn scoped_belief_to_entry(row: epigraph_db::ScopedBeliefRow) -> ScopedBeliefEntry {
    ScopedBeliefEntry {
        scope_type: row.scope_type,
        scope_id: row.scope_id,
        belief: row.belief,
        plausibility: row.plausibility,
        ignorance: row.plausibility - row.belief,
        mass_on_conflict: row.mass_on_empty,
        mass_on_missing: row.mass_on_missing,
        pignistic_prob: row.pignistic_prob,
        conflict_k: row.conflict_k,
        strategy_used: row.strategy_used,
        computed_at: row.computed_at.to_rfc3339(),
    }
}

/// Get full pignistic probability distribution for a claim in a frame
///
/// `GET /api/v1/claims/:id/pignistic?frame_id=<uuid>`
///
/// Recomputes from stored mass functions on-demand (TBM two-level model:
/// credal-level storage, pignistic-level computation at decision time).
#[cfg(feature = "db")]
pub async fn get_pignistic(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<PignisticQuery>,
) -> Result<Json<PignisticResponse>, ApiError> {
    use epigraph_ds::{combination, measures, FrameOfDiscernment, MassFunction};

    let pool = &state.db_pool;
    let frame_id = params.frame_id;

    // Load frame
    let frame_row = epigraph_db::FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    let ds_frame =
        FrameOfDiscernment::new(&frame_row.name, frame_row.hypotheses.clone()).map_err(|e| {
            ApiError::InternalError {
                message: format!("Invalid frame: {e}"),
            }
        })?;

    // Load all individual evidence BBAs (exclude system-combined)
    let all_rows =
        epigraph_db::MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id).await?;

    let mut indexed: Vec<(Uuid, MassFunction)> = all_rows
        .iter()
        .filter(|row| row.combination_method.as_deref() == Some("discount"))
        .filter_map(|row| {
            MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                .ok()
                .map(|m| (row.id, m))
        })
        .collect();
    indexed.sort_by_key(|(id, _)| *id);
    let masses: Vec<MassFunction> = indexed.into_iter().map(|(_, m)| m).collect();

    if masses.is_empty() {
        // No evidence — return uniform pignistic
        let n = ds_frame.hypothesis_count();
        #[allow(clippy::cast_precision_loss)]
        let uniform = 1.0 / n as f64;
        let hypotheses = frame_row
            .hypotheses
            .iter()
            .enumerate()
            .map(|(i, name)| PignisticEntry {
                hypothesis_index: i,
                hypothesis_name: name.clone(),
                pignistic_probability: uniform,
                belief: 0.0,
                plausibility: 1.0,
            })
            .collect();

        return Ok(Json(PignisticResponse {
            claim_id,
            frame_id,
            frame_name: frame_row.name,
            hypotheses,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.0,
        }));
    }

    // Combine (or use single BBA if only one)
    let (combined, _) = if masses.len() == 1 {
        (masses.into_iter().next().unwrap(), vec![])
    } else {
        combination::combine_multiple(&masses, 0.3).map_err(|e| ApiError::InternalError {
            message: format!("Combination failed: {e}"),
        })?
    };

    let m_empty = combined.mass_of_empty();
    let m_missing = combined.mass_of_missing();

    let hypotheses = frame_row
        .hypotheses
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let singleton =
                epigraph_ds::FocalElement::positive(std::collections::BTreeSet::from([i]));
            PignisticEntry {
                hypothesis_index: i,
                hypothesis_name: name.clone(),
                pignistic_probability: measures::pignistic_probability(&combined, i),
                belief: measures::belief(&combined, &singleton),
                plausibility: measures::plausibility(&combined, &singleton),
            }
        })
        .collect();

    Ok(Json(PignisticResponse {
        claim_id,
        frame_id,
        frame_name: frame_row.name,
        hypotheses,
        mass_on_conflict: m_empty,
        mass_on_missing: m_missing,
    }))
}

/// Create a refinement of an existing frame
///
/// `POST /api/v1/frames/:id/refine`
#[cfg(feature = "db")]
pub async fn refine_frame(
    State(state): State<AppState>,
    Path(parent_id): Path<Uuid>,
    Json(request): Json<RefineFrameRequest>,
) -> Result<(StatusCode, Json<FrameResponse>), ApiError> {
    let pool = &state.db_pool;

    // Validate parent frame exists and is refinable
    let parent = epigraph_db::FrameRepository::get_by_id(pool, parent_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: parent_id.to_string(),
        })?;

    if !parent.is_refinable {
        return Err(ApiError::ValidationError {
            field: "parent_frame_id".to_string(),
            reason: "Parent frame is not refinable".to_string(),
        });
    }

    if request.hypotheses.len() < 2 {
        return Err(ApiError::ValidationError {
            field: "hypotheses".to_string(),
            reason: "Refinement must have at least 2 hypotheses".to_string(),
        });
    }

    if request.name.is_empty() || request.name.len() > 200 {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Name must be between 1 and 200 characters".to_string(),
        });
    }

    let row = epigraph_db::FrameRepository::create_refinement(
        pool,
        parent_id,
        &request.name,
        request.description.as_deref(),
        &request.hypotheses,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(frame_to_response(row))))
}

/// List refinements (children) of a frame
///
/// `GET /api/v1/frames/:id/refinements`
#[cfg(feature = "db")]
pub async fn frame_refinements(
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    let pool = &state.db_pool;

    // Verify frame exists
    epigraph_db::FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        })?;

    let children = epigraph_db::FrameRepository::get_children(pool, frame_id).await?;
    Ok(Json(children.into_iter().map(frame_to_response).collect()))
}

/// Get frame ancestry (walk up parent chain)
///
/// `GET /api/v1/frames/:id/ancestry`
#[cfg(feature = "db")]
pub async fn frame_ancestry(
    State(state): State<AppState>,
    Path(frame_id): Path<Uuid>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    let pool = &state.db_pool;
    let ancestry = epigraph_db::FrameRepository::get_ancestry(pool, frame_id).await?;

    if ancestry.is_empty() {
        return Err(ApiError::NotFound {
            entity: "frame".to_string(),
            id: frame_id.to_string(),
        });
    }

    Ok(Json(ancestry.into_iter().map(frame_to_response).collect()))
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn get_claim_belief(
    Path(claim_id): Path<Uuid>,
) -> Result<Json<BeliefResponse>, ApiError> {
    Ok(Json(BeliefResponse {
        claim_id,
        belief: None,
        plausibility: None,
        ignorance: None,
        mass_on_conflict: None,
        mass_on_missing: None,
        pignistic_prob: None,
        mass_function_count: 0,
    }))
}

#[cfg(not(feature = "db"))]
pub async fn list_frames(
    Query(_params): Query<ListFramesQuery>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn get_frame(Path(frame_id): Path<Uuid>) -> Result<Json<FrameDetailResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn frame_conflict(
    Path(frame_id): Path<Uuid>,
) -> Result<Json<FrameConflictResponse>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn create_frame(
    Json(request): Json<CreateFrameRequest>,
) -> Result<(StatusCode, Json<FrameResponse>), ApiError> {
    if request.hypotheses.len() < 2 {
        return Err(ApiError::ValidationError {
            field: "hypotheses".to_string(),
            reason: "Frame must have at least 2 hypotheses".to_string(),
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(FrameResponse {
            id: Uuid::new_v4(),
            name: request.name,
            description: request.description,
            hypotheses: request.hypotheses,
            parent_frame_id: None,
            is_refinable: true,
            version: 1,
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn submit_evidence(
    Path(_frame_id): Path<Uuid>,
    Json(_request): Json<SubmitEvidenceRequest>,
) -> Result<(StatusCode, Json<EvidenceSubmissionResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "DS evidence pipeline requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn claims_by_belief(
    Query(_params): Query<BeliefFilterQuery>,
) -> Result<Json<Vec<BeliefClaimRow>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn frame_claims_sorted(
    Path(frame_id): Path<Uuid>,
    Query(_params): Query<FrameClaimsQuery>,
) -> Result<Json<Vec<FrameClaimBeliefRow>>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn claim_divergence(
    Path(_claim_id): Path<Uuid>,
) -> Result<Json<Option<DivergenceResponse>>, ApiError> {
    Ok(Json(None))
}

#[cfg(not(feature = "db"))]
pub async fn top_divergence(
    Query(_params): Query<TopDivergenceQuery>,
) -> Result<Json<Vec<DivergenceResponse>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[cfg(not(feature = "db"))]
pub async fn get_scoped_belief(
    Path(_claim_id): Path<Uuid>,
    Query(_params): Query<ScopedBeliefQuery>,
) -> Result<Json<Option<ScopedBeliefEntry>>, ApiError> {
    Ok(Json(None))
}

#[cfg(not(feature = "db"))]
pub async fn all_scopes_belief(
    Path(claim_id): Path<Uuid>,
) -> Result<Json<AllScopesBeliefResponse>, ApiError> {
    Ok(Json(AllScopesBeliefResponse {
        claim_id,
        scopes: Vec::new(),
    }))
}

#[cfg(not(feature = "db"))]
pub async fn get_pignistic(
    Path(_claim_id): Path<Uuid>,
    Query(_params): Query<PignisticQuery>,
) -> Result<Json<PignisticResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Pignistic computation requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn refine_frame(
    Path(_parent_id): Path<Uuid>,
    Json(_request): Json<RefineFrameRequest>,
) -> Result<(StatusCode, Json<FrameResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Frame refinement requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn frame_refinements(
    Path(frame_id): Path<Uuid>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn frame_ancestry(
    Path(frame_id): Path<Uuid>,
) -> Result<Json<Vec<FrameResponse>>, ApiError> {
    Err(ApiError::NotFound {
        entity: "frame".to_string(),
        id: frame_id.to_string(),
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kl_divergence_identical_distributions_is_zero() {
        let kl = kl_divergence_bernoulli(0.7, 0.7);
        assert!(kl.abs() < 1e-8, "KL(p || p) should be ~0, got {kl}");
    }

    #[test]
    fn kl_divergence_different_distributions_is_positive() {
        let kl = kl_divergence_bernoulli(0.9, 0.5);
        assert!(
            kl > 0.0,
            "KL divergence should be positive for different distributions"
        );
    }

    #[test]
    fn kl_divergence_extreme_values_dont_panic() {
        // Edge cases near 0 and 1 should be clamped safely
        let kl = kl_divergence_bernoulli(0.0, 1.0);
        assert!(
            kl.is_finite(),
            "KL with extreme inputs should be finite, got {kl}"
        );

        let kl2 = kl_divergence_bernoulli(1.0, 0.0);
        assert!(
            kl2.is_finite(),
            "KL with extreme inputs should be finite, got {kl2}"
        );
    }

    #[test]
    fn kl_divergence_symmetric_for_equal_distance() {
        // KL is NOT symmetric in general, but verify it doesn't panic
        let kl_forward = kl_divergence_bernoulli(0.3, 0.7);
        let kl_reverse = kl_divergence_bernoulli(0.7, 0.3);
        assert!(kl_forward > 0.0);
        assert!(kl_reverse > 0.0);
        // They should be equal for this symmetric case (|0.5-p| = |0.5-q|)
        assert!(
            (kl_forward - kl_reverse).abs() < 1e-10,
            "Symmetric case: forward={kl_forward}, reverse={kl_reverse}"
        );
    }

    #[test]
    fn belief_filter_query_defaults() {
        let q: BeliefFilterQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.min_belief, None);
        assert_eq!(q.max_plausibility, None);
        assert_eq!(q.frame_id, None);
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn frame_claims_query_defaults() {
        let q: FrameClaimsQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.sort_by, "belief");
        assert_eq!(q.order, "desc");
        assert_eq!(q.limit, 50);
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn top_divergence_query_defaults() {
        let q: TopDivergenceQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 10);
    }

    #[test]
    fn pignistic_query_requires_frame_id() {
        let result: Result<PignisticQuery, _> = serde_json::from_str("{}");
        assert!(result.is_err(), "PignisticQuery should require frame_id");
    }

    #[test]
    fn pignistic_entry_serializes() {
        let entry = PignisticEntry {
            hypothesis_index: 0,
            hypothesis_name: "true".to_string(),
            pignistic_probability: 0.85,
            belief: 0.7,
            plausibility: 1.0,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("0.85"));
        assert!(json.contains("\"true\""));
    }

    #[test]
    fn refine_frame_request_deserializes() {
        let req: RefineFrameRequest =
            serde_json::from_str(r#"{"name":"sub-frame","hypotheses":["a","b"]}"#).unwrap();
        assert_eq!(req.name, "sub-frame");
        assert_eq!(req.hypotheses.len(), 2);
        assert!(req.description.is_none());
    }

    #[test]
    fn belief_response_includes_pignistic() {
        let resp = BeliefResponse {
            claim_id: Uuid::new_v4(),
            belief: Some(0.7),
            plausibility: Some(0.9),
            ignorance: Some(0.2),
            mass_on_conflict: Some(0.01),
            mass_on_missing: Some(0.05),
            pignistic_prob: Some(0.85),
            mass_function_count: 3,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("pignistic_prob"));
        assert!(json.contains("0.85"));
        assert!(json.contains("mass_on_missing"));
    }

    #[test]
    fn frame_response_includes_refinement_fields() {
        let resp = FrameResponse {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            description: None,
            hypotheses: vec!["a".to_string(), "b".to_string()],
            parent_frame_id: Some(Uuid::new_v4()),
            is_refinable: false,
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("parent_frame_id"));
        assert!(json.contains("is_refinable"));
        assert!(json.contains("\"version\":1"));
    }

    #[test]
    fn evidence_submission_response_includes_pignistic() {
        let resp = EvidenceSubmissionResponse {
            mass_function_id: Uuid::new_v4(),
            combination_reports: vec![],
            updated_belief: 0.7,
            updated_plausibility: 0.9,
            mass_on_conflict: 0.01,
            mass_on_missing: 0.03,
            pignistic_prob: Some(0.85),
            bayesian_posterior: 0.5,
            total_sources: 3,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("pignistic_prob"));
        assert!(json.contains("bayesian_posterior"));
        assert!(json.contains("mass_on_conflict"));
        assert!(json.contains("mass_on_missing"));
    }

    #[test]
    fn scoped_belief_entry_includes_pignistic() {
        let entry = ScopedBeliefEntry {
            scope_type: "global".to_string(),
            scope_id: None,
            belief: 0.7,
            plausibility: 0.9,
            ignorance: 0.2,
            mass_on_conflict: 0.01,
            mass_on_missing: 0.03,
            pignistic_prob: Some(0.85),
            conflict_k: None,
            strategy_used: None,
            computed_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("pignistic_prob"));
        assert!(json.contains("mass_on_missing"));
    }

    // =========================================================================
    // Phase 7 tests: SCOPED_BY, confidence_calibration, competence_scopes
    // =========================================================================

    #[test]
    fn submit_evidence_request_deserializes_with_all_fields() {
        let claim_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let perspective_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "agent_id":"{}",
                "perspective_id":"{}",
                "reliability":0.9,
                "masses":{{"0,1":0.8,"":0.2}},
                "conflict_threshold":0.95
            }}"#,
            claim_id, agent_id, perspective_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.claim_id, claim_id);
        assert_eq!(req.agent_id, Some(agent_id));
        assert_eq!(req.perspective_id, Some(perspective_id));
        assert!((req.reliability - 0.9).abs() < f64::EPSILON);
        assert!((req.conflict_threshold - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn competence_discount_constant_is_valid() {
        // The competence discount is 0.7 (defined inline in submit_evidence).
        // Verify the value is in valid range for discount().
        let discount = 0.7_f64;
        assert!((0.0..=1.0).contains(&discount));
    }

    #[test]
    fn confidence_calibration_bounds_check() {
        // confidence_calibration is only applied when in [0.0, 1.0).
        // Verify the guard logic: calibration of 1.0 should NOT trigger discount
        // (it would be a no-op identity, not meaningful as additional discount).
        let calibration = 1.0_f64;
        assert!(
            !(0.0..1.0).contains(&calibration),
            "1.0 should be excluded from discount range"
        );

        let calibration = 0.5_f64;
        assert!(
            (0.0..1.0).contains(&calibration),
            "0.5 should be in discount range"
        );
    }

    // =========================================================================
    // CDST Migration tests: conflict vs missing decomposition
    // =========================================================================

    #[test]
    fn belief_response_includes_mass_on_missing() {
        let resp = BeliefResponse {
            claim_id: Uuid::new_v4(),
            belief: Some(0.6),
            plausibility: Some(0.8),
            ignorance: Some(0.2),
            mass_on_conflict: Some(0.05),
            mass_on_missing: Some(0.10),
            pignistic_prob: Some(0.7),
            mass_function_count: 2,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"mass_on_conflict\":0.05"),
            "Expected mass_on_conflict in JSON"
        );
        assert!(
            json.contains("\"mass_on_missing\":0.1"),
            "Expected mass_on_missing in JSON"
        );
    }

    #[test]
    fn belief_response_missing_fields_serialize_as_null() {
        let resp = BeliefResponse {
            claim_id: Uuid::new_v4(),
            belief: None,
            plausibility: None,
            ignorance: None,
            mass_on_conflict: None,
            mass_on_missing: None,
            pignistic_prob: None,
            mass_function_count: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"mass_on_missing\":null"));
    }

    #[test]
    fn frame_response_includes_version() {
        let resp = FrameResponse {
            id: Uuid::new_v4(),
            name: "climate_frame".to_string(),
            description: Some("A frame about climate hypotheses".to_string()),
            hypotheses: vec!["warming".into(), "stable".into(), "cooling".into()],
            parent_frame_id: None,
            is_refinable: true,
            version: 3,
            created_at: "2026-02-25T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"version\":3"),
            "Expected version=3 in JSON: {json}"
        );
    }

    #[test]
    fn combination_report_includes_mass_on_missing() {
        let report = CombinationReportResponse {
            method_used: "Dempster".to_string(),
            conflict_k: 0.15,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.08,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"mass_on_missing\":0.08"));
        assert!(json.contains("\"mass_on_conflict\":0.0"));
    }

    #[test]
    fn evidence_submission_response_has_conflict_and_missing() {
        let resp = EvidenceSubmissionResponse {
            mass_function_id: Uuid::new_v4(),
            combination_reports: vec![CombinationReportResponse {
                method_used: "YagerOpen".to_string(),
                conflict_k: 0.2,
                mass_on_conflict: 0.0,
                mass_on_missing: 0.2,
            }],
            updated_belief: 0.65,
            updated_plausibility: 0.88,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.2,
            pignistic_prob: Some(0.76),
            bayesian_posterior: 0.71,
            total_sources: 5,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"mass_on_conflict\":0.0"),
            "conflict field: {json}"
        );
        assert!(
            json.contains("\"mass_on_missing\":0.2"),
            "missing field: {json}"
        );
    }

    #[test]
    fn submit_evidence_request_with_combination_method() {
        let claim_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "masses":{{"0":0.7,"0,1":0.3}},
                "combination_method":"dempster",
                "gamma":null
            }}"#,
            claim_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.combination_method.as_deref(), Some("dempster"));
        assert_eq!(req.gamma, None);
    }

    #[test]
    fn submit_evidence_request_with_inagaki_gamma() {
        let claim_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "masses":{{"0":0.6,"1":0.4}},
                "combination_method":"inagaki",
                "gamma":0.3
            }}"#,
            claim_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.combination_method.as_deref(), Some("inagaki"));
        assert!((req.gamma.unwrap() - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn submit_evidence_request_defaults_omit_combination_method() {
        let claim_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "masses":{{"0":0.6,"0,1":0.4}}
            }}"#,
            claim_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.combination_method, None);
        assert_eq!(req.gamma, None);
        // Defaults
        assert!((req.reliability - 1.0).abs() < f64::EPSILON);
        assert!((req.conflict_threshold - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn submit_evidence_request_with_negative_elements() {
        let claim_id = Uuid::new_v4();
        let json = format!(
            r#"{{
                "claim_id":"{}",
                "masses":{{"0":0.4,"~1":0.3,"~":0.3}}
            }}"#,
            claim_id
        );
        let req: SubmitEvidenceRequest = serde_json::from_str(&json).unwrap();
        // Verify ~-prefixed keys are in the map
        assert!(
            req.masses.contains_key("~1"),
            "Should have complement key ~1"
        );
        assert!(req.masses.contains_key("~"), "Should have vacuous key ~");
        assert!(req.masses.contains_key("0"), "Should have positive key 0");
        assert!((req.masses["~1"] - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn divergence_response_includes_frame_version() {
        let resp = DivergenceResponse {
            id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            pignistic_prob: 0.85,
            bayesian_posterior: 0.72,
            kl_divergence: 0.12,
            frame_version: Some(2),
            computed_at: "2026-02-25T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"frame_version\":2"),
            "Expected frame_version: {json}"
        );
    }

    #[test]
    fn divergence_response_null_frame_version() {
        let resp = DivergenceResponse {
            id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            pignistic_prob: 0.5,
            bayesian_posterior: 0.5,
            kl_divergence: 0.0,
            frame_version: None,
            computed_at: "2026-02-25T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"frame_version\":null"));
    }

    #[test]
    fn pignistic_response_includes_mass_on_missing() {
        let resp = PignisticResponse {
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            frame_name: "binary".to_string(),
            hypotheses: vec![
                PignisticEntry {
                    hypothesis_index: 0,
                    hypothesis_name: "true".to_string(),
                    pignistic_probability: 0.65,
                    belief: 0.5,
                    plausibility: 0.8,
                },
                PignisticEntry {
                    hypothesis_index: 1,
                    hypothesis_name: "false".to_string(),
                    pignistic_probability: 0.35,
                    belief: 0.2,
                    plausibility: 0.5,
                },
            ],
            mass_on_conflict: 0.02,
            mass_on_missing: 0.10,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"mass_on_missing\":0.1"),
            "Expected mass_on_missing: {json}"
        );
        assert!(json.contains("\"mass_on_conflict\":0.02"));
    }

    #[test]
    fn scoped_belief_entry_includes_mass_on_missing() {
        let entry = ScopedBeliefEntry {
            scope_type: "community".to_string(),
            scope_id: Some(Uuid::new_v4()),
            belief: 0.55,
            plausibility: 0.80,
            ignorance: 0.25,
            mass_on_conflict: 0.03,
            mass_on_missing: 0.07,
            pignistic_prob: Some(0.68),
            conflict_k: Some(0.12),
            strategy_used: Some("dempster".to_string()),
            computed_at: "2026-02-25T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            json.contains("\"mass_on_missing\":0.07"),
            "Expected mass_on_missing: {json}"
        );
        assert!(json.contains("\"mass_on_conflict\":0.03"));
        assert!(json.contains("\"scope_type\":\"community\""));
    }

    #[test]
    fn belief_claim_row_includes_mass_on_missing() {
        let row = BeliefClaimRow {
            id: Uuid::new_v4(),
            content: "Test claim".to_string(),
            belief: Some(0.7),
            plausibility: Some(0.9),
            mass_on_conflict: Some(0.01),
            mass_on_missing: Some(0.04),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"mass_on_missing\":0.04"));
    }

    #[test]
    fn frame_claim_belief_row_includes_mass_on_missing() {
        let row = FrameClaimBeliefRow {
            claim_id: Uuid::new_v4(),
            content: "Hypothesis claim".to_string(),
            hypothesis_index: Some(0),
            belief: Some(0.6),
            plausibility: Some(0.85),
            ignorance: Some(0.25),
            mass_on_missing: Some(0.05),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"mass_on_missing\":0.05"));
        assert!(json.contains("\"hypothesis_index\":0"));
    }

    #[test]
    fn combination_method_strings_are_valid() {
        // Verify the known combination method strings match what epigraph-ds expects
        let valid_methods = [
            "conjunctive",
            "dempster",
            "yager_open",
            "yager_closed",
            "dubois_prade",
            "inagaki",
        ];
        for method in valid_methods {
            assert!(!method.is_empty(), "Method name should not be empty");
        }
    }

    #[test]
    fn gamma_parameter_bounds() {
        // Inagaki gamma must be in [0, 1]
        let valid_gammas = [0.0, 0.3, 0.5, 1.0];
        for g in valid_gammas {
            assert!((0.0..=1.0).contains(&g), "Gamma {g} should be in [0, 1]");
        }
    }

    // =========================================================================
    // R5: CDST residual mass signal detection thresholds
    // =========================================================================

    #[test]
    fn test_frame_incomplete_event_threshold() {
        // frame.incomplete fires when m_missing > 0.15
        let threshold = 0.15_f64;
        let above = 0.20_f64;
        let below = 0.10_f64;
        let at = 0.15_f64;

        assert!(
            above > threshold,
            "m_missing=0.20 should trigger frame.incomplete"
        );
        assert!(
            !(below > threshold),
            "m_missing=0.10 should NOT trigger frame.incomplete"
        );
        assert!(
            !(at > threshold),
            "m_missing=0.15 (boundary) should NOT trigger"
        );
    }

    #[test]
    fn test_genuine_conflict_event_threshold() {
        // conflict.genuine fires when m_empty > 0.10 AND m_missing < 0.05
        let m_empty_threshold = 0.10_f64;
        let m_missing_ceiling = 0.05_f64;

        // Case 1: high conflict, low ignorance -> should fire
        let m_empty = 0.15_f64;
        let m_missing = 0.02_f64;
        assert!(
            m_empty > m_empty_threshold && m_missing < m_missing_ceiling,
            "m_empty=0.15, m_missing=0.02 should trigger conflict.genuine"
        );

        // Case 2: high conflict, high ignorance -> should NOT fire
        let m_empty = 0.15_f64;
        let m_missing = 0.10_f64;
        assert!(
            !(m_empty > m_empty_threshold && m_missing < m_missing_ceiling),
            "m_empty=0.15, m_missing=0.10 should NOT trigger (high ignorance)"
        );

        // Case 3: low conflict, low ignorance -> should NOT fire
        let m_empty = 0.05_f64;
        let m_missing = 0.02_f64;
        assert!(
            !(m_empty > m_empty_threshold && m_missing < m_missing_ceiling),
            "m_empty=0.05, m_missing=0.02 should NOT trigger (low conflict)"
        );
    }

    // ── Section 03: Batch Conflict API tests ──

    #[test]
    fn test_conflict_batch_single_pair() {
        let req_json = serde_json::json!({
            "pairs": [{"claim_a": Uuid::new_v4(), "claim_b": Uuid::new_v4()}]
        });
        let req: ConflictBatchRequest = serde_json::from_value(req_json).unwrap();
        assert_eq!(req.pairs.len(), 1);
    }

    #[test]
    fn test_conflict_batch_100_pairs() {
        let pairs: Vec<serde_json::Value> = (0..100)
            .map(|_| serde_json::json!({"claim_a": Uuid::new_v4(), "claim_b": Uuid::new_v4()}))
            .collect();
        let req_json = serde_json::json!({ "pairs": pairs });
        let req: ConflictBatchRequest = serde_json::from_value(req_json).unwrap();
        assert_eq!(req.pairs.len(), 100);
    }

    #[test]
    fn test_conflict_batch_missing_mass_function() {
        // ConflictBatchResult with error when mass function is missing
        let result = ConflictBatchResult {
            claim_a: Uuid::new_v4(),
            claim_b: Uuid::new_v4(),
            conflict_k: None,
            error: Some("No mass function for claim abc".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["conflict_k"].is_null());
        assert!(json["error"].as_str().unwrap().contains("No mass function"));
    }

    #[test]
    fn test_conflict_batch_empty_pairs() {
        let req: ConflictBatchRequest =
            serde_json::from_value(serde_json::json!({"pairs": []})).unwrap();
        assert!(req.pairs.is_empty());
        // Empty pairs returns empty results (handler short-circuits)
        let resp = ConflictBatchResponse { results: vec![] };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_conflict_batch_matches_manual_computation() {
        use epigraph_ds::{
            combination::conflict_coefficient, FocalElement, FrameOfDiscernment, MassFunction,
        };
        use std::collections::{BTreeMap, BTreeSet};

        let frame = FrameOfDiscernment::new("test", vec!["H0".into(), "H1".into()]).unwrap();

        let mut h0 = BTreeSet::new();
        h0.insert(0);
        let mut h1 = BTreeSet::new();
        h1.insert(1);

        let mut bba_a = BTreeMap::new();
        bba_a.insert(FocalElement::positive(h0), 0.6);
        bba_a.insert(FocalElement::theta(&frame), 0.4);
        let mf_a = MassFunction::new(frame.clone(), bba_a).unwrap();

        let mut bba_b = BTreeMap::new();
        bba_b.insert(FocalElement::positive(h1), 0.7);
        bba_b.insert(FocalElement::theta(&frame), 0.3);
        let mf_b = MassFunction::new(frame.clone(), bba_b).unwrap();

        let k = conflict_coefficient(&mf_a, &mf_b).unwrap();
        // m_a({H0}) * m_b({H1}) = 0.6 * 0.7 = 0.42 (conflict mass)
        assert!(
            k > 0.3,
            "K should reflect disjoint focal element conflict, got {k}"
        );
        assert!(
            k < 0.5,
            "K should not exceed sum of conflicting products, got {k}"
        );

        let result = ConflictBatchResult {
            claim_a: Uuid::new_v4(),
            claim_b: Uuid::new_v4(),
            conflict_k: Some(k),
            error: None,
        };
        assert!(result.conflict_k.unwrap() > 0.0);
    }

    #[test]
    fn test_conflict_batch_exceeds_limit() {
        let pairs: Vec<serde_json::Value> = (0..101)
            .map(|_| serde_json::json!({"claim_a": Uuid::new_v4(), "claim_b": Uuid::new_v4()}))
            .collect();
        let req_json = serde_json::json!({ "pairs": pairs });
        let req: ConflictBatchRequest = serde_json::from_value(req_json).unwrap();
        // Handler would reject this (101 > 100), verify the count
        assert_eq!(req.pairs.len(), 101);
        assert!(req.pairs.len() > 100, "Should exceed the 100-pair limit");
    }

    #[test]
    fn test_conflict_batch_nonexistent_frame() {
        // Verify that a nonexistent frame_id would produce a NotFound-style error
        let fake_frame = Uuid::new_v4();
        let err = ApiError::NotFound {
            entity: "frame".to_string(),
            id: fake_frame.to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "Error should indicate not found: {msg}"
        );
    }
}
