//! Convention & skill endpoints (Phase 7)
//!
//! Protected (POST/DELETE):
//! - `POST /api/v1/conventions` — learn a convention (create claim with "convention" label)
//! - `DELETE /api/v1/conventions/:id` — forget a convention (add counter-evidence)
//! - `POST /api/v1/skills/share` — share a workflow to global scope
//!
//! Public (GET):
//! - `GET /api/v1/skills` — list workflow skills

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

/// Request to learn a new convention
#[derive(Debug, Deserialize)]
pub struct LearnConventionRequest {
    /// The convention content (e.g. "Always use snake_case for Rust functions")
    pub content: String,
    /// Supporting evidence for this convention
    pub evidence: String,
    /// Confidence in this convention (0.0-1.0, default 0.7)
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_confidence() -> f64 {
    0.7
}

/// Response for a convention
#[derive(Debug, Serialize)]
pub struct ConventionResponse {
    pub claim_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub labels: Vec<String>,
}

/// Request to share a workflow skill to global scope
#[derive(Debug, Deserialize)]
pub struct ShareSkillRequest {
    /// UUID of the workflow to share
    pub workflow_id: Uuid,
}

/// Response for a shared skill
#[derive(Debug, Serialize)]
pub struct ShareSkillResponse {
    pub shared_claim_id: Uuid,
    pub original_workflow_id: Uuid,
    pub edge_id: Uuid,
}

/// Query parameters for listing skills
#[derive(Debug, Deserialize)]
pub struct ListSkillsQuery {
    pub category: Option<String>,
    #[serde(default = "default_min_truth")]
    pub min_truth: f64,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_min_truth() -> f64 {
    0.3
}

fn default_limit() -> i64 {
    20
}

/// Response for a skill entry
#[derive(Debug, Serialize)]
pub struct SkillResponse {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub properties: Option<serde_json::Value>,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Learn a convention — creates a claim with "convention" label and empirical evidence.
///
/// `POST /api/v1/conventions`
pub async fn learn_convention(
    State(state): State<AppState>,
    Json(request): Json<LearnConventionRequest>,
) -> Result<(StatusCode, Json<ConventionResponse>), ApiError> {
    if request.content.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "content".to_string(),
            reason: "Convention content cannot be empty".to_string(),
        });
    }

    let confidence = request.confidence.clamp(0.0, 1.0);
    let pool = &state.db_pool;

    // Ensure system agent exists for API-created conventions
    let pub_key = [0u8; 32];
    let system_agent = if let Some(a) =
        epigraph_db::AgentRepository::get_by_public_key(pool, &pub_key)
            .await
            .map_err(|e| ApiError::InternalError {
                message: e.to_string(),
            })? {
        a
    } else {
        let agent = epigraph_core::Agent::new(pub_key, Some("api-system".to_string()));
        epigraph_db::AgentRepository::create(pool, &agent)
            .await
            .map_err(|e| ApiError::InternalError {
                message: e.to_string(),
            })?
    };
    let agent_id = epigraph_core::AgentId::from_uuid(system_agent.id.as_uuid());
    let truth = epigraph_core::TruthValue::clamped(confidence);

    let mut claim = epigraph_core::Claim::new(request.content.clone(), agent_id, pub_key, truth);
    claim.content_hash = epigraph_crypto::ContentHasher::hash(request.content.as_bytes());

    epigraph_db::ClaimRepository::create(pool, &claim).await?;

    // Set labels: convention + any user tags
    let mut labels = vec!["convention".to_string(), "learned".to_string()];
    labels.extend(request.tags);

    sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
        .bind(&labels)
        .bind(claim.id.as_uuid())
        .execute(pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?;

    // Create evidence
    let evidence_hash = epigraph_crypto::ContentHasher::hash(request.evidence.as_bytes());
    let evidence = epigraph_core::Evidence::new(
        agent_id,
        pub_key,
        evidence_hash,
        epigraph_core::EvidenceType::Observation {
            observed_at: chrono::Utc::now(),
            method: "convention_learning".to_string(),
            location: None,
        },
        Some(request.evidence),
        claim.id,
    );
    epigraph_db::EvidenceRepository::create(pool, &evidence).await?;

    // Create reasoning trace
    let trace = epigraph_core::ReasoningTrace::new(
        agent_id,
        pub_key,
        epigraph_core::Methodology::Heuristic,
        vec![epigraph_core::TraceInput::Evidence { id: evidence.id }],
        confidence,
        format!("Convention learned: {}", request.content),
    );
    epigraph_db::ReasoningTraceRepository::create(pool, &trace, claim.id).await?;
    epigraph_db::ClaimRepository::update_trace_id(pool, claim.id, trace.id).await?;

    // Materialize graph edges
    let claim_uuid = claim.id.as_uuid();
    let evidence_uuid = evidence.id.as_uuid();
    let trace_uuid = trace.id.as_uuid();
    let agent_uuid = system_agent.id.as_uuid();

    let _ = epigraph_db::EdgeRepository::create(
        pool, agent_uuid, "agent", claim_uuid, "claim", "AUTHORED", None, None, None,
    )
    .await;
    let _ = epigraph_db::EdgeRepository::create(
        pool,
        evidence_uuid,
        "evidence",
        claim_uuid,
        "claim",
        "SUPPORTS",
        None,
        None,
        None,
    )
    .await;
    let _ = epigraph_db::EdgeRepository::create(
        pool, trace_uuid, "trace", claim_uuid, "claim", "TRACES", None, None, None,
    )
    .await;
    let _ = epigraph_db::EdgeRepository::create(
        pool,
        claim_uuid,
        "claim",
        trace_uuid,
        "trace",
        "HAS_TRACE",
        None,
        None,
        None,
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(ConventionResponse {
            claim_id: claim.id.as_uuid(),
            content: request.content,
            truth_value: confidence,
            labels,
        }),
    ))
}

/// Forget a convention — adds strong counter-evidence to drive truth toward 0.
///
/// `DELETE /api/v1/conventions/:id`
pub async fn forget_convention(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<ConventionResponse>, ApiError> {
    let pool = &state.db_pool;
    let claim_id_typed = epigraph_core::ClaimId::from_uuid(claim_id);

    let claim = epigraph_db::ClaimRepository::get_by_id(pool, claim_id_typed)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "convention".to_string(),
            id: claim_id.to_string(),
        })?;

    // Add strong counter-evidence using system agent
    let pub_key = [0u8; 32];
    let system_agent = epigraph_db::AgentRepository::get_by_public_key(pool, &pub_key)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::InternalError {
            message: "System agent not found — learn a convention first".to_string(),
        })?;
    let agent_id = epigraph_core::AgentId::from_uuid(system_agent.id.as_uuid());
    let evidence_text = "Convention explicitly forgotten/deprecated";
    let evidence_hash = epigraph_crypto::ContentHasher::hash(evidence_text.as_bytes());
    let evidence = epigraph_core::Evidence::new(
        agent_id,
        pub_key,
        evidence_hash,
        epigraph_core::EvidenceType::Observation {
            observed_at: chrono::Utc::now(),
            method: "convention_deprecation".to_string(),
            location: None,
        },
        Some(evidence_text.to_string()),
        claim_id_typed,
    );
    epigraph_db::EvidenceRepository::create(pool, &evidence).await?;

    // Materialize evidence --REFUTES--> claim edge
    let _ = epigraph_db::EdgeRepository::create(
        pool,
        evidence.id.as_uuid(),
        "evidence",
        claim_id,
        "claim",
        "REFUTES",
        None,
        None,
        None,
    )
    .await;

    // Drive truth to near-zero via Bayesian refutation
    // TODO: migrate to CDST pignistic probability (BayesianUpdater is deprecated)
    #[allow(deprecated)]
    let updater = epigraph_engine::BayesianUpdater::new();
    let new_truth = updater
        .update_with_refutation(claim.truth_value, 1.0)
        .unwrap_or(epigraph_core::TruthValue::clamped(0.05));

    epigraph_db::ClaimRepository::update_truth_value(pool, claim_id_typed, new_truth).await?;

    // Read labels
    let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .unwrap_or_default();

    Ok(Json(ConventionResponse {
        claim_id,
        content: claim.content,
        truth_value: new_truth.value(),
        labels,
    }))
}

/// List workflow skills.
///
/// `GET /api/v1/skills`
pub async fn list_skills(
    State(state): State<AppState>,
    Query(params): Query<ListSkillsQuery>,
) -> Result<Json<Vec<SkillResponse>>, ApiError> {
    let pool = &state.db_pool;

    let rows = epigraph_db::WorkflowRepository::list(
        pool,
        params.min_truth,
        params.category.as_deref(),
        params.limit,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: e.to_string(),
    })?;

    let results: Vec<SkillResponse> = rows
        .into_iter()
        .map(|r| SkillResponse {
            id: r.id,
            content: r.content,
            truth_value: r.truth_value,
            properties: Some(r.properties),
        })
        .collect();

    Ok(Json(results))
}

/// Share a workflow skill to global scope.
///
/// `POST /api/v1/skills/share`
pub async fn share_skill(
    State(state): State<AppState>,
    Json(request): Json<ShareSkillRequest>,
) -> Result<(StatusCode, Json<ShareSkillResponse>), ApiError> {
    let pool = &state.db_pool;
    let claim_id_typed = epigraph_core::ClaimId::from_uuid(request.workflow_id);

    let claim = epigraph_db::ClaimRepository::get_by_id(pool, claim_id_typed)
        .await?
        .ok_or(ApiError::NotFound {
            entity: "workflow".to_string(),
            id: request.workflow_id.to_string(),
        })?;

    // Create a copy with global labels using system agent
    let pub_key = [0u8; 32];
    let system_agent = if let Some(a) =
        epigraph_db::AgentRepository::get_by_public_key(pool, &pub_key)
            .await
            .map_err(|e| ApiError::InternalError {
                message: e.to_string(),
            })? {
        a
    } else {
        let agent = epigraph_core::Agent::new(pub_key, Some("api-system".to_string()));
        epigraph_db::AgentRepository::create(pool, &agent)
            .await
            .map_err(|e| ApiError::InternalError {
                message: e.to_string(),
            })?
    };
    let agent_id = epigraph_core::AgentId::from_uuid(system_agent.id.as_uuid());

    let mut shared_claim =
        epigraph_core::Claim::new(claim.content.clone(), agent_id, pub_key, claim.truth_value);
    shared_claim.content_hash = epigraph_crypto::ContentHasher::hash(claim.content.as_bytes());

    epigraph_db::ClaimRepository::create(pool, &shared_claim).await?;

    // Set labels
    let labels = vec![
        "workflow".to_string(),
        "global".to_string(),
        "shared".to_string(),
    ];
    sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
        .bind(&labels)
        .bind(shared_claim.id.as_uuid())
        .execute(pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?;

    // Create SHARED_BY edge from shared → original
    let edge_id = epigraph_db::EdgeRepository::create(
        pool,
        shared_claim.id.as_uuid(),
        "claim",
        request.workflow_id,
        "claim",
        "SHARED_BY",
        None,
        None,
        None,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ShareSkillResponse {
            shared_claim_id: shared_claim.id.as_uuid(),
            original_workflow_id: request.workflow_id,
            edge_id,
        }),
    ))
}
