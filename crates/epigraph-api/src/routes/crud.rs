//! CRUD endpoints for entities missing create/update routes.
//!
//! - `POST /api/v1/evidence` — Create evidence record
//! - `PUT /api/v1/evidence/:id` — Update evidence (raw_content backfill)
//! - `POST /api/v1/reasoning-traces` — Create reasoning trace
//! - `POST /api/v1/analyses` — Create analysis record
//! - `POST /api/v1/clusters` — Upsert cluster assignment
//! - `POST /api/v1/frames/:id/assign-claim` — Assign claim to frame
//! - `POST /api/v1/edges-staging/promote` — Promote approved staged edges

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// CREATE EVIDENCE
// =============================================================================

/// Request to create a new evidence record
#[derive(Deserialize)]
pub struct CreateEvidenceRequest {
    /// Agent that submitted the evidence
    pub agent_id: Uuid,
    /// Claim this evidence supports/refutes
    pub claim_id: Uuid,
    /// Raw text content of the evidence (optional, may be external)
    pub raw_content: Option<String>,
    /// Evidence type as JSONB (must match EvidenceType enum shape)
    pub evidence_type: serde_json::Value,
    /// Optional pre-computed content hash (hex). If omitted, computed from raw_content.
    pub content_hash: Option<String>,
    /// Optional JSONB properties
    pub properties: Option<serde_json::Value>,
}

/// Evidence creation response
#[derive(Serialize)]
pub struct CreateEvidenceResponse {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub agent_id: Uuid,
    pub content_hash: String,
    pub evidence_type: String,
    pub created_at: String,
}

/// Create a new evidence record
///
/// POST /api/v1/evidence
#[cfg(feature = "db")]
pub async fn create_evidence(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreateEvidenceRequest>,
) -> Result<(StatusCode, Json<CreateEvidenceResponse>), ApiError> {
    use epigraph_core::{AgentId, ClaimId, Evidence, EvidenceType};
    use epigraph_db::EvidenceRepository;

    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        // Accept either evidence:write or evidence:submit (naming inconsistency)
        if !auth.has_scope("evidence:write") && !auth.has_scope("evidence:submit") {
            return Err(crate::errors::ApiError::Forbidden {
                reason: "Missing required scope: evidence:write or evidence:submit".to_string(),
            });
        }
    }

    // Parse evidence_type from JSON
    let evidence_type: EvidenceType = serde_json::from_value(request.evidence_type.clone())
        .map_err(|e| ApiError::ValidationError {
            field: "evidence_type".to_string(),
            reason: format!("Invalid evidence_type JSON: {e}"),
        })?;

    // Compute content hash from raw_content (or use provided hash)
    let content_hash: [u8; 32] = if let Some(ref hex_hash) = request.content_hash {
        let bytes = hex::decode(hex_hash).map_err(|e| ApiError::ValidationError {
            field: "content_hash".to_string(),
            reason: format!("Invalid hex: {e}"),
        })?;
        bytes.try_into().map_err(|_| ApiError::ValidationError {
            field: "content_hash".to_string(),
            reason: "content_hash must be exactly 32 bytes (64 hex chars)".to_string(),
        })?
    } else {
        let hashable = request.raw_content.as_deref().unwrap_or("");
        let hash = blake3::hash(hashable.as_bytes());
        *hash.as_bytes()
    };

    // Resolve public key for the agent
    let public_key = epigraph_db::AgentRepository::get_by_id(
        &state.db_pool,
        AgentId::from_uuid(request.agent_id),
    )
    .await
    .ok()
    .flatten()
    .map(|a| a.public_key)
    .unwrap_or([0u8; 32]);

    let evidence = Evidence::new(
        AgentId::from_uuid(request.agent_id),
        public_key,
        content_hash,
        evidence_type.clone(),
        request.raw_content,
        ClaimId::from_uuid(request.claim_id),
    );

    let created = EvidenceRepository::create(&state.db_pool, &evidence).await?;
    let evidence_id: Uuid = created.id.into();

    // Materialize claim --DERIVED_FROM--> evidence edge
    let _ = epigraph_db::EdgeRepository::create(
        &state.db_pool,
        request.claim_id,
        "claim",
        evidence_id,
        "evidence",
        "DERIVED_FROM",
        None,
        None,
        None,
    )
    .await;

    // Record provenance when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let hash = blake3::hash(&content_hash);
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "evidence",
            evidence_id,
            "create",
            hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(evidence_id = %evidence_id, error = %e, "Failed to record evidence provenance");
        }
    }

    let evidence_type_str = match &evidence_type {
        EvidenceType::Document { .. } => "document",
        EvidenceType::Observation { .. } => "observation",
        EvidenceType::Testimony { .. } => "testimony",
        EvidenceType::Literature { .. } => "literature",
        EvidenceType::Consensus { .. } => "consensus",
        EvidenceType::Figure { .. } => "figure",
    };

    Ok((
        StatusCode::CREATED,
        Json(CreateEvidenceResponse {
            id: evidence_id,
            claim_id: request.claim_id,
            agent_id: request.agent_id,
            content_hash: hex::encode(content_hash),
            evidence_type: evidence_type_str.to_string(),
            created_at: created.created_at.to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn create_evidence(
    State(_state): State<AppState>,
    Json(_request): Json<CreateEvidenceRequest>,
) -> Result<(StatusCode, Json<CreateEvidenceResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Evidence creation requires database".to_string(),
    })
}

// =============================================================================
// UPDATE EVIDENCE (raw_content backfill)
// =============================================================================

/// Request to update evidence (typically raw_content backfill)
#[derive(Deserialize)]
pub struct UpdateEvidenceRequest {
    pub raw_content: Option<String>,
}

/// Update an evidence record
///
/// PUT /api/v1/evidence/:id
///
/// Currently supports backfilling raw_content on existing evidence.
#[cfg(feature = "db")]
pub async fn update_evidence(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateEvidenceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        // Accept either evidence:write or evidence:submit (naming inconsistency)
        if !auth.has_scope("evidence:write") && !auth.has_scope("evidence:submit") {
            return Err(crate::errors::ApiError::Forbidden {
                reason: "Missing required scope: evidence:write or evidence:submit".to_string(),
            });
        }
    }

    if request.raw_content.is_none() {
        return Err(ApiError::ValidationError {
            field: "raw_content".to_string(),
            reason: "At least one field must be provided for update".to_string(),
        });
    }

    // Update raw_content via direct SQL (no repo method exists yet)
    if let Some(ref content) = request.raw_content {
        sqlx::query("UPDATE evidence SET raw_content = $2 WHERE id = $1")
            .bind(id)
            .bind(content)
            .execute(&state.db_pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to update evidence: {e}"),
            })?;
    }

    // Record provenance
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let hash = blake3::hash(id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "evidence",
            id,
            "update",
            hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(evidence_id = %id, error = %e, "Failed to record evidence update provenance");
        }
    }

    Ok(Json(serde_json::json!({
        "id": id,
        "updated": true,
    })))
}

#[cfg(not(feature = "db"))]
pub async fn update_evidence(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<UpdateEvidenceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Evidence updates require database".to_string(),
    })
}

// =============================================================================
// CREATE REASONING TRACE
// =============================================================================

/// Request to create a reasoning trace
#[derive(Deserialize)]
pub struct CreateReasoningTraceRequest {
    /// ID of the claim this trace explains
    pub claim_id: Uuid,
    /// Agent that produced the reasoning
    pub agent_id: Uuid,
    /// Methodology: deductive, inductive, abductive, statistical
    pub methodology: String,
    /// Confidence in [0.0, 1.0]
    pub confidence: f64,
    /// Human-readable explanation
    pub explanation: String,
    /// Structured inputs (parent claim IDs, evidence IDs, etc.)
    pub inputs: Option<serde_json::Value>,
}

/// Reasoning trace response
#[derive(Serialize)]
pub struct ReasoningTraceResponse {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub agent_id: Uuid,
    pub methodology: String,
    pub confidence: f64,
    pub explanation: String,
    pub created_at: String,
}

/// Create a new reasoning trace
///
/// POST /api/v1/reasoning-traces
#[cfg(feature = "db")]
pub async fn create_reasoning_trace(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreateReasoningTraceRequest>,
) -> Result<(StatusCode, Json<ReasoningTraceResponse>), ApiError> {
    use epigraph_core::{AgentId, ClaimId, Methodology, ReasoningTrace, TraceInput};
    use epigraph_db::ReasoningTraceRepository;

    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    // Validate confidence
    if !(0.0..=1.0).contains(&request.confidence) {
        return Err(ApiError::ValidationError {
            field: "confidence".to_string(),
            reason: "Confidence must be between 0.0 and 1.0".to_string(),
        });
    }

    // Parse methodology
    let methodology = match request.methodology.as_str() {
        "deductive" => Methodology::Deductive,
        "inductive" => Methodology::Inductive,
        "abductive" => Methodology::Abductive,
        "statistical" | "bayesian" => Methodology::BayesianInference,
        "extraction" => Methodology::Extraction,
        "instrumental" => Methodology::Instrumental,
        "visual" => Methodology::VisualInspection,
        "formal_proof" => Methodology::FormalProof,
        "heuristic" => Methodology::Heuristic,
        other => {
            return Err(ApiError::ValidationError {
                field: "methodology".to_string(),
                reason: format!("Unknown methodology '{}'. Valid: deductive, inductive, abductive, statistical, extraction, instrumental, visual, formal_proof, heuristic", other),
            });
        }
    };

    // Parse inputs
    let inputs: Vec<TraceInput> = if let Some(ref inputs_json) = request.inputs {
        serde_json::from_value(inputs_json.clone()).unwrap_or_default()
    } else {
        vec![]
    };

    // Resolve public key
    let public_key = epigraph_db::AgentRepository::get_by_id(
        &state.db_pool,
        AgentId::from_uuid(request.agent_id),
    )
    .await
    .ok()
    .flatten()
    .map(|a| a.public_key)
    .unwrap_or([0u8; 32]);

    let trace = ReasoningTrace::new(
        AgentId::from_uuid(request.agent_id),
        public_key,
        methodology,
        inputs,
        request.confidence,
        request.explanation.clone(),
    );

    let created = ReasoningTraceRepository::create(
        &state.db_pool,
        &trace,
        ClaimId::from_uuid(request.claim_id),
    )
    .await?;

    let trace_id: Uuid = created.id.into();

    // Materialize claim --HAS_TRACE--> trace edge
    let _ = epigraph_db::EdgeRepository::create(
        &state.db_pool,
        request.claim_id,
        "claim",
        trace_id,
        "trace",
        "HAS_TRACE",
        None,
        None,
        None,
    )
    .await;

    // Record provenance
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let hash = blake3::hash(trace_id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "trace",
            trace_id,
            "create",
            hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(trace_id = %trace_id, error = %e, "Failed to record trace provenance");
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(ReasoningTraceResponse {
            id: trace_id,
            claim_id: request.claim_id,
            agent_id: request.agent_id,
            methodology: request.methodology,
            confidence: request.confidence,
            explanation: request.explanation,
            created_at: created.created_at.to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn create_reasoning_trace(
    State(_state): State<AppState>,
    Json(_request): Json<CreateReasoningTraceRequest>,
) -> Result<(StatusCode, Json<ReasoningTraceResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Reasoning trace creation requires database".to_string(),
    })
}

// =============================================================================
// CREATE ANALYSIS
// =============================================================================

/// Request to create an analysis record
#[derive(Deserialize)]
pub struct CreateAnalysisRequest {
    /// Type of analysis (e.g. "CDST_coverage", "cross_source_corroboration")
    pub analysis_type: String,
    /// Description of the analytical method used
    pub method_description: String,
    /// Inference path taken (e.g. "evidence → interpretation → conclusion")
    pub inference_path: String,
    /// Agent that performed the analysis
    pub agent_id: Uuid,
    /// Evidence IDs that were input to this analysis
    pub input_evidence_ids: Vec<Uuid>,
    /// Claim IDs that this analysis concludes
    pub claim_ids: Option<Vec<Uuid>>,
    /// Optional constraints or limitations
    pub constraints: Option<String>,
    /// Coverage context metadata
    pub coverage_context: Option<serde_json::Value>,
    /// Additional properties
    pub properties: Option<serde_json::Value>,
}

/// Analysis creation response
#[derive(Serialize)]
pub struct CreateAnalysisResponse {
    pub id: Uuid,
    pub analysis_type: String,
    pub agent_id: Uuid,
    pub input_evidence_count: usize,
    pub claim_count: usize,
    pub created_at: String,
}

/// Create a new analysis record with links to evidence and claims
///
/// POST /api/v1/analyses
#[cfg(feature = "db")]
pub async fn create_analysis(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreateAnalysisRequest>,
) -> Result<(StatusCode, Json<CreateAnalysisResponse>), ApiError> {
    use epigraph_db::AnalysisRepository;

    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    if request.analysis_type.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "analysis_type".to_string(),
            reason: "analysis_type cannot be empty".to_string(),
        });
    }

    let now = chrono::Utc::now();
    let analysis = epigraph_db::AnalysisRecord {
        id: Uuid::new_v4(),
        analysis_type: request.analysis_type.clone(),
        method_description: request.method_description,
        inference_path: request.inference_path,
        constraints: request.constraints,
        coverage_context: request.coverage_context.unwrap_or(serde_json::json!({})),
        input_evidence_ids: request.input_evidence_ids.clone(),
        agent_id: request.agent_id,
        properties: request.properties.unwrap_or(serde_json::json!({})),
        created_at: now,
    };

    let claim_ids = request.claim_ids.unwrap_or_default();

    // Persist analysis + edges atomically
    let analysis_id = AnalysisRepository::persist_bundle(
        &state.db_pool,
        &analysis,
        &claim_ids,
        &request.input_evidence_ids,
    )
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to persist analysis bundle: {e}"),
    })?;

    // Record provenance
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let hash = blake3::hash(analysis_id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "analysis",
            analysis_id,
            "create",
            hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(analysis_id = %analysis_id, error = %e, "Failed to record analysis provenance");
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(CreateAnalysisResponse {
            id: analysis_id,
            analysis_type: request.analysis_type,
            agent_id: request.agent_id,
            input_evidence_count: request.input_evidence_ids.len(),
            claim_count: claim_ids.len(),
            created_at: now.to_rfc3339(),
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn create_analysis(
    State(_state): State<AppState>,
    Json(_request): Json<CreateAnalysisRequest>,
) -> Result<(StatusCode, Json<CreateAnalysisResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Analysis creation requires database".to_string(),
    })
}

// =============================================================================
// UPSERT CLUSTER ASSIGNMENT
// =============================================================================

/// Request to assign a claim to a cluster
#[derive(Deserialize)]
pub struct UpsertClusterRequest {
    /// Claim ID to assign to a cluster
    pub claim_id: Uuid,
    /// Cluster label (e.g. "molecular_biology", "quantum_mechanics")
    pub cluster_label: String,
    /// Similarity score to cluster centroid [0.0, 1.0]
    pub similarity: Option<f64>,
    /// Additional metadata
    pub properties: Option<serde_json::Value>,
}

/// Upsert a claim's cluster assignment
///
/// POST /api/v1/clusters
///
/// Creates or updates a cluster assignment via WITHIN_FRAME edges to a frame
/// named after the cluster. If no frame exists for the cluster, creates one.
#[cfg(feature = "db")]
pub async fn upsert_cluster(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<UpsertClusterRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    use epigraph_db::FrameRepository;

    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    let frame_name = format!("cluster:{}", request.cluster_label);

    // Find or create the frame for this cluster
    let frame = FrameRepository::get_by_name(&state.db_pool, &frame_name).await?;
    let frame_id = match frame {
        Some(f) => f.id,
        None => {
            // Create a minimal 2-hypothesis frame (required by constraint)
            let created = FrameRepository::create(
                &state.db_pool,
                &frame_name,
                Some(&format!(
                    "Auto-created cluster frame for {}",
                    request.cluster_label
                )),
                &[
                    format!("in_{}", request.cluster_label),
                    format!("not_in_{}", request.cluster_label),
                ],
            )
            .await?;
            created.id
        }
    };

    // Assign claim to frame (hypothesis_index 0 = "in cluster")
    FrameRepository::assign_claim(&state.db_pool, request.claim_id, frame_id, Some(0)).await?;

    // Record provenance
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let hash = blake3::hash(request.claim_id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "claim",
            request.claim_id,
            "cluster_assign",
            hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(claim_id = %request.claim_id, error = %e, "Failed to record cluster provenance");
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "claim_id": request.claim_id,
            "frame_id": frame_id,
            "cluster_label": request.cluster_label,
            "assigned": true,
        })),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn upsert_cluster(
    State(_state): State<AppState>,
    Json(_request): Json<UpsertClusterRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Cluster assignment requires database".to_string(),
    })
}

// =============================================================================
// ASSIGN CLAIM TO FRAME
// =============================================================================

/// Request to assign a claim to a frame
#[derive(Deserialize)]
pub struct AssignClaimToFrameRequest {
    pub claim_id: Uuid,
    /// Which hypothesis index this claim maps to (optional)
    pub hypothesis_index: Option<i32>,
}

/// Assign a claim to a frame
///
/// POST /api/v1/frames/:id/assign-claim
#[cfg(feature = "db")]
pub async fn assign_claim_to_frame(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(frame_id): Path<Uuid>,
    Json(request): Json<AssignClaimToFrameRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    use epigraph_db::FrameRepository;

    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    // Verify frame exists
    FrameRepository::get_by_id(&state.db_pool, frame_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Frame".to_string(),
            id: frame_id.to_string(),
        })?;

    FrameRepository::assign_claim(
        &state.db_pool,
        request.claim_id,
        frame_id,
        request.hypothesis_index,
    )
    .await?;

    // Record provenance
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let hash = blake3::hash(request.claim_id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "frame",
            frame_id,
            "assign_claim",
            hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(frame_id = %frame_id, error = %e, "Failed to record frame assign provenance");
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "claim_id": request.claim_id,
            "frame_id": frame_id,
            "hypothesis_index": request.hypothesis_index,
            "assigned": true,
        })),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn assign_claim_to_frame(
    State(_state): State<AppState>,
    Path(_frame_id): Path<Uuid>,
    Json(_request): Json<AssignClaimToFrameRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Frame assignment requires database".to_string(),
    })
}

// =============================================================================
// PROMOTE STAGED EDGES
// =============================================================================

/// Request to promote approved staged edges to production
#[derive(Deserialize)]
pub struct PromoteStagedEdgesRequest {
    /// Optional list of specific staging edge IDs to promote.
    /// If omitted, promotes all edges with review_status = 'approved'.
    pub edge_ids: Option<Vec<Uuid>>,
}

/// Promote approved staged edges to the production edges table
///
/// POST /api/v1/edges-staging/promote
///
/// Copies approved edges from edges_staging to edges, then marks them as 'promoted'.
#[cfg(feature = "db")]
pub async fn promote_staged_edges(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<PromoteStagedEdgesRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["edges:write"])?;
    }

    // Build the query based on whether specific IDs were provided
    let promoted_count: i64 = if let Some(ref ids) = request.edge_ids {
        if ids.is_empty() {
            return Err(ApiError::ValidationError {
                field: "edge_ids".to_string(),
                reason: "edge_ids array must not be empty when provided".to_string(),
            });
        }

        // Promote specific IDs (must be 'approved')
        let result = sqlx::query_scalar::<_, i64>(
            "WITH to_promote AS (
                SELECT id, source_id, source_type, target_id, target_type,
                       relationship, properties
                FROM edges_staging
                WHERE id = ANY($1) AND review_status = 'approved'
            ),
            inserted AS (
                INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
                SELECT source_id, source_type, target_id, target_type, relationship, properties
                FROM to_promote
                ON CONFLICT DO NOTHING
                RETURNING id
            ),
            updated AS (
                UPDATE edges_staging
                SET review_status = 'promoted', reviewed_at = NOW()
                WHERE id IN (SELECT id FROM to_promote)
            )
            SELECT COUNT(*) FROM to_promote",
        )
        .bind(ids)
        .fetch_one(&state.db_pool)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to promote staged edges: {e}"),
        })?;
        result
    } else {
        // Promote all approved
        let result = sqlx::query_scalar::<_, i64>(
            "WITH to_promote AS (
                SELECT id, source_id, source_type, target_id, target_type,
                       relationship, properties
                FROM edges_staging
                WHERE review_status = 'approved'
            ),
            inserted AS (
                INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
                SELECT source_id, source_type, target_id, target_type, relationship, properties
                FROM to_promote
                ON CONFLICT DO NOTHING
                RETURNING id
            ),
            updated AS (
                UPDATE edges_staging
                SET review_status = 'promoted', reviewed_at = NOW()
                WHERE id IN (SELECT id FROM to_promote)
            )
            SELECT COUNT(*) FROM to_promote",
        )
        .fetch_one(&state.db_pool)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to promote staged edges: {e}"),
        })?;
        result
    };

    Ok(Json(serde_json::json!({
        "promoted_count": promoted_count,
        "status": "ok",
    })))
}

#[cfg(not(feature = "db"))]
pub async fn promote_staged_edges(
    State(_state): State<AppState>,
    Json(_request): Json<PromoteStagedEdgesRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Edge promotion requires database".to_string(),
    })
}

// =============================================================================
// BOUNDARY CLAIMS (cluster-level misplacement detection)
// =============================================================================

/// Query parameters for `GET /api/v1/clusters/boundary-claims`
#[derive(Deserialize)]
pub struct BoundaryClaimsQuery {
    /// Minimum boundary_ratio threshold (default 0.90)
    pub min_boundary_ratio: Option<f64>,
    /// Minimum centroid_distance threshold (default 0.45)
    pub min_centroid_distance: Option<f64>,
    /// Maximum results (default 500)
    pub limit: Option<i64>,
}

/// Get claims with high boundary_ratio and centroid_distance.
///
/// GET /api/v1/clusters/boundary-claims
///
/// Returns claims that sit on cluster boundaries and are far from their
/// assigned centroid — candidates for theme reassignment.
#[cfg(feature = "db")]
pub async fn get_boundary_claims(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    axum::extract::Query(params): axum::extract::Query<BoundaryClaimsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:read"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    let min_br = params.min_boundary_ratio.unwrap_or(0.90);
    let min_cd = params.min_centroid_distance.unwrap_or(0.45);
    let limit = params.limit.unwrap_or(500).min(500);

    let rows =
        ClaimThemeRepository::find_boundary_claims(&state.db_pool, min_br, min_cd, limit).await?;

    let results: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "claim_id": r.claim_id,
                "theme_id": r.theme_id,
                "boundary_ratio": r.boundary_ratio,
                "centroid_distance": r.centroid_distance,
                "content_preview": r.content_preview,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "count": results.len(),
        "claims": results,
    })))
}

#[cfg(not(feature = "db"))]
pub async fn get_boundary_claims(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    axum::extract::Query(_params): axum::extract::Query<BoundaryClaimsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Boundary claims requires database".to_string(),
    })
}

// =============================================================================
// THEME REASSIGNMENT
// =============================================================================

/// Request to evaluate/execute theme reassignment for a single claim.
#[derive(Deserialize)]
pub struct ReassignClaimRequest {
    /// Claim to evaluate for reassignment
    pub claim_id: Uuid,
    /// If true, actually perform the reassignment. If false, dry-run preview.
    #[serde(default)]
    pub execute: bool,
    /// Improvement ratio threshold — reassign if best_alt / current < this (default 0.85)
    pub improvement_threshold: Option<f64>,
    /// Current distance threshold for untheming outliers (default 0.60)
    pub outlier_distance: Option<f64>,
    /// Alternative distance threshold below which a theme is "good enough" (default 0.50)
    pub alt_distance_cap: Option<f64>,
}

/// Evaluate and optionally reassign a claim to a better-fitting theme.
///
/// POST /api/v1/themes/reassign
///
/// Fetches the claim's embedding, compares distance to current theme vs
/// top-5 alternative themes. Auto-reassigns if improvement exceeds threshold,
/// unthemes if claim is an outlier everywhere, or leaves in place.
#[cfg(feature = "db")]
pub async fn reassign_claim(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<ReassignClaimRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    let improvement_threshold = request.improvement_threshold.unwrap_or(0.85);
    let outlier_distance = request.outlier_distance.unwrap_or(0.60);
    let alt_distance_cap = request.alt_distance_cap.unwrap_or(0.50);

    // Get claim's embedding as pgvector string
    let emb_str =
        ClaimThemeRepository::get_claim_embedding_str(&state.db_pool, request.claim_id).await?;

    let emb_str = match emb_str {
        Some(e) => e,
        None => {
            return Ok(Json(serde_json::json!({
                "claim_id": request.claim_id,
                "action": "skipped",
                "reason": "claim has no embedding",
                "executed": false,
            })));
        }
    };

    // Get current theme distance
    let current_distance =
        ClaimThemeRepository::get_claim_theme_distance(&state.db_pool, request.claim_id).await?;

    // Get current theme_id and label
    let current_theme = sqlx::query(
        "SELECT c.theme_id, COALESCE(ct.label, '') AS label \
         FROM claims c \
         LEFT JOIN claim_themes ct ON c.theme_id = ct.id \
         WHERE c.id = $1",
    )
    .bind(request.claim_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(epigraph_db::errors::DbError::from)?;

    let (current_theme_id, current_theme_label): (Option<Uuid>, String) = match current_theme {
        Some(row) => {
            use sqlx::Row;
            (row.get("theme_id"), row.get("label"))
        }
        None => {
            return Ok(Json(serde_json::json!({
                "claim_id": request.claim_id,
                "action": "skipped",
                "reason": "claim not found",
                "executed": false,
            })));
        }
    };

    // Find top-5 similar themes
    let similar = ClaimThemeRepository::find_similar_themes(&state.db_pool, &emb_str, 5).await?;

    // Find best alternative (different from current theme)
    let best_alt = similar
        .iter()
        .find(|(id, _, _)| current_theme_id != Some(*id));

    let current_dist = current_distance.unwrap_or(1.0);

    // Decision logic
    let (action, new_theme_id, new_theme_label, best_alt_distance, improvement_ratio) =
        match best_alt {
            Some((alt_id, alt_label, alt_similarity)) => {
                let alt_dist = 1.0 - alt_similarity; // similarity to distance
                let ratio = if current_dist > 0.0 {
                    alt_dist / current_dist
                } else {
                    1.0
                };

                if ratio < improvement_threshold {
                    // Best alt is significantly closer — reassign
                    (
                        "reassigned",
                        Some(*alt_id),
                        alt_label.clone(),
                        alt_dist,
                        ratio,
                    )
                } else if current_dist > outlier_distance && alt_dist > alt_distance_cap {
                    // Far from everything — untheme
                    ("unthemed", None::<Uuid>, String::new(), alt_dist, ratio)
                } else {
                    // Marginal improvement — leave in place
                    (
                        "kept",
                        current_theme_id,
                        current_theme_label.clone(),
                        alt_dist,
                        ratio,
                    )
                }
            }
            None => {
                // No alternative themes exist
                if current_dist > outlier_distance {
                    ("unthemed", None::<Uuid>, String::new(), 1.0, 1.0)
                } else {
                    (
                        "kept",
                        current_theme_id,
                        current_theme_label.clone(),
                        1.0,
                        1.0,
                    )
                }
            }
        };

    // Execute if requested
    let executed = if request.execute && action != "kept" {
        match action {
            "reassigned" => {
                if let Some(new_id) = new_theme_id {
                    ClaimThemeRepository::assign_claim(&state.db_pool, request.claim_id, new_id)
                        .await?;
                }
                true
            }
            "unthemed" => {
                ClaimThemeRepository::unassign_claim(&state.db_pool, request.claim_id).await?;
                true
            }
            _ => false,
        }
    } else {
        false
    };

    Ok(Json(serde_json::json!({
        "claim_id": request.claim_id,
        "current_theme_id": current_theme_id,
        "current_theme_label": current_theme_label,
        "current_distance": current_dist,
        "best_alternative_theme_id": new_theme_id,
        "best_alternative_label": new_theme_label,
        "best_alternative_distance": best_alt_distance,
        "improvement_ratio": improvement_ratio,
        "action": action,
        "executed": executed,
    })))
}

#[cfg(not(feature = "db"))]
pub async fn reassign_claim(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(_request): Json<ReassignClaimRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Theme reassignment requires database".to_string(),
    })
}

// =============================================================================
// THEME MAINTENANCE: BUILD FROM CORPUS
// =============================================================================

/// Request to bootstrap themes from the existing corpus by k-means.
#[derive(Deserialize)]
pub struct BuildThemesFromCorpusRequest {
    /// If `Some`, fit k-means with exactly this many clusters. If `None`,
    /// search `k_min..=k_max` and pick the best inertia (elbow-penalized).
    pub k: Option<usize>,
    /// Lower bound when searching k. Default 4.
    pub k_min: Option<usize>,
    /// Upper bound when searching k. Default 16.
    pub k_max: Option<usize>,
    /// Skip clusters with fewer than this many claims (no theme created;
    /// claims left unthemed). Default 5.
    pub min_claims_per_theme: Option<usize>,
    /// Cap on claims pulled into k-means. Default 500. Higher values risk
    /// OOM on small VMs (the calibration done on the wrhq deployment OOMs
    /// the kernel host above ~2000 embeddings).
    pub limit: Option<i64>,
    /// Theme labels are auto-named `"{prefix}-{idx}"`. Default `"auto"`.
    pub label_prefix: Option<String>,
    /// If true, `DELETE FROM claim_themes` before building. Default false —
    /// callers that want a clean slate must opt in explicitly.
    pub wipe_first: Option<bool>,
}

/// k-means bootstrap of `claim_themes` from the existing corpus. Required
/// before `/api/v1/search/semantic?diverse=true` can return diverse-by-
/// theme results on a fresh deployment.
///
/// Synchronous: blocks the HTTP request until k-means + theme creation
/// finishes. Sub-second on the wrhq-scale corpus (1607 claims, 1536d).
/// Larger corpora should expect tens of seconds and may OOM small VMs;
/// see the `limit` field on the request.
///
/// **Quality caveat**: themes built from `claims.embedding` (currently
/// `vector(1536)`) sit at the `text-embedding-3-small` noise floor on
/// short hierarchical claims (#48 part 2 — widening to 3072d is a
/// separate migration). Bootstrap works, but the resulting themes will
/// be lower-quality than 3072d would produce.
///
/// POST /api/v1/themes/build-from-corpus
#[cfg(feature = "db")]
pub async fn build_themes_from_corpus(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<BuildThemesFromCorpusRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use linfa::prelude::*;
    use linfa_clustering::KMeans;
    use ndarray::Array2;

    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    let k_min = request.k_min.unwrap_or(4);
    let k_max = request.k_max.unwrap_or(16);
    let min_claims = request.min_claims_per_theme.unwrap_or(5);
    let limit = request.limit.unwrap_or(500).max(1);
    let label_prefix = request
        .label_prefix
        .unwrap_or_else(|| "auto".to_string());
    let wipe_first = request.wipe_first.unwrap_or(false);

    if k_min == 0 || k_max < k_min {
        return Err(ApiError::BadRequest {
            message: "k_min must be ≥1 and k_max ≥ k_min".to_string(),
        });
    }

    if wipe_first {
        epigraph_db::ClaimThemeRepository::delete_all(&state.db_pool).await?;
    }

    // 1. Pull claims with embeddings.
    let rows: Vec<(Uuid, Vec<f32>)> = sqlx::query_as(
        "SELECT id, embedding::text::float4[] \
         FROM claims \
         WHERE embedding IS NOT NULL \
         ORDER BY id \
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch claim embeddings: {e}"),
    })?;

    let n_claims = rows.len();
    if n_claims < k_min {
        return Ok(Json(serde_json::json!({
            "themes_created": 0,
            "claims_assigned": 0,
            "k_used": null,
            "claims_with_embeddings": n_claims,
            "skipped_reason": format!("only {} claims with embeddings (need ≥ k_min={})", n_claims, k_min),
        })));
    }

    // 2. Build the dense matrix.
    let dim = rows[0].1.len();
    let mut data = Array2::<f64>::zeros((n_claims, dim));
    for (i, (_, emb)) in rows.iter().enumerate() {
        if emb.len() != dim {
            return Err(ApiError::InternalError {
                message: format!(
                    "embedding dim mismatch at claim {}: got {}, expected {}",
                    rows[i].0, emb.len(), dim,
                ),
            });
        }
        for (j, &v) in emb.iter().enumerate() {
            data[[i, j]] = f64::from(v);
        }
    }
    let dataset = linfa::DatasetBase::from(data.view());

    // 3. Pick k. Either explicit or elbow-penalized search.
    let actual_k_max = k_max.min(n_claims);
    let chosen_k = if let Some(k) = request.k {
        if k == 0 || k > n_claims {
            return Err(ApiError::BadRequest {
                message: format!("k must be in 1..={n_claims}"),
            });
        }
        k
    } else {
        let mut best_k = k_min;
        let mut best_score = f64::NEG_INFINITY;
        for k in k_min..=actual_k_max {
            let model = KMeans::params(k)
                .max_n_iterations(100)
                .tolerance(1e-4)
                .fit(&dataset)
                .map_err(|e| ApiError::InternalError {
                    message: format!("k-means fit failed at k={k}: {e}"),
                })?;
            let labels: Vec<usize> = model.predict(&dataset).iter().copied().collect();
            let centroids = model.centroids();
            let mut total_dist = 0.0;
            for (i, label) in labels.iter().enumerate() {
                let centroid = centroids.row(*label);
                let point = data.row(i);
                let dist: f64 = point
                    .iter()
                    .zip(centroid.iter())
                    .map(|(a, b)| (a - b).powi(2))
                    .sum();
                total_dist += dist;
            }
            let inertia = -total_dist / n_claims as f64;
            // Elbow penalty: discourage runaway k.
            let penalized = inertia * (1.0 - 0.05 * k as f64);
            if penalized > best_score {
                best_score = penalized;
                best_k = k;
            }
        }
        best_k
    };

    // 4. Final fit at chosen_k.
    let model = KMeans::params(chosen_k)
        .max_n_iterations(200)
        .tolerance(1e-5)
        .fit(&dataset)
        .map_err(|e| ApiError::InternalError {
            message: format!("Final k-means fit failed at k={chosen_k}: {e}"),
        })?;
    let labels: Vec<usize> = model.predict(&dataset).iter().copied().collect();
    let centroids = model.centroids();

    // 5. Persist: theme per cluster, then bulk-assign claim_ids.
    let mut themes_created = 0_usize;
    let mut claims_assigned = 0_usize;

    for cluster_idx in 0..chosen_k {
        let cluster_claim_ids: Vec<Uuid> = labels
            .iter()
            .enumerate()
            .filter(|(_, &l)| l == cluster_idx)
            .map(|(i, _)| rows[i].0)
            .collect();

        if cluster_claim_ids.len() < min_claims {
            continue;
        }

        let theme_label = format!("{label_prefix}-{cluster_idx:02}");
        let theme_description = format!(
            "Auto-built from {} claims by k-means at k={} (1536d embedding)",
            cluster_claim_ids.len(),
            chosen_k,
        );
        let theme = epigraph_db::ClaimThemeRepository::create(
            &state.db_pool,
            &theme_label,
            &theme_description,
        )
        .await?;

        let centroid_row = centroids.row(cluster_idx);
        let centroid_str = format!(
            "[{}]",
            centroid_row
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        epigraph_db::ClaimThemeRepository::set_centroid(
            &state.db_pool,
            theme.id,
            &centroid_str,
        )
        .await?;

        let assigned = epigraph_db::ClaimThemeRepository::bulk_assign(
            &state.db_pool,
            &cluster_claim_ids,
            theme.id,
        )
        .await?;
        epigraph_db::ClaimThemeRepository::update_count(
            &state.db_pool,
            theme.id,
            assigned as i32,
        )
        .await?;

        themes_created += 1;
        claims_assigned += assigned as usize;
    }

    Ok(Json(serde_json::json!({
        "themes_created": themes_created,
        "claims_assigned": claims_assigned,
        "k_used": chosen_k,
        "claims_with_embeddings": n_claims,
        "centroid_dim": dim,
    })))
}

#[cfg(not(feature = "db"))]
pub async fn build_themes_from_corpus(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(_request): Json<BuildThemesFromCorpusRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Build themes requires database".to_string(),
    })
}

// =============================================================================
// THEME MAINTENANCE: ASSIGN UNTHEMED
// =============================================================================

/// Request for batch assignment of unthemed claims.
#[derive(Deserialize)]
pub struct AssignUnthemedRequest {
    /// Batch size per iteration (default 500)
    pub batch_size: Option<i64>,
}

/// Assign all unthemed claims (with embeddings) to their nearest theme centroid.
///
/// POST /api/v1/themes/assign-unthemed
///
/// Loops internally in batches until no more unthemed claims remain.
/// Returns total count of newly assigned claims.
#[cfg(feature = "db")]
pub async fn assign_unthemed(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<AssignUnthemedRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    let batch_size = request.batch_size.unwrap_or(500).min(1000);
    let mut total = 0i64;

    loop {
        let assigned =
            ClaimThemeRepository::assign_unthemed_batch(&state.db_pool, batch_size).await?;

        if assigned == 0 {
            break;
        }
        total += assigned;
    }

    Ok(Json(serde_json::json!({
        "assigned": total,
    })))
}

#[cfg(not(feature = "db"))]
pub async fn assign_unthemed(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(_request): Json<AssignUnthemedRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Assign unthemed requires database".to_string(),
    })
}

// =============================================================================
// THEME MAINTENANCE: RECOMPUTE CENTROIDS
// =============================================================================

/// Request for centroid recomputation.
#[derive(Deserialize)]
pub struct RecomputeCentroidsRequest {
    /// If provided, only recompute these themes. If omitted, recompute all.
    pub theme_ids: Option<Vec<Uuid>>,
}

/// Recompute theme centroids as avg(member embeddings).
///
/// POST /api/v1/themes/recompute-centroids
///
/// If theme_ids provided, only recompute those. Otherwise recompute all.
#[cfg(feature = "db")]
pub async fn recompute_centroids(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<RecomputeCentroidsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    let themes = match request.theme_ids {
        Some(ids) => {
            let mut results = Vec::new();
            for id in &ids {
                if let Some((label, count)) =
                    ClaimThemeRepository::recompute_centroid_for_theme(&state.db_pool, *id).await?
                {
                    results.push(serde_json::json!({
                        "id": id,
                        "label": label,
                        "claim_count": count,
                    }));
                }
            }
            results
        }
        None => {
            let rows = ClaimThemeRepository::recompute_all_centroids(&state.db_pool).await?;
            rows.iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "label": r.label,
                        "claim_count": r.claim_count,
                    })
                })
                .collect()
        }
    };

    Ok(Json(serde_json::json!({
        "updated": themes.len(),
        "themes": themes,
    })))
}

#[cfg(not(feature = "db"))]
pub async fn recompute_centroids(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(_request): Json<RecomputeCentroidsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Recompute centroids requires database".to_string(),
    })
}

// =============================================================================
// THEME MAINTENANCE: ANALYTICS (read-only)
// =============================================================================

/// Query params for split candidates.
#[derive(Deserialize)]
pub struct SplitCandidatesQuery {
    pub variance_threshold: Option<f64>,
    pub min_claims: Option<i64>,
    pub limit: Option<i64>,
}

/// Find themes with high intra-cluster variance.
///
/// GET /api/v1/themes/split-candidates
#[cfg(feature = "db")]
pub async fn get_split_candidates(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    axum::extract::Query(params): axum::extract::Query<SplitCandidatesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:read"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    let rows = ClaimThemeRepository::find_split_candidates(
        &state.db_pool,
        params.variance_threshold.unwrap_or(0.35),
        params.min_claims.unwrap_or(500),
        params.limit.unwrap_or(20),
    )
    .await?;

    let candidates: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "theme_id": r.theme_id,
                "label": r.label,
                "claim_count": r.claim_count,
                "avg_distance": r.avg_distance,
                "max_distance": r.max_distance,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "candidates": candidates })))
}

#[cfg(not(feature = "db"))]
pub async fn get_split_candidates(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    axum::extract::Query(_params): axum::extract::Query<SplitCandidatesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Split candidates requires database".to_string(),
    })
}

/// Query params for distant claims.
#[derive(Deserialize)]
pub struct DistantClaimsQuery {
    pub distance_threshold: Option<f64>,
    pub min_cluster_size: Option<i64>,
    pub limit: Option<i64>,
}

/// Find themes with many claims far from their centroid.
///
/// GET /api/v1/themes/distant-claims
#[cfg(feature = "db")]
pub async fn get_distant_claims(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    axum::extract::Query(params): axum::extract::Query<DistantClaimsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:read"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    let rows = ClaimThemeRepository::find_distant_claims(
        &state.db_pool,
        params.distance_threshold.unwrap_or(0.45),
        params.min_cluster_size.unwrap_or(20),
        params.limit.unwrap_or(20),
    )
    .await?;

    let candidates: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "source_theme": r.source_theme,
                "distant_claims": r.distant_claims,
                "avg_distance": r.avg_distance,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "candidates": candidates })))
}

#[cfg(not(feature = "db"))]
pub async fn get_distant_claims(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    axum::extract::Query(_params): axum::extract::Query<DistantClaimsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Distant claims requires database".to_string(),
    })
}

/// Query params for theme embeddings.
#[derive(Deserialize)]
pub struct ThemeEmbeddingsQuery {
    pub limit: Option<i64>,
}

/// Get claim IDs and embeddings for a theme (for client-side k-means).
///
/// GET /api/v1/themes/:id/embeddings
#[cfg(feature = "db")]
pub async fn get_theme_embeddings(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(theme_id): Path<Uuid>,
    axum::extract::Query(params): axum::extract::Query<ThemeEmbeddingsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:read"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    let limit = params.limit.unwrap_or(5000).min(5000);
    let rows = ClaimThemeRepository::get_theme_embeddings(&state.db_pool, theme_id, limit).await?;

    let claims: Vec<serde_json::Value> = rows
        .iter()
        .map(|(id, emb_str)| {
            // Parse pgvector text "[0.1,0.2,...]" to JSON array
            let nums: Vec<f64> = emb_str
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .filter_map(|s| s.trim().parse::<f64>().ok())
                .collect();
            serde_json::json!({
                "id": id,
                "embedding": nums,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "count": claims.len(),
        "claims": claims,
    })))
}

#[cfg(not(feature = "db"))]
pub async fn get_theme_embeddings(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(_theme_id): Path<Uuid>,
    axum::extract::Query(_params): axum::extract::Query<ThemeEmbeddingsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Theme embeddings requires database".to_string(),
    })
}

// =============================================================================
// THEME MAINTENANCE: CREATE WITH CENTROID
// =============================================================================

/// Request to create a theme with centroid and assign claims.
#[derive(Deserialize)]
pub struct CreateThemeWithCentroidRequest {
    pub label: String,
    pub description: String,
    pub centroid: Vec<f64>,
    pub claim_ids: Vec<Uuid>,
}

/// Create a new theme with centroid and bulk-assign claims.
///
/// POST /api/v1/themes/create-with-centroid
///
/// Used by auto-split to persist k-means results.
#[cfg(feature = "db")]
pub async fn create_theme_with_centroid(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreateThemeWithCentroidRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    // Create theme
    let theme =
        ClaimThemeRepository::create(&state.db_pool, &request.label, &request.description).await?;

    // Set centroid (convert Vec<f64> to pgvector string)
    let centroid_str = format!(
        "[{}]",
        request
            .centroid
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    ClaimThemeRepository::set_centroid(&state.db_pool, theme.id, &centroid_str).await?;

    // Bulk assign claims
    let assigned =
        ClaimThemeRepository::bulk_assign(&state.db_pool, &request.claim_ids, theme.id).await?;

    // Update count
    ClaimThemeRepository::update_count(&state.db_pool, theme.id, assigned as i32).await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "theme_id": theme.id,
            "label": theme.label,
            "claim_count": assigned,
        })),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn create_theme_with_centroid(
    State(_state): State<AppState>,
    _auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(_request): Json<CreateThemeWithCentroidRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Create theme requires database".to_string(),
    })
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "db"))]
mod tests {
    use super::*;
    use crate::state::{AppState, ApiConfig};

    async fn try_test_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .ok()?;
        sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    macro_rules! test_pool_or_skip {
        () => {{
            match try_test_pool().await {
                Some(p) => p,
                None => {
                    eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                    return;
                }
            }
        }};
    }

    /// Empty-corpus path: when no claim has an embedding, build-from-corpus
    /// returns 0 themes and 0 assigned with a `skipped_reason`. This is the
    /// path operators hit on a fresh deployment before any document has
    /// been ingested + embedded; it must succeed (200), not error.
    #[tokio::test]
    async fn build_themes_from_corpus_empty_corpus_returns_zero_themes() {
        let pool = test_pool_or_skip!();
        // Clear any prior claims to make the empty-corpus assertion stable.
        let _ = sqlx::query("UPDATE claims SET embedding = NULL")
            .execute(&pool)
            .await;

        let state = AppState::with_db(pool, ApiConfig::default());
        let result = build_themes_from_corpus(
            axum::extract::State(state),
            None,
            axum::Json(BuildThemesFromCorpusRequest {
                k: None,
                k_min: Some(2),
                k_max: Some(4),
                min_claims_per_theme: None,
                limit: Some(100),
                label_prefix: None,
                wipe_first: Some(false),
            }),
        )
        .await
        .expect("build-from-corpus must succeed on empty corpus");

        let body = result.0;
        assert_eq!(body["themes_created"], serde_json::json!(0));
        assert_eq!(body["claims_assigned"], serde_json::json!(0));
        assert!(body.get("skipped_reason").is_some());
    }
}
