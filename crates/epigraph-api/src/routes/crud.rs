//! CRUD endpoints for entities missing create/update routes.
//!
//! - `GET  /api/v1/evidence` — List evidence (paged, filtered, redacted)
//! - `POST /api/v1/evidence` — Create evidence record
//! - `PUT /api/v1/evidence/:id` — Update evidence (raw_content backfill)
//! - `POST /api/v1/reasoning-traces` — Create reasoning trace
//! - `POST /api/v1/analyses` — Create analysis record
//! - `POST /api/v1/clusters` — Upsert cluster assignment
//! - `POST /api/v1/frames/:id/assign-claim` — Assign claim to frame
//! - `POST /api/v1/edges-staging/promote` — Promote approved staged edges
//!
//! # Tenancy: 4 of this file's 40 raw-pool sites are converted
//!
//! Conversion shard 7. The four read-only `ClaimThemeRepository` handlers —
//! `get_boundary_claims`, `get_split_candidates`, `get_distant_claims` and
//! `get_theme_embeddings` — each run their single read on a viewer-stamped
//! connection from [`AppState::read_as`].
//!
//! **What that suppression is and is not, stated rather than implied.** Each of
//! those four statements joins `claim_themes` to `claims`, and the viewer
//! predicate is over `claims`. `claim_themes` is derived clustering output that
//! carries no tenancy columns and no RLS at migration head 92, so the filtering
//! these handlers gain is over the CLAIMS in a theme, never over the themes
//! themselves. Stamping the connection does not change that and is not claimed
//! to.
//!
//! The other 36 sites all sit in WRITE handlers — the densest write-blocked file
//! in the series. [`AppState::read_as`] is documented read-only and a write
//! routed through a `ScopedRead` is rolled back on drop under
//! `SessionGucMode::Transaction` while still type-checking; their owner is
//! `ScopedPool::begin_as` plus `Viewer::splice_write`.
//!
//! [`AppState::read_as`]: crate::AppState::read_as

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// LIST EVIDENCE
// =============================================================================

/// Query parameters for `GET /api/v1/evidence`.
#[derive(Debug, Default, Deserialize)]
pub struct ListEvidenceQuery {
    /// Restrict to evidence attached to this claim.
    pub claim_id: Option<Uuid>,
    /// Exact match on the stored `evidence_type` column. Vocabulary:
    /// `document`, `observation`, `testimony`, `computation`, `reference`,
    /// `figure`, `conversational` (the `evidence_type_valid` CHECK
    /// constraint). Note `Literature` is stored as `reference` and
    /// `Consensus` as `computation`.
    pub evidence_type: Option<String>,
    /// Case-insensitive substring match on `raw_content`. Rows with a NULL
    /// `raw_content` never match this predicate.
    pub content_contains: Option<String>,
    /// Page size; clamped to `[MIN_PAGE_LIMIT, MAX_PAGE_LIMIT]`.
    pub limit: Option<i64>,
    /// Rows to skip; negative values are clamped to 0.
    pub offset: Option<i64>,
}

/// One row of `GET /api/v1/evidence`.
///
/// Field set mirrors [`super::edges::get_evidence`]'s single-row response.
///
/// There is no `redacted` flag and no blanked `content`. A row the viewer
/// cannot see is ABSENT from this list, not present-and-emptied: the
/// visibility predicate runs inside the SQL, above `LIMIT`/`OFFSET`, so a
/// withheld row never reaches this struct. A per-row "you may not see this"
/// marker would reintroduce exactly the existence oracle the tenancy series
/// removed when it deleted the post-fetch redaction pass.
#[derive(Debug, Serialize)]
pub struct EvidenceListItem {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub evidence_type: String,
    pub content: Option<String>,
    pub content_hash: String,
    pub source_url: Option<String>,
    pub caption: Option<String>,
    /// `evidence.signer_id`; NULL for unsigned evidence.
    pub agent_id: Option<Uuid>,
    pub created_at: String,
}

/// Response body for `GET /api/v1/evidence`.
#[derive(Debug, Serialize)]
pub struct ListEvidenceResponse {
    pub evidence: Vec<EvidenceListItem>,
    /// Exact `COUNT(*)` over the same predicates, evaluated by PostgreSQL —
    /// NOT `evidence.len()`.
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// List evidence rows, paged and filtered.
///
/// `GET /api/v1/evidence?claim_id=…&evidence_type=…&content_contains=…&limit=…&offset=…`
///
/// Before this route existed the collection path carried only `post`, so a
/// `GET` fell through to axum's 405 and the 123k-row `evidence` table could
/// only be read one row at a time through `GET /api/v1/evidence/:id` (backlog
/// `d7aab418`). An export or redaction sweep had to either join from a claim
/// keep-set — which misses evidence whose claim is gone — or go around the API
/// with raw SQL, which the no-raw-SQL convention forbids.
///
/// # Tenancy
///
/// This is a BRAND-NEW public read route over `evidence`, a table that had no
/// collection reader at all before it. Evidence rows hold verbatim tool/API
/// transcripts and routinely name people the claim text never mentions, so an
/// unscoped version of this handler would expose the whole 123k-row table
/// corpus-wide in one request.
///
/// It is scoped the way every other read on this branch is: `ViewerExtractor`
/// supplies the viewer (and 401s an unauthenticated caller — there is no
/// anonymous `Viewer`), and BOTH the page and its `total` run through
/// `EvidenceRepository`'s shared `FILTER_WHERE`, which carries the visibility
/// marker. `evidence` is a migration-062 `tier_a` root, so it has real
/// `visibility` / `owner_group_id` columns to filter on.
///
/// The predicate is on the evidence row ITSELF, not on its linked claim. The
/// pre-tenancy draft of this handler gated on `evidence.claim_id` via the
/// now-deleted `check_content_access`; filtering the row directly is strictly
/// tighter and does not depend on the FK being populated.
///
/// Both statements run on ONE viewer-stamped connection from
/// [`AppState::read_as`] rather than the raw pool, so the in-query `$n`
/// predicate and the connection's tenancy GUCs agree under FORCEd RLS.
#[cfg(feature = "db")]
pub async fn list_evidence(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<ListEvidenceQuery>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
) -> Result<Json<ListEvidenceResponse>, ApiError> {
    // `else return Unauthorized` rather than `if let Some(..)`, deliberately.
    // The conditional form is a FAIL-OPEN scope site: absent an `AuthContext`
    // the check silently no-ops. `viewer_route_table_lint`'s
    // `fail_open_scope_check_sites_do_not_increase` ratchets the count of those
    // per file precisely so a new one cannot appear unnoticed, and crud.rs is
    // registered at 6.
    //
    // It is true that the conditional form would be unreachable here —
    // `ViewerExtractor` is this handler's FIRST extractor and
    // `ViewerExtractor::from_request_parts` returns `ApiError::Unauthorized`
    // when no `AuthContext` is present, so the body cannot run with
    // `auth_ctx == None`. Registering a 7th fail-open site on that reasoning
    // would make the guard's safety depend on extractor ORDERING, which is
    // invisible at the check itself and one reorder away from being false.
    // This form is safe on its own terms and keeps the register at 6.
    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["claims:read"])?;

    use epigraph_db::{EvidenceListFilter, EvidenceRepository};

    let limit = params
        .limit
        .unwrap_or(super::claims::DEFAULT_PAGE_LIMIT)
        .clamp(super::claims::MIN_PAGE_LIMIT, super::claims::MAX_PAGE_LIMIT);
    let offset = params.offset.unwrap_or(0).max(0);

    let filter = EvidenceListFilter {
        claim_id: params.claim_id,
        evidence_type: params.evidence_type.as_deref(),
        content_contains: params.content_contains.as_deref(),
    };

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "list_evidence",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Page and total run on the SAME connection and the SAME `FILTER_WHERE`,
    // so `total` describes exactly the population the page is drawn from —
    // including its visibility predicate.
    let rows =
        EvidenceRepository::list_filtered(&mut *read, &viewer, &filter, limit, offset).await?;
    let total = EvidenceRepository::count_filtered(&mut *read, &viewer, &filter).await?;

    let evidence: Vec<EvidenceListItem> = rows
        .into_iter()
        .map(|row| {
            let caption = row
                .properties
                .get("caption")
                .and_then(|v| v.as_str())
                .map(str::to_owned);

            EvidenceListItem {
                id: row.id,
                claim_id: row.claim_id,
                evidence_type: row.evidence_type,
                content: row.raw_content,
                content_hash: hex::encode(&row.content_hash),
                source_url: row.source_url,
                caption,
                agent_id: row.signer_id,
                created_at: row.created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(ListEvidenceResponse {
        evidence,
        total,
        limit,
        offset,
    }))
}

/// List evidence rows (no-database build).
///
/// Mirrors [`super::edges::get_evidence`]'s `cfg(not(feature = "db"))` twin:
/// the route stays registered so the path reports "no backing store" rather
/// than reverting to the 405 this change removed.
#[cfg(not(feature = "db"))]
pub async fn list_evidence(
    State(_state): State<AppState>,
    Query(_params): Query<ListEvidenceQuery>,
) -> Result<Json<ListEvidenceResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database".to_string(),
    })
}

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
///
/// # The write-side tenancy gate (PR-16, delivered as 16b)
///
/// This is the first handler behind the write-side predicate. Three things
/// changed and each is load-bearing:
///
/// * The `UPDATE` moved out of this file into
///   `EvidenceRepository::update_raw_content`, which carries a
///   `/* {WRITABLE:e} */` marker. A route handler cannot carry a marker — it
///   does not own the SQL — so a gate that lives here can only ever be a
///   second, separately-forgettable check. This is the same structural argument
///   `viewer_route_table_lint.rs` makes for reads.
/// * The scope check is unconditional. It was `if let Some(..) = auth_ctx { .. }`
///   with no `else`, which authorized nothing at all when the extension was
///   absent.
/// * A row the caller may not write is a **404, not a 403**. A 403 would confirm
///   that evidence with this id exists inside a group the caller cannot write
///   to, which is a disclosure the predicate was added to prevent.
///
/// The `record_provenance` block below deliberately keeps its
/// `if let Some(..) = auth_ctx` shape. It is auth-OPTIONAL audit, not
/// authorization, and it is counted by a different register.
#[cfg(feature = "db")]
pub async fn update_evidence(
    State(state): State<AppState>,
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateEvidenceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // An ABSENT auth context is a refusal, not a pass — the shape PR-18a
    // prescribes. This route is on the `protected` chain, so the branch is
    // unreachable today; writing it as a refusal is what stops the handler's
    // correctness from depending on which router chain it is registered on.
    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    // Accept either evidence:write or evidence:submit (naming inconsistency)
    if !auth.has_scope("evidence:write") && !auth.has_scope("evidence:submit") {
        return Err(crate::errors::ApiError::Forbidden {
            reason: "Missing required scope: evidence:write or evidence:submit".to_string(),
        });
    }

    let Some(ref content) = request.raw_content else {
        return Err(ApiError::ValidationError {
            field: "raw_content".to_string(),
            reason: "At least one field must be provided for update".to_string(),
        });
    };

    let updated = epigraph_db::repos::EvidenceRepository::update_raw_content(
        &state.db_pool,
        &viewer,
        id.into(),
        content,
    )
    .await?;

    if !updated {
        // Indistinguishable by design: "no such evidence" and "you may not write
        // this evidence" are the same answer.
        return Err(ApiError::NotFound {
            entity: "evidence".to_string(),
            id: id.to_string(),
        });
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<UpsertClusterRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    use epigraph_db::FrameRepository;

    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "upsert_cluster requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;

    let frame_name = format!("cluster:{}", request.cluster_label);

    // Find or create the frame for this cluster
    let frame = FrameRepository::get_by_name(&state.db_pool, &viewer, &frame_name).await?;
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
    {
        let hash = blake3::hash(request.claim_id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            &auth,
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(frame_id): Path<Uuid>,
    Json(request): Json<AssignClaimToFrameRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    use epigraph_db::FrameRepository;

    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "assign_claim_to_frame requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;

    // Verify frame exists
    FrameRepository::get_by_id(&state.db_pool, &viewer, frame_id)
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
    {
        let hash = blake3::hash(request.claim_id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            &auth,
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
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "promote_staged_edges requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;

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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
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

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_boundary_claims",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let rows =
        ClaimThemeRepository::find_boundary_claims(&mut *read, &viewer, min_br, min_cd, limit)
            .await?;

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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    _scope: crate::middleware::bearer::RequireScopeAdmin,
    Json(request): Json<ReassignClaimRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Scope gate ran in the extractor; if we reach the body, the caller has
    // `claims:admin`. See `RequireScopeAdmin` in `middleware::bearer`.

    use epigraph_db::ClaimThemeRepository;

    let improvement_threshold = request.improvement_threshold.unwrap_or(0.85);
    let outlier_distance = request.outlier_distance.unwrap_or(0.60);
    let alt_distance_cap = request.alt_distance_cap.unwrap_or(0.50);

    // Get claim's embedding as pgvector string
    let emb_str =
        ClaimThemeRepository::get_claim_embedding_str(&state.db_pool, &viewer, request.claim_id)
            .await?;

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
        ClaimThemeRepository::get_claim_theme_distance(&state.db_pool, &viewer, request.claim_id)
            .await?;

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
    /// Embedding dimension to source. `None` or `Some(1536)` uses the legacy
    /// `claims.embedding` column and writes to `claim_themes.centroid`.
    /// `Some(3072)` uses `claims.embedding_3072` and writes to
    /// `claim_themes.centroid_3072` (operator must run `epigraph-cli reembed`
    /// first, otherwise this returns 412 Precondition Failed).
    pub centroid_dim: Option<u32>,
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
    use epigraph_engine::theme_kmeans::{run_theme_kmeans, RunThemeKmeansConfig, ThemeKmeansError};

    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "build_themes_from_corpus requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;

    let config = RunThemeKmeansConfig {
        k: request.k.map(|k| u32::try_from(k).unwrap_or(u32::MAX)),
        k_min: request
            .k_min
            .map_or(4, |v| u32::try_from(v).unwrap_or(u32::MAX)),
        k_max: request
            .k_max
            .map_or(16, |v| u32::try_from(v).unwrap_or(u32::MAX)),
        min_claims_per_theme: request
            .min_claims_per_theme
            .map_or(5, |v| u32::try_from(v).unwrap_or(u32::MAX)),
        limit: request
            .limit
            .map_or(500, |v| u32::try_from(v.max(1)).unwrap_or(u32::MAX))
            .max(1),
        label_prefix: request.label_prefix.unwrap_or_else(|| "auto".to_string()),
        wipe_first: request.wipe_first.unwrap_or(false),
        centroid_dim: request.centroid_dim.unwrap_or(1536),
    };

    let summary = run_theme_kmeans(&state.db_pool, &config)
        .await
        .map_err(|e| match e {
            ThemeKmeansError::BadRequest(msg) => ApiError::BadRequest { message: msg },
            ThemeKmeansError::Centroid3072Empty => ApiError::BadRequest {
                message: e.to_string(),
            },
            ThemeKmeansError::Repo(repo_err) => ApiError::from(repo_err),
            other => ApiError::InternalError {
                message: other.to_string(),
            },
        })?;

    // Preserve byte-identical legacy JSON shape.
    //
    // - Skip path: `k_used` is JSON null and a `skipped_reason` field is
    //   emitted; `centroid_dim` is the *requested* config dim
    //   (`summary.centroid_dim` already reflects this on skip).
    // - Success path: `k_used` is the chosen integer; `centroid_dim` is
    //   the *measured* dim from the first row.  The original handler also
    //   omitted `skipped_reason` on this path — we do the same.
    let body = if let Some(k_used) = summary.k_used {
        serde_json::json!({
            "themes_created": summary.themes_created,
            "claims_assigned": summary.claims_assigned,
            "k_used": k_used,
            "claims_with_embeddings": summary.claims_with_embeddings,
            "centroid_dim": summary.centroid_dim,
        })
    } else {
        serde_json::json!({
            "themes_created": summary.themes_created,
            "claims_assigned": summary.claims_assigned,
            "k_used": serde_json::Value::Null,
            "claims_with_embeddings": summary.claims_with_embeddings,
            "centroid_dim": summary.centroid_dim,
            "skipped_reason": summary.skipped_reason.unwrap_or_default(),
        })
    };

    Ok(Json(body))
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<AssignUnthemedRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "assign_unthemed requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;

    use epigraph_db::ClaimThemeRepository;

    let batch_size = request.batch_size.unwrap_or(500).min(1000);
    let mut total = 0i64;

    loop {
        let assigned =
            ClaimThemeRepository::assign_unthemed_batch(&state.db_pool, &viewer, batch_size)
                .await?;

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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<RecomputeCentroidsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "recompute_centroids requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;

    use epigraph_db::ClaimThemeRepository;

    let themes = match request.theme_ids {
        Some(ids) => {
            let mut results = Vec::new();
            for id in &ids {
                if let Some((label, count)) =
                    ClaimThemeRepository::recompute_centroid_for_theme(&state.db_pool, &viewer, *id)
                        .await?
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
            let rows =
                ClaimThemeRepository::recompute_all_centroids(&state.db_pool, &viewer).await?;
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    axum::extract::Query(params): axum::extract::Query<SplitCandidatesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:read"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_split_candidates",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let rows = ClaimThemeRepository::find_split_candidates(
        &mut *read,
        &viewer,
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
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    axum::extract::Query(params): axum::extract::Query<DistantClaimsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["claims:read"])?;
    }

    use epigraph_db::ClaimThemeRepository;

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_distant_claims",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let rows = ClaimThemeRepository::find_distant_claims(
        &mut *read,
        &viewer,
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

/// Get claim IDs and a 2-D projection of their embeddings for a theme.
///
/// GET /api/v1/themes/:id/embeddings
///
/// # Why this returns a projection and not the vectors (plan §4.9 row 4)
///
/// This handler used to serialise the complete raw 1536-d `claims.embedding`
/// for up to 5000 claims, gated on `claims:read`. `PENDING_SERVICE_SCOPES`
/// grants `claims:read`, so every registrant could bulk-download the embedding
/// corpus — and embeddings are approximately invertible to the content they
/// encode. Tenancy filtering (`ClaimThemeRepository::get_theme_embeddings`
/// takes a `&Viewer`) bounds that to *within* a tenant; it does not make bulk
/// embedding export acceptable, which is why the plan rates it a blocker in all
/// three columns and assigns the fix here.
///
/// Two changes discharge it:
///
/// * The response carries `projection: [x, y]` — two floats — instead of
///   `embedding: [...1536 floats...]`. The projection is a deterministic 2-D
///   PCA (see [`crate::routes::projection`]) that preserves the dominant
///   separating axis k-means needs to split an oversized theme.
/// * The gate moves from `claims:read` to `claims:admin`, matching its sibling
///   `create_theme_with_centroid`. Theme maintenance is an operator activity.
///
/// The one real consumer, `scripts/maintain_themes.py::split_oversized_theme`,
/// used the raw vectors for two things: k-means labels (served by the
/// projection) and the resulting sub-theme centroids (now computed server-side
/// — `CreateThemeWithCentroidRequest::centroid` is optional, and omitting it
/// averages the claims' real embeddings in the database).
///
/// The scope check is deliberately **not** written as
/// `if let Some(auth) = auth_ctx { check_scopes(...) }`. That idiom performs no
/// authorization at all when `AuthContext` is absent, and is neutralized only
/// by `ViewerExtractor` running first and 401-ing — which makes an authz
/// control load-bearing on axum parameter order. It is `ok_or` here so the
/// control stands on its own.
#[cfg(feature = "db")]
pub async fn get_theme_embeddings(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(theme_id): Path<Uuid>,
    axum::extract::Query(params): axum::extract::Query<ThemeEmbeddingsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "theme embeddings require authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;

    use epigraph_db::ClaimThemeRepository;

    let limit = params.limit.unwrap_or(5000).min(5000);
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_theme_embeddings",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let rows =
        ClaimThemeRepository::get_theme_embeddings(&mut *read, &viewer, theme_id, limit).await?;

    // Parse pgvector text "[0.1,0.2,...]" into vectors for the projection.
    // These never leave this function: only the 2-D result is serialised.
    let vectors: Vec<Vec<f64>> = rows
        .iter()
        .map(|(_, emb_str)| {
            emb_str
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .filter_map(|s| s.trim().parse::<f64>().ok())
                .collect()
        })
        .collect();

    let projected = crate::routes::projection::project_to_2d(&vectors);

    let claims: Vec<serde_json::Value> = rows
        .iter()
        .zip(projected.iter())
        .map(|((id, _), xy)| {
            serde_json::json!({
                "id": id,
                "projection": [xy[0], xy[1]],
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "count": claims.len(),
        "dimensions": 2,
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
    /// Optional explicit centroid.
    ///
    /// Omit it (or send an empty array) to have the server average the
    /// `claim_ids`' own embeddings instead. That is now the preferred form:
    /// PR-07 stopped `GET /themes/:id/embeddings` returning raw vectors, so a
    /// theme-splitting client has nothing to average client-side, and the
    /// server has the real vectors anyway.
    #[serde(default)]
    pub centroid: Option<Vec<f64>>,
    pub claim_ids: Vec<Uuid>,
}

/// Create a new theme with centroid and bulk-assign claims.
///
/// POST /api/v1/themes/create-with-centroid
///
/// Used by auto-split to persist k-means results.
#[cfg(feature = "db")]
pub async fn create_theme_with_centroid(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreateThemeWithCentroidRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "create_theme_with_centroid requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;

    use epigraph_db::ClaimThemeRepository;

    // Create theme
    let theme =
        ClaimThemeRepository::create(&state.db_pool, &request.label, &request.description).await?;

    // Centroid: use the caller's vector when supplied, otherwise average the
    // claims' own embeddings server-side. The latter is the path a theme-split
    // client takes now that `/themes/:id/embeddings` no longer returns raw
    // vectors for it to average itself.
    match request.centroid.as_ref().filter(|c| !c.is_empty()) {
        Some(centroid) => {
            let centroid_str = format!(
                "[{}]",
                centroid
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            ClaimThemeRepository::set_centroid(&state.db_pool, theme.id, &centroid_str).await?;
        }
        None => {
            ClaimThemeRepository::set_centroid_from_claims(
                &state.db_pool,
                &viewer,
                theme.id,
                &request.claim_ids,
            )
            .await?;
        }
    }

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
