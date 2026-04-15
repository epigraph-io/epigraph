//! Claim versioning and supersession endpoints
//!
//! POST /api/v1/claims/:id/supersede - Create a new claim that supersedes an existing one
//! GET  /api/v1/claims/:id/history   - Get the full version history for a claim
//!
//! Supersession is the mechanism by which claims evolve over time. Rather than
//! mutating a claim in-place (which would break cryptographic integrity), a new
//! claim is created that explicitly supersedes the old one. This preserves the
//! full epistemic history: every version of a belief is recorded and traceable.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;
use epigraph_core::{AgentId, ClaimId, TruthValue};
use epigraph_db::ClaimRepository;
use epigraph_events::EpiGraphEvent;

// =============================================================================
// SECURITY CONSTANTS
// =============================================================================

/// Maximum length of supersession reason in bytes.
/// Prevents memory exhaustion from excessively large explanations.
const MAX_REASON_LENGTH: usize = 32_768;

/// Maximum length of new claim content in bytes.
/// Matches the MAX_CLAIM_CONTENT_LENGTH in submit.rs (64KB).
const MAX_CONTENT_LENGTH: usize = 65_536;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request body for superseding a claim
#[derive(Debug, Deserialize)]
pub struct SupersedeRequest {
    /// New claim content
    pub content: String,
    /// New truth value [0.0, 1.0]
    pub truth_value: f64,
    /// Why the claim is being superseded
    pub reason: String,
}

/// Response for a successful supersession
#[derive(Debug, Serialize, Deserialize)]
pub struct SupersessionResponse {
    /// The ID of the newly created claim
    pub new_claim_id: Uuid,
    /// The ID of the claim that was superseded
    pub superseded_claim_id: Uuid,
    /// The truth value of the new claim
    pub new_truth_value: f64,
    /// Version number in the supersession chain
    pub version: u32,
    /// When the new claim was created
    pub created_at: DateTime<Utc>,
}

/// A single version entry in a claim's history
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimVersion {
    /// The claim ID for this version
    pub claim_id: Uuid,
    /// The claim content at this version
    pub content: String,
    /// The truth value at this version
    pub truth_value: f64,
    /// The version number (1-indexed, oldest first)
    pub version: u32,
    /// Whether this is the current (latest) version
    pub is_current: bool,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// The ID of the claim that superseded this one (forward link)
    pub superseded_by: Option<Uuid>,
}

/// Response for a version history query
#[derive(Debug, Serialize, Deserialize)]
pub struct VersionHistoryResponse {
    /// The claim ID that was queried
    pub claim_id: Uuid,
    /// All versions in chronological order (oldest first)
    pub versions: Vec<ClaimVersion>,
    /// Total number of versions in the chain
    pub total_versions: usize,
    /// The version number of the current (latest) version
    pub current_version: u32,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Supersede an existing claim with a new version
///
/// POST /api/v1/claims/:id/supersede
///
/// Creates a new Claim that supersedes the given claim. The old claim
/// is marked as non-current (`is_current = false`) and the new claim
/// is linked via `supersedes = Some(old_id)`.
///
/// # Validation
///
/// - truth_value must be in [0.0, 1.0]
/// - content must be non-empty
/// - reason must be non-empty
/// - The target claim must exist
/// - The target claim must be current (cannot supersede an already-superseded claim)
///
/// # Errors
///
/// - 400 Bad Request: Validation failures or claim already superseded
/// - 404 Not Found: Claim does not exist
/// - 201 Created: New claim created successfully
pub async fn supersede_claim(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Json(request): Json<SupersedeRequest>,
) -> Result<(StatusCode, Json<SupersessionResponse>), ApiError> {
    // 1. Validate content is not empty
    if request.content.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "content".to_string(),
            reason: "Content cannot be empty".to_string(),
        });
    }

    // 2. Validate content length (DoS prevention)
    if request.content.len() > MAX_CONTENT_LENGTH {
        return Err(ApiError::ValidationError {
            field: "content".to_string(),
            reason: format!(
                "Content too long: {} bytes, maximum is {} bytes",
                request.content.len(),
                MAX_CONTENT_LENGTH
            ),
        });
    }

    // 3. Validate reason is not empty
    if request.reason.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "reason".to_string(),
            reason: "Reason cannot be empty".to_string(),
        });
    }

    // 4. Validate reason length (DoS prevention)
    if request.reason.len() > MAX_REASON_LENGTH {
        return Err(ApiError::ValidationError {
            field: "reason".to_string(),
            reason: format!(
                "Reason too long: {} bytes, maximum is {} bytes",
                request.reason.len(),
                MAX_REASON_LENGTH
            ),
        });
    }

    // 5. Validate truth value bounds
    if !request.truth_value.is_finite() || !(0.0..=1.0).contains(&request.truth_value) {
        return Err(ApiError::ValidationError {
            field: "truth_value".to_string(),
            reason: "Truth value must be between 0.0 and 1.0".to_string(),
        });
    }

    let truth_value =
        TruthValue::new(request.truth_value).map_err(|_| ApiError::ValidationError {
            field: "truth_value".to_string(),
            reason: "Truth value must be between 0.0 and 1.0".to_string(),
        })?;

    // 6. Fetch agent_id for event emission before supersession
    let agent_uuid: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("DB error: {e}"),
        })?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        })?;

    // 7. Perform supersession in the database (atomic transaction)
    let old_claim_id = ClaimId::from_uuid(claim_id);
    let (new_uuid, _old_uuid) = ClaimRepository::supersede(
        &state.db_pool,
        old_claim_id,
        &request.content,
        truth_value,
        &request.reason,
    )
    .await
    .map_err(|e| {
        // Map DB errors to appropriate API errors
        let msg = e.to_string();
        if msg.contains("not found") {
            ApiError::NotFound {
                entity: "Claim".to_string(),
                id: claim_id.to_string(),
            }
        } else if msg.contains("already been superseded") {
            ApiError::BadRequest { message: msg }
        } else {
            ApiError::InternalError {
                message: format!("Supersession failed: {msg}"),
            }
        }
    })?;

    let now = Utc::now();
    let new_claim_id = ClaimId::from_uuid(new_uuid);

    // 8. Record version history for the new claim (non-blocking, supplementary)
    #[cfg(feature = "db")]
    {
        use epigraph_db::repos::claim_version::ClaimVersionRow;
        use epigraph_db::ClaimVersionRepository;

        // Get the next version number for the old claim chain, then +1 for new claim
        let version_number: i32 =
            ClaimVersionRepository::latest_version_number(&state.db_pool, claim_id)
                .await
                .unwrap_or(0)
                + 1;

        let version_row = ClaimVersionRow {
            id: uuid::Uuid::new_v4(),
            claim_id: new_uuid,
            version_number,
            content: request.content.clone(),
            truth_value: request.truth_value,
            created_by: Some(agent_uuid),
            created_at: now,
        };

        if let Err(e) = ClaimVersionRepository::create(&state.db_pool, &version_row).await {
            tracing::warn!("Failed to record claim version: {e}");
            // Don't fail the supersede — version history is supplementary
        }
    }

    // 9. Publish ClaimSubmitted event for the new claim (fire-and-forget)
    let _ = state
        .event_bus
        .publish(EpiGraphEvent::ClaimSubmitted {
            claim_id: new_claim_id,
            agent_id: AgentId::from_uuid(agent_uuid),
            initial_truth: truth_value,
        })
        .await;

    // 10. Trigger belief propagation for downstream factors (fire-and-forget).
    //
    // Supersession creates stale downstream beliefs: any factor that referenced
    // the old claim via variable_ids now needs its beliefs re-propagated from
    // the new claim. We identify affected factors here and log them so Task 6
    // (unified BP dispatcher) can pick them up. The spawn is intentionally
    // non-blocking — a propagation failure must never abort a supersession.
    {
        let pool = state.db_pool.clone();
        tokio::spawn(async move {
            let factor_ids: Result<Vec<(Uuid,)>, sqlx::Error> =
                sqlx::query_as("SELECT id FROM factors WHERE $1 = ANY(variable_ids)")
                    .bind(new_uuid)
                    .fetch_all(&pool)
                    .await;

            match factor_ids {
                Err(e) => {
                    tracing::warn!(
                        claim_id = %new_uuid,
                        error = %e,
                        "BP trigger: failed to query factors for new claim after supersession"
                    );
                }
                Ok(rows) if rows.is_empty() => {
                    tracing::debug!(
                        claim_id = %new_uuid,
                        "BP trigger: no factors reference new claim, skipping propagation"
                    );
                }
                Ok(rows) => {
                    tracing::info!(
                        claim_id = %new_uuid,
                        factor_count = rows.len(),
                        "BP trigger: supersession requires belief propagation across factors"
                    );
                }
            }
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(SupersessionResponse {
            new_claim_id: new_uuid,
            superseded_claim_id: claim_id,
            new_truth_value: request.truth_value,
            version: 0, // version counting now handled by DB chain walk
            created_at: now,
        }),
    ))
}

/// Get the full version history for a claim
///
/// GET /api/v1/claims/:id/history
///
/// Walks the supersession chain in both directions to build a complete
/// version history. Returns all versions sorted by creation time (oldest first).
///
/// # Errors
///
/// - 404 Not Found: Claim does not exist
/// - 200 OK: Version history returned
pub async fn claim_history(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<VersionHistoryResponse>, ApiError> {
    // Walk the supersession chain using database queries
    // First, walk backwards to find the root
    let mut root_id = claim_id;
    loop {
        let row: Option<(Option<Uuid>,)> =
            sqlx::query_as("SELECT supersedes FROM claims WHERE id = $1")
                .bind(root_id)
                .fetch_optional(&state.db_pool)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("DB error: {e}"),
                })?;

        match row {
            None => {
                return Err(ApiError::NotFound {
                    entity: "Claim".to_string(),
                    id: claim_id.to_string(),
                });
            }
            Some((Some(prev_id),)) => root_id = prev_id,
            Some((None,)) => break,
        }
    }

    // Walk forward from root to build version list
    let mut versions = Vec::new();
    let mut current_id = Some(root_id);
    let mut version_number: u32 = 1;
    let mut current_version: u32 = 1;

    while let Some(id) = current_id {
        let row: Option<(Uuid, String, f64, bool, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, content, truth_value, COALESCE(is_current, true), created_at FROM claims WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("DB error: {e}"),
        })?;

        if let Some((cid, content, truth_value, is_current, created_at)) = row {
            // Find forward link: which claim supersedes this one?
            let superseded_by: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM claims WHERE supersedes = $1")
                    .bind(cid)
                    .fetch_optional(&state.db_pool)
                    .await
                    .map_err(|e| ApiError::InternalError {
                        message: format!("DB error: {e}"),
                    })?;

            versions.push(ClaimVersion {
                claim_id: cid,
                content,
                truth_value,
                version: version_number,
                is_current,
                created_at,
                superseded_by,
            });

            if is_current {
                current_version = version_number;
            }

            current_id = superseded_by;
            version_number += 1;
        } else {
            break;
        }
    }

    let total_versions = versions.len();

    Ok(Json(VersionHistoryResponse {
        claim_id,
        versions,
        total_versions,
        current_version,
    }))
}

// =============================================================================
// TESTS
// =============================================================================
// Note: Handler tests now require a real database since we migrated from
// in-memory claim_store to ClaimRepository::supersede(). The old unit tests
// for helper functions (count_version_chain, find_chain_root, etc.) were
// removed along with the helper functions themselves.
//
// Integration tests for supersession should use a test database fixture.

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Handler integration tests (require DB) ----
    // Formerly in-memory tests gated behind #[cfg(not(feature = "db"))].
    // These need to be rewritten as proper DB integration tests.

    #[cfg(not(feature = "db"))]
    mod handler_tests_placeholder {
        use super::super::*;
        use crate::state::{ApiConfig, AppState};
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::{get, post};
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        /// Helper to parse JSON response body
        async fn parse_body<T: serde::de::DeserializeOwned>(
            response: axum::http::Response<Body>,
        ) -> T {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice(&body).unwrap()
        }

        /// Helper to create a state with a claim pre-populated in the store
        async fn state_with_claim(claim_id: Uuid) -> (AppState, Uuid) {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let claim = Claim::new(
                "Original claim content".to_string(),
                epigraph_core::AgentId::new(),
                [0u8; 32],
                TruthValue::new(0.7).unwrap(),
            );

            // Override the claim's ID to match the requested one
            let claim = Claim {
                id: ClaimId::from_uuid(claim_id),
                ..claim
            };

            let mut store = state.claim_store.write().await;
            store.insert(claim_id, claim);
            drop(store);

            (state, claim_id)
        }

        /// Create a test router with versioning endpoints (no auth middleware)
        fn test_router(state: AppState) -> Router {
            Router::new()
                .route("/api/v1/claims/:id/supersede", post(supersede_claim))
                .route("/api/v1/claims/:id/history", get(claim_history))
                .with_state(state)
        }

        // ==================================================================
        // SUPERSESSION TESTS
        // ==================================================================

        #[tokio::test]
        async fn test_supersede_creates_new_claim() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;
            let router = test_router(state.clone());

            let body = serde_json::json!({
                "content": "Updated claim content",
                "truth_value": 0.85,
                "reason": "New evidence discovered"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            let resp: SupersessionResponse = parse_body(response).await;
            assert_eq!(resp.superseded_claim_id, claim_id);
            assert_ne!(resp.new_claim_id, claim_id);
            assert!((resp.new_truth_value - 0.85).abs() < f64::EPSILON);
            assert_eq!(resp.version, 2);
        }

        #[tokio::test]
        async fn test_supersede_marks_old_claim_non_current() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;
            let router = test_router(state.clone());

            let body = serde_json::json!({
                "content": "Updated content",
                "truth_value": 0.9,
                "reason": "Better evidence"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            // Verify old claim is now non-current
            let store = state.claim_store.read().await;
            let old_claim = store.get(&claim_id).unwrap();
            assert!(!old_claim.is_current);
            assert!(old_claim.is_superseded());
        }

        #[tokio::test]
        async fn test_supersede_nonexistent_claim_returns_404() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });
            let router = test_router(state);

            let fake_id = Uuid::new_v4();
            let body = serde_json::json!({
                "content": "New content",
                "truth_value": 0.5,
                "reason": "Some reason"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{fake_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_supersede_already_superseded_claim_returns_400() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;

            // First supersession
            let router = test_router(state.clone());
            let body = serde_json::json!({
                "content": "Version 2",
                "truth_value": 0.8,
                "reason": "First update"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            // Second supersession of same (now non-current) claim should fail
            let router = test_router(state.clone());
            let body2 = serde_json::json!({
                "content": "Version 3 attempt",
                "truth_value": 0.9,
                "reason": "Second update"
            });

            let request2 = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body2).unwrap()))
                .unwrap();

            let response2 = router.oneshot(request2).await.unwrap();
            assert_eq!(response2.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_supersede_invalid_truth_value_too_high() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;
            let router = test_router(state);

            let body = serde_json::json!({
                "content": "Updated content",
                "truth_value": 1.5,
                "reason": "Some reason"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_supersede_invalid_truth_value_negative() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;
            let router = test_router(state);

            let body = serde_json::json!({
                "content": "Updated content",
                "truth_value": -0.1,
                "reason": "Some reason"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_supersede_empty_content_rejected() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;
            let router = test_router(state);

            let body = serde_json::json!({
                "content": "",
                "truth_value": 0.5,
                "reason": "Some reason"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_supersede_empty_reason_rejected() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;
            let router = test_router(state);

            let body = serde_json::json!({
                "content": "Valid content",
                "truth_value": 0.5,
                "reason": ""
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_supersede_whitespace_only_content_rejected() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;
            let router = test_router(state);

            let body = serde_json::json!({
                "content": "   \n\t  ",
                "truth_value": 0.5,
                "reason": "Some reason"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        // ==================================================================
        // VERSION HISTORY TESTS
        // ==================================================================

        #[tokio::test]
        async fn test_history_single_version() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;
            let router = test_router(state);

            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_id}/history"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let history: VersionHistoryResponse = parse_body(response).await;
            assert_eq!(history.claim_id, claim_id);
            assert_eq!(history.total_versions, 1);
            assert_eq!(history.current_version, 1);
            assert_eq!(history.versions.len(), 1);
            assert!(history.versions[0].is_current);
            assert_eq!(history.versions[0].version, 1);
            assert!(history.versions[0].superseded_by.is_none());
        }

        #[tokio::test]
        async fn test_history_after_supersession() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;

            // Supersede the claim
            let router = test_router(state.clone());
            let body = serde_json::json!({
                "content": "Version 2 content",
                "truth_value": 0.85,
                "reason": "Updated evidence"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let resp = router.oneshot(request).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            let supersession: SupersessionResponse = parse_body(resp).await;

            // Query history for the original claim
            let router = test_router(state.clone());
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_id}/history"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let history: VersionHistoryResponse = parse_body(response).await;
            assert_eq!(history.total_versions, 2);
            assert_eq!(history.current_version, 2);

            // First version: original claim (non-current)
            assert_eq!(history.versions[0].claim_id, claim_id);
            assert!(!history.versions[0].is_current);
            assert_eq!(history.versions[0].version, 1);
            assert_eq!(
                history.versions[0].superseded_by,
                Some(supersession.new_claim_id)
            );

            // Second version: new claim (current)
            assert_eq!(history.versions[1].claim_id, supersession.new_claim_id);
            assert!(history.versions[1].is_current);
            assert_eq!(history.versions[1].version, 2);
            assert!(history.versions[1].superseded_by.is_none());
        }

        #[tokio::test]
        async fn test_history_nonexistent_claim_returns_404() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });
            let router = test_router(state);

            let fake_id = Uuid::new_v4();
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{fake_id}/history"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_version_numbering_is_correct() {
            let claim_id = Uuid::new_v4();
            let (state, _) = state_with_claim(claim_id).await;

            // First supersession: v1 -> v2
            let router = test_router(state.clone());
            let body = serde_json::json!({
                "content": "Version 2",
                "truth_value": 0.8,
                "reason": "Update 1"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let resp = router.oneshot(request).await.unwrap();
            let sup1: SupersessionResponse = parse_body(resp).await;
            assert_eq!(sup1.version, 2);

            // Second supersession: v2 -> v3
            let router = test_router(state.clone());
            let body = serde_json::json!({
                "content": "Version 3",
                "truth_value": 0.9,
                "reason": "Update 2"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{}/supersede", sup1.new_claim_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let resp = router.oneshot(request).await.unwrap();
            let sup2: SupersessionResponse = parse_body(resp).await;
            assert_eq!(sup2.version, 3);

            // Verify full history from the root claim
            let router = test_router(state.clone());
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_id}/history"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            let history: VersionHistoryResponse = parse_body(response).await;
            assert_eq!(history.total_versions, 3);
            assert_eq!(history.current_version, 3);

            // Verify version numbers are sequential
            for (i, version) in history.versions.iter().enumerate() {
                assert_eq!(version.version, (i + 1) as u32);
            }
        }
        // ==================================================================
        // AUTH / MIDDLEWARE INTEGRATION TESTS
        // ==================================================================

        /// Test that superseding a claim without signature headers returns 401
        /// when the request goes through the full create_router middleware stack.
        ///
        /// This is a true integration test: it uses the production router
        /// (including the require_signature middleware layer) rather than a
        /// bare handler router, proving that unauthenticated writes are rejected.
        #[tokio::test]
        async fn test_supersede_without_signature_returns_401() {
            let claim_id = Uuid::new_v4();
            let state = AppState::new(ApiConfig {
                require_signatures: false, // irrelevant; middleware always checks headers
                ..ApiConfig::default()
            });

            // Pre-populate a claim so we know the 401 comes from auth, not 404
            {
                let claim = epigraph_core::Claim::new(
                    "Original claim".to_string(),
                    epigraph_core::AgentId::new(),
                    [0u8; 32],
                    TruthValue::new(0.7).unwrap(),
                );
                let claim = epigraph_core::Claim {
                    id: epigraph_core::ClaimId::from_uuid(claim_id),
                    ..claim
                };
                let mut store = state.claim_store.write().await;
                store.insert(claim_id, claim);
            }

            // Use the full production router with middleware
            let router = crate::routes::create_router(state);

            let body = serde_json::json!({
                "content": "Updated claim content",
                "truth_value": 0.85,
                "reason": "New evidence discovered"
            });

            // POST without any signature headers -> middleware rejects with 401
            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "Supersede without signature headers must return 401"
            );
        }

        // ==================================================================
        // HISTORY CHAIN TRAVERSAL TESTS
        // ==================================================================

        /// Test that querying history from a mid-chain claim still returns
        /// the complete version chain from root to current.
        ///
        /// Chain: root (v1) -> v2 -> v3 (current)
        /// Query history from v2 => should return all three versions.
        #[tokio::test]
        async fn test_history_queried_from_middle_of_chain() {
            let root_id = Uuid::new_v4();
            let (state, _) = state_with_claim(root_id).await;

            // Supersede root -> v2
            let router = test_router(state.clone());
            let body = serde_json::json!({
                "content": "Version 2",
                "truth_value": 0.8,
                "reason": "First update"
            });
            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{root_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();
            let resp = router.oneshot(request).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            let sup1: SupersessionResponse = parse_body(resp).await;

            // Supersede v2 -> v3
            let router = test_router(state.clone());
            let body = serde_json::json!({
                "content": "Version 3",
                "truth_value": 0.9,
                "reason": "Second update"
            });
            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{}/supersede", sup1.new_claim_id))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();
            let resp = router.oneshot(request).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);

            // Query history from the MIDDLE claim (v2), not root or current
            let router = test_router(state.clone());
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{}/history", sup1.new_claim_id))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let history: VersionHistoryResponse = parse_body(response).await;
            assert_eq!(
                history.total_versions, 3,
                "History from mid-chain claim should include all versions"
            );
            assert_eq!(history.current_version, 3);

            // Versions must be in chronological order (oldest first)
            assert_eq!(history.versions[0].version, 1);
            assert_eq!(history.versions[0].claim_id, root_id);
            assert!(!history.versions[0].is_current);

            assert_eq!(history.versions[1].version, 2);
            assert_eq!(history.versions[1].claim_id, sup1.new_claim_id);
            assert!(!history.versions[1].is_current);

            assert_eq!(history.versions[2].version, 3);
            assert!(history.versions[2].is_current);
        }

        /// Test that the GET /history endpoint is publicly accessible
        /// (no signature headers required) through the full router.
        #[tokio::test]
        async fn test_history_accessible_without_signature() {
            let claim_id = Uuid::new_v4();
            let state = AppState::new(ApiConfig::default());

            // Pre-populate a claim
            {
                let claim = epigraph_core::Claim::new(
                    "A claim".to_string(),
                    epigraph_core::AgentId::new(),
                    [0u8; 32],
                    TruthValue::new(0.5).unwrap(),
                );
                let claim = epigraph_core::Claim {
                    id: epigraph_core::ClaimId::from_uuid(claim_id),
                    ..claim
                };
                let mut store = state.claim_store.write().await;
                store.insert(claim_id, claim);
            }

            // Use the full production router (with middleware)
            let router = crate::routes::create_router(state);

            // GET without any signature headers -> should succeed (200) because
            // the history endpoint is on the public router
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_id}/history"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "History endpoint should be publicly accessible without signature"
            );

            let history: VersionHistoryResponse = parse_body(response).await;
            assert_eq!(history.total_versions, 1);
        }
    } // end mod handler_tests

    #[cfg(not(feature = "db"))]
    mod event_tests {
        use super::super::*;
        use crate::state::{ApiConfig, AppState};
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::post;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        /// Helper to parse JSON response body
        async fn parse_body<T: serde::de::DeserializeOwned>(
            response: axum::http::Response<Body>,
        ) -> T {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice(&body).unwrap()
        }

        /// Helper to create a state with a claim pre-populated in the store
        async fn state_with_claim(claim_id: Uuid) -> AppState {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let claim = Claim::new(
                "Original claim content".to_string(),
                epigraph_core::AgentId::new(),
                [0u8; 32],
                TruthValue::new(0.7).unwrap(),
            );

            let claim = Claim {
                id: ClaimId::from_uuid(claim_id),
                ..claim
            };

            let mut store = state.claim_store.write().await;
            store.insert(claim_id, claim);
            drop(store);

            state
        }

        #[tokio::test]
        async fn test_supersede_publishes_claim_submitted_event() {
            let claim_id = Uuid::new_v4();
            let state = state_with_claim(claim_id).await;

            let router = Router::new()
                .route("/api/v1/claims/:id/supersede", post(supersede_claim))
                .with_state(state.clone());

            let body = serde_json::json!({
                "content": "Updated claim via supersession",
                "truth_value": 0.85,
                "reason": "New evidence discovered"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            // Verify that a ClaimSubmitted event was published for the new claim
            assert_eq!(
                state.event_bus.history_size(),
                1,
                "Event bus should contain exactly one event after successful supersession"
            );

            let history = state.event_bus.get_history().unwrap();
            assert_eq!(history[0].event.event_type(), "ClaimSubmitted");

            // Verify the event references the NEW claim, not the old one
            let resp: SupersessionResponse = parse_body(response).await;
            match &history[0].event {
                epigraph_events::EpiGraphEvent::ClaimSubmitted {
                    claim_id: event_claim_id,
                    ..
                } => {
                    let event_uuid: Uuid = (*event_claim_id).into();
                    assert_eq!(
                        event_uuid, resp.new_claim_id,
                        "Event claim_id should match the newly created claim"
                    );
                }
                _ => panic!("Expected ClaimSubmitted event"),
            }
        }

        #[tokio::test]
        async fn test_supersede_no_event_on_validation_failure() {
            let claim_id = Uuid::new_v4();
            let state = state_with_claim(claim_id).await;

            let router = Router::new()
                .route("/api/v1/claims/:id/supersede", post(supersede_claim))
                .with_state(state.clone());

            // Invalid: empty content
            let body = serde_json::json!({
                "content": "",
                "truth_value": 0.5,
                "reason": "Some reason"
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/supersede"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            // No event should be published on validation failure
            assert_eq!(
                state.event_bus.history_size(),
                0,
                "Event bus should be empty after failed supersession"
            );
        }
    } // end mod event_tests
}
