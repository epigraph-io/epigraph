//! Batch claim import endpoints
//!
//! POST /api/v1/claims/batch - Import multiple claims in a single request (protected)
//!
//! Batch import enables efficient bulk creation of claims. Each item in the
//! batch is validated independently: valid claims are created even if other
//! items in the batch fail validation. This partial-success model provides
//! per-item error reporting so the caller knows exactly which items failed
//! and why.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;
use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_events::EpiGraphEvent;

// =============================================================================
// SECURITY CONSTANTS
// =============================================================================

/// Maximum number of claims in a single batch request.
/// Prevents memory exhaustion and excessive lock hold times.
const MAX_BATCH_SIZE: usize = 100;

/// Maximum length of claim content in bytes.
/// Matches the limit used in submit.rs and versioning.rs (64KB).
const MAX_CLAIM_CONTENT_LENGTH: usize = 65_536;

/// Default truth value for claims that omit the field.
/// 0.5 represents maximum uncertainty: neither true nor false.
const DEFAULT_TRUTH_VALUE: f64 = 0.5;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request body for batch claim creation
#[derive(Debug, Deserialize)]
pub struct BatchClaimRequest {
    /// Array of claim items to create
    pub claims: Vec<BatchClaimItem>,
}

/// A single claim item within a batch request
#[derive(Debug, Deserialize)]
pub struct BatchClaimItem {
    /// The statement content of the claim
    pub content: String,
    /// Truth value in [0.0, 1.0]; defaults to 0.5 if omitted
    pub truth_value: Option<f64>,
}

/// Response for a batch claim creation request
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchClaimResponse {
    /// Number of claims successfully created
    pub created: usize,
    /// Number of claims that failed validation
    pub failed: usize,
    /// Per-item results in the same order as the request
    pub results: Vec<BatchClaimResult>,
}

/// Result for a single item in a batch
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchClaimResult {
    /// Index of this item in the original request array
    pub index: usize,
    /// The ID of the created claim, if successful
    pub claim_id: Option<Uuid>,
    /// Error message, if validation failed
    pub error: Option<String>,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Import multiple claims in a single batch request
///
/// POST /api/v1/claims/batch
///
/// Accepts a JSON body with an array of claim items. Each item is validated
/// independently: valid claims are stored even if other items fail. Returns
/// per-item results so the caller knows exactly which succeeded and which failed.
///
/// # Validation (per item)
///
/// - content must be non-empty (after trimming whitespace)
/// - content length must not exceed MAX_CLAIM_CONTENT_LENGTH (65,536 bytes)
/// - truth_value, if provided, must be finite and in [0.0, 1.0]
///
/// # Batch-level validation
///
/// - The batch must not exceed MAX_BATCH_SIZE (100) claims
///
/// # Events
///
/// A `ClaimSubmitted` event is published (fire-and-forget) for each
/// successfully created claim.
///
/// # Errors
///
/// - 400 Bad Request: Batch exceeds MAX_BATCH_SIZE
/// - 200 OK: Batch processed (check per-item results for individual errors)
pub async fn batch_create_claims(
    State(state): State<AppState>,
    Json(request): Json<BatchClaimRequest>,
) -> Result<Json<BatchClaimResponse>, ApiError> {
    // 1. Validate batch size
    if request.claims.len() > MAX_BATCH_SIZE {
        return Err(ApiError::BadRequest {
            message: format!(
                "Batch size {} exceeds maximum of {}",
                request.claims.len(),
                MAX_BATCH_SIZE
            ),
        });
    }

    // 2. Process each item independently, collecting results
    let mut results = Vec::with_capacity(request.claims.len());
    let mut created_count: usize = 0;
    let mut failed_count: usize = 0;

    // Collect successfully validated claims before acquiring the write lock
    // to minimize lock hold time.
    let mut valid_claims: Vec<(usize, Claim)> = Vec::new();

    for (index, item) in request.claims.iter().enumerate() {
        match validate_batch_item(item) {
            Ok(claim) => {
                valid_claims.push((index, claim));
            }
            Err(error_msg) => {
                results.push(BatchClaimResult {
                    index,
                    claim_id: None,
                    error: Some(error_msg),
                });
                failed_count += 1;
            }
        }
    }

    // 3. Acquire write lock once and insert all valid claims
    {
        let mut store = state.claim_store.write().await;
        for (index, claim) in &valid_claims {
            let claim_uuid: Uuid = claim.id.into();
            store.insert(claim_uuid, claim.clone());
            results.push(BatchClaimResult {
                index: *index,
                claim_id: Some(claim_uuid),
                error: None,
            });
            created_count += 1;
        }
    }

    // 4. Publish events for each created claim (fire-and-forget)
    //
    // Event publishing must not fail the request. If the event bus is
    // unavailable or the publish fails, the batch creation still succeeds.
    for (_index, claim) in &valid_claims {
        let _ = state
            .event_bus
            .publish(EpiGraphEvent::ClaimSubmitted {
                claim_id: claim.id,
                agent_id: claim.agent_id,
                initial_truth: claim.truth_value,
            })
            .await;
    }

    // 5. Sort results by index so they match the original request order
    results.sort_by_key(|r| r.index);

    Ok(Json(BatchClaimResponse {
        created: created_count,
        failed: failed_count,
        results,
    }))
}

// =============================================================================
// VALIDATION HELPERS
// =============================================================================

/// Validate a single batch claim item and construct a Claim if valid.
///
/// Returns Ok(Claim) on success, or Err(String) with a human-readable
/// error message on validation failure.
fn validate_batch_item(item: &BatchClaimItem) -> Result<Claim, String> {
    // 1. Content must not be empty
    if item.content.trim().is_empty() {
        return Err("Content cannot be empty".to_string());
    }

    // 2. Content must not exceed length limit
    if item.content.len() > MAX_CLAIM_CONTENT_LENGTH {
        return Err(format!(
            "Content too long: {} bytes, maximum is {} bytes",
            item.content.len(),
            MAX_CLAIM_CONTENT_LENGTH
        ));
    }

    // 3. Validate truth value if provided
    let truth_raw = item.truth_value.unwrap_or(DEFAULT_TRUTH_VALUE);

    if !truth_raw.is_finite() {
        return Err("Truth value must be a finite number (not NaN or infinity)".to_string());
    }

    if !(0.0..=1.0).contains(&truth_raw) {
        return Err(format!(
            "Truth value {} out of bounds, must be in [0.0, 1.0]",
            truth_raw
        ));
    }

    let truth_value = TruthValue::new(truth_raw)
        .map_err(|_| "Truth value must be between 0.0 and 1.0".to_string())?;

    // 4. Construct the claim
    //
    // Batch-imported claims use a synthetic agent ID and zero public key
    // because they arrive through a protected route (signature already
    // verified at the middleware layer). The trace is generated per-claim
    // to maintain the "no naked assertions" invariant.
    let claim = Claim::new(item.content.clone(), AgentId::new(), [0u8; 32], truth_value);

    Ok(claim)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(all(test, not(feature = "db")))]
mod tests {
    use super::*;
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Helper to parse JSON response body
    async fn parse_body<T: serde::de::DeserializeOwned>(response: axum::http::Response<Body>) -> T {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// Create a test router with the batch endpoint (no auth middleware)
    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/claims/batch", post(batch_create_claims))
            .with_state(state)
    }

    /// Create a default test state
    fn test_state() -> AppState {
        AppState::new(ApiConfig {
            require_signatures: false,
            ..ApiConfig::default()
        })
    }

    /// Helper to build a POST request with JSON body
    fn batch_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/v1/claims/batch")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap()
    }

    // ==================================================================
    // TEST 1: Empty batch returns 200 with created=0
    // ==================================================================

    #[tokio::test]
    async fn test_empty_batch_returns_200_with_zero_created() {
        let state = test_state();
        let router = test_router(state);

        let body = serde_json::json!({ "claims": [] });
        let response = router.oneshot(batch_request(body)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 0);
        assert_eq!(resp.failed, 0);
        assert!(resp.results.is_empty());
    }

    // ==================================================================
    // TEST 2: Single valid claim creates successfully
    // ==================================================================

    #[tokio::test]
    async fn test_single_valid_claim_creates_successfully() {
        let state = test_state();
        let router = test_router(state.clone());

        let body = serde_json::json!({
            "claims": [
                { "content": "The Earth orbits the Sun", "truth_value": 0.95 }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 1);
        assert_eq!(resp.failed, 0);
        assert_eq!(resp.results.len(), 1);
        assert!(resp.results[0].claim_id.is_some());
        assert!(resp.results[0].error.is_none());
        assert_eq!(resp.results[0].index, 0);

        // Verify claim is in the store
        let store = state.claim_store.read().await;
        let claim_id = resp.results[0].claim_id.unwrap();
        assert!(store.contains_key(&claim_id));
        let stored = store.get(&claim_id).unwrap();
        assert_eq!(stored.content, "The Earth orbits the Sun");
        assert!((stored.truth_value.value() - 0.95).abs() < f64::EPSILON);
    }

    // ==================================================================
    // TEST 3: Multiple valid claims all succeed
    // ==================================================================

    #[tokio::test]
    async fn test_multiple_valid_claims_all_succeed() {
        let state = test_state();
        let router = test_router(state.clone());

        let body = serde_json::json!({
            "claims": [
                { "content": "Claim A", "truth_value": 0.6 },
                { "content": "Claim B", "truth_value": 0.7 },
                { "content": "Claim C" }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 3);
        assert_eq!(resp.failed, 0);
        assert_eq!(resp.results.len(), 3);

        // All should have claim_ids and no errors
        for (i, result) in resp.results.iter().enumerate() {
            assert_eq!(result.index, i);
            assert!(result.claim_id.is_some(), "Item {} should have claim_id", i);
            assert!(result.error.is_none(), "Item {} should have no error", i);
        }

        // The third claim (no truth_value) should default to 0.5
        let store = state.claim_store.read().await;
        let third_id = resp.results[2].claim_id.unwrap();
        let third_claim = store.get(&third_id).unwrap();
        assert!(
            (third_claim.truth_value.value() - 0.5).abs() < f64::EPSILON,
            "Missing truth_value should default to 0.5"
        );

        // Verify all three are in the store
        assert_eq!(store.len(), 3);
    }

    // ==================================================================
    // TEST 4: Batch exceeding MAX_BATCH_SIZE returns 400
    // ==================================================================

    #[tokio::test]
    async fn test_batch_exceeding_max_size_returns_400() {
        let state = test_state();
        let router = test_router(state);

        // Create 101 claims (exceeds MAX_BATCH_SIZE of 100)
        let claims: Vec<serde_json::Value> = (0..101)
            .map(|i| {
                serde_json::json!({
                    "content": format!("Claim number {}", i),
                    "truth_value": 0.5
                })
            })
            .collect();

        let body = serde_json::json!({ "claims": claims });
        let response = router.oneshot(batch_request(body)).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ==================================================================
    // TEST 5: Invalid truth value (> 1.0) reported as per-item error
    // ==================================================================

    #[tokio::test]
    async fn test_invalid_truth_value_reported_as_per_item_error() {
        let state = test_state();
        let router = test_router(state);

        let body = serde_json::json!({
            "claims": [
                { "content": "Invalid claim", "truth_value": 1.5 }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 0);
        assert_eq!(resp.failed, 1);
        assert_eq!(resp.results.len(), 1);
        assert!(resp.results[0].claim_id.is_none());
        assert!(resp.results[0].error.is_some());
        assert!(
            resp.results[0]
                .error
                .as_ref()
                .unwrap()
                .contains("out of bounds"),
            "Error should mention out of bounds, got: {}",
            resp.results[0].error.as_ref().unwrap()
        );
    }

    // ==================================================================
    // TEST 6: Empty content string reported as per-item error
    // ==================================================================

    #[tokio::test]
    async fn test_empty_content_reported_as_per_item_error() {
        let state = test_state();
        let router = test_router(state);

        let body = serde_json::json!({
            "claims": [
                { "content": "", "truth_value": 0.5 }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 0);
        assert_eq!(resp.failed, 1);
        assert!(resp.results[0].claim_id.is_none());
        assert!(resp.results[0].error.is_some());
        assert!(
            resp.results[0].error.as_ref().unwrap().contains("empty"),
            "Error should mention empty content, got: {}",
            resp.results[0].error.as_ref().unwrap()
        );
    }

    // ==================================================================
    // TEST 7: Content exceeding length limit reported as per-item error
    // ==================================================================

    #[tokio::test]
    async fn test_content_exceeding_length_limit_reported_as_per_item_error() {
        let state = test_state();
        let router = test_router(state);

        let oversized_content = "x".repeat(MAX_CLAIM_CONTENT_LENGTH + 1);
        let body = serde_json::json!({
            "claims": [
                { "content": oversized_content, "truth_value": 0.5 }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 0);
        assert_eq!(resp.failed, 1);
        assert!(resp.results[0].claim_id.is_none());
        assert!(resp.results[0].error.is_some());
        assert!(
            resp.results[0].error.as_ref().unwrap().contains("too long"),
            "Error should mention content too long, got: {}",
            resp.results[0].error.as_ref().unwrap()
        );
    }

    // ==================================================================
    // TEST 8: Mixed valid/invalid items: valid ones succeed, invalid get errors
    // ==================================================================

    #[tokio::test]
    async fn test_mixed_valid_invalid_items_partial_success() {
        let state = test_state();
        let router = test_router(state.clone());

        let body = serde_json::json!({
            "claims": [
                { "content": "Valid claim one", "truth_value": 0.8 },
                { "content": "", "truth_value": 0.5 },
                { "content": "Valid claim two", "truth_value": 0.3 },
                { "content": "Bad truth", "truth_value": -0.1 },
                { "content": "Valid claim three" }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 3);
        assert_eq!(resp.failed, 2);
        assert_eq!(resp.results.len(), 5);

        // Results should be in original index order
        for (i, result) in resp.results.iter().enumerate() {
            assert_eq!(result.index, i, "Result index should match position");
        }

        // Index 0: valid
        assert!(resp.results[0].claim_id.is_some());
        assert!(resp.results[0].error.is_none());

        // Index 1: invalid (empty content)
        assert!(resp.results[1].claim_id.is_none());
        assert!(resp.results[1].error.is_some());

        // Index 2: valid
        assert!(resp.results[2].claim_id.is_some());
        assert!(resp.results[2].error.is_none());

        // Index 3: invalid (negative truth value)
        assert!(resp.results[3].claim_id.is_none());
        assert!(resp.results[3].error.is_some());

        // Index 4: valid (default truth value)
        assert!(resp.results[4].claim_id.is_some());
        assert!(resp.results[4].error.is_none());

        // Verify only valid claims are in the store
        let store = state.claim_store.read().await;
        assert_eq!(store.len(), 3);
    }

    // ==================================================================
    // ADDITIONAL EDGE CASE TESTS
    // ==================================================================

    #[tokio::test]
    async fn test_nan_truth_value_rejected() {
        // NaN cannot be represented in JSON, so we test the validation function directly
        let item = BatchClaimItem {
            content: "Test claim".to_string(),
            truth_value: Some(f64::NAN),
        };
        let result = validate_batch_item(&item);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finite"));
    }

    #[tokio::test]
    async fn test_infinity_truth_value_rejected() {
        let item = BatchClaimItem {
            content: "Test claim".to_string(),
            truth_value: Some(f64::INFINITY),
        };
        let result = validate_batch_item(&item);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finite"));
    }

    #[tokio::test]
    async fn test_whitespace_only_content_rejected() {
        let state = test_state();
        let router = test_router(state);

        let body = serde_json::json!({
            "claims": [
                { "content": "   \n\t  ", "truth_value": 0.5 }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 0);
        assert_eq!(resp.failed, 1);
        assert!(resp.results[0].error.as_ref().unwrap().contains("empty"));
    }

    #[tokio::test]
    async fn test_exact_max_batch_size_succeeds() {
        let state = test_state();
        let router = test_router(state);

        // Exactly 100 claims should succeed (boundary test)
        let claims: Vec<serde_json::Value> = (0..100)
            .map(|i| {
                serde_json::json!({
                    "content": format!("Claim {}", i),
                    "truth_value": 0.5
                })
            })
            .collect();

        let body = serde_json::json!({ "claims": claims });
        let response = router.oneshot(batch_request(body)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 100);
        assert_eq!(resp.failed, 0);
    }

    #[tokio::test]
    async fn test_truth_value_boundary_zero_succeeds() {
        let item = BatchClaimItem {
            content: "Boundary test".to_string(),
            truth_value: Some(0.0),
        };
        assert!(validate_batch_item(&item).is_ok());
    }

    #[tokio::test]
    async fn test_truth_value_boundary_one_succeeds() {
        let item = BatchClaimItem {
            content: "Boundary test".to_string(),
            truth_value: Some(1.0),
        };
        assert!(validate_batch_item(&item).is_ok());
    }

    // ==================================================================
    // AUTH / MIDDLEWARE INTEGRATION TESTS
    // ==================================================================

    /// Test that POST /api/v1/claims/batch without signature headers
    /// returns 401 when routed through the full production middleware stack.
    ///
    /// The batch endpoint is a protected (write) route. The require_signature
    /// middleware rejects requests that lack the X-Signature, X-Public-Key,
    /// and X-Timestamp headers before the handler is ever invoked.
    #[tokio::test]
    async fn test_batch_without_signature_returns_401() {
        let state = test_state();
        // Use the full production router (includes require_signature middleware)
        let router = crate::routes::create_router(state);

        let body = serde_json::json!({
            "claims": [
                { "content": "A claim", "truth_value": 0.6 }
            ]
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/claims/batch")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Batch create without signature headers must return 401"
        );
    }

    // ==================================================================
    // EVENT PUBLISHING TESTS
    // ==================================================================

    /// Test that a ClaimSubmitted event is published for each successfully
    /// created claim in a batch, and that failed items produce no events.
    #[tokio::test]
    async fn test_batch_publishes_events_for_each_created_claim() {
        let state = test_state();
        let router = test_router(state.clone());

        // 2 valid + 1 invalid = 2 events expected
        let body = serde_json::json!({
            "claims": [
                { "content": "Valid claim A", "truth_value": 0.6 },
                { "content": "", "truth_value": 0.5 },
                { "content": "Valid claim B", "truth_value": 0.8 }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 2);
        assert_eq!(resp.failed, 1);

        // Verify exactly 2 events were published (one per valid claim)
        assert_eq!(
            state.event_bus.history_size(),
            2,
            "Event bus should contain exactly 2 events (one per valid claim)"
        );

        let history = state.event_bus.get_history().unwrap();
        for entry in &history {
            assert_eq!(
                entry.event.event_type(),
                "ClaimSubmitted",
                "All batch events should be ClaimSubmitted"
            );
        }
    }

    /// Test that no events are published when all items in the batch fail validation.
    #[tokio::test]
    async fn test_batch_no_events_when_all_fail() {
        let state = test_state();
        let router = test_router(state.clone());

        let body = serde_json::json!({
            "claims": [
                { "content": "", "truth_value": 0.5 },
                { "content": "ok", "truth_value": 2.0 }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 0);
        assert_eq!(resp.failed, 2);

        assert_eq!(
            state.event_bus.history_size(),
            0,
            "No events should be published when all batch items fail"
        );
    }

    // ==================================================================
    // ADDITIONAL INTEGRATION EDGE CASES
    // ==================================================================

    /// Test that a request with a malformed JSON body (missing "claims" field)
    /// returns a 422 Unprocessable Entity, since Axum cannot deserialize
    /// the body into BatchClaimRequest.
    #[tokio::test]
    async fn test_batch_malformed_body_missing_claims_field() {
        let state = test_state();
        let router = test_router(state);

        // JSON body without the required "claims" field
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/claims/batch")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"not_claims": []}"#))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "Missing 'claims' field should fail deserialization with 422"
        );
    }

    /// Test that a request with a non-JSON body returns a 415 or 422 error.
    #[tokio::test]
    async fn test_batch_non_json_body_rejected() {
        let state = test_state();
        let router = test_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/claims/batch")
            .header("content-type", "text/plain")
            .body(Body::from("this is not json"))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // Axum rejects non-JSON content types for Json<T> extractors
        let status = response.status();
        assert!(
            status == StatusCode::UNSUPPORTED_MEDIA_TYPE
                || status == StatusCode::UNPROCESSABLE_ENTITY
                || status == StatusCode::BAD_REQUEST,
            "Non-JSON body should be rejected, got {}",
            status
        );
    }

    /// Test that all created claims in a batch are independently stored
    /// with unique IDs and correct content.
    #[tokio::test]
    async fn test_batch_claims_stored_with_correct_content() {
        let state = test_state();
        let router = test_router(state.clone());

        let body = serde_json::json!({
            "claims": [
                { "content": "Alpha claim", "truth_value": 0.1 },
                { "content": "Beta claim", "truth_value": 0.9 }
            ]
        });

        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp: BatchClaimResponse = parse_body(response).await;
        assert_eq!(resp.created, 2);

        let store = state.claim_store.read().await;

        // Verify each claim's content matches what was submitted
        let alpha_id = resp.results[0].claim_id.unwrap();
        let beta_id = resp.results[1].claim_id.unwrap();

        assert_ne!(alpha_id, beta_id, "Each batch claim must get a unique ID");

        let alpha = store.get(&alpha_id).unwrap();
        assert_eq!(alpha.content, "Alpha claim");
        assert!((alpha.truth_value.value() - 0.1).abs() < f64::EPSILON);

        let beta = store.get(&beta_id).unwrap();
        assert_eq!(beta.content, "Beta claim");
        assert!((beta.truth_value.value() - 0.9).abs() < f64::EPSILON);
    }

    /// Test that the oversized batch rejection happens BEFORE any claims
    /// are stored, preventing partial writes from an invalid request.
    #[tokio::test]
    async fn test_oversized_batch_stores_nothing() {
        let state = test_state();
        let router = test_router(state.clone());

        let claims: Vec<serde_json::Value> = (0..101)
            .map(|i| {
                serde_json::json!({
                    "content": format!("Claim {}", i),
                    "truth_value": 0.5
                })
            })
            .collect();

        let body = serde_json::json!({ "claims": claims });
        let response = router.oneshot(batch_request(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Verify that no claims leaked into the store
        let store = state.claim_store.read().await;
        assert_eq!(
            store.len(),
            0,
            "Oversized batch rejection must not store any claims"
        );
    }
}
