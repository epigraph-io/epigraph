//! Harvest endpoint: Accept text for extraction via the Reflective Harvester.
//!
//! `POST /api/v1/harvest` accepts a text fragment and forwards it to the
//! Python harvester gRPC service for claim extraction. The harvester runs the
//! Council of Critics audit pipeline and returns verified claims.
//!
//! This endpoint is protected (requires Ed25519 signature).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;

/// Maximum content length for harvest requests (1MB)
const MAX_HARVEST_CONTENT_LENGTH: usize = 1_048_576;

/// Request body for the harvest endpoint
#[derive(Debug, Deserialize)]
pub struct HarvestRequest {
    /// The text content to extract claims from
    pub content: String,
    /// Optional source identifier for provenance tracking
    pub source_id: Option<String>,
    /// Content modality (default: "text")
    pub modality: Option<String>,
    /// Optional metadata about the source document
    pub metadata: Option<HarvestMetadata>,
}

/// Optional metadata for harvest source tracking
#[derive(Debug, Deserialize)]
pub struct HarvestMetadata {
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub page_number: Option<i32>,
    pub section_title: Option<String>,
}

/// Response from a successful harvest operation
#[derive(Debug, Serialize)]
pub struct HarvestResponse {
    /// Unique identifier for this harvest operation
    pub harvest_id: Uuid,
    /// Status of the harvest operation
    pub status: String,
    /// Number of claims extracted
    pub claims_extracted: usize,
    /// Overall confidence from the Council of Critics audit
    pub overall_confidence: f64,
    /// Whether the extraction passed the audit
    pub passed_audit: bool,
    /// Individual extracted claim summaries
    pub claims: Vec<ExtractedClaimSummary>,
}

/// Summary of an extracted claim
#[derive(Debug, Serialize)]
pub struct ExtractedClaimSummary {
    /// Statement of the claim
    pub statement: String,
    /// Confidence in this specific claim
    pub confidence: f64,
    /// Type of claim (factual, hypothesis, opinion, definition)
    pub claim_type: String,
    /// Whether this claim was flagged as low confidence
    pub low_confidence_flag: bool,
}

/// POST /api/v1/harvest
///
/// Accept a text fragment for claim extraction via the Reflective Harvester.
///
/// # Request Body
///
/// ```json
/// {
///   "content": "The Earth orbits the Sun at a mean distance of 149.6 million km...",
///   "source_id": "optional-source-uuid",
///   "modality": "text",
///   "metadata": {
///     "filename": "astronomy.pdf",
///     "page_number": 42
///   }
/// }
/// ```
///
/// # Responses
///
/// - `200 OK` — Claims extracted and audited successfully
/// - `400 Bad Request` — Invalid input (empty content, oversized, invalid modality)
/// - `401 Unauthorized` — Missing or invalid signature
/// - `503 Service Unavailable` — Harvester gRPC service is not connected
pub async fn submit_harvest(
    State(state): State<AppState>,
    Json(request): Json<HarvestRequest>,
) -> Result<(StatusCode, Json<HarvestResponse>), ApiError> {
    // Validate content is non-empty
    if request.content.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "content".to_string(),
            reason: "Content must not be empty".to_string(),
        });
    }

    // Validate content size
    if request.content.len() > MAX_HARVEST_CONTENT_LENGTH {
        return Err(ApiError::ValidationError {
            field: "content".to_string(),
            reason: format!(
                "Content exceeds maximum size of {} bytes",
                MAX_HARVEST_CONTENT_LENGTH
            ),
        });
    }

    // Validate modality
    let modality = request.modality.as_deref().unwrap_or("text");
    if !["text", "pdf", "audio"].contains(&modality) {
        return Err(ApiError::ValidationError {
            field: "modality".to_string(),
            reason: format!(
                "Invalid modality '{}'. Must be one of: text, pdf, audio",
                modality
            ),
        });
    }

    // Check if harvester client is available
    let harvester = state.harvester_client.as_ref().ok_or_else(|| {
        tracing::warn!("Harvest request received but harvester gRPC client is not configured");
        ApiError::ServiceUnavailable {
            service: "harvester".to_string(),
        }
    })?;

    // Forward to the harvester gRPC service
    let result = harvester
        .process_fragment(
            &request.content,
            modality,
            request.source_id.as_deref(),
            request.metadata.as_ref(),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Harvester gRPC call failed");
            ApiError::ServiceUnavailable {
                service: "harvester".to_string(),
            }
        })?;

    let response = HarvestResponse {
        harvest_id: result.harvest_id,
        status: result.status,
        claims_extracted: result.claims.len(),
        overall_confidence: result.overall_confidence,
        passed_audit: result.passed_audit,
        claims: result.claims,
    };

    Ok((StatusCode::OK, Json(response)))
}

/// Result from the harvester gRPC service
pub struct HarvestResult {
    pub harvest_id: Uuid,
    pub status: String,
    pub overall_confidence: f64,
    pub passed_audit: bool,
    pub claims: Vec<ExtractedClaimSummary>,
}

/// Trait for harvester gRPC client abstraction
///
/// This allows the handler to work with both a real gRPC client
/// and a mock client for testing.
#[async_trait::async_trait]
pub trait HarvesterClient: Send + Sync {
    async fn process_fragment(
        &self,
        content: &str,
        modality: &str,
        source_id: Option<&str>,
        metadata: Option<&HarvestMetadata>,
    ) -> Result<HarvestResult, HarvesterError>;
}

/// Errors from the harvester client
#[derive(Debug, thiserror::Error)]
pub enum HarvesterError {
    #[error("Harvester connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Harvester processing failed: {0}")]
    ProcessingFailed(String),

    #[error("Harvester returned invalid response: {0}")]
    InvalidResponse(String),
}

impl std::fmt::Display for HarvestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HarvestResult {{ id: {}, claims: {}, confidence: {:.2} }}",
            self.harvest_id,
            self.claims.len(),
            self.overall_confidence
        )
    }
}

// ==================== Tests ====================

#[cfg(all(test, not(feature = "db")))]
mod tests {
    use super::*;
    use crate::state::ApiConfig;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Mock harvester client for testing
    struct MockHarvesterClient {
        should_succeed: bool,
    }

    #[async_trait::async_trait]
    impl HarvesterClient for MockHarvesterClient {
        async fn process_fragment(
            &self,
            content: &str,
            _modality: &str,
            _source_id: Option<&str>,
            _metadata: Option<&HarvestMetadata>,
        ) -> Result<HarvestResult, HarvesterError> {
            if !self.should_succeed {
                return Err(HarvesterError::ConnectionFailed(
                    "Mock connection failure".to_string(),
                ));
            }

            Ok(HarvestResult {
                harvest_id: Uuid::new_v4(),
                status: "success".to_string(),
                overall_confidence: 0.85,
                passed_audit: true,
                claims: vec![ExtractedClaimSummary {
                    statement: format!("Extracted from: {}", &content[..content.len().min(50)]),
                    confidence: 0.9,
                    claim_type: "factual".to_string(),
                    low_confidence_flag: false,
                }],
            })
        }
    }

    fn create_test_router(harvester: Option<Arc<dyn HarvesterClient>>) -> Router {
        let mut state = AppState::new(ApiConfig::default());
        state.harvester_client = harvester;
        Router::new()
            .route("/api/v1/harvest", post(submit_harvest))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_harvest_success() {
        let client = Arc::new(MockHarvesterClient {
            should_succeed: true,
        });
        let router = create_test_router(Some(client));

        let body = serde_json::json!({
            "content": "The Earth orbits the Sun at 149.6 million km."
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/harvest")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(result["status"], "success");
        assert_eq!(result["claims_extracted"], 1);
        assert!(result["passed_audit"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_harvest_empty_content_returns_400() {
        let client = Arc::new(MockHarvesterClient {
            should_succeed: true,
        });
        let router = create_test_router(Some(client));

        let body = serde_json::json!({
            "content": "   "
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/harvest")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_harvest_oversized_content_returns_400() {
        let client = Arc::new(MockHarvesterClient {
            should_succeed: true,
        });
        let router = create_test_router(Some(client));

        let body = serde_json::json!({
            "content": "x".repeat(MAX_HARVEST_CONTENT_LENGTH + 1)
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/harvest")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_harvest_invalid_modality_returns_400() {
        let client = Arc::new(MockHarvesterClient {
            should_succeed: true,
        });
        let router = create_test_router(Some(client));

        let body = serde_json::json!({
            "content": "Some text content",
            "modality": "video"
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/harvest")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_harvest_no_client_returns_503() {
        let router = create_test_router(None);

        let body = serde_json::json!({
            "content": "Some text content"
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/harvest")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_harvest_client_failure_returns_503() {
        let client = Arc::new(MockHarvesterClient {
            should_succeed: false,
        });
        let router = create_test_router(Some(client));

        let body = serde_json::json!({
            "content": "Some text content"
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/harvest")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_harvest_with_metadata() {
        let client = Arc::new(MockHarvesterClient {
            should_succeed: true,
        });
        let router = create_test_router(Some(client));

        let body = serde_json::json!({
            "content": "The Earth orbits the Sun at 149.6 million km.",
            "source_id": "source-123",
            "modality": "pdf",
            "metadata": {
                "filename": "astronomy.pdf",
                "page_number": 42,
                "section_title": "Orbital Mechanics"
            }
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/harvest")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_harvest_malformed_json_returns_400() {
        let client = Arc::new(MockHarvesterClient {
            should_succeed: true,
        });
        let router = create_test_router(Some(client));

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/harvest")
            .header("content-type", "application/json")
            .body(Body::from("{not valid json"))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // Axum returns 422 for deserialization errors by default
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}
