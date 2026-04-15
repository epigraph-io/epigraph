//! Challenge endpoints for disputing claims
//!
//! POST /api/v1/claims/:id/challenge - Submit a challenge (protected)
//! GET  /api/v1/claims/:id/challenges - List challenges for a claim (public)
//!
//! Challenges allow agents to dispute existing claims with counter-evidence.
//! This is a core epistemic mechanism: truth must be contestable to be trustworthy.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;
use epigraph_core::challenge::{Challenge, ChallengeType};

// =============================================================================
// SECURITY CONSTANTS
// =============================================================================

/// Maximum length of challenge explanation in bytes.
/// Prevents memory exhaustion from excessively large explanations.
/// Matches the MAX_EXPLANATION_LENGTH used in submit.rs (32KB).
const MAX_EXPLANATION_LENGTH: usize = 32_768;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request body for submitting a challenge against a claim
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SubmitChallengeRequest {
    /// The agent raising the challenge
    pub challenger_id: Uuid,

    /// Type of challenge (snake_case string matching ChallengeType variants)
    pub challenge_type: String,

    /// Detailed explanation of why this claim is being challenged
    pub explanation: String,
}

/// API response for a challenge
///
/// Uses snake_case strings for enum variants to follow REST API conventions.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChallengeResponse {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub challenger_id: Uuid,
    pub challenge_type: String,
    pub explanation: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<Uuid>,
}

impl From<Challenge> for ChallengeResponse {
    fn from(c: Challenge) -> Self {
        Self {
            id: c.id.into(),
            claim_id: c.claim_id.into(),
            challenger_id: c.challenger_id.into(),
            challenge_type: format_challenge_type(c.challenge_type),
            explanation: c.explanation,
            state: c.state.to_string(),
            created_at: c.created_at,
            resolved_at: c.resolved_at,
            resolved_by: c.resolved_by.map(Into::into),
        }
    }
}

/// Response for listing challenges
#[derive(Debug, Serialize, Deserialize)]
pub struct ListChallengesResponse {
    pub challenges: Vec<ChallengeResponse>,
    pub total: usize,
}

// =============================================================================
// ENUM CONVERSION
// =============================================================================

/// Parse a snake_case string into a `ChallengeType` enum variant.
///
/// Returns `None` if the string does not match any known variant.
fn parse_challenge_type(s: &str) -> Option<ChallengeType> {
    match s {
        "insufficient_evidence" => Some(ChallengeType::InsufficientEvidence),
        "outdated_evidence" => Some(ChallengeType::OutdatedEvidence),
        "flawed_methodology" => Some(ChallengeType::FlawedMethodology),
        "contradicting_evidence" => Some(ChallengeType::ContradictingEvidence),
        "factual_error" => Some(ChallengeType::FactualError),
        _ => None,
    }
}

/// Format a `ChallengeType` as a snake_case string for API responses.
fn format_challenge_type(ct: ChallengeType) -> String {
    match ct {
        ChallengeType::InsufficientEvidence => "insufficient_evidence".to_string(),
        ChallengeType::OutdatedEvidence => "outdated_evidence".to_string(),
        ChallengeType::FlawedMethodology => "flawed_methodology".to_string(),
        ChallengeType::ContradictingEvidence => "contradicting_evidence".to_string(),
        ChallengeType::FactualError => "factual_error".to_string(),
    }
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Submit a challenge against a claim
///
/// POST /api/v1/claims/:id/challenge
///
/// This is a protected endpoint requiring Ed25519 signature verification.
/// Agents must provide a valid challenge type and non-empty explanation
/// to dispute a claim's truth value.
///
/// # Errors
///
/// - 400 Bad Request: Invalid challenge type, empty explanation, or duplicate challenge
/// - 401 Unauthorized: Missing or invalid signature (handled by middleware)
/// - 201 Created: Challenge submitted successfully
pub async fn submit_challenge(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Json(request): Json<SubmitChallengeRequest>,
) -> Result<(StatusCode, Json<ChallengeResponse>), ApiError> {
    // 1. Validate challenge_type is a known variant
    // Named with leading underscore in the db path where it's used only for validation.
    #[cfg(feature = "db")]
    let _challenge_type =
        parse_challenge_type(&request.challenge_type).ok_or_else(|| ApiError::ValidationError {
            field: "challenge_type".to_string(),
            reason: format!(
                "Unknown challenge type '{}'. Valid types: insufficient_evidence, \
                 outdated_evidence, flawed_methodology, contradicting_evidence, factual_error",
                request.challenge_type
            ),
        })?;
    #[cfg(not(feature = "db"))]
    let challenge_type =
        parse_challenge_type(&request.challenge_type).ok_or_else(|| ApiError::ValidationError {
            field: "challenge_type".to_string(),
            reason: format!(
                "Unknown challenge type '{}'. Valid types: insufficient_evidence, \
                 outdated_evidence, flawed_methodology, contradicting_evidence, factual_error",
                request.challenge_type
            ),
        })?;

    // 2. Validate explanation is not empty
    if request.explanation.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "explanation".to_string(),
            reason: "Explanation cannot be empty".to_string(),
        });
    }

    // 3. Validate explanation length (DoS prevention)
    if request.explanation.len() > MAX_EXPLANATION_LENGTH {
        return Err(ApiError::ValidationError {
            field: "explanation".to_string(),
            reason: format!(
                "Explanation too long: {} bytes, maximum is {} bytes",
                request.explanation.len(),
                MAX_EXPLANATION_LENGTH
            ),
        });
    }

    // 4. Create and submit the challenge
    //
    // When `db` feature is enabled, persist to PostgreSQL via ChallengeRepository.
    // Otherwise, use the in-memory ChallengeService.
    #[cfg(feature = "db")]
    let response = {
        let challenge_id = epigraph_db::ChallengeRepository::create(
            &state.db_pool,
            claim_id,
            Some(request.challenger_id),
            &request.challenge_type,
            &request.explanation,
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to persist challenge: {e}"),
        })?;

        // Also emit a DB event
        let _ = epigraph_db::EventRepository::insert(
            &state.db_pool,
            "claim.challenged",
            Some(request.challenger_id),
            &serde_json::json!({
                "challenge_id": challenge_id,
                "claim_id": claim_id,
                "challenge_type": request.challenge_type,
            }),
        )
        .await;

        ChallengeResponse {
            id: challenge_id,
            claim_id,
            challenger_id: request.challenger_id,
            challenge_type: request.challenge_type.clone(),
            explanation: request.explanation.clone(),
            state: "pending".to_string(),
            created_at: Utc::now(),
            resolved_at: None,
            resolved_by: None,
        }
    };

    #[cfg(not(feature = "db"))]
    let response = {
        let challenge = Challenge::new(
            ClaimId::from_uuid(claim_id),
            AgentId::from_uuid(request.challenger_id),
            challenge_type,
            request.explanation,
        );

        let _challenge_id =
            state
                .challenge_service
                .submit(challenge.clone())
                .map_err(|e| match e {
                    epigraph_core::challenge::ChallengeError::Duplicate { claim_id: cid } => {
                        ApiError::BadRequest {
                            message: format!(
                                "A pending challenge already exists for claim {} by this agent",
                                Uuid::from(cid)
                            ),
                        }
                    }
                    other => ApiError::InternalError {
                        message: format!("Failed to submit challenge: {other}"),
                    },
                })?;

        // Publish ClaimChallenged event (fire-and-forget)
        let _ = state
            .event_bus
            .publish(EpiGraphEvent::ClaimChallenged {
                claim_id: ClaimId::from_uuid(claim_id),
                challenger_id: AgentId::from_uuid(request.challenger_id),
                challenge_id: epigraph_events::events::ChallengeId::from_uuid(
                    challenge.id.as_uuid(),
                ),
            })
            .await;

        ChallengeResponse::from(challenge)
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// List all challenges for a specific claim
///
/// GET /api/v1/claims/:id/challenges
///
/// This is a public endpoint. Transparency is a core epistemic principle:
/// anyone can see what challenges have been raised against a claim.
///
/// # Errors
///
/// Returns 200 OK with an empty list if no challenges exist for the claim.
pub async fn list_challenges(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<ListChallengesResponse>, ApiError> {
    #[cfg(feature = "db")]
    let challenge_responses = {
        let rows = epigraph_db::ChallengeRepository::list_for_claim(&state.db_pool, claim_id)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to list challenges: {e}"),
            })?;
        rows.into_iter()
            .map(|r| ChallengeResponse {
                id: r.id,
                claim_id: r.claim_id,
                challenger_id: r.challenger_id.unwrap_or(Uuid::nil()),
                challenge_type: r.challenge_type,
                explanation: r.explanation,
                state: r.state,
                created_at: r.created_at,
                resolved_at: r.resolved_at,
                resolved_by: r.resolved_by,
            })
            .collect::<Vec<_>>()
    };

    #[cfg(not(feature = "db"))]
    let challenge_responses = {
        let challenges = state
            .challenge_service
            .list_by_claim(ClaimId::from_uuid(claim_id));
        challenges
            .into_iter()
            .map(ChallengeResponse::from)
            .collect::<Vec<_>>()
    };

    let total = challenge_responses.len();
    Ok(Json(ListChallengesResponse {
        challenges: challenge_responses,
        total,
    }))
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_core::{AgentId, ClaimId};

    // ---- Unit tests (no DB needed) ----

    #[test]
    fn test_parse_challenge_type_valid() {
        assert!(parse_challenge_type("insufficient_evidence").is_some());
        assert!(parse_challenge_type("outdated_evidence").is_some());
        assert!(parse_challenge_type("flawed_methodology").is_some());
        assert!(parse_challenge_type("contradicting_evidence").is_some());
        assert!(parse_challenge_type("factual_error").is_some());
    }

    #[test]
    fn test_parse_challenge_type_invalid() {
        assert!(parse_challenge_type("invalid_type").is_none());
        assert!(parse_challenge_type("").is_none());
    }

    #[test]
    fn test_challenge_response_from_domain() {
        let challenge = Challenge::new(
            ClaimId::from_uuid(Uuid::new_v4()),
            AgentId::from_uuid(Uuid::new_v4()),
            ChallengeType::InsufficientEvidence,
            "Not enough data",
        );
        let response = ChallengeResponse::from(challenge);
        assert_eq!(response.challenge_type, "insufficient_evidence");
        assert_eq!(response.state, "pending");
    }

    // ---- Handler integration tests (need AppState without DB) ----

    #[cfg(not(feature = "db"))]
    mod handler_tests {
        use super::super::*;
        use crate::state::ApiConfig;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::{get, post};
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        /// Create a test router with challenge endpoints (no auth middleware for unit tests)
        fn test_router() -> Router {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            Router::new()
                .route("/api/v1/claims/:id/challenge", post(submit_challenge))
                .route("/api/v1/claims/:id/challenges", get(list_challenges))
                .with_state(state)
        }

        /// Helper to parse JSON response body
        async fn parse_body<T: serde::de::DeserializeOwned>(
            response: axum::http::Response<Body>,
        ) -> T {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice(&body).unwrap()
        }

        #[tokio::test]
        async fn test_submit_challenge_valid() {
            let router = test_router();
            let claim_id = Uuid::new_v4();

            let body = serde_json::json!({
                "challenger_id": Uuid::new_v4(),
                "challenge_type": "insufficient_evidence",
                "explanation": "The claim lacks sufficient peer-reviewed evidence."
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            let challenge: ChallengeResponse = parse_body(response).await;
            assert_eq!(challenge.claim_id, claim_id);
            assert_eq!(challenge.challenge_type, "insufficient_evidence");
            assert_eq!(challenge.state, "pending");
            assert_eq!(
                challenge.explanation,
                "The claim lacks sufficient peer-reviewed evidence."
            );
        }

        #[tokio::test]
        async fn test_submit_challenge_invalid_type() {
            let router = test_router();
            let claim_id = Uuid::new_v4();

            let body = serde_json::json!({
                "challenger_id": Uuid::new_v4(),
                "challenge_type": "invalid_type",
                "explanation": "Some explanation."
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_submit_challenge_empty_explanation() {
            let router = test_router();
            let claim_id = Uuid::new_v4();

            let body = serde_json::json!({
                "challenger_id": Uuid::new_v4(),
                "challenge_type": "factual_error",
                "explanation": ""
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_submit_challenge_whitespace_only_explanation() {
            let router = test_router();
            let claim_id = Uuid::new_v4();

            let body = serde_json::json!({
                "challenger_id": Uuid::new_v4(),
                "challenge_type": "factual_error",
                "explanation": "   \n\t  "
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_submit_challenge_explanation_too_long() {
            let router = test_router();
            let claim_id = Uuid::new_v4();
            let long_explanation = "x".repeat(MAX_EXPLANATION_LENGTH + 1);

            let body = serde_json::json!({
                "challenger_id": Uuid::new_v4(),
                "challenge_type": "flawed_methodology",
                "explanation": long_explanation
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_list_challenges_empty() {
            let router = test_router();
            let claim_id = Uuid::new_v4();

            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_id}/challenges"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let list: ListChallengesResponse = parse_body(response).await;
            assert_eq!(list.total, 0);
            assert!(list.challenges.is_empty());
        }

        #[tokio::test]
        async fn test_list_challenges_after_submission() {
            // Use shared state so both requests see the same ChallengeService
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let claim_id = Uuid::new_v4();
            let challenger_id = Uuid::new_v4();

            // Submit a challenge directly to the service
            let challenge = Challenge::new(
                ClaimId::from_uuid(claim_id),
                AgentId::from_uuid(challenger_id),
                ChallengeType::FactualError,
                "The earth is not flat.",
            );
            state.challenge_service.submit(challenge).unwrap();

            // Build router with the same state
            let router = Router::new()
                .route("/api/v1/claims/:id/challenges", get(list_challenges))
                .with_state(state);

            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_id}/challenges"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let list: ListChallengesResponse = parse_body(response).await;
            assert_eq!(list.total, 1);
            assert_eq!(list.challenges[0].claim_id, claim_id);
            assert_eq!(list.challenges[0].challenger_id, challenger_id);
            assert_eq!(list.challenges[0].challenge_type, "factual_error");
            assert_eq!(list.challenges[0].state, "pending");
        }

        #[tokio::test]
        async fn test_duplicate_challenge_rejected() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let claim_id = Uuid::new_v4();
            let challenger_id = Uuid::new_v4();

            let router = Router::new()
                .route("/api/v1/claims/:id/challenge", post(submit_challenge))
                .with_state(state);

            let body = serde_json::json!({
                "challenger_id": challenger_id,
                "challenge_type": "insufficient_evidence",
                "explanation": "First challenge."
            });
            let body_str = serde_json::to_string(&body).unwrap();

            // First submission should succeed
            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(body_str.clone()))
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            // Second submission with same agent + claim should fail (duplicate)
            let body2 = serde_json::json!({
                "challenger_id": challenger_id,
                "challenge_type": "factual_error",
                "explanation": "Second challenge attempt."
            });

            let request2 = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body2).unwrap()))
                .unwrap();

            let response2 = router.oneshot(request2).await.unwrap();
            assert_eq!(response2.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_all_challenge_types_accepted() {
            let valid_types = [
                "insufficient_evidence",
                "outdated_evidence",
                "flawed_methodology",
                "contradicting_evidence",
                "factual_error",
            ];

            for challenge_type in valid_types {
                let state = AppState::new(ApiConfig {
                    require_signatures: false,
                    ..ApiConfig::default()
                });

                let router = Router::new()
                    .route("/api/v1/claims/:id/challenge", post(submit_challenge))
                    .with_state(state);

                let claim_id = Uuid::new_v4();
                let body = serde_json::json!({
                    "challenger_id": Uuid::new_v4(),
                    "challenge_type": challenge_type,
                    "explanation": format!("Testing {challenge_type} challenge type.")
                });

                let request = Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap();

                let response = router.oneshot(request).await.unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::CREATED,
                    "Challenge type '{challenge_type}' should be accepted"
                );

                let challenge: ChallengeResponse = parse_body(response).await;
                assert_eq!(challenge.challenge_type, challenge_type);
            }
        }
        // ================================================================
        // Integration tests using the full create_router (with middleware)
        // ================================================================

        /// Helper: build a challenge JSON body
        fn challenge_body(challenger_id: Uuid, challenge_type: &str, explanation: &str) -> String {
            serde_json::to_string(&serde_json::json!({
                "challenger_id": challenger_id,
                "challenge_type": challenge_type,
                "explanation": explanation,
            }))
            .unwrap()
        }

        #[tokio::test]
        async fn test_submit_challenge_without_signature_returns_401() {
            // Use create_router which wires up the require_signature middleware.
            // Any POST to a protected route without signature headers must be rejected.
            let state = AppState::new(ApiConfig {
                require_signatures: false, // even with flag off, middleware still checks headers
                ..ApiConfig::default()
            });
            let router = crate::routes::create_router(state);

            let claim_id = Uuid::new_v4();
            let body = challenge_body(
                Uuid::new_v4(),
                "insufficient_evidence",
                "No supporting studies cited.",
            );

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "POST to protected challenge route without signature headers should return 401"
            );
        }

        #[tokio::test]
        async fn test_list_challenges_via_full_router_returns_empty_for_nonexistent_claim() {
            // The GET endpoint is public - no auth required.
            // A random UUID that has no challenges should return an empty list, not 404.
            let state = AppState::new(ApiConfig::default());
            let router = crate::routes::create_router(state);

            let nonexistent_id = Uuid::new_v4();
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{nonexistent_id}/challenges"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let list: ListChallengesResponse = parse_body(response).await;
            assert_eq!(list.total, 0);
            assert!(list.challenges.is_empty());
        }

        #[tokio::test]
        async fn test_list_challenges_returns_multiple() {
            // Submit multiple challenges from different agents against the same claim,
            // then verify list_challenges returns all of them.
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let claim_id = Uuid::new_v4();

            // Submit 3 challenges directly to the service (bypass auth for setup)
            let types = [
                (ChallengeType::InsufficientEvidence, "insufficient_evidence"),
                (ChallengeType::FlawedMethodology, "flawed_methodology"),
                (ChallengeType::FactualError, "factual_error"),
            ];
            for (ct, _label) in &types {
                let challenge = Challenge::new(
                    ClaimId::from_uuid(claim_id),
                    AgentId::from_uuid(Uuid::new_v4()), // distinct agent each time
                    *ct,
                    format!("Challenge for {:?}", ct),
                );
                state.challenge_service.submit(challenge).unwrap();
            }

            // Build router with same state for the GET endpoint
            let router = Router::new()
                .route("/api/v1/claims/:id/challenges", get(list_challenges))
                .with_state(state);

            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_id}/challenges"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let list: ListChallengesResponse = parse_body(response).await;
            assert_eq!(list.total, 3, "Expected 3 challenges, got {}", list.total);
            assert_eq!(list.challenges.len(), 3);

            // All should be for the same claim
            for ch in &list.challenges {
                assert_eq!(ch.claim_id, claim_id);
                assert_eq!(ch.state, "pending");
            }

            // Verify that the challenge types we submitted are present
            let returned_types: Vec<&str> = list
                .challenges
                .iter()
                .map(|c| c.challenge_type.as_str())
                .collect();
            assert!(returned_types.contains(&"insufficient_evidence"));
            assert!(returned_types.contains(&"flawed_methodology"));
            assert!(returned_types.contains(&"factual_error"));
        }

        #[tokio::test]
        async fn test_list_challenges_different_claims_are_isolated() {
            // Challenges for claim A must not appear in the listing for claim B.
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let claim_a = Uuid::new_v4();
            let claim_b = Uuid::new_v4();

            // Submit 2 challenges for claim_a
            for _ in 0..2 {
                let challenge = Challenge::new(
                    ClaimId::from_uuid(claim_a),
                    AgentId::from_uuid(Uuid::new_v4()),
                    ChallengeType::FactualError,
                    "Challenge for claim A",
                );
                state.challenge_service.submit(challenge).unwrap();
            }

            // Submit 1 challenge for claim_b
            let challenge = Challenge::new(
                ClaimId::from_uuid(claim_b),
                AgentId::from_uuid(Uuid::new_v4()),
                ChallengeType::OutdatedEvidence,
                "Challenge for claim B",
            );
            state.challenge_service.submit(challenge).unwrap();

            let router = Router::new()
                .route("/api/v1/claims/:id/challenges", get(list_challenges))
                .with_state(state);

            // List for claim A → expect 2
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_a}/challenges"))
                .body(Body::empty())
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            let list_a: ListChallengesResponse = parse_body(response).await;
            assert_eq!(list_a.total, 2, "Claim A should have 2 challenges");

            // List for claim B → expect 1
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_b}/challenges"))
                .body(Body::empty())
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            let list_b: ListChallengesResponse = parse_body(response).await;
            assert_eq!(list_b.total, 1, "Claim B should have 1 challenge");
            assert_eq!(list_b.challenges[0].challenge_type, "outdated_evidence");
        }

        #[tokio::test]
        async fn test_duplicate_challenge_same_agent_same_claim_via_service() {
            // Verify that submitting two challenges from the same agent against
            // the same claim is rejected as a duplicate, even with different types.
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let claim_id = Uuid::new_v4();
            let challenger_id = Uuid::new_v4();

            // First challenge should succeed
            let c1 = Challenge::new(
                ClaimId::from_uuid(claim_id),
                AgentId::from_uuid(challenger_id),
                ChallengeType::InsufficientEvidence,
                "First challenge",
            );
            assert!(state.challenge_service.submit(c1).is_ok());

            // Second challenge with same agent + claim should fail
            let c2 = Challenge::new(
                ClaimId::from_uuid(claim_id),
                AgentId::from_uuid(challenger_id),
                ChallengeType::FlawedMethodology,
                "Second challenge - different type",
            );
            let result = state.challenge_service.submit(c2);
            assert!(result.is_err(), "Duplicate challenge should be rejected");

            // Verify only 1 challenge exists
            let challenges = state
                .challenge_service
                .list_by_claim(ClaimId::from_uuid(claim_id));
            assert_eq!(challenges.len(), 1);
        }

        #[tokio::test]
        async fn test_duplicate_challenge_different_agent_same_claim_allowed() {
            // Two different agents should be able to challenge the same claim.
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let claim_id = Uuid::new_v4();
            let agent_a = Uuid::new_v4();
            let agent_b = Uuid::new_v4();

            let router = Router::new()
                .route("/api/v1/claims/:id/challenge", post(submit_challenge))
                .with_state(state);

            // Agent A challenges
            let body_a = challenge_body(agent_a, "insufficient_evidence", "Agent A's challenge.");
            let req_a = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(body_a))
                .unwrap();
            let resp_a = router.clone().oneshot(req_a).await.unwrap();
            assert_eq!(resp_a.status(), StatusCode::CREATED);

            // Agent B challenges the same claim
            let body_b = challenge_body(agent_b, "factual_error", "Agent B's challenge.");
            let req_b = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(body_b))
                .unwrap();
            let resp_b = router.oneshot(req_b).await.unwrap();
            assert_eq!(
                resp_b.status(),
                StatusCode::CREATED,
                "Different agents should be able to challenge the same claim"
            );
        }

        #[tokio::test]
        async fn test_submit_challenge_response_fields_match_request() {
            // Verify the response body accurately reflects the submitted challenge.
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let router = Router::new()
                .route("/api/v1/claims/:id/challenge", post(submit_challenge))
                .with_state(state);

            let claim_id = Uuid::new_v4();
            let challenger_id = Uuid::new_v4();
            let explanation = "The cited study used a sample size of n=3.";

            let body = challenge_body(challenger_id, "flawed_methodology", explanation);
            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            let challenge: ChallengeResponse = parse_body(response).await;
            assert_eq!(challenge.claim_id, claim_id);
            assert_eq!(challenge.challenger_id, challenger_id);
            assert_eq!(challenge.challenge_type, "flawed_methodology");
            assert_eq!(challenge.explanation, explanation);
            assert_eq!(challenge.state, "pending");
            assert!(challenge.resolved_at.is_none());
            assert!(challenge.resolved_by.is_none());
            // ID should be a valid UUID (non-nil)
            assert_ne!(challenge.id, Uuid::nil());
        }

        #[tokio::test]
        async fn test_list_challenges_via_full_router_after_direct_submission() {
            // Submit a challenge via the service, then verify it appears through
            // the full router's GET endpoint (proving routing + handler work end-to-end).
            let state = AppState::new(ApiConfig::default());

            let claim_id = Uuid::new_v4();
            let challenger_id = Uuid::new_v4();

            let challenge = Challenge::new(
                ClaimId::from_uuid(claim_id),
                AgentId::from_uuid(challenger_id),
                ChallengeType::ContradictingEvidence,
                "A 2025 meta-analysis contradicts this claim.",
            );
            state.challenge_service.submit(challenge).unwrap();

            let router = crate::routes::create_router(state);

            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/claims/{claim_id}/challenges"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let list: ListChallengesResponse = parse_body(response).await;
            assert_eq!(list.total, 1);
            assert_eq!(list.challenges[0].claim_id, claim_id);
            assert_eq!(list.challenges[0].challenger_id, challenger_id);
            assert_eq!(list.challenges[0].challenge_type, "contradicting_evidence");
        }
    } // end mod handler_tests

    #[cfg(not(feature = "db"))]
    mod event_tests {
        use super::super::*;
        use crate::state::ApiConfig;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::post;
        use axum::Router;
        use tower::ServiceExt;

        #[tokio::test]
        async fn test_submit_challenge_publishes_claim_challenged_event() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let router = Router::new()
                .route("/api/v1/claims/:id/challenge", post(submit_challenge))
                .with_state(state.clone());

            let claim_id = Uuid::new_v4();
            let body = serde_json::json!({
                "challenger_id": Uuid::new_v4(),
                "challenge_type": "insufficient_evidence",
                "explanation": "This claim lacks peer-reviewed evidence."
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            // Verify that a ClaimChallenged event was published
            assert_eq!(
                state.event_bus.history_size(),
                1,
                "Event bus should contain exactly one event after successful challenge"
            );

            let history = state.event_bus.get_history().unwrap();
            assert_eq!(history[0].event.event_type(), "ClaimChallenged");
        }

        #[tokio::test]
        async fn test_submit_challenge_no_event_on_validation_failure() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            let router = Router::new()
                .route("/api/v1/claims/:id/challenge", post(submit_challenge))
                .with_state(state.clone());

            let claim_id = Uuid::new_v4();
            // Invalid: empty explanation
            let body = serde_json::json!({
                "challenger_id": Uuid::new_v4(),
                "challenge_type": "factual_error",
                "explanation": ""
            });

            let request = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/claims/{claim_id}/challenge"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            // No event should be published on validation failure
            assert_eq!(
                state.event_bus.history_size(),
                0,
                "Event bus should be empty after failed challenge submission"
            );
        }
    } // end mod event_tests
}
