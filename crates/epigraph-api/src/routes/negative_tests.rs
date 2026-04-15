//! Negative and edge-case tests for the EpiGraph API
//!
//! This module exercises three categories of failure and boundary conditions:
//!
//! 1. **Malformed Input Tests** (Suite 3.1): Invalid JSON, missing fields, oversized
//!    payloads, empty strings, out-of-bounds values, and unicode edge cases.
//!
//! 2. **Auth Failure Tests** (Suite 3.2): Missing headers, expired timestamps,
//!    future timestamps, malformed timestamps, and coverage of all protected routes.
//!
//! 3. **Concurrency Tests** (Suite 3.3): Thread safety of shared AppState under
//!    parallel submissions, queries, and admin stats requests.
//!
//! # Design Decisions
//!
//! - Malformed input tests use **direct routers** (no auth middleware layer) so
//!   validation logic is exercised without signature verification interference.
//! - Auth tests use the full `create_router()` which includes the `require_signature`
//!   middleware layer, proving that unauthenticated requests are properly rejected.
//! - Concurrency tests clone `AppState` (which is `Arc`-backed) across multiple
//!   tokio tasks, each creating its own router via `create_router` to avoid
//!   consuming the router with `oneshot`.

#[cfg(all(test, not(feature = "db")))]
mod malformed_input_tests {
    use crate::routes::batch::batch_create_claims;
    use crate::routes::challenge::submit_challenge;
    use crate::routes::rag::rag_context;
    use crate::routes::submit::submit_packet;
    use crate::routes::webhooks::register_webhook;
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use epigraph_crypto::ContentHasher;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    /// Create a direct router for the submit endpoint (no auth middleware).
    fn submit_router() -> Router {
        let state = AppState::new(ApiConfig::default());
        Router::new()
            .route("/api/v1/submit/packet", post(submit_packet))
            .with_state(state)
    }

    /// Create a direct router for the challenge endpoint (no auth middleware).
    fn challenge_router() -> Router {
        let state = AppState::new(ApiConfig::default());
        Router::new()
            .route("/api/v1/claims/:id/challenge", post(submit_challenge))
            .with_state(state)
    }

    /// Create a direct router for the batch endpoint (no auth middleware).
    fn batch_router() -> Router {
        let state = AppState::new(ApiConfig::default());
        Router::new()
            .route("/api/v1/claims/batch", post(batch_create_claims))
            .with_state(state)
    }

    /// Create a direct router for the RAG endpoint.
    fn rag_router() -> Router {
        let state = AppState::new(ApiConfig::default());
        Router::new()
            .route("/api/v1/query/rag", get(rag_context))
            .with_state(state)
    }

    /// Create a direct router for the webhook registration endpoint (no auth middleware).
    fn webhook_router() -> Router {
        let state = AppState::new(ApiConfig::default());
        Router::new()
            .route("/api/v1/webhooks", post(register_webhook))
            .with_state(state)
    }

    /// Build a valid epistemic packet JSON for mutation in negative tests.
    fn valid_packet_json() -> serde_json::Value {
        let raw_content = "test evidence content";
        let hash = ContentHasher::hash(raw_content.as_bytes());
        let hex_hash = ContentHasher::to_hex(&hash);

        serde_json::json!({
            "claim": {
                "content": "Test claim for negative tests",
                "agent_id": Uuid::new_v4()
            },
            "evidence": [{
                "content_hash": hex_hash,
                "evidence_type": {
                    "type": "document",
                    "source_url": "https://example.com",
                    "mime_type": "text/plain"
                },
                "raw_content": raw_content
            }],
            "reasoning_trace": {
                "methodology": "deductive",
                "inputs": [{ "type": "evidence", "index": 0 }],
                "confidence": 0.8,
                "explanation": "Deductive reasoning from document evidence"
            },
            "signature": "0".repeat(128)
        })
    }

    /// Helper to build a POST request with a JSON body to a given URI.
    fn post_json(uri: &str, body: &serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(body).unwrap()))
            .unwrap()
    }

    /// Helper to build a POST request with raw bytes to a given URI.
    fn post_raw(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    // ====================================================================
    // 3.1.1 Malformed JSON body returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_malformed_json_body_returns_400() {
        let router = submit_router();
        let request = post_raw("/api/v1/submit/packet", "{{{invalid json");

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Completely invalid JSON should return 400"
        );
    }

    // ====================================================================
    // 3.1.2 Missing required fields returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_missing_required_fields_returns_400() {
        let router = submit_router();

        // Valid JSON but missing `reasoning_trace` and `signature`
        let body = serde_json::json!({
            "claim": {
                "content": "Incomplete packet",
                "agent_id": Uuid::new_v4()
            },
            "evidence": []
        });

        let request = post_json("/api/v1/submit/packet", &body);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Missing required fields should return 400"
        );
    }

    // ====================================================================
    // 3.1.3 Invalid UUID in challenge path returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_invalid_uuid_in_challenge_path_returns_400() {
        let router = challenge_router();

        let body = serde_json::json!({
            "challenger_id": Uuid::new_v4(),
            "challenge_type": "factual_error",
            "explanation": "Valid explanation"
        });

        let request = post_json("/api/v1/claims/not-a-uuid/challenge", &body);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Invalid UUID in path should return 400"
        );
    }

    // ====================================================================
    // 3.1.4 Oversized claim content returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_oversized_claim_content_returns_400() {
        let router = submit_router();

        let mut packet = valid_packet_json();
        // 100KB content exceeds MAX_CLAIM_CONTENT_LENGTH (65,536 bytes)
        packet["claim"]["content"] = serde_json::Value::String("x".repeat(100_000));

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "100KB claim content should exceed the 64KB limit and return 400"
        );
    }

    // ====================================================================
    // 3.1.5 Empty string fields returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_empty_string_fields_returns_400() {
        let router = submit_router();

        let mut packet = valid_packet_json();
        packet["claim"]["content"] = serde_json::Value::String(String::new());

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Empty claim content should return 400"
        );
    }

    // ====================================================================
    // 3.1.6 Whitespace-only claim content returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_whitespace_only_claim_content_returns_400() {
        let router = submit_router();

        let mut packet = valid_packet_json();
        packet["claim"]["content"] = serde_json::Value::String("   \n\t  ".to_string());

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Whitespace-only claim content should return 400"
        );
    }

    // ====================================================================
    // 3.1.7 Unicode zero-width chars in content accepted
    // ====================================================================

    #[tokio::test]
    async fn test_unicode_zero_width_chars_in_content() {
        let router = submit_router();

        // Zero-width space (U+200B), zero-width joiner (U+200D), and a visible char
        let zwsp_content = "Valid\u{200B}claim\u{200D}content";
        let raw_content = "test evidence content";
        let hash = ContentHasher::hash(raw_content.as_bytes());
        let hex_hash = ContentHasher::to_hex(&hash);

        let packet = serde_json::json!({
            "claim": {
                "content": zwsp_content,
                "agent_id": Uuid::new_v4()
            },
            "evidence": [{
                "content_hash": hex_hash,
                "evidence_type": {
                    "type": "document",
                    "source_url": "https://example.com",
                    "mime_type": "text/plain"
                },
                "raw_content": raw_content
            }],
            "reasoning_trace": {
                "methodology": "deductive",
                "inputs": [{ "type": "evidence", "index": 0 }],
                "confidence": 0.8,
                "explanation": "Deductive reasoning from document evidence"
            },
            "signature": "0".repeat(128)
        });

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "Zero-width unicode characters are valid and should be accepted"
        );
    }

    // ====================================================================
    // 3.1.8 Empty explanation returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_empty_explanation_returns_400() {
        let router = submit_router();

        let mut packet = valid_packet_json();
        packet["reasoning_trace"]["explanation"] = serde_json::Value::String(String::new());

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Empty reasoning trace explanation violates 'no naked assertions' and should return 400"
        );
    }

    // ====================================================================
    // 3.1.9 Confidence out of bounds (> 1.0) returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_confidence_out_of_bounds_returns_400() {
        let router = submit_router();

        let mut packet = valid_packet_json();
        packet["reasoning_trace"]["confidence"] = serde_json::json!(1.5);

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Confidence 1.5 exceeds [0.0, 1.0] bounds and should return 400"
        );
    }

    // ====================================================================
    // 3.1.10 Negative confidence returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_confidence_negative_returns_400() {
        let router = submit_router();

        let mut packet = valid_packet_json();
        packet["reasoning_trace"]["confidence"] = serde_json::json!(-0.1);

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Negative confidence should return 400"
        );
    }

    // ====================================================================
    // 3.1.11 Truth value "NaN" string returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_truth_value_nan_string_returns_400() {
        let router = submit_router();

        let mut packet = valid_packet_json();
        // JSON does not have a NaN literal, so "NaN" as a string should fail
        // type deserialization for the f64 field
        packet["claim"]["initial_truth"] = serde_json::Value::String("NaN".to_string());

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "String 'NaN' cannot be parsed as a number and should return 400"
        );
    }

    // ====================================================================
    // 3.1.12 Oversized batch returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_oversized_batch_returns_400() {
        let router = batch_router();

        // 101 claims exceeds MAX_BATCH_SIZE of 100
        let claims: Vec<serde_json::Value> = (0..101)
            .map(|i| {
                serde_json::json!({
                    "content": format!("Claim number {}", i),
                    "truth_value": 0.5
                })
            })
            .collect();

        let body = serde_json::json!({ "claims": claims });
        let request = post_json("/api/v1/claims/batch", &body);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Batch with 101 items should exceed MAX_BATCH_SIZE and return 400"
        );
    }

    // ====================================================================
    // 3.1.13 Empty batch returns 200 (not 400)
    // ====================================================================

    #[tokio::test]
    async fn test_empty_batch_returns_200() {
        let router = batch_router();

        let body = serde_json::json!({ "claims": [] });
        let request = post_json("/api/v1/claims/batch", &body);
        let response = router.oneshot(request).await.unwrap();

        // Empty batch is valid per the existing handler behavior:
        // returns 200 with created=0, failed=0
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Empty batch is accepted with 200 (created=0, failed=0)"
        );

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp["created"], 0);
        assert_eq!(resp["failed"], 0);
    }

    // ====================================================================
    // 3.1.14 Challenge with empty explanation returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_challenge_empty_explanation_returns_400() {
        let router = challenge_router();
        let claim_id = Uuid::new_v4();

        let body = serde_json::json!({
            "challenger_id": Uuid::new_v4(),
            "challenge_type": "factual_error",
            "explanation": ""
        });

        let request = post_json(&format!("/api/v1/claims/{}/challenge", claim_id), &body);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Challenge with empty explanation should return 400"
        );
    }

    // ====================================================================
    // 3.1.15 RAG oversized query returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_rag_oversized_query_returns_400() {
        let router = rag_router();

        // Create a query > 10KB (MAX_QUERY_LENGTH = 10,240)
        // Use ASCII 'x' characters which do not require URL-encoding
        let long_query = "x".repeat(11_000);
        let uri = format!("/api/v1/query/rag?query={}", long_query);

        let request = Request::builder().uri(&uri).body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "RAG query > 10KB should return 400"
        );
    }

    // ====================================================================
    // 3.1.16 Webhook with short secret returns 400
    // ====================================================================

    #[tokio::test]
    async fn test_webhook_short_secret_returns_400() {
        let router = webhook_router();

        let body = serde_json::json!({
            "url": "https://example.com/webhook",
            "event_types": ["ClaimSubmitted"],
            "secret": "too-short"  // < 32 chars
        });

        let request = post_json("/api/v1/webhooks", &body);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Webhook secret < 32 characters should return 400"
        );
    }

    // ====================================================================
    // Additional edge cases for completeness
    // ====================================================================

    /// Null initial_truth should be rejected (could represent NaN from other languages)
    #[tokio::test]
    async fn test_null_initial_truth_returns_400() {
        let router = submit_router();

        let mut packet = valid_packet_json();
        packet["claim"]["initial_truth"] = serde_json::Value::Null;

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Explicit null initial_truth should be rejected (NaN guard)"
        );
    }

    /// Evidence with wrong content hash should be rejected (integrity check)
    #[tokio::test]
    async fn test_evidence_hash_mismatch_returns_400() {
        let router = submit_router();

        let mut packet = valid_packet_json();
        // Replace content_hash with a valid-format but incorrect hash
        packet["evidence"][0]["content_hash"] = serde_json::Value::String("a".repeat(64));

        let request = post_json("/api/v1/submit/packet", &packet);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Evidence hash mismatch should return 400"
        );
    }

    /// Challenge with unknown challenge_type string returns 400
    #[tokio::test]
    async fn test_challenge_unknown_type_returns_400() {
        let router = challenge_router();
        let claim_id = Uuid::new_v4();

        let body = serde_json::json!({
            "challenger_id": Uuid::new_v4(),
            "challenge_type": "nonexistent_type",
            "explanation": "This is a valid explanation."
        });

        let request = post_json(&format!("/api/v1/claims/{}/challenge", claim_id), &body);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Unknown challenge_type should return 400"
        );
    }

    /// RAG query with invalid domain filter returns 400
    #[tokio::test]
    async fn test_rag_invalid_domain_returns_400() {
        let router = rag_router();

        let request = Request::builder()
            .uri("/api/v1/query/rag?query=test&domain=invalid_domain")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Invalid domain filter should return 400"
        );
    }

    /// Webhook with empty URL returns 400
    #[tokio::test]
    async fn test_webhook_empty_url_returns_400() {
        let router = webhook_router();

        let body = serde_json::json!({
            "url": "",
            "event_types": [],
            "secret": "a".repeat(32)
        });

        let request = post_json("/api/v1/webhooks", &body);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Empty webhook URL should return 400"
        );
    }
}

#[cfg(all(test, not(feature = "db")))]
mod auth_failure_tests {
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::{Duration, Utc};
    use epigraph_crypto::ContentHasher;
    use tower::ServiceExt;
    use uuid::Uuid;

    /// Create the full application router with `require_signatures: true`.
    fn app_with_auth() -> axum::Router {
        let state = AppState::new(ApiConfig {
            require_signatures: true,
            ..ApiConfig::default()
        });
        crate::routes::create_router(state)
    }

    /// Build a valid packet JSON body (used as payload for auth tests).
    fn valid_packet_body() -> String {
        let raw_content = "test evidence content";
        let hash = ContentHasher::hash(raw_content.as_bytes());
        let hex_hash = ContentHasher::to_hex(&hash);

        serde_json::to_string(&serde_json::json!({
            "claim": {
                "content": "Auth test claim",
                "agent_id": Uuid::new_v4()
            },
            "evidence": [{
                "content_hash": hex_hash,
                "evidence_type": {
                    "type": "document",
                    "source_url": "https://example.com",
                    "mime_type": "text/plain"
                },
                "raw_content": raw_content
            }],
            "reasoning_trace": {
                "methodology": "deductive",
                "inputs": [{ "type": "evidence", "index": 0 }],
                "confidence": 0.8,
                "explanation": "Deductive reasoning from document evidence"
            },
            "signature": "0".repeat(128)
        }))
        .unwrap()
    }

    // ====================================================================
    // 3.2.1 Protected route without any auth headers returns 401
    // ====================================================================

    #[tokio::test]
    async fn test_protected_route_without_any_auth_headers_returns_401() {
        let router = app_with_auth();

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/submit/packet")
            .header("content-type", "application/json")
            .body(Body::from(valid_packet_body()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "POST to protected route without auth headers should return 401"
        );
    }

    // ====================================================================
    // 3.2.2 Missing X-Signature header returns 401
    // ====================================================================

    #[tokio::test]
    async fn test_protected_route_missing_signature_header_returns_401() {
        let router = app_with_auth();

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/submit/packet")
            .header("content-type", "application/json")
            .header("X-Public-Key", "a".repeat(64))
            .header("X-Timestamp", Utc::now().to_rfc3339())
            // Intentionally omit X-Signature
            .body(Body::from(valid_packet_body()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Missing X-Signature should return 401"
        );
    }

    // ====================================================================
    // 3.2.3 Missing X-Public-Key header returns 401
    // ====================================================================

    #[tokio::test]
    async fn test_protected_route_missing_public_key_header_returns_401() {
        let router = app_with_auth();

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/submit/packet")
            .header("content-type", "application/json")
            .header(
                "X-Signature",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]),
            )
            .header("X-Timestamp", Utc::now().to_rfc3339())
            // Intentionally omit X-Public-Key
            .body(Body::from(valid_packet_body()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Missing X-Public-Key should return 401"
        );
    }

    // ====================================================================
    // 3.2.4 Missing X-Timestamp header returns 401
    // ====================================================================

    #[tokio::test]
    async fn test_protected_route_missing_timestamp_header_returns_401() {
        let router = app_with_auth();

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/submit/packet")
            .header("content-type", "application/json")
            .header(
                "X-Signature",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]),
            )
            .header("X-Public-Key", "a".repeat(64))
            // Intentionally omit X-Timestamp
            .body(Body::from(valid_packet_body()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Missing X-Timestamp should return 401"
        );
    }

    // ====================================================================
    // 3.2.5 Expired timestamp returns 401
    // ====================================================================

    #[tokio::test]
    async fn test_expired_timestamp_returns_401() {
        let router = app_with_auth();

        // 10 minutes ago exceeds MAX_SIGNATURE_AGE_SECONDS (300s / 5min)
        let old_timestamp = (Utc::now() - Duration::minutes(10)).to_rfc3339();

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/submit/packet")
            .header("content-type", "application/json")
            .header(
                "X-Signature",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]),
            )
            .header("X-Public-Key", "a".repeat(64))
            .header("X-Timestamp", old_timestamp)
            .body(Body::from(valid_packet_body()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Timestamp 10 minutes in the past should be rejected as expired"
        );
    }

    // ====================================================================
    // 3.2.6 Future timestamp returns 401
    // ====================================================================

    #[tokio::test]
    async fn test_future_timestamp_returns_401() {
        let router = app_with_auth();

        // 10 minutes in the future exceeds CLOCK_SKEW_TOLERANCE_SECONDS (30s)
        let future_timestamp = (Utc::now() + Duration::minutes(10)).to_rfc3339();

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/submit/packet")
            .header("content-type", "application/json")
            .header(
                "X-Signature",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]),
            )
            .header("X-Public-Key", "a".repeat(64))
            .header("X-Timestamp", future_timestamp)
            .body(Body::from(valid_packet_body()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Timestamp 10 minutes in the future should be rejected"
        );
    }

    // ====================================================================
    // 3.2.7 Malformed timestamp returns 401
    // ====================================================================

    #[tokio::test]
    async fn test_malformed_timestamp_returns_401() {
        let router = app_with_auth();

        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/submit/packet")
            .header("content-type", "application/json")
            .header(
                "X-Signature",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]),
            )
            .header("X-Public-Key", "a".repeat(64))
            .header("X-Timestamp", "not-a-date")
            .body(Body::from(valid_packet_body()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // Malformed timestamp results in MalformedData which maps to 400,
        // not 401. Both are acceptable rejections.
        let status = response.status();
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
            "Malformed timestamp should be rejected with 400 or 401, got {}",
            status
        );
    }

    // ====================================================================
    // 3.2.8 All protected routes reject without auth headers
    // ====================================================================

    #[tokio::test]
    async fn test_all_protected_routes_reject_without_auth() {
        // Each protected route is a POST or DELETE that sits behind the
        // require_signature middleware. Without auth headers, all should 401.
        let claim_id = Uuid::new_v4();
        let webhook_id = Uuid::new_v4();

        // Pre-compute formatted URIs so they live long enough for the vec
        let challenge_uri = format!("/api/v1/claims/{}/challenge", claim_id);
        let supersede_uri = format!("/api/v1/claims/{}/supersede", claim_id);
        let webhook_get_uri = format!("/api/v1/webhooks/{}", webhook_id);
        let webhook_delete_uri = format!("/api/v1/webhooks/{}", webhook_id);

        let protected_routes: Vec<(&str, &str, Option<String>)> = vec![
            ("POST", "/api/v1/submit/packet", Some(valid_packet_body())),
            (
                "POST",
                &challenge_uri,
                Some(
                    serde_json::to_string(&serde_json::json!({
                        "challenger_id": Uuid::new_v4(),
                        "challenge_type": "factual_error",
                        "explanation": "Test explanation"
                    }))
                    .unwrap(),
                ),
            ),
            (
                "POST",
                &supersede_uri,
                Some(
                    serde_json::to_string(&serde_json::json!({
                        "content": "New version",
                        "truth_value": 0.8,
                        "reason": "Updated evidence"
                    }))
                    .unwrap(),
                ),
            ),
            (
                "POST",
                "/api/v1/claims/batch",
                Some(
                    serde_json::to_string(&serde_json::json!({
                        "claims": [{ "content": "Test", "truth_value": 0.5 }]
                    }))
                    .unwrap(),
                ),
            ),
            (
                "POST",
                "/api/v1/webhooks",
                Some(
                    serde_json::to_string(&serde_json::json!({
                        "url": "https://example.com/hook",
                        "event_types": [],
                        "secret": "a".repeat(32)
                    }))
                    .unwrap(),
                ),
            ),
            ("GET", "/api/v1/webhooks", None),
            ("GET", &webhook_get_uri, None),
            ("DELETE", &webhook_delete_uri, None),
        ];

        for (method, uri, body) in protected_routes {
            let router = app_with_auth();

            let mut builder = Request::builder().method(method).uri(uri);

            if body.is_some() {
                builder = builder.header("content-type", "application/json");
            }

            let request = builder
                .body(match body {
                    Some(b) => Body::from(b),
                    None => Body::empty(),
                })
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{} {} without auth headers should return 401",
                method,
                uri
            );
        }
    }
}

#[cfg(all(test, not(feature = "db")))]
mod concurrency_tests {
    use crate::routes::admin::SystemStats;
    use crate::routes::batch::batch_create_claims;
    use crate::routes::challenge::submit_challenge;
    use crate::routes::rag::RagContextResponse;
    use crate::routes::submit::submit_packet;
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use epigraph_crypto::ContentHasher;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    /// Build a valid epistemic packet JSON with a unique agent_id.
    fn valid_packet_json() -> serde_json::Value {
        let raw_content = "test evidence content";
        let hash = ContentHasher::hash(raw_content.as_bytes());
        let hex_hash = ContentHasher::to_hex(&hash);

        serde_json::json!({
            "claim": {
                "content": "Concurrent test claim",
                "agent_id": Uuid::new_v4()
            },
            "evidence": [{
                "content_hash": hex_hash,
                "evidence_type": {
                    "type": "document",
                    "source_url": "https://example.com",
                    "mime_type": "text/plain"
                },
                "raw_content": raw_content
            }],
            "reasoning_trace": {
                "methodology": "deductive",
                "inputs": [{ "type": "evidence", "index": 0 }],
                "confidence": 0.8,
                "explanation": "Deductive reasoning from document evidence"
            },
            "signature": "0".repeat(128)
        })
    }

    // ====================================================================
    // 3.3.1 Concurrent claim submissions
    // ====================================================================

    #[tokio::test]
    async fn test_concurrent_claim_submissions() {
        let state = AppState::new(ApiConfig::default());

        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let state = state.clone();
                tokio::spawn(async move {
                    let router = Router::new()
                        .route("/api/v1/submit/packet", post(submit_packet))
                        .with_state(state);

                    let body = valid_packet_json();
                    let request = Request::builder()
                        .method("POST")
                        .uri("/api/v1/submit/packet")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap();

                    router.oneshot(request).await.unwrap()
                })
            })
            .collect();

        let mut claim_ids = Vec::new();
        for task in tasks {
            let response = task.await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::CREATED,
                "All concurrent submissions should succeed with 201"
            );

            let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
            let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
            let claim_id = resp["claim_id"].as_str().unwrap().to_string();
            claim_ids.push(claim_id);
        }

        // All claim IDs should be unique
        let unique_ids: std::collections::HashSet<_> = claim_ids.iter().collect();
        assert_eq!(
            unique_ids.len(),
            10,
            "All 10 concurrent submissions should produce unique claim IDs"
        );
    }

    // ====================================================================
    // 3.3.2 Concurrent challenge submissions on different claims
    // ====================================================================

    #[tokio::test]
    async fn test_concurrent_challenge_submissions_different_claims() {
        let state = AppState::new(ApiConfig::default());

        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let state = state.clone();
                tokio::spawn(async move {
                    let router = Router::new()
                        .route("/api/v1/claims/:id/challenge", post(submit_challenge))
                        .with_state(state);

                    let claim_id = Uuid::new_v4();
                    let body = serde_json::json!({
                        "challenger_id": Uuid::new_v4(),
                        "challenge_type": "factual_error",
                        "explanation": "Concurrent challenge test"
                    });

                    let request = Request::builder()
                        .method("POST")
                        .uri(format!("/api/v1/claims/{}/challenge", claim_id))
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap();

                    router.oneshot(request).await.unwrap()
                })
            })
            .collect();

        for task in tasks {
            let response = task.await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::CREATED,
                "All concurrent challenges on different claims should succeed"
            );
        }

        // Verify all 10 challenges are stored
        assert_eq!(
            state.challenge_service.total_challenges(),
            10,
            "Challenge service should contain all 10 concurrently submitted challenges"
        );
    }

    // ====================================================================
    // 3.3.3 Concurrent RAG queries
    // ====================================================================

    #[tokio::test]
    async fn test_concurrent_rag_queries() {
        let state = AppState::new(ApiConfig::default());

        let tasks: Vec<_> = (0..10)
            .map(|i| {
                let state = state.clone();
                tokio::spawn(async move {
                    let router = crate::routes::create_router(state);

                    let request = Request::builder()
                        .uri(format!("/api/v1/query/rag?query=concurrent+test+{}", i))
                        .body(Body::empty())
                        .unwrap();

                    router.oneshot(request).await.unwrap()
                })
            })
            .collect();

        for task in tasks {
            let response = task.await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "All concurrent RAG queries should return 200"
            );

            let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
            let resp: RagContextResponse = serde_json::from_slice(&body_bytes).unwrap();
            // Without a DB, results are empty but the response structure is valid
            assert_eq!(resp.count, 0);
        }
    }

    // ====================================================================
    // 3.3.4 Concurrent admin stats
    // ====================================================================

    #[tokio::test]
    async fn test_concurrent_admin_stats() {
        let state = AppState::new(ApiConfig::default());

        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let state = state.clone();
                tokio::spawn(async move {
                    let router = crate::routes::create_router(state);

                    let request = Request::builder()
                        .uri("/api/v1/admin/stats")
                        .body(Body::empty())
                        .unwrap();

                    router.oneshot(request).await.unwrap()
                })
            })
            .collect();

        for task in tasks {
            let response = task.await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "All concurrent admin stats requests should return 200"
            );

            let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
            let stats: SystemStats = serde_json::from_slice(&body_bytes).unwrap();

            // All stats should be consistent (initial state: everything is zero)
            assert_eq!(stats.caches.idempotency_store_size, 0);
            assert!(!stats.config.require_signatures);
        }
    }

    // ====================================================================
    // 3.3.5 Concurrent submissions then admin stats shows correct count
    // ====================================================================

    #[tokio::test]
    async fn test_concurrent_submissions_then_stats_consistent() {
        let state = AppState::new(ApiConfig::default());

        // First: submit 5 claims concurrently via batch (direct router, no middleware)
        let batch_tasks: Vec<_> = (0..5)
            .map(|i| {
                let state = state.clone();
                tokio::spawn(async move {
                    let router = Router::new()
                        .route("/api/v1/claims/batch", post(batch_create_claims))
                        .with_state(state);

                    let body = serde_json::json!({
                        "claims": [{ "content": format!("Concurrent batch {}", i), "truth_value": 0.5 }]
                    });

                    let request = Request::builder()
                        .method("POST")
                        .uri("/api/v1/claims/batch")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap();

                    router.oneshot(request).await.unwrap()
                })
            })
            .collect();

        for task in batch_tasks {
            let response = task.await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        // Then: check admin stats reflect the 5 stored claims
        let store = state.claim_store.read().await;
        assert_eq!(
            store.len(),
            5,
            "All 5 concurrent batch submissions should be reflected in claim store"
        );
    }
}
