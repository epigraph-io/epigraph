//! Integration tests for rate limiting middleware
//!
//! # Security Properties Validated
//!
//! 1. **DoS Prevention**: Excessive requests are rejected with 429
//! 2. **Fair Quota**: Each agent gets their configured rate limit
//! 3. **Bypass Routes**: Health checks are exempt from rate limiting
//! 4. **Retry Guidance**: 429 responses include Retry-After header
//! 5. **IP Fallback**: Unauthenticated requests are rate-limited by IP

use axum::{response::IntoResponse, Json};

#[cfg(not(feature = "db"))]
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    middleware,
    routing::{get, post},
    Router,
};
#[cfg(not(feature = "db"))]
use epigraph_api::{AgentRateLimiter, RateLimitConfig};
#[cfg(not(feature = "db"))]
use tower::ServiceExt;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Simple test handler
#[allow(dead_code)]
async fn test_handler() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

/// Health check handler
#[allow(dead_code)]
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({"status": "healthy"}))
}

// ============================================================================
// Test 1: First Request Always Succeeds
// ============================================================================

/// Validates: The first request from any client always succeeds
///
/// Security Invariant: Rate limiting should not block legitimate initial requests.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn test_first_request_always_succeeds() {
    use epigraph_api::middleware::rate_limit_middleware;
    use epigraph_api::state::{ApiConfig, AppState};

    let config = RateLimitConfig {
        default_rpm: 5, // 5 requests per minute
        global_rpm: 100,
        replenish_interval_secs: 1,
        enable_global_limit: true,
    };

    let rate_limiter = AgentRateLimiter::new(config);

    #[cfg(not(feature = "db"))]
    let state = AppState::new(ApiConfig::default()).with_rate_limiter(rate_limiter);

    let router = Router::new()
        .route("/api/test", post(test_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/test")
        .header("X-Forwarded-For", "192.168.1.1")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "First request should always succeed"
    );
}

// ============================================================================
// Test 2: Limit+1 Request Fails with 429
// ============================================================================

/// Validates: Exceeding rate limit returns 429 Too Many Requests
///
/// Security Invariant: DoS protection must reject excessive requests.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn test_exceeding_rate_limit_returns_429() {
    use epigraph_api::middleware::rate_limit_middleware;
    use epigraph_api::state::{ApiConfig, AppState};

    // Very restrictive limit for testing
    let config = RateLimitConfig {
        default_rpm: 2, // Only 2 requests per minute
        global_rpm: 100,
        replenish_interval_secs: 60, // Slow replenishment for test
        enable_global_limit: false,
    };

    let rate_limiter = AgentRateLimiter::new(config);

    #[cfg(not(feature = "db"))]
    let state = AppState::new(ApiConfig::default()).with_rate_limiter(rate_limiter);

    // Make 3 requests (limit is 2)
    for i in 0..3 {
        let router = Router::new()
            .route("/api/test", post(test_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state.clone());

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/test")
            .header("X-Forwarded-For", "192.168.1.100")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        if i < 2 {
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Request {} should succeed (within limit)",
                i + 1
            );
        } else {
            assert_eq!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Request {} should fail (over limit)",
                i + 1
            );

            // Verify Retry-After header is present
            let retry_after = response.headers().get("Retry-After");
            assert!(
                retry_after.is_some(),
                "429 response should include Retry-After header"
            );
        }
    }
}

// ============================================================================
// Test 3: Health Endpoint Bypasses Rate Limiting
// ============================================================================

/// Validates: Health check endpoints are exempt from rate limiting
///
/// Security Invariant: Monitoring endpoints must always be accessible
/// for operational visibility, even during rate limit events.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn test_health_endpoint_bypasses_rate_limiting() {
    use epigraph_api::middleware::rate_limit_middleware;
    use epigraph_api::state::{ApiConfig, AppState};

    // Very restrictive limit
    let config = RateLimitConfig {
        default_rpm: 1, // Only 1 request per minute
        global_rpm: 1,
        replenish_interval_secs: 60,
        enable_global_limit: true,
    };

    let rate_limiter = AgentRateLimiter::new(config);

    #[cfg(not(feature = "db"))]
    let state = AppState::new(ApiConfig::default()).with_rate_limiter(rate_limiter);

    // Make many health check requests - all should succeed
    for i in 0..10 {
        let router = Router::new()
            .route("/health", get(health_handler))
            .route("/api/test", post(test_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state.clone());

        let request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .header("X-Forwarded-For", "192.168.1.200")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Health request {} should bypass rate limiting",
            i + 1
        );
    }
}

// ============================================================================
// Test 4: Different IPs Have Separate Quotas
// ============================================================================

/// Validates: Rate limits are per-IP for unauthenticated requests
///
/// Security Invariant: One client's rate limit exhaustion should not
/// affect other legitimate clients.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn test_different_ips_have_separate_quotas() {
    use epigraph_api::middleware::rate_limit_middleware;
    use epigraph_api::state::{ApiConfig, AppState};

    let config = RateLimitConfig {
        default_rpm: 2,
        global_rpm: 100, // High global limit
        replenish_interval_secs: 60,
        enable_global_limit: false,
    };

    let rate_limiter = AgentRateLimiter::new(config);

    #[cfg(not(feature = "db"))]
    let state = AppState::new(ApiConfig::default()).with_rate_limiter(rate_limiter);

    // Exhaust quota for IP1
    for _ in 0..3 {
        let router = Router::new()
            .route("/api/test", post(test_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state.clone());

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/test")
            .header("X-Forwarded-For", "10.0.0.1")
            .body(Body::empty())
            .unwrap();

        let _ = router.oneshot(request).await.unwrap();
    }

    // IP2 should still have full quota
    let router = Router::new()
        .route("/api/test", post(test_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state.clone());

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/test")
        .header("X-Forwarded-For", "10.0.0.2")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Different IP should have separate quota"
    );
}

// ============================================================================
// Test 5: 429 Response Contains Error Details
// ============================================================================

/// Validates: Rate limit errors include useful information
///
/// Security Invariant: Clients should receive enough information to
/// implement proper backoff without leaking system internals.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn test_429_response_contains_error_details() {
    use epigraph_api::middleware::rate_limit_middleware;
    use epigraph_api::state::{ApiConfig, AppState};

    let config = RateLimitConfig {
        default_rpm: 1,
        global_rpm: 100,
        replenish_interval_secs: 60,
        enable_global_limit: false,
    };

    let rate_limiter = AgentRateLimiter::new(config);

    #[cfg(not(feature = "db"))]
    let state = AppState::new(ApiConfig::default()).with_rate_limiter(rate_limiter);

    // Make 2 requests to trigger rate limit
    for i in 0..2 {
        let router = Router::new()
            .route("/api/test", post(test_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state.clone());

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/test")
            .header("X-Forwarded-For", "192.168.1.150")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        if i == 1 {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

            // Check Retry-After header
            let retry_after = response
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());

            assert!(
                retry_after.is_some(),
                "Should have numeric Retry-After header"
            );
            assert!(retry_after.unwrap() > 0, "Retry-After should be positive");

            // Check response body
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert!(
                json.get("error").is_some(),
                "Response should have error field"
            );
            assert!(
                json.get("message").is_some(),
                "Response should have message field"
            );
        }
    }
}

// ============================================================================
// Test 6: Global Rate Limit Protection
// ============================================================================

/// Validates: Global rate limit prevents system overload
///
/// Security Invariant: Even distributed requests from many IPs
/// cannot exceed the global system capacity.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn test_global_rate_limit_protection() {
    use epigraph_api::middleware::rate_limit_middleware;
    use epigraph_api::state::{ApiConfig, AppState};

    let config = RateLimitConfig {
        default_rpm: 100, // High per-IP limit
        global_rpm: 3,    // Low global limit
        replenish_interval_secs: 60,
        enable_global_limit: true,
    };

    let rate_limiter = AgentRateLimiter::new(config);

    #[cfg(not(feature = "db"))]
    let state = AppState::new(ApiConfig::default()).with_rate_limiter(rate_limiter);

    // Make requests from different IPs
    let mut hit_global_limit = false;

    for i in 0..5 {
        let router = Router::new()
            .route("/api/test", post(test_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state.clone());

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/test")
            .header("X-Forwarded-For", format!("192.168.{}.1", i))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            hit_global_limit = true;
            break;
        }
    }

    assert!(
        hit_global_limit,
        "Global rate limit should be triggered by requests from multiple IPs"
    );
}

// ============================================================================
// Test 7: Rate Limit Headers on Success
// ============================================================================

/// Validates: Successful responses include rate limit headers
///
/// UX Invariant: Clients should be able to track their quota usage.
#[cfg(not(feature = "db"))]
#[tokio::test]
async fn test_rate_limit_headers_on_success() {
    use epigraph_api::middleware::rate_limit_middleware;
    use epigraph_api::state::{ApiConfig, AppState};

    let config = RateLimitConfig {
        default_rpm: 60,
        global_rpm: 1000,
        replenish_interval_secs: 1,
        enable_global_limit: true,
    };

    let rate_limiter = AgentRateLimiter::new(config);

    #[cfg(not(feature = "db"))]
    let state = AppState::new(ApiConfig::default()).with_rate_limiter(rate_limiter);

    let router = Router::new()
        .route("/api/test", post(test_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/test")
        .header("X-Forwarded-For", "192.168.1.50")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check for rate limit headers
    let remaining = response.headers().get("X-RateLimit-Remaining");
    let limit = response.headers().get("X-RateLimit-Limit");

    assert!(
        remaining.is_some(),
        "Response should include X-RateLimit-Remaining header"
    );
    assert!(
        limit.is_some(),
        "Response should include X-RateLimit-Limit header"
    );
}
