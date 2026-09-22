//! Integration tests for rate limiting middleware
//!
//! # Security Properties Validated
//!
//! 1. **DoS Prevention**: Excessive requests are rejected with 429
//! 2. **Fair Quota**: Each client gets their configured rate limit
//! 3. **Bypass Routes**: Health checks are exempt from rate limiting
//! 4. **Retry Guidance**: 429 responses include Retry-After header
//! 5. **IP Fallback**: Unauthenticated requests are rate-limited by the TCP
//!    peer, and by `X-Forwarded-For` only behind a trusted proxy
//! 6. **No shared bucket**: a request with no identifiable client is never
//!    pooled with other such requests
//!
//! # These tests now run
//!
//! Every test in this file used to be `#[cfg(not(feature = "db"))]`.
//! `epigraph-api`'s default features include `db` and every CI job builds with
//! defaults, so the binary compiled to zero tests and nothing here ever ran.
//! The state is now built the way `webhook_tenancy.rs` builds one under `db`:
//! a lazy pool at an unroutable address. The middleware touches the pool only
//! to persist a 429's security event, fire-and-forget, and that write failing
//! is logged and ignored.
//!
//! # Every request carries a peer address
//!
//! The middleware keys an anonymous request on `ConnectInfo<SocketAddr>`,
//! which the production listener supplies. `tower::oneshot` does not, so each
//! request here inserts one by hand ([`from_peer`]).

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use epigraph_api::middleware::rate_limit_middleware;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_api::{AgentRateLimiter, RateLimitConfig};
use std::net::SocketAddr;
use tower::ServiceExt;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Simple test handler
async fn test_handler() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

/// Health check handler
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({"status": "healthy"}))
}

/// An `AppState` carrying `limiter`, buildable under either feature set.
fn state_with(limiter: AgentRateLimiter) -> AppState {
    #[cfg(feature = "db")]
    let state = {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/nobody")
            .expect("lazy pool");
        AppState::with_db(pool, ApiConfig::default())
    };
    #[cfg(not(feature = "db"))]
    let state = AppState::new(ApiConfig::default());
    state.with_rate_limiter(limiter)
}

fn config(default_rpm: u32, global_rpm: u32, enable_global_limit: bool) -> RateLimitConfig {
    RateLimitConfig {
        default_rpm,
        global_rpm,
        replenish_interval_secs: 60,
        enable_global_limit,
    }
}

fn router(state: &AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/api/test", post(test_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state.clone())
}

/// `POST /api/test` arriving over a TCP connection from `peer`.
fn from_peer(peer: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/api/test")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().expect("peer addr")));
    request
}

/// `from_peer` plus an `X-Forwarded-For` header.
fn from_peer_forwarded(peer: &str, forwarded_for: &str) -> Request<Body> {
    let mut request = from_peer(peer);
    request
        .headers_mut()
        .insert("X-Forwarded-For", forwarded_for.parse().unwrap());
    request
}

async fn send(state: &AppState, request: Request<Body>) -> Response {
    router(state).oneshot(request).await.unwrap()
}

// ============================================================================
// Test 1: First Request Always Succeeds
// ============================================================================

/// Validates: The first request from any client always succeeds
///
/// Security Invariant: Rate limiting should not block legitimate initial requests.
#[tokio::test]
async fn test_first_request_always_succeeds() {
    let state = state_with(AgentRateLimiter::new(config(5, 100, true)));

    let response = send(&state, from_peer("192.168.1.1:50000")).await;

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
#[tokio::test]
async fn test_exceeding_rate_limit_returns_429() {
    let state = state_with(AgentRateLimiter::new(config(2, 100, false)));

    // Make 3 requests (limit is 2)
    for i in 0..3 {
        let response = send(&state, from_peer("192.168.1.100:50000")).await;

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
#[tokio::test]
async fn test_health_endpoint_bypasses_rate_limiting() {
    let state = state_with(AgentRateLimiter::new(config(1, 1, true)));

    // Make many health check requests - all should succeed
    for i in 0..10 {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "192.168.1.200:50000".parse::<SocketAddr>().unwrap(),
        ));

        let response = send(&state, request).await;

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
#[tokio::test]
async fn test_different_ips_have_separate_quotas() {
    let state = state_with(AgentRateLimiter::new(config(2, 100, false)));

    // Exhaust quota for IP1
    for _ in 0..3 {
        let _ = send(&state, from_peer("10.0.0.1:50000")).await;
    }

    // IP2 should still have full quota
    let response = send(&state, from_peer("10.0.0.2:50000")).await;

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
#[tokio::test]
async fn test_429_response_contains_error_details() {
    let state = state_with(AgentRateLimiter::new(config(1, 100, false)));

    // Make 2 requests to trigger rate limit
    for i in 0..2 {
        let response = send(&state, from_peer("192.168.1.150:50000")).await;

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
#[tokio::test]
async fn test_global_rate_limit_protection() {
    let state = state_with(AgentRateLimiter::new(config(100, 3, true)));

    // Make requests from different IPs
    let mut hit_global_limit = false;

    for i in 0..5 {
        let response = send(&state, from_peer(&format!("192.168.{i}.1:50000"))).await;

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
#[tokio::test]
async fn test_rate_limit_headers_on_success() {
    let state = state_with(AgentRateLimiter::new(config(60, 1000, true)));

    let response = send(&state, from_peer("192.168.1.50:50000")).await;

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

// ============================================================================
// Client identity: forwarding headers, peers, and the removed shared bucket
// ============================================================================

/// A client that is not a trusted proxy cannot pick its own bucket by writing
/// `X-Forwarded-For`. The middleware used to key on the header's first entry
/// from any sender, so rotating it bought a fresh quota per request.
#[tokio::test]
async fn a_spoofed_forwarded_for_from_an_untrusted_peer_is_ignored() {
    let state = state_with(AgentRateLimiter::new(config(2, 1000, false)));
    let peer = "203.0.113.7:40000";

    for (i, spoofed) in ["198.51.100.1", "198.51.100.2"].iter().enumerate() {
        let response = send(&state, from_peer_forwarded(peer, spoofed)).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "request {} in quota",
            i + 1
        );
    }

    let response = send(&state, from_peer_forwarded(peer, "198.51.100.3")).await;
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "three different X-Forwarded-For values from ONE untrusted peer must share \
         that peer's quota of 2"
    );
}

/// Behind a trusted proxy (loopback, the default) `X-Forwarded-For` IS the
/// client, so two clients behind the same proxy get separate quotas instead of
/// sharing the proxy's.
#[tokio::test]
async fn forwarded_for_is_honoured_behind_a_trusted_proxy() {
    let state = state_with(AgentRateLimiter::new(config(1, 1000, false)));
    let proxy = "127.0.0.1:50000";

    let first = send(&state, from_peer_forwarded(proxy, "198.51.100.10")).await;
    assert_eq!(first.status(), StatusCode::OK);
    let again = send(&state, from_peer_forwarded(proxy, "198.51.100.10")).await;
    assert_eq!(
        again.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the forwarded client's quota of 1 is spent"
    );

    let other = send(&state, from_peer_forwarded(proxy, "198.51.100.11")).await;
    assert_eq!(
        other.status(),
        StatusCode::OK,
        "a different client behind the same trusted proxy has its own quota"
    );
}

/// Through a proxy that APPENDS to `X-Forwarded-For`, a client can prepend
/// whatever it likes. The right-most untrusted entry is the address the proxy
/// saw, and that is the one the quota follows; the old "first entry" rule
/// keyed on the client's own invention.
#[tokio::test]
async fn a_client_prepended_forwarded_for_entry_does_not_escape_its_quota() {
    let state = state_with(AgentRateLimiter::new(config(1, 1000, false)));
    let proxy = "127.0.0.1:50000";

    let first = send(&state, from_peer_forwarded(proxy, "1.1.1.1, 198.51.100.20")).await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = send(&state, from_peer_forwarded(proxy, "2.2.2.2, 198.51.100.20")).await;
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "rotating the client-written left-hand entry must not buy a new bucket"
    );
}

/// Loopback is trusted only because a limiter defaults to it. A limiter told
/// to trust no one keys the proxy hop on the proxy, headers or not.
#[tokio::test]
async fn an_empty_trusted_set_keys_every_request_on_its_tcp_peer() {
    let limiter = AgentRateLimiter::new(config(1, 1000, false)).with_trusted_proxies(vec![]);
    let state = state_with(limiter);
    let proxy = "127.0.0.1:50000";

    assert_eq!(
        send(&state, from_peer_forwarded(proxy, "198.51.100.30"))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&state, from_peer_forwarded(proxy, "198.51.100.31"))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS,
        "with no trusted proxies, X-Forwarded-For is ignored even from loopback"
    );
}

/// One IPv6 end site holds a whole /64 and can source from any address in it.
#[tokio::test]
async fn ipv6_clients_share_a_quota_across_their_64() {
    let state = state_with(AgentRateLimiter::new(config(1, 1000, false)));

    assert_eq!(
        send(&state, from_peer("[2001:db8:1:2::1]:50000"))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&state, from_peer("[2001:db8:1:2::ffff]:50000"))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a second address in the same /64 is the same client"
    );
    assert_eq!(
        send(&state, from_peer("[2001:db8:1:3::1]:50000"))
            .await
            .status(),
        StatusCode::OK,
        "a different /64 is a different client"
    );
}

/// The shared nil-UUID bucket is gone. A request the middleware cannot
/// attribute used to land in ONE bucket with every other such request, so a
/// single client could spend it and 429 all the rest. Two unattributable
/// requests past a quota of 1 must both go through.
#[tokio::test]
async fn requests_with_no_identifiable_client_are_never_pooled_into_one_bucket() {
    let state = state_with(AgentRateLimiter::new(config(1, 1000, false)));

    for i in 0..2 {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/test")
            .body(Body::empty())
            .unwrap();
        let response = send(&state, request).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "unattributable request {} must not share a bucket with the other",
            i + 1
        );
    }
}

// ============================================================================
// Authenticated requests: keyed on the bearer principal
// ============================================================================

/// A bearer token minted by `state`'s own JWT config for `agent_id`, under a
/// fresh OAuth client each call.
fn token_for(state: &AppState, agent_id: uuid::Uuid) -> String {
    let (token, _jti) = state
        .jwt_config
        .issue_access_token(
            uuid::Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "agent",
            None,
            Some(agent_id),
            chrono::Duration::minutes(5),
        )
        .expect("test token");
    token
}

fn with_bearer(mut request: Request<Body>, token: &str) -> Request<Body> {
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    request
}

/// The point of the item: two principals behind ONE address (a NAT, or
/// everything arriving through one proxy hop) each get their own quota.
/// Keyed on the address, the second principal was refused because of the
/// first one's traffic.
#[tokio::test]
async fn two_principals_behind_one_address_have_separate_quotas() {
    let state = state_with(AgentRateLimiter::new(config(1, 1000, false)));
    let alice = token_for(&state, uuid::Uuid::new_v4());
    let bob = token_for(&state, uuid::Uuid::new_v4());
    let shared = "203.0.113.50:40000";

    assert_eq!(
        send(&state, with_bearer(from_peer(shared), &alice))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&state, with_bearer(from_peer(shared), &alice))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS,
        "alice's quota of 1 is spent"
    );
    assert_eq!(
        send(&state, with_bearer(from_peer(shared), &bob))
            .await
            .status(),
        StatusCode::OK,
        "bob shares alice's address but not her quota"
    );
}

/// The converse: a principal's quota follows the principal, so hopping
/// addresses does not buy a fresh one.
#[tokio::test]
async fn a_principal_keeps_its_quota_across_addresses() {
    let state = state_with(AgentRateLimiter::new(config(1, 1000, false)));
    let alice = token_for(&state, uuid::Uuid::new_v4());

    assert_eq!(
        send(&state, with_bearer(from_peer("203.0.113.60:40000"), &alice))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(
            &state,
            with_bearer(from_peer("198.51.100.60:40000"), &alice)
        )
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the same principal from a second address is the same bucket"
    );
}

/// The principal is the AGENT, not the OAuth client: two tokens for one
/// agent, minted under different clients, share one quota.
#[tokio::test]
async fn tokens_for_one_agent_under_different_clients_share_a_quota() {
    let state = state_with(AgentRateLimiter::new(config(1, 1000, false)));
    let agent = uuid::Uuid::new_v4();
    let (first, second) = (token_for(&state, agent), token_for(&state, agent));

    assert_eq!(
        send(&state, with_bearer(from_peer("203.0.113.70:40000"), &first))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(
            &state,
            with_bearer(from_peer("203.0.113.71:40000"), &second)
        )
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// A token that authentication would refuse earns no principal bucket: it is
/// keyed on its address, so rotating junk tokens cannot escape the address
/// quota. Covers a malformed token and a correctly signed but revoked one.
#[tokio::test]
async fn a_token_auth_would_refuse_is_keyed_on_its_address() {
    let state = state_with(AgentRateLimiter::new(config(1, 1000, false)));
    let peer = "203.0.113.80:40000";

    let revoked = token_for(&state, uuid::Uuid::new_v4());
    state.revoke_access_token(&revoked);

    assert_eq!(
        send(&state, with_bearer(from_peer(peer), "not-a-jwt"))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&state, with_bearer(from_peer(peer), &revoked))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a revoked token must not buy its principal's bucket; both requests \
         share the address quota of 1"
    );
}

/// A principal is identifiable without a peer address, so it is limited even
/// where `ConnectInfo` is absent.
#[tokio::test]
async fn a_principal_is_limited_even_without_a_peer_address() {
    let state = state_with(AgentRateLimiter::new(config(1, 1000, false)));
    let alice = token_for(&state, uuid::Uuid::new_v4());

    let no_peer = || {
        Request::builder()
            .method(Method::POST)
            .uri("/api/test")
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        send(&state, with_bearer(no_peer(), &alice)).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&state, with_bearer(no_peer(), &alice)).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}
