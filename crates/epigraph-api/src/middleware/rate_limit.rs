//! Rate Limiting Middleware for EpiGraph API
//!
//! # Security Properties
//!
//! 1. **DoS Prevention**: Limits request rates to prevent service overload
//! 2. **Fair Quotas**: Per-IP/per-agent rate limiting ensures fairness
//! 3. **Transparency**: Returns Retry-After header on rate limit
//! 4. **Bypass Routes**: Health endpoints are exempt for monitoring
//!
//! # Rate Limiting Strategy
//!
//! - **Authenticated requests**: Rate limited by principal (agent, else client)
//! - **Unauthenticated requests**: Rate limited by TCP peer, or behind a
//!   configured trusted proxy by the right-most untrusted X-Forwarded-For hop
//! - **Health endpoints**: Exempt from rate limiting

// UNSCOPED-POOL-EXEMPT: One `db_pool.clone()` handed to a detached task that records security
// events. It runs after the rate-limit decision and outside any request's viewer scope, and on the
// anonymous routers (the allowlist without a token, OAuth) the request has no principal to scope
// to at all.

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use epigraph_core::domain::AgentId;
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

use crate::middleware::AuthContext;
use crate::security::audit::SecurityAuditLog;
use crate::security::{RateLimitError, SecurityEvent, TrustedProxies};
use crate::state::AppState;

// ============================================================================
// Constants
// ============================================================================

/// Header for forwarded client IP, read only from a trusted proxy
const X_FORWARDED_FOR: &str = "X-Forwarded-For";

/// Header for real IP, read only from a trusted proxy that sent no X-Forwarded-For
const X_REAL_IP: &str = "X-Real-IP";

/// Routes that bypass rate limiting.
///
/// `/metrics` was removed from this list in PR-03: Prometheus exposition is no
/// longer routable on the application listener at all (it moved to the internal
/// listener `bin/server.rs` binds from `EPIGRAPH_METRICS_ADDR`), so the entry
/// could only ever have matched a request this router now 404s. It was also the
/// widest entry here — matching is `path.starts_with`, so `/metrics-anything`
/// inherited the bypass.
///
/// The three that remain are liveness probes: a rate-limited health check turns
/// a traffic spike into a false unhealthy verdict and then into a restart loop.
const BYPASS_ROUTES: &[&str] = &["/health", "/readiness", "/liveness"];

// ============================================================================
// Rate Limit Response
// ============================================================================

/// Error returned when rate limit is exceeded
#[derive(Debug, Clone)]
pub struct RateLimitResponse {
    /// Seconds until the client can retry
    pub retry_after_secs: u64,
    /// Error message for the client
    pub message: String,
}

impl IntoResponse for RateLimitResponse {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": "RateLimitExceeded",
            "message": self.message,
            "retry_after_secs": self.retry_after_secs,
        });

        let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();

        // Add Retry-After header (RFC 7231)
        response.headers_mut().insert(
            "Retry-After",
            self.retry_after_secs
                .to_string()
                .parse()
                .expect("Numeric retry_after is valid header"),
        );
        // Never cached, on every route's 429: a refusal that a cache replayed
        // would refuse a client after its window has reopened. (On /oauth/*
        // and /.well-known/* `routes::oauth_response_headers` wraps this layer
        // and sets the same RFC 6749 section 5.1 headers; elsewhere nothing
        // else would.)
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response.headers_mut().insert(
            axum::http::header::PRAGMA,
            axum::http::HeaderValue::from_static("no-cache"),
        );

        response
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// The client address an anonymous request is charged to.
///
/// 1. The TCP peer, from the `ConnectInfo<SocketAddr>` that `bin/server.rs`
///    serves with (`into_make_service_with_connect_info`).
/// 2. Only when that peer is a trusted proxy ([`TrustedProxies`]): the
///    right-most `X-Forwarded-For` hop that is not itself a trusted proxy,
///    walking right to left across every `X-Forwarded-For` header in order.
///    Each trusted proxy APPENDS the address it received the request from, so
///    hops to the left of the last untrusted one were written by the client
///    and are never read. If every hop is a trusted proxy, the left-most is
///    the client. A hop that does not parse ends the walk at the last trusted
///    hop seen. With no `X-Forwarded-For` at all, a trusted proxy's
///    `X-Real-IP` is used.
///
/// Before backlog bd5c0f40 this read the FIRST `X-Forwarded-For` hop (or
/// `X-Real-IP`) from any peer. Both are client-written, so a client that
/// changed the header on every request got a fresh bucket every time.
///
/// `None` only when the request carries no `ConnectInfo` (a router driven
/// without `into_make_service_with_connect_info`, e.g. in a test).
fn client_ip(request: &Request<Body>, trusted: &TrustedProxies) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()?
        .0
        .ip()
        .to_canonical();
    if !trusted.contains(peer) {
        return Some(peer);
    }

    let hops: Vec<&str> = request
        .headers()
        .get_all(X_FORWARDED_FOR)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();

    if hops.is_empty() {
        let real_ip = request
            .headers()
            .get(X_REAL_IP)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical());
        return Some(real_ip.unwrap_or(peer));
    }

    let mut last_trusted = peer;
    for hop in hops.iter().rev() {
        match hop.parse::<IpAddr>() {
            Ok(ip) => {
                let ip = ip.to_canonical();
                if !trusted.contains(ip) {
                    return Some(ip);
                }
                last_trusted = ip;
            }
            Err(_) => return Some(last_trusted),
        }
    }
    Some(last_trusted)
}

/// The bucket a request is charged to.
///
/// 1. The authenticated principal: the `AuthContext` a bearer layer inserted
///    (its agent, else its OAuth client). `routes::create_router` places this
///    middleware INSIDE `bearer_auth_middleware` (protected router) and
///    `optional_bearer_auth_middleware` (anonymous allowlist), so a token
///    presented there is already verified when this runs.
/// 2. A `VerifiedAgent` (Ed25519-signed request), where a router installs
///    `signature_verification_middleware`; no production router does.
/// 3. The client address ([`client_ip`]).
///
/// `None` when none of these is available.
fn rate_limit_key(request: &Request<Body>, trusted: &TrustedProxies) -> Option<AgentId> {
    if let Some(auth) = request.extensions().get::<AuthContext>() {
        return Some(AgentId::from_uuid(auth.agent_id.unwrap_or(auth.client_id)));
    }
    if let Some(agent) = request
        .extensions()
        .get::<crate::middleware::VerifiedAgent>()
    {
        return Some(agent.agent_id);
    }
    client_ip(request, trusted).map(ip_to_agent_id)
}

/// Check if a route should bypass rate limiting
fn should_bypass_rate_limit(path: &str, method: &Method) -> bool {
    // OPTIONS requests bypass for CORS preflight
    if method == Method::OPTIONS {
        return true;
    }

    // Check configured bypass routes
    BYPASS_ROUTES.iter().any(|route| path.starts_with(route))
}

/// The bucket key of a client address.
///
/// Injective, not hashed: the address bytes are the key, so two clients can
/// never share a bucket by collision. An IPv6 client is keyed by its /64,
/// the smallest prefix a site is normally assigned; keying the full address
/// would hand one host 2^64 buckets.
fn ip_to_agent_id(ip: IpAddr) -> AgentId {
    let mut bytes = [0u8; 16];
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            bytes[0] = 6;
            bytes[1..9].copy_from_slice(&v6.octets()[..8]);
        }
    }
    // A fixed tail keeps address keys apart from (random) principal UUIDs.
    bytes[12..16].copy_from_slice(b"rlip");
    AgentId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

// ============================================================================
// Middleware Implementation
// ============================================================================

/// Rate limiting middleware
///
/// # Rate Limiting Strategy
///
/// 1. Check if route bypasses rate limiting (health endpoints)
/// 2. Extract client identifier (agent ID or IP)
/// 3. Check rate limit against token bucket
/// 4. If exceeded, return 429 with Retry-After header
/// 5. If allowed, add rate limit headers to response
///
/// # Usage
///
/// ```ignore
/// use axum::{Router, middleware, routing::post};
/// use epigraph_api::middleware::rate_limit_middleware;
///
/// let app = Router::new()
///     .route("/api/test", post(handler))
///     .layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
///     .with_state(state);
/// ```
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, RateLimitResponse> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();

    // Check if route should bypass rate limiting
    if should_bypass_rate_limit(&path, &method) {
        return Ok(next.run(request).await);
    }

    // Get rate limiter from state
    let rate_limiter = match &state.rate_limiter {
        Some(limiter) => limiter,
        None => {
            // Rate limiting not configured, allow all requests
            return Ok(next.run(request).await);
        }
    };

    // Which bucket: principal > signed agent > client address
    // ([`rate_limit_key`]). The nil fallback is reachable only for a router
    // served WITHOUT connect info, which `bin/server.rs` never does; it is one
    // shared bucket, so it is logged.
    let agent_id = rate_limit_key(&request, rate_limiter.trusted_proxies()).unwrap_or_else(|| {
        tracing::warn!(
            path = %path,
            "Rate limiting request without identifiable client - using fallback ID \
             (is the router served with into_make_service_with_connect_info?)"
        );
        AgentId::from_uuid(uuid::Uuid::nil())
    });

    // Check rate limit
    if let Err(err) = rate_limiter.check(&agent_id) {
        let (message, retry_after, current_rate, limit) = match &err {
            RateLimitError::AgentLimitExceeded {
                retry_after_secs,
                current_rate,
                limit,
                ..
            } => (
                "Rate limit exceeded. Please slow down.".to_string(),
                *retry_after_secs,
                *current_rate,
                *limit,
            ),
            RateLimitError::GlobalLimitExceeded { retry_after_secs } => (
                "Service is experiencing high load. Please retry later.".to_string(),
                *retry_after_secs,
                0, // Global rate exceeded
                rate_limiter.config().global_rpm,
            ),
        };

        // Log rate limit exceeded event to audit log (in-memory)
        let correlation_id = Uuid::new_v4().to_string();
        let rate_event = SecurityEvent::rate_limit_exceeded(
            agent_id,
            path.clone(),
            current_rate,
            limit,
            correlation_id,
        );
        state.audit_log.log(rate_event.clone());

        // DB persistence (non-blocking, fire-and-forget)
        #[cfg(feature = "db")]
        {
            use crate::security::audit::security_event_row_from;
            use epigraph_db::repos::security_event::SecurityEventRepository;
            let pool = state.db_pool.clone();
            let row = security_event_row_from(&rate_event);
            tokio::spawn(async move {
                if let Err(e) = SecurityEventRepository::log(&pool, row).await {
                    tracing::warn!("Failed to persist security event: {e}");
                }
            });
        }

        tracing::info!(
            path = %path,
            agent_id = %agent_id,
            retry_after = retry_after,
            "Rate limit exceeded"
        );

        return Err(RateLimitResponse {
            retry_after_secs: retry_after,
            message,
        });
    }

    // Run the next middleware/handler
    let mut response = next.run(request).await;

    // Add rate limit headers to successful responses
    let remaining = rate_limiter.remaining_quota(&agent_id);
    let limit = rate_limiter.config().default_rpm;

    response.headers_mut().insert(
        "X-RateLimit-Limit",
        limit
            .to_string()
            .parse()
            .expect("Numeric limit is valid header"),
    );

    response.headers_mut().insert(
        "X-RateLimit-Remaining",
        remaining
            .to_string()
            .parse()
            .expect("Numeric remaining is valid header"),
    );

    Ok(response)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_bypass_health_route() {
        assert!(should_bypass_rate_limit("/health", &Method::GET));
        assert!(should_bypass_rate_limit("/health/ready", &Method::GET));
        assert!(should_bypass_rate_limit("/readiness", &Method::GET));
        assert!(should_bypass_rate_limit("/liveness", &Method::GET));
    }

    /// `/metrics` lost its bypass in PR-03 because it lost its route: it is no
    /// longer registered on either application router (it moved to the internal
    /// listener `bin/server.rs` binds from `EPIGRAPH_METRICS_ADDR`), so the
    /// entry could only ever have matched a request the router now 404s.
    ///
    /// Asserted rather than deleted so that re-adding `/metrics` to
    /// `BYPASS_ROUTES` fails here — matching is `path.starts_with`, so the entry
    /// also handed the bypass to `/metrics-anything`, and it was the widest
    /// prefix in the list.
    #[test]
    fn metrics_no_longer_bypasses_rate_limiting() {
        assert!(!should_bypass_rate_limit("/metrics", &Method::GET));
        assert!(!should_bypass_rate_limit(
            "/metrics-not-really",
            &Method::GET
        ));
    }

    #[test]
    fn test_bypass_options_method() {
        assert!(should_bypass_rate_limit("/api/claims", &Method::OPTIONS));
        assert!(should_bypass_rate_limit("/any/path", &Method::OPTIONS));
    }

    #[test]
    fn test_does_not_bypass_api_routes() {
        assert!(!should_bypass_rate_limit("/api/claims", &Method::POST));
        assert!(!should_bypass_rate_limit("/api/v1/submit", &Method::POST));
        assert!(!should_bypass_rate_limit("/claims", &Method::GET));
    }

    #[test]
    fn test_ip_to_agent_id_is_deterministic() {
        let ip1: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let ip3: IpAddr = Ipv4Addr::new(192, 168, 1, 2).into();

        let id1 = ip_to_agent_id(ip1);
        let id2 = ip_to_agent_id(ip2);
        let id3 = ip_to_agent_id(ip3);

        assert_eq!(id1, id2, "Same IP should produce same agent ID");
        assert_ne!(id1, id3, "Different IPs should produce different agent IDs");
    }

    #[test]
    fn test_ip_to_agent_id_works_for_ipv6() {
        let ip: IpAddr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).into();
        let id = ip_to_agent_id(ip);

        // Just verify it doesn't panic and produces an ID
        assert!(!id.to_string().is_empty());
    }

    fn req(peer: Option<&str>, headers: &[(&str, &str)]) -> Request<Body> {
        let mut b = Request::builder().uri("/x");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut r = b.body(Body::empty()).unwrap();
        if let Some(p) = peer {
            r.extensions_mut()
                .insert(ConnectInfo(p.parse::<SocketAddr>().unwrap()));
        }
        r
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn forwarding_headers_from_an_untrusted_peer_are_ignored() {
        let none = TrustedProxies::none();
        let r = req(
            Some("203.0.113.5:1"),
            &[
                ("X-Forwarded-For", "198.51.100.1"),
                ("X-Real-IP", "198.51.100.2"),
            ],
        );
        assert_eq!(client_ip(&r, &none), ip("203.0.113.5"));
    }

    #[test]
    fn trusted_proxy_hops_are_walked_right_to_left() {
        let t = TrustedProxies::parse("192.0.2.0/24").unwrap();
        // Two X-Forwarded-For headers are one list, in order.
        let r = req(
            Some("192.0.2.1:1"),
            &[
                ("X-Forwarded-For", "198.51.100.1, 203.0.113.9"),
                ("X-Forwarded-For", "192.0.2.7"),
            ],
        );
        assert_eq!(client_ip(&r, &t), ip("203.0.113.9"));
        // Every hop trusted: the left-most is the client.
        let r = req(
            Some("192.0.2.1:1"),
            &[("X-Forwarded-For", "192.0.2.8, 192.0.2.9")],
        );
        assert_eq!(client_ip(&r, &t), ip("192.0.2.8"));
        // An unparseable hop stops the walk at the last trusted hop.
        let r = req(
            Some("192.0.2.1:1"),
            &[("X-Forwarded-For", "198.51.100.1, junk, 192.0.2.9")],
        );
        assert_eq!(client_ip(&r, &t), ip("192.0.2.9"));
        // No X-Forwarded-For: a trusted proxy's X-Real-IP, else the proxy.
        let r = req(Some("192.0.2.1:1"), &[("X-Real-IP", "203.0.113.44")]);
        assert_eq!(client_ip(&r, &t), ip("203.0.113.44"));
        let r = req(Some("192.0.2.1:1"), &[]);
        assert_eq!(client_ip(&r, &t), ip("192.0.2.1"));
    }

    #[test]
    fn no_connect_info_means_no_client_address() {
        let r = req(None, &[("X-Forwarded-For", "198.51.100.1")]);
        assert_eq!(client_ip(&r, &TrustedProxies::loopback()), None);
    }

    #[test]
    fn the_principal_outranks_the_address() {
        let agent = Uuid::new_v4();
        let client = Uuid::new_v4();
        let mut r = req(Some("203.0.113.5:1"), &[]);
        let jwt = crate::oauth::JwtConfig::from_secret(b"0123456789abcdef0123456789abcdef");
        let (tok, _) = jwt
            .issue_access_token(
                client,
                vec![],
                "agent",
                None,
                Some(agent),
                chrono::Duration::minutes(1),
                epigraph_auth::AccessTokenBinding::NONE,
            )
            .unwrap();
        let ctx: AuthContext = jwt.validate_token(&tok).unwrap().into();
        r.extensions_mut().insert(ctx.clone());
        assert_eq!(
            rate_limit_key(&r, &TrustedProxies::none()),
            Some(AgentId::from_uuid(agent))
        );
        // A token with no agent is keyed by its client.
        let mut ctx = ctx;
        ctx.agent_id = None;
        r.extensions_mut().insert(ctx);
        assert_eq!(
            rate_limit_key(&r, &TrustedProxies::none()),
            Some(AgentId::from_uuid(client))
        );
    }

    #[test]
    fn ipv6_keys_cover_the_slash_64_and_v4_mapped_is_v4() {
        let a = ip_to_agent_id("2001:db8:1:2::1".parse().unwrap());
        let b = ip_to_agent_id("2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap());
        let c = ip_to_agent_id("2001:db8:1:3::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(
            ip_to_agent_id("::ffff:192.0.2.1".parse().unwrap()),
            ip_to_agent_id("192.0.2.1".parse().unwrap())
        );
    }

    #[test]
    fn test_rate_limit_response_has_retry_after() {
        let response = RateLimitResponse {
            retry_after_secs: 30,
            message: "Rate limit exceeded".to_string(),
        };

        let http_response = response.into_response();

        assert_eq!(http_response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(http_response.headers().get("Retry-After").unwrap(), "30");
        assert_eq!(
            http_response.headers().get("cache-control").unwrap(),
            "no-store"
        );
        assert_eq!(http_response.headers().get("pragma").unwrap(), "no-cache");
    }
}
