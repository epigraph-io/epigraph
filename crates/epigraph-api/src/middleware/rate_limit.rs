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
//! - **Authenticated requests**: Rate limited by agent ID
//! - **Unauthenticated requests**: Rate limited by client IP, where the client
//!   IP is the TCP peer (`ConnectInfo<SocketAddr>`) unless that peer is a
//!   trusted proxy (`AgentRateLimiter::trusted_proxies`), in which case it is
//!   the right-most `X-Forwarded-For` entry that is not itself a trusted proxy.
//!   IPv6 clients are keyed by their /64.
//! - **No identifiable client**: NOT rate limited, and never pooled into one
//!   shared bucket (see [`rate_limit_middleware`]).
//! - **Health endpoints**: Exempt from rate limiting

// UNSCOPED-POOL-EXEMPT: One `db_pool.clone()` handed to a detached task that records security
// events. It runs after the rate-limit decision and outside any request's viewer scope, and rate
// limiting precedes authentication, so the request may have no principal to scope to at all.

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use epigraph_core::domain::AgentId;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

use crate::security::audit::SecurityAuditLog;
use crate::security::{AgentRateLimiter, RateLimitError, SecurityEvent};
use crate::state::AppState;

// ============================================================================
// Constants
// ============================================================================

/// Header for forwarded client IP (from reverse proxy)
const X_FORWARDED_FOR: &str = "X-Forwarded-For";

/// Header for real IP (alternative to X-Forwarded-For)
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

/// Set once the "no identifiable client" warning has been logged.
static NO_PEER_WARNED: AtomicBool = AtomicBool::new(false);

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

        response
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// The client address an anonymous request is rate limited under, or `None`
/// when the request carries no peer address at all.
///
/// The peer comes from `ConnectInfo<SocketAddr>`, which `bin/server.rs`
/// supplies by serving with `into_make_service_with_connect_info`. It is
/// absent only when a router is driven without it — `tower::oneshot` in tests,
/// or an embedder that serves with plain `into_make_service`.
fn client_ip(request: &Request<Body>, limiter: &AgentRateLimiter) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()?
        .0
        .ip();
    Some(resolve_client_ip(request.headers(), peer, |ip| {
        limiter.is_trusted_proxy(ip)
    }))
}

/// Resolve the originating client of a request that arrived from `peer`.
///
/// # Only a trusted peer's headers are believed
///
/// This used to return the FIRST `X-Forwarded-For` entry, then `X-Real-IP`,
/// from any peer at all. Both headers are written by whoever sends the
/// request, so a client chose its own bucket per request and no per-client
/// quota could hold. Now:
///
/// 1. A peer that is not a trusted proxy IS the client. Its headers are
///    ignored.
/// 2. Behind a trusted proxy, walk `X-Forwarded-For` from the RIGHT, skipping
///    entries that are themselves trusted proxies, and take the first that is
///    not. Every entry to the right of it was appended by a proxy we trust;
///    every entry to its left came from the client and is ignored. That is
///    the difference from "first entry": a client that sends
///    `X-Forwarded-For: <anything>` through a proxy that appends gets
///    `<anything>, <its real address>`, and the real address is what is used.
///    If every entry is trusted, the left-most one is the client (a
///    same-host caller that went through the proxy). A malformed entry stops
///    the walk at the last well-formed trusted hop.
/// 3. No usable `X-Forwarded-For`: `X-Real-IP`, then the peer itself.
fn resolve_client_ip(
    headers: &HeaderMap,
    peer: IpAddr,
    is_trusted: impl Fn(IpAddr) -> bool,
) -> IpAddr {
    let peer = peer.to_canonical();
    if !is_trusted(peer) {
        return peer;
    }

    let chain: Vec<&str> = headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();

    let mut nearest_untrusted_or_leftmost = None;
    for entry in chain.iter().rev() {
        let Some(ip) = parse_forwarded_ip(entry) else {
            break;
        };
        nearest_untrusted_or_leftmost = Some(ip);
        if !is_trusted(ip) {
            break;
        }
    }
    if let Some(ip) = nearest_untrusted_or_leftmost {
        return ip;
    }

    headers
        .get(X_REAL_IP)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_forwarded_ip)
        .unwrap_or(peer)
}

/// Parse one forwarding-header entry: a bare address, or an address with a
/// port (`203.0.113.9:4711`, `[2001:db8::1]:443`), or a bracketed IPv6
/// address. IPv4-mapped IPv6 is reduced to the IPv4 address it carries.
fn parse_forwarded_ip(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim().trim_matches('"');
    let ip = entry
        .parse::<IpAddr>()
        .ok()
        .or_else(|| entry.parse::<SocketAddr>().ok().map(|sa| sa.ip()))
        .or_else(|| {
            entry
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|inner| inner.parse::<IpAddr>().ok())
        })?;
    Some(ip.to_canonical())
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

/// The address a client is bucketed under: IPv4 as-is, IPv6 by its /64.
///
/// A single IPv6 subscriber is routinely delegated a whole /64 and can source
/// from any address in it, so a per-address IPv6 key would let one client
/// choose among 2^64 buckets — the same escape the forwarding headers used to
/// offer. /64 is the smallest prefix one end site is expected to hold.
fn rate_limit_subject(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
        v4 => v4,
    }
}

/// Generate a rate limit key from client IP
fn ip_to_agent_id(ip: IpAddr) -> AgentId {
    // Convert IP to a deterministic AgentId for rate limiting purposes
    // This uses a hash of the IP address as the UUID
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    rate_limit_subject(ip).hash(&mut hasher);
    let hash = hasher.finish();

    // Create a UUID v4-like ID from the hash (not a real UUID, but deterministic)
    let bytes = hash.to_le_bytes();
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes[..8].copy_from_slice(&bytes);
    uuid_bytes[8..16].copy_from_slice(&bytes); // Duplicate for full 16 bytes

    AgentId::from_uuid(uuid::Uuid::from_bytes(uuid_bytes))
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

    // Extract client identifier
    // Priority: VerifiedAgent (if present) > IP address > fallback
    //
    // PR-03 note: the `VerifiedAgent` arm is now permanently `None` in
    // production. `VerifiedAgent` is inserted only by
    // `middleware::auth::signature_verification_middleware`, whose sole
    // production caller (`middleware::require_signature`) was deleted with the
    // router inversion. It is kept rather than collapsed to IP-only because the
    // middleware integration tests still exercise this precedence, and because
    // PR-07 will replace it with the `ViewerExtractor` principal — which is a
    // strictly better rate-limit key than the client IP and restores the
    // intent of this branch.
    let identified = request
        .extensions()
        .get::<crate::middleware::VerifiedAgent>()
        .map(|agent| agent.agent_id)
        .or_else(|| client_ip(&request, rate_limiter).map(ip_to_agent_id));

    // No identifiable client: let it through UNLIMITED rather than into a
    // shared bucket.
    //
    // This used to be `AgentId::from_uuid(Uuid::nil())` — one bucket for every
    // request that carried no forwarding header, so any one such client could
    // spend it and 429 all the others. There is no correct shared key: the
    // global bucket already exists for aggregate load, and a per-client key is
    // exactly what is missing. It cannot happen on the production listener,
    // which serves with `ConnectInfo`; it happens under `tower::oneshot` and
    // under an embedder that serves without it, and the first such request
    // warns once so the second case is visible in the log.
    let Some(agent_id) = identified else {
        if !NO_PEER_WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                path = %path,
                "rate limiting skipped: request carries no ConnectInfo peer address \
                 and no principal. Serve the router with \
                 `into_make_service_with_connect_info::<SocketAddr>()` for \
                 anonymous traffic to be rate limited. Logged once per process."
            );
        }
        return Ok(next.run(request).await);
    };

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

    fn loopback_only(ip: IpAddr) -> bool {
        ip.is_loopback()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_its_headers_say() {
        let h = headers(&[
            (X_FORWARDED_FOR, "198.51.100.1"),
            (X_REAL_IP, "198.51.100.2"),
        ]);
        assert_eq!(
            resolve_client_ip(&h, ip("203.0.113.9"), loopback_only),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn behind_a_trusted_peer_the_rightmost_untrusted_hop_is_the_client() {
        // client-written junk, then the real client, then a second trusted hop
        let h = headers(&[(X_FORWARDED_FOR, "6.6.6.6, 198.51.100.7, 127.0.0.2")]);
        assert_eq!(
            resolve_client_ip(&h, ip("127.0.0.1"), loopback_only),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn repeated_forwarded_for_lines_are_read_as_one_list_in_order() {
        let h = headers(&[
            (X_FORWARDED_FOR, "6.6.6.6"),
            (X_FORWARDED_FOR, "198.51.100.8"),
        ]);
        assert_eq!(
            resolve_client_ip(&h, ip("127.0.0.1"), loopback_only),
            ip("198.51.100.8")
        );
    }

    #[test]
    fn an_all_trusted_chain_resolves_to_its_leftmost_hop() {
        let h = headers(&[(X_FORWARDED_FOR, "127.0.0.5, 127.0.0.6")]);
        assert_eq!(
            resolve_client_ip(&h, ip("127.0.0.1"), loopback_only),
            ip("127.0.0.5")
        );
    }

    #[test]
    fn a_malformed_entry_stops_the_walk_at_the_last_trusted_hop() {
        let h = headers(&[(X_FORWARDED_FOR, "198.51.100.1, unknown, 127.0.0.9")]);
        assert_eq!(
            resolve_client_ip(&h, ip("127.0.0.1"), loopback_only),
            ip("127.0.0.9"),
            "an entry left of garbage cannot be attributed to a trusted hop"
        );
    }

    #[test]
    fn x_real_ip_then_the_peer_when_forwarded_for_is_unusable() {
        let h = headers(&[(X_REAL_IP, "198.51.100.3")]);
        assert_eq!(
            resolve_client_ip(&h, ip("127.0.0.1"), loopback_only),
            ip("198.51.100.3")
        );
        let h = headers(&[(X_FORWARDED_FOR, "garbage")]);
        assert_eq!(
            resolve_client_ip(&h, ip("127.0.0.1"), loopback_only),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn an_ipv4_mapped_peer_is_judged_as_the_ipv4_address_it_carries() {
        let h = headers(&[(X_FORWARDED_FOR, "198.51.100.4")]);
        assert_eq!(
            resolve_client_ip(&h, ip("::ffff:127.0.0.1"), loopback_only),
            ip("198.51.100.4"),
            "a dual-stack listener reports loopback IPv4 as ::ffff:127.0.0.1"
        );
    }

    #[test]
    fn forwarded_entries_with_ports_and_brackets_parse() {
        assert_eq!(
            parse_forwarded_ip("203.0.113.9:4711"),
            Some(ip("203.0.113.9"))
        );
        assert_eq!(
            parse_forwarded_ip("[2001:db8::1]:443"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(parse_forwarded_ip("[2001:db8::1]"), Some(ip("2001:db8::1")));
        assert_eq!(
            parse_forwarded_ip("\"2001:db8::1\""),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(
            parse_forwarded_ip("::ffff:198.51.100.5"),
            Some(ip("198.51.100.5"))
        );
        assert_eq!(parse_forwarded_ip("unknown"), None);
    }

    #[test]
    fn ipv6_keys_are_per_64_and_ipv4_keys_are_per_address() {
        assert_eq!(
            ip_to_agent_id(ip("2001:db8:1:2::1")),
            ip_to_agent_id(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"))
        );
        assert_ne!(
            ip_to_agent_id(ip("2001:db8:1:2::1")),
            ip_to_agent_id(ip("2001:db8:1:3::1"))
        );
        assert_ne!(
            ip_to_agent_id(ip("192.0.2.1")),
            ip_to_agent_id(ip("192.0.2.2"))
        );
        assert_eq!(
            ip_to_agent_id(ip("::ffff:192.0.2.1")),
            ip_to_agent_id(ip("192.0.2.1"))
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
    }
}
