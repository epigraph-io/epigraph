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
//! - **Unauthenticated requests**: Rate limited by client IP
//! - **Health endpoints**: Exempt from rate limiting

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use epigraph_core::domain::AgentId;
use std::net::IpAddr;
use uuid::Uuid;

use crate::security::audit::SecurityAuditLog;
use crate::security::{RateLimitError, SecurityEvent};
use crate::state::AppState;

// ============================================================================
// Constants
// ============================================================================

/// Header for forwarded client IP (from reverse proxy)
const X_FORWARDED_FOR: &str = "X-Forwarded-For";

/// Header for real IP (alternative to X-Forwarded-For)
const X_REAL_IP: &str = "X-Real-IP";

/// Routes that bypass rate limiting
const BYPASS_ROUTES: &[&str] = &["/health", "/readiness", "/liveness", "/metrics"];

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

/// Extract client IP from request headers or connection info
///
/// Priority:
/// 1. X-Forwarded-For (first IP in chain)
/// 2. X-Real-IP
/// 3. Connected peer address (fallback)
///
/// # Security Note
///
/// X-Forwarded-For can be spoofed by clients. In production, ensure
/// your reverse proxy overwrites this header with the actual client IP.
fn extract_client_ip(request: &Request<Body>) -> Option<IpAddr> {
    // Try X-Forwarded-For first
    if let Some(forwarded) = request.headers().get(X_FORWARDED_FOR) {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // The first one is the original client
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = request.headers().get(X_REAL_IP) {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.trim().parse() {
                return Some(ip);
            }
        }
    }

    // No header found - connection info would need ConnectInfo extractor
    // which requires additional setup. Return None for now.
    None
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

/// Generate a rate limit key from client IP
fn ip_to_agent_id(ip: IpAddr) -> AgentId {
    // Convert IP to a deterministic AgentId for rate limiting purposes
    // This uses a hash of the IP address as the UUID
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    ip.hash(&mut hasher);
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
    let agent_id = request
        .extensions()
        .get::<crate::middleware::VerifiedAgent>()
        .map(|agent| agent.agent_id)
        .or_else(|| extract_client_ip(&request).map(ip_to_agent_id))
        .unwrap_or_else(|| {
            // Fallback: use a fixed ID for requests without identifiable source
            // This is a security concern - should be logged
            tracing::warn!(
                path = %path,
                "Rate limiting request without identifiable client - using fallback ID"
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
        assert!(should_bypass_rate_limit("/metrics", &Method::GET));
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
