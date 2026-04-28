pub mod auth;
pub mod auth_chain;
pub mod bearer;
#[cfg(feature = "db")]
pub mod group_authz;
#[cfg(feature = "db")]
pub mod provenance;
pub mod rate_limit;
pub mod scopes;

// Re-export common types for convenience
pub use auth::{
    signature_verification_middleware, SignatureError, SignatureVerificationState, VerifiedAgent,
    PUBLIC_KEY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER,
};

// Re-export rate limiting middleware
pub use rate_limit::{rate_limit_middleware, RateLimitResponse};

// Re-export OAuth2 middleware
#[allow(deprecated)]
pub use bearer::{bearer_auth_middleware, AuthContext, ClientType};
pub use auth_chain::auth_chain_middleware;
#[cfg(feature = "db")]
pub use group_authz::require_group_admin;
#[cfg(feature = "db")]
pub use provenance::record_provenance;
pub use scopes::check_scopes;

// Legacy export (deprecated)
#[allow(deprecated)]
pub use auth::signature_verification_layer;

use crate::security::audit::SecurityAuditLog;
use crate::security::SecurityEvent;
use crate::state::AppState;
use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use epigraph_core::domain::AgentId;
use std::net::IpAddr;
use uuid::Uuid;

/// Signature verification middleware wrapper for AppState
///
/// This middleware wraps the signature verification middleware to work with
/// the application's `AppState` instead of the standalone `SignatureVerificationState`.
///
/// # Protected Routes
///
/// Apply this middleware to write operations that require authentication:
/// - POST /claims
/// - POST /agents
/// - POST /api/v1/submit/packet
///
/// # Security Properties
///
/// 1. **Authentication**: Verifies Ed25519 signatures on requests
/// 2. **Authorization**: Confirms agent is registered in the system
/// 3. **Integrity**: Ensures request body hasn't been tampered with
/// 4. **Freshness**: Validates timestamp to prevent replay attacks
/// 5. **Context Injection**: Injects `VerifiedAgent` into request extensions
///
/// # Usage
///
/// ```ignore
/// use axum::{Router, middleware, routing::post};
/// use epigraph_api::middleware::require_signature;
///
/// let protected = Router::new()
///     .route("/claims", post(create_claim))
///     .layer(middleware::from_fn_with_state(state.clone(), require_signature));
/// ```
/// Extract client IP address from request headers
///
/// Priority:
/// 1. X-Forwarded-For (first IP in chain)
/// 2. X-Real-IP
/// 3. None (no identifiable source)
fn extract_client_ip(request: &Request<Body>) -> Option<IpAddr> {
    // Try X-Forwarded-For first
    if let Some(forwarded) = request.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = request.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.trim().parse() {
                return Some(ip);
            }
        }
    }

    None
}

/// Extract User-Agent header from request
fn extract_user_agent(request: &Request<Body>) -> Option<String> {
    request
        .headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .map(|s| s.to_string())
}

pub async fn require_signature(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, SignatureError> {
    // If bearer auth already authenticated this request, skip signature verification
    if request.extensions().get::<bearer::AuthContext>().is_some() {
        return Ok(next.run(request).await);
    }

    // Generate a correlation ID for this request
    let correlation_id = Uuid::new_v4().to_string();

    // Extract metadata for audit logging before consuming the request
    let ip_address = extract_client_ip(&request);
    let user_agent = extract_user_agent(&request);

    // Try to extract agent ID from public key header for audit logging
    // (before signature verification, so we can log failed attempts too)
    let agent_id_for_audit = request
        .headers()
        .get(PUBLIC_KEY_HEADER)
        .and_then(|pk| pk.to_str().ok())
        .map(|pk_str| {
            // Create a deterministic AgentId from the public key for audit purposes
            // This allows us to track failed attempts even when we don't know the real agent
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            pk_str.hash(&mut hasher);
            let hash = hasher.finish();
            let bytes = hash.to_le_bytes();
            let mut uuid_bytes = [0u8; 16];
            uuid_bytes[..8].copy_from_slice(&bytes);
            uuid_bytes[8..16].copy_from_slice(&bytes);
            AgentId::from_uuid(Uuid::from_bytes(uuid_bytes))
        })
        .unwrap_or_default();

    // Clone state.signature_state for the underlying middleware
    let signature_state = state.signature_state.clone();
    let audit_log = state.audit_log.clone();

    // Delegate to the underlying signature verification middleware
    let result = signature_verification_middleware(State(signature_state), request, next).await;

    // Log the authentication/signature verification result
    match &result {
        Ok(response) => {
            // Check if the response indicates success (2xx status)
            let success = response.status().is_success() || response.status().is_redirection();

            // Log successful signature verification
            let sig_event = SecurityEvent::signature_verification(
                agent_id_for_audit,
                success,
                None,
                correlation_id.clone(),
            );
            audit_log.log(sig_event.clone()); // in-memory

            // DB persistence (non-blocking, fire-and-forget)
            #[cfg(feature = "db")]
            {
                use crate::security::audit::security_event_row_from;
                use epigraph_db::repos::security_event::SecurityEventRepository;
                let pool = state.db_pool.clone();
                let row = security_event_row_from(&sig_event);
                tokio::spawn(async move {
                    if let Err(e) = SecurityEventRepository::log(&pool, row).await {
                        tracing::warn!("Failed to persist security event: {e}");
                    }
                });
            }

            // Also log successful auth attempt
            let auth_event = SecurityEvent::auth_attempt(
                agent_id_for_audit,
                true,
                ip_address,
                user_agent,
                correlation_id,
            );
            audit_log.log(auth_event.clone()); // in-memory

            // DB persistence (non-blocking, fire-and-forget)
            #[cfg(feature = "db")]
            {
                use crate::security::audit::security_event_row_from;
                use epigraph_db::repos::security_event::SecurityEventRepository;
                let pool = state.db_pool.clone();
                let row = security_event_row_from(&auth_event);
                tokio::spawn(async move {
                    if let Err(e) = SecurityEventRepository::log(&pool, row).await {
                        tracing::warn!("Failed to persist security event: {e}");
                    }
                });
            }
        }
        Err(err) => {
            // Log signature verification failure with reason
            let failure_reason = match err {
                SignatureError::MissingHeader(h) => format!("Missing header: {}", h),
                SignatureError::MalformedData(msg) => format!("Malformed data: {}", msg),
                SignatureError::InvalidSignature => "Invalid signature".to_string(),
                SignatureError::ExpiredTimestamp => "Expired timestamp".to_string(),
                SignatureError::UnknownAgent => "Unknown agent".to_string(),
                SignatureError::ReplayDetected => "Replay attack detected".to_string(),
            };

            let sig_fail_event = SecurityEvent::signature_verification(
                agent_id_for_audit,
                false,
                Some(failure_reason.clone()),
                correlation_id.clone(),
            );
            audit_log.log(sig_fail_event.clone()); // in-memory

            // DB persistence (non-blocking, fire-and-forget)
            #[cfg(feature = "db")]
            {
                use crate::security::audit::security_event_row_from;
                use epigraph_db::repos::security_event::SecurityEventRepository;
                let pool = state.db_pool.clone();
                let row = security_event_row_from(&sig_fail_event);
                tokio::spawn(async move {
                    if let Err(e) = SecurityEventRepository::log(&pool, row).await {
                        tracing::warn!("Failed to persist security event: {e}");
                    }
                });
            }

            // Also log failed auth attempt
            let auth_fail_event = SecurityEvent::auth_attempt(
                agent_id_for_audit,
                false,
                ip_address,
                user_agent,
                correlation_id,
            );
            audit_log.log(auth_fail_event.clone()); // in-memory

            // DB persistence (non-blocking, fire-and-forget)
            #[cfg(feature = "db")]
            {
                use crate::security::audit::security_event_row_from;
                use epigraph_db::repos::security_event::SecurityEventRepository;
                let pool = state.db_pool.clone();
                let row = security_event_row_from(&auth_fail_event);
                tokio::spawn(async move {
                    if let Err(e) = SecurityEventRepository::log(&pool, row).await {
                        tracing::warn!("Failed to persist security event: {e}");
                    }
                });
            }

            // Log at warning level for security monitoring
            tracing::warn!(
                agent_id = %agent_id_for_audit,
                failure_reason = %failure_reason,
                ip = ?ip_address,
                "Authentication failed"
            );
        }
    }

    result
}
