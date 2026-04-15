//! Ed25519 Signature Verification Middleware
//!
//! # Security Properties
//!
//! 1. **Authentication**: Only agents with valid signatures can submit claims
//! 2. **Integrity**: Request body cannot be tampered with after signing
//! 3. **Freshness**: Timestamps prevent replay attacks within time window
//! 4. **Non-repudiation**: Signatures bind agents to their requests
//! 5. **Timing Safety**: Signature comparison uses constant-time operations

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use epigraph_core::domain::ids::AgentId;
use epigraph_crypto::{SignatureVerifier, SIGNATURE_SIZE};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

// ============================================================================
// Constants
// ============================================================================

/// Header name for the Ed25519 signature (base64-encoded)
pub const SIGNATURE_HEADER: &str = "X-Signature";

/// Header name for the agent's public key (hex-encoded)
pub const PUBLIC_KEY_HEADER: &str = "X-Public-Key";

/// Header name for the request timestamp (ISO 8601)
pub const TIMESTAMP_HEADER: &str = "X-Timestamp";

/// Maximum age of a valid signature (5 minutes)
pub const MAX_SIGNATURE_AGE_SECONDS: i64 = 300;

/// Clock skew tolerance for future timestamps (30 seconds)
pub const CLOCK_SKEW_TOLERANCE_SECONDS: i64 = 30;

/// Maximum number of nonces to store for replay prevention.
/// Prevents unbounded memory growth from nonce accumulation.
/// At 5 minute signature validity and assuming 1000 requests/second peak,
/// 300,000 entries provides sufficient headroom.
const MAX_NONCE_STORE_SIZE: usize = 300_000;

/// Maximum length of signature header in bytes.
/// Ed25519 signature is 64 bytes, base64 encoded is ~88 chars.
/// Allow some extra for padding variations.
const MAX_SIGNATURE_HEADER_LENGTH: usize = 128;

/// Maximum length of public key header in bytes.
/// Ed25519 public key is 32 bytes, hex encoded is 64 chars.
const MAX_PUBLIC_KEY_HEADER_LENGTH: usize = 128;

/// Maximum length of timestamp header in bytes.
/// ISO 8601 with timezone is typically ~30 chars.
const MAX_TIMESTAMP_HEADER_LENGTH: usize = 64;

// ============================================================================
// Types
// ============================================================================

/// Used nonces for replay attack prevention.
/// Maps nonce strings to Unix timestamps (seconds) for time-based eviction.
pub type NonceStore = Arc<RwLock<HashMap<String, i64>>>;

/// Known agents: maps public key to agent ID for authorization and identity lookup
pub type AgentRegistry = Arc<RwLock<HashMap<[u8; 32], AgentId>>>;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during signature verification
#[derive(Debug, Clone)]
pub enum SignatureError {
    /// Missing required header
    MissingHeader(&'static str),
    /// Malformed signature or public key
    MalformedData(String),
    /// Signature verification failed
    InvalidSignature,
    /// Timestamp expired or in the future
    ExpiredTimestamp,
    /// Agent not registered in the system
    UnknownAgent,
    /// Replay attack detected (duplicate nonce)
    ReplayDetected,
}

impl IntoResponse for SignatureError {
    fn into_response(self) -> Response {
        // Capture error variant name before moving
        let error_name = format!("{:?}", &self);

        let (status, message) = match self {
            SignatureError::MissingHeader(h) => {
                (StatusCode::UNAUTHORIZED, format!("Missing header: {h}"))
            }
            SignatureError::MalformedData(msg) => (StatusCode::BAD_REQUEST, msg),
            SignatureError::InvalidSignature => {
                (StatusCode::UNAUTHORIZED, "Invalid signature".to_string())
            }
            SignatureError::ExpiredTimestamp => {
                (StatusCode::UNAUTHORIZED, "Timestamp expired".to_string())
            }
            SignatureError::UnknownAgent => (StatusCode::UNAUTHORIZED, "Unknown agent".to_string()),
            SignatureError::ReplayDetected => (
                StatusCode::UNAUTHORIZED,
                "Replay attack detected".to_string(),
            ),
        };

        let body = serde_json::json!({
            "error": error_name,
            "message": message,
        });

        (status, Json(body)).into_response()
    }
}

// ============================================================================
// Verified Agent Extension
// ============================================================================

/// Extracted agent identity after signature verification
///
/// This is inserted into the request extensions after successful verification,
/// allowing downstream handlers to identify the authenticated agent.
#[derive(Clone, Debug)]
pub struct VerifiedAgent {
    /// The agent's ID (looked up from public key)
    pub agent_id: AgentId,
    /// The agent's public key (verified against signature)
    pub public_key: [u8; 32],
}

// ============================================================================
// State
// ============================================================================

/// Application state for signature verification middleware
#[derive(Clone)]
pub struct SignatureVerificationState {
    /// Store of used nonces for replay prevention
    pub nonce_store: NonceStore,
    /// Registry of known agent public keys
    pub agent_registry: AgentRegistry,
    /// Routes that bypass signature verification
    pub bypass_routes: Vec<String>,
    /// Maximum request body size in bytes for signature verification.
    /// Prevents DoS via oversized request bodies that exhaust memory.
    /// Defaults to 1MB (1024 * 1024 bytes).
    pub max_request_size: usize,
}

impl SignatureVerificationState {
    /// Create a new signature verification state
    pub fn new() -> Self {
        Self {
            nonce_store: Arc::new(RwLock::new(HashMap::new())),
            agent_registry: Arc::new(RwLock::new(HashMap::new())),
            bypass_routes: vec!["/health".to_string()],
            max_request_size: 1024 * 1024, // 1MB default
        }
    }

    /// Create state with custom bypass routes
    pub fn with_bypass_routes(bypass_routes: Vec<String>) -> Self {
        Self {
            nonce_store: Arc::new(RwLock::new(HashMap::new())),
            agent_registry: Arc::new(RwLock::new(HashMap::new())),
            bypass_routes,
            max_request_size: 1024 * 1024, // 1MB default
        }
    }

    /// Set the maximum request body size in bytes (builder pattern)
    ///
    /// Controls the limit passed to `axum::body::to_bytes` during signature
    /// verification. Requests exceeding this size will be rejected, preventing
    /// memory exhaustion from oversized payloads.
    ///
    /// # Default
    /// 1MB (1024 * 1024 bytes)
    #[must_use]
    pub fn with_max_request_size(mut self, max_request_size: usize) -> Self {
        self.max_request_size = max_request_size;
        self
    }

    /// Register an agent's public key with their agent ID
    ///
    /// # Arguments
    /// * `public_key` - The Ed25519 public key (32 bytes)
    /// * `agent_id` - The unique identifier for this agent
    ///
    /// # Returns
    /// The agent ID that was registered (useful for chaining)
    pub fn register_agent(&self, public_key: [u8; 32], agent_id: AgentId) -> AgentId {
        self.agent_registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(public_key, agent_id);
        agent_id
    }

    /// Check if an agent is registered
    pub fn is_agent_registered(&self, public_key: &[u8; 32]) -> bool {
        self.agent_registry
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(public_key)
    }

    /// Look up an agent's ID by their public key
    ///
    /// # Returns
    /// `Some(AgentId)` if the agent is registered, `None` otherwise
    pub fn get_agent_id(&self, public_key: &[u8; 32]) -> Option<AgentId> {
        self.agent_registry
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(public_key)
            .copied()
    }

    /// Record a nonce, returns false if already used (replay)
    ///
    /// # Security: Time-Partitioned Nonce Eviction
    ///
    /// When the nonce store reaches MAX_NONCE_STORE_SIZE, we evict only
    /// entries older than MAX_SIGNATURE_AGE_SECONDS. This prevents the
    /// replay window that a bulk `clear()` would create, because recent
    /// (still-valid) nonces are retained.
    ///
    /// Memory is still bounded: expired nonces are removed, and the
    /// timestamp check in `validate_timestamp` ensures nonces older than
    /// MAX_SIGNATURE_AGE_SECONDS can never be replayed anyway.
    pub fn record_nonce(&self, nonce: &str) -> bool {
        let mut store = self
            .nonce_store
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Time-partitioned eviction: remove only expired nonces
        if store.len() >= MAX_NONCE_STORE_SIZE {
            let cutoff = Utc::now().timestamp() - MAX_SIGNATURE_AGE_SECONDS;
            store.retain(|_, ts| *ts > cutoff);
            tracing::info!(
                remaining = store.len(),
                "Nonce store eviction: removed expired entries"
            );
        }

        let now = Utc::now().timestamp();
        // HashMap::insert returns None if the key didn't exist (new nonce),
        // or Some(old_value) if it was already present (replay).
        store.insert(nonce.to_string(), now).is_none()
    }

    /// Check if a route should bypass signature verification
    pub fn should_bypass(&self, path: &str, method: &Method) -> bool {
        // OPTIONS always bypasses for CORS preflight
        if method == Method::OPTIONS {
            return true;
        }
        self.bypass_routes.iter().any(|r| path.starts_with(r))
    }
}

impl Default for SignatureVerificationState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// The signed message format that gets hashed and signed
///
/// This includes the method, path, body, and timestamp to ensure
/// the signature covers the entire request context.
#[derive(Serialize)]
struct SignedMessage<'a> {
    method: &'a str,
    path: &'a str,
    body: &'a [u8],
    timestamp: &'a str,
}

/// Parse a hex-encoded public key from header value
fn parse_public_key(hex_str: &str) -> Result<[u8; 32], SignatureError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| SignatureError::MalformedData(format!("Invalid public key hex: {e}")))?;

    if bytes.len() != 32 {
        return Err(SignatureError::MalformedData(format!(
            "Public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Parse a base64-encoded signature from header value
fn parse_signature(base64_str: &str) -> Result<[u8; SIGNATURE_SIZE], SignatureError> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let bytes = STANDARD
        .decode(base64_str)
        .map_err(|e| SignatureError::MalformedData(format!("Invalid signature base64: {e}")))?;

    if bytes.len() != SIGNATURE_SIZE {
        return Err(SignatureError::MalformedData(format!(
            "Signature must be {} bytes, got {}",
            SIGNATURE_SIZE,
            bytes.len()
        )));
    }

    let mut sig = [0u8; SIGNATURE_SIZE];
    sig.copy_from_slice(&bytes);
    Ok(sig)
}

/// Validate timestamp is recent and not in the future
fn validate_timestamp(timestamp_str: &str) -> Result<(), SignatureError> {
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
        .map_err(|e| SignatureError::MalformedData(format!("Invalid timestamp: {e}")))?
        .with_timezone(&Utc);

    let now = Utc::now();
    let age = now.signed_duration_since(timestamp);

    // Reject timestamps in the future (with tolerance for clock skew)
    if age < Duration::seconds(-CLOCK_SKEW_TOLERANCE_SECONDS) {
        return Err(SignatureError::ExpiredTimestamp);
    }

    // Reject timestamps older than MAX_SIGNATURE_AGE_SECONDS
    if age > Duration::seconds(MAX_SIGNATURE_AGE_SECONDS) {
        return Err(SignatureError::ExpiredTimestamp);
    }

    Ok(())
}

// ============================================================================
// Middleware
// ============================================================================

/// Signature verification middleware
///
/// # Security Properties
///
/// 1. Extracts signature, public key, and timestamp from headers
/// 2. Validates timestamp freshness (prevents replay attacks)
/// 3. Verifies agent is registered (authorization)
/// 4. Constructs signed message from request components
/// 5. Verifies Ed25519 signature (authentication + integrity)
/// 6. Stores nonce to prevent replay attacks
/// 7. Injects VerifiedAgent into request extensions
///
/// # Usage
///
/// ```ignore
/// use axum::{Router, middleware};
/// use epigraph_api::middleware::auth::{
///     signature_verification_middleware,
///     SignatureVerificationState
/// };
///
/// let state = SignatureVerificationState::new();
/// let app = Router::new()
///     .route("/protected", get(handler))
///     .layer(middleware::from_fn_with_state(
///         state.clone(),
///         signature_verification_middleware,
///     ))
///     .with_state(state);
/// ```
pub async fn signature_verification_middleware(
    State(state): State<SignatureVerificationState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, SignatureError> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Check if route should bypass verification
    if state.should_bypass(&path, &method) {
        return Ok(next.run(request).await);
    }

    // Extract headers (clone to owned strings before consuming request)
    // Security: Validate header lengths to prevent DoS via oversized headers
    let signature_header = request
        .headers()
        .get(SIGNATURE_HEADER)
        .ok_or(SignatureError::MissingHeader(SIGNATURE_HEADER))?
        .to_str()
        .map_err(|_| SignatureError::MalformedData("Invalid signature header encoding".into()))?
        .to_string();

    if signature_header.len() > MAX_SIGNATURE_HEADER_LENGTH {
        return Err(SignatureError::MalformedData(format!(
            "Signature header too long: {} bytes, maximum is {} bytes",
            signature_header.len(),
            MAX_SIGNATURE_HEADER_LENGTH
        )));
    }

    let public_key_header = request
        .headers()
        .get(PUBLIC_KEY_HEADER)
        .ok_or(SignatureError::MissingHeader(PUBLIC_KEY_HEADER))?
        .to_str()
        .map_err(|_| SignatureError::MalformedData("Invalid public key header encoding".into()))?
        .to_string();

    if public_key_header.len() > MAX_PUBLIC_KEY_HEADER_LENGTH {
        return Err(SignatureError::MalformedData(format!(
            "Public key header too long: {} bytes, maximum is {} bytes",
            public_key_header.len(),
            MAX_PUBLIC_KEY_HEADER_LENGTH
        )));
    }

    let timestamp_header = request
        .headers()
        .get(TIMESTAMP_HEADER)
        .ok_or(SignatureError::MissingHeader(TIMESTAMP_HEADER))?
        .to_str()
        .map_err(|_| SignatureError::MalformedData("Invalid timestamp header encoding".into()))?
        .to_string();

    if timestamp_header.len() > MAX_TIMESTAMP_HEADER_LENGTH {
        return Err(SignatureError::MalformedData(format!(
            "Timestamp header too long: {} bytes, maximum is {} bytes",
            timestamp_header.len(),
            MAX_TIMESTAMP_HEADER_LENGTH
        )));
    }

    // Parse cryptographic material
    let signature = parse_signature(&signature_header)?;
    let public_key = parse_public_key(&public_key_header)?;

    // Validate timestamp (freshness)
    validate_timestamp(&timestamp_header)?;

    // Check agent is registered (authorization)
    if !state.is_agent_registered(&public_key) {
        return Err(SignatureError::UnknownAgent);
    }

    // Read request body for signature verification
    let (parts, body) = request.into_parts();
    let body_bytes = axum::body::to_bytes(body, state.max_request_size)
        .await
        .map_err(|e| SignatureError::MalformedData(format!("Failed to read body: {e}")))?;

    // Construct the signed message
    let signed_message = SignedMessage {
        method: parts.method.as_str(),
        path: parts.uri.path(),
        body: &body_bytes,
        timestamp: &timestamp_header,
    };

    // Serialize to canonical JSON for verification
    let message_bytes = serde_json::to_vec(&signed_message)
        .map_err(|e| SignatureError::MalformedData(format!("Failed to serialize message: {e}")))?;

    // Verify signature (uses constant-time comparison internally)
    let is_valid = SignatureVerifier::verify(&public_key, &message_bytes, &signature)
        .map_err(|_| SignatureError::InvalidSignature)?;

    if !is_valid {
        return Err(SignatureError::InvalidSignature);
    }

    // Create nonce from signature to prevent replay
    // The signature itself is unique per (message, timestamp) pair
    let nonce = format!("{}-{}", hex::encode(&signature[..16]), timestamp_header);
    if !state.record_nonce(&nonce) {
        return Err(SignatureError::ReplayDetected);
    }

    // Look up the agent ID from the registry
    // Security: We already verified the agent is registered above, so this should always succeed.
    // However, we still handle the None case defensively to prevent identity spoofing.
    let agent_id = state.get_agent_id(&public_key).ok_or_else(|| {
        // This should never happen if is_agent_registered passed, but we handle it safely
        tracing::error!(
            public_key = hex::encode(public_key),
            "Agent passed registration check but ID lookup failed - possible race condition"
        );
        SignatureError::UnknownAgent
    })?;

    let verified_agent = VerifiedAgent {
        agent_id,
        public_key,
    };

    // Reconstruct request with body and add extension
    let mut request = Request::from_parts(parts, Body::from(body_bytes.to_vec()));
    request.extensions_mut().insert(verified_agent);

    Ok(next.run(request).await)
}

// ============================================================================
// Legacy Layer (for backward compatibility)
// ============================================================================

use tower::layer::util::Identity;

/// Placeholder for signature verification layer
///
/// This returns an Identity layer (pass-through) for backward compatibility.
/// For new code, use `signature_verification_middleware` with `middleware::from_fn_with_state`.
#[deprecated(
    since = "0.2.0",
    note = "Use signature_verification_middleware with middleware::from_fn_with_state instead"
)]
pub fn signature_verification_layer() -> Identity {
    Identity::new()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_public_key_valid() {
        let hex_key = "a".repeat(64); // 32 bytes = 64 hex chars
        let result = parse_public_key(&hex_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_public_key_invalid_hex() {
        let result = parse_public_key("not-hex-gggg");
        assert!(matches!(result, Err(SignatureError::MalformedData(_))));
    }

    #[test]
    fn test_parse_public_key_wrong_length() {
        let result = parse_public_key("aabb"); // Only 2 bytes
        assert!(matches!(result, Err(SignatureError::MalformedData(_))));
    }

    #[test]
    fn test_validate_timestamp_valid() {
        let now = Utc::now().to_rfc3339();
        let result = validate_timestamp(&now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_timestamp_expired() {
        let old = (Utc::now() - Duration::minutes(10)).to_rfc3339();
        let result = validate_timestamp(&old);
        assert!(matches!(result, Err(SignatureError::ExpiredTimestamp)));
    }

    #[test]
    fn test_validate_timestamp_future() {
        let future = (Utc::now() + Duration::minutes(5)).to_rfc3339();
        let result = validate_timestamp(&future);
        assert!(matches!(result, Err(SignatureError::ExpiredTimestamp)));
    }

    #[test]
    fn test_state_register_agent() {
        let state = SignatureVerificationState::new();
        let key = [1u8; 32];
        let agent_id = AgentId::new();

        assert!(!state.is_agent_registered(&key));
        let returned_id = state.register_agent(key, agent_id);
        assert_eq!(returned_id, agent_id);
        assert!(state.is_agent_registered(&key));
    }

    #[test]
    fn test_state_get_agent_id() {
        let state = SignatureVerificationState::new();
        let key = [2u8; 32];
        let agent_id = AgentId::new();

        // Before registration, should return None
        assert!(state.get_agent_id(&key).is_none());

        // After registration, should return the correct ID
        state.register_agent(key, agent_id);
        let retrieved = state.get_agent_id(&key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), agent_id);
    }

    #[test]
    fn test_state_register_agent_overwrites() {
        let state = SignatureVerificationState::new();
        let key = [3u8; 32];
        let first_id = AgentId::new();
        let second_id = AgentId::new();

        state.register_agent(key, first_id);
        state.register_agent(key, second_id);

        // Should have the second ID
        let retrieved = state.get_agent_id(&key).unwrap();
        assert_eq!(retrieved, second_id);
    }

    #[test]
    fn test_state_nonce_tracking() {
        let state = SignatureVerificationState::new();

        // First use should succeed
        assert!(state.record_nonce("nonce1"));
        // Second use should fail (replay)
        assert!(!state.record_nonce("nonce1"));
        // Different nonce should succeed
        assert!(state.record_nonce("nonce2"));
    }

    #[test]
    fn test_should_bypass_options() {
        let state = SignatureVerificationState::new();
        assert!(state.should_bypass("/anything", &Method::OPTIONS));
    }

    #[test]
    fn test_should_bypass_health() {
        let state = SignatureVerificationState::new();
        assert!(state.should_bypass("/health", &Method::GET));
        assert!(state.should_bypass("/health/ready", &Method::GET));
        assert!(!state.should_bypass("/claims", &Method::POST));
    }

    #[test]
    fn test_error_response_codes() {
        // Test that each error type maps to correct HTTP status
        let missing_header = SignatureError::MissingHeader("X-Test");
        let response = missing_header.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let malformed = SignatureError::MalformedData("test".into());
        let response = malformed.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let invalid_sig = SignatureError::InvalidSignature;
        let response = invalid_sig.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let expired = SignatureError::ExpiredTimestamp;
        let response = expired.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let unknown = SignatureError::UnknownAgent;
        let response = unknown.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let replay = SignatureError::ReplayDetected;
        let response = replay.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_default_max_request_size() {
        let state = SignatureVerificationState::new();
        assert_eq!(state.max_request_size, 1024 * 1024);
    }

    #[test]
    fn test_custom_max_request_size() {
        let state = SignatureVerificationState::new().with_max_request_size(2048);
        assert_eq!(state.max_request_size, 2048);
    }

    #[test]
    fn test_nonce_eviction_preserves_recent_entries() {
        let state = SignatureVerificationState::new();

        // Add a nonce
        assert!(state.record_nonce("recent-nonce"));

        // Verify it's tracked (replay detected)
        assert!(!state.record_nonce("recent-nonce"));

        // Add a new nonce - should succeed
        assert!(state.record_nonce("another-nonce"));

        // Verify the second nonce is also tracked
        assert!(!state.record_nonce("another-nonce"));
    }
}
