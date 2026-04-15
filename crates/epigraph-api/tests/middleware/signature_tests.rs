//! Comprehensive tests for Ed25519 Signature Verification Middleware
//!
//! # Security Invariants Validated
//!
//! 1. **Authentication**: Only agents with valid signatures can submit claims
//! 2. **Integrity**: Request body cannot be tampered with after signing
//! 3. **Freshness**: Timestamps prevent replay attacks within time window
//! 4. **Non-repudiation**: Signatures bind agents to their requests
//! 5. **Timing Safety**: Signature comparison uses constant-time operations
//!
//! # Test Categories
//!
//! - **Happy Path**: Valid signatures are accepted
//! - **Authentication Failures**: Missing/invalid signatures rejected (401)
//! - **Authorization Failures**: Unknown agents rejected (403)
//! - **Validation Failures**: Malformed data rejected (400)
//! - **Security**: Timing attacks and replay attacks prevented
//! - **Routing**: Certain routes bypass signature checks

use axum::{
    body::Body,
    extract::{Extension, State},
    http::{header, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use epigraph_core::domain::ids::AgentId;
use epigraph_crypto::{AgentSigner, SignatureVerifier, SIGNATURE_SIZE};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Instant,
};
use tower::ServiceExt;

// ============================================================================
// Test Infrastructure: Signature Middleware Implementation
// ============================================================================

/// Header name for the Ed25519 signature (base64-encoded)
const SIGNATURE_HEADER: &str = "X-Signature";

/// Header name for the agent's public key (hex-encoded)
const PUBLIC_KEY_HEADER: &str = "X-Public-Key";

/// Header name for the request timestamp (ISO 8601)
const TIMESTAMP_HEADER: &str = "X-Timestamp";

/// Maximum age of a valid signature (5 minutes)
const MAX_SIGNATURE_AGE_SECONDS: i64 = 300;

/// Used nonces for replay attack prevention
type NonceStore = Arc<RwLock<HashSet<String>>>;

/// Known agents: maps public key to agent ID for authorization and identity lookup
type AgentRegistry = Arc<RwLock<HashMap<[u8; 32], AgentId>>>;

/// Extracted agent identity after signature verification
#[derive(Clone, Debug)]
pub struct VerifiedAgent {
    pub agent_id: AgentId,
    pub public_key: [u8; 32],
}

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
            SignatureError::UnknownAgent => (StatusCode::FORBIDDEN, "Unknown agent".to_string()),
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

/// Application state for signature verification middleware
#[derive(Clone)]
pub struct SignatureVerificationState {
    /// Store of used nonces for replay prevention
    pub nonce_store: NonceStore,
    /// Registry of known agent public keys
    pub agent_registry: AgentRegistry,
    /// Routes that bypass signature verification
    pub bypass_routes: Vec<String>,
}

impl SignatureVerificationState {
    pub fn new() -> Self {
        Self {
            nonce_store: Arc::new(RwLock::new(HashSet::new())),
            agent_registry: Arc::new(RwLock::new(HashMap::new())),
            bypass_routes: vec!["/health".to_string()],
        }
    }

    /// Register an agent's public key with their agent ID
    pub fn register_agent(&self, public_key: [u8; 32], agent_id: AgentId) -> AgentId {
        self.agent_registry
            .write()
            .unwrap()
            .insert(public_key, agent_id);
        agent_id
    }

    /// Check if an agent is registered
    pub fn is_agent_registered(&self, public_key: &[u8; 32]) -> bool {
        self.agent_registry.read().unwrap().contains_key(public_key)
    }

    /// Look up an agent's ID by their public key
    pub fn get_agent_id(&self, public_key: &[u8; 32]) -> Option<AgentId> {
        self.agent_registry.read().unwrap().get(public_key).copied()
    }

    /// Record a nonce, returns false if already used (replay)
    pub fn record_nonce(&self, nonce: &str) -> bool {
        self.nonce_store.write().unwrap().insert(nonce.to_string())
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

    // Reject timestamps in the future (with 30s tolerance for clock skew)
    if age < Duration::seconds(-30) {
        return Err(SignatureError::ExpiredTimestamp);
    }

    // Reject timestamps older than MAX_SIGNATURE_AGE_SECONDS
    if age > Duration::seconds(MAX_SIGNATURE_AGE_SECONDS) {
        return Err(SignatureError::ExpiredTimestamp);
    }

    Ok(())
}

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
    let signature_header = request
        .headers()
        .get(SIGNATURE_HEADER)
        .ok_or(SignatureError::MissingHeader(SIGNATURE_HEADER))?
        .to_str()
        .map_err(|_| SignatureError::MalformedData("Invalid signature header encoding".into()))?
        .to_string();

    let public_key_header = request
        .headers()
        .get(PUBLIC_KEY_HEADER)
        .ok_or(SignatureError::MissingHeader(PUBLIC_KEY_HEADER))?
        .to_str()
        .map_err(|_| SignatureError::MalformedData("Invalid public key header encoding".into()))?
        .to_string();

    let timestamp_header = request
        .headers()
        .get(TIMESTAMP_HEADER)
        .ok_or(SignatureError::MissingHeader(TIMESTAMP_HEADER))?
        .to_str()
        .map_err(|_| SignatureError::MalformedData("Invalid timestamp header encoding".into()))?
        .to_string();

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
    let body_bytes = axum::body::to_bytes(body, 1024 * 1024)
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
    let agent_id = state.get_agent_id(&public_key).ok_or({
        // This should never happen if is_agent_registered passed
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
// Test Helpers
// ============================================================================

/// Create a test signer and register it with the state
fn create_registered_signer(state: &SignatureVerificationState) -> AgentSigner {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();
    state.register_agent(signer.public_key(), agent_id);
    signer
}

/// Sign a request and return (signature_base64, public_key_hex, timestamp)
fn sign_request(
    signer: &AgentSigner,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: &str,
) -> (String, String, String) {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let message = SignedMessage {
        method,
        path,
        body,
        timestamp,
    };

    let message_bytes = serde_json::to_vec(&message).unwrap();
    let signature = signer.sign(&message_bytes);

    (
        STANDARD.encode(signature),
        hex::encode(signer.public_key()),
        timestamp.to_string(),
    )
}

/// Create a signed request with all required headers
fn create_signed_request(
    method: Method,
    path: &str,
    body: Vec<u8>,
    signature: &str,
    public_key: &str,
    timestamp: &str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(SIGNATURE_HEADER, signature)
        .header(PUBLIC_KEY_HEADER, public_key)
        .header(TIMESTAMP_HEADER, timestamp)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Simple test handler that returns the verified agent info
async fn protected_handler(Extension(agent): Extension<VerifiedAgent>) -> impl IntoResponse {
    Json(serde_json::json!({
        "agent_id": agent.agent_id.to_string(),
        "public_key": hex::encode(agent.public_key),
    }))
}

/// Simple health check handler (should bypass auth)
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({"status": "healthy"}))
}

/// Test payload for claim submission
#[derive(Serialize, Deserialize, Debug)]
struct TestClaimPayload {
    content: String,
    truth_value: f64,
}

/// Build test router with signature middleware
fn build_test_router(state: SignatureVerificationState) -> Router {
    Router::new()
        .route("/claims", post(protected_handler))
        .route("/protected", get(protected_handler))
        .route("/health", get(health_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            signature_verification_middleware,
        ))
        .with_state(state)
}

// ============================================================================
// Test 1: Valid Signature Passes Middleware
// ============================================================================

/// Validates: Valid Ed25519 signatures are accepted
///
/// Security Invariant: Properly signed requests from registered agents
/// should be authenticated and allowed to proceed.
#[tokio::test]
async fn test_valid_signature_passes_middleware() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let body = serde_json::to_vec(&TestClaimPayload {
        content: "Test claim".to_string(),
        truth_value: 0.8,
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();
    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Valid signature should be accepted"
    );

    // Verify the agent was extracted
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("public_key").is_some());
}

// ============================================================================
// Test 2: Missing Signature Header Returns 401
// ============================================================================

/// Validates: Requests without signature header are rejected
///
/// Security Invariant: Anonymous requests must not be able to submit claims.
#[tokio::test]
async fn test_missing_signature_header_returns_401() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let body = b"test body".to_vec();
    let timestamp = Utc::now().to_rfc3339();

    // Create request WITHOUT signature header
    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(PUBLIC_KEY_HEADER, hex::encode(signer.public_key()))
        .header(TIMESTAMP_HEADER, &timestamp)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Missing signature should return 401"
    );

    // Verify error message mentions the missing header
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let message = json.get("message").and_then(|m| m.as_str()).unwrap_or("");
    assert!(
        message.contains(SIGNATURE_HEADER),
        "Error should mention missing header"
    );
}

/// Validates: Requests without public key header are rejected
#[tokio::test]
async fn test_missing_public_key_header_returns_401() {
    let state = SignatureVerificationState::new();
    let router = build_test_router(state);

    let timestamp = Utc::now().to_rfc3339();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, "fake_signature")
        .header(TIMESTAMP_HEADER, &timestamp)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Missing public key should return 401"
    );
}

/// Validates: Requests without timestamp header are rejected
#[tokio::test]
async fn test_missing_timestamp_header_returns_401() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, "fake_signature")
        .header(PUBLIC_KEY_HEADER, hex::encode(signer.public_key()))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Missing timestamp should return 401"
    );
}

// ============================================================================
// Test 3: Malformed Signature Returns 400
// ============================================================================

/// Validates: Malformed base64 signature is rejected with 400
///
/// Security Invariant: Invalid data formats should be rejected early
/// with clear error messages.
#[tokio::test]
async fn test_malformed_base64_signature_returns_400() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let timestamp = Utc::now().to_rfc3339();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, "not-valid-base64!@#$")
        .header(PUBLIC_KEY_HEADER, hex::encode(signer.public_key()))
        .header(TIMESTAMP_HEADER, &timestamp)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Malformed signature should return 400"
    );
}

/// Validates: Signature with wrong length is rejected
#[tokio::test]
async fn test_wrong_length_signature_returns_400() {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let timestamp = Utc::now().to_rfc3339();

    // Create a signature that's too short (32 bytes instead of 64)
    let short_sig = STANDARD.encode([0u8; 32]);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, &short_sig)
        .header(PUBLIC_KEY_HEADER, hex::encode(signer.public_key()))
        .header(TIMESTAMP_HEADER, &timestamp)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Wrong length signature should return 400"
    );
}

/// Validates: Malformed hex public key is rejected
#[tokio::test]
async fn test_malformed_public_key_returns_400() {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let state = SignatureVerificationState::new();
    let router = build_test_router(state);

    let timestamp = Utc::now().to_rfc3339();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, STANDARD.encode([0u8; 64]))
        .header(PUBLIC_KEY_HEADER, "not-valid-hex-gggg")
        .header(TIMESTAMP_HEADER, &timestamp)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Malformed public key should return 400"
    );
}

/// Validates: Wrong length public key is rejected
#[tokio::test]
async fn test_wrong_length_public_key_returns_400() {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let state = SignatureVerificationState::new();
    let router = build_test_router(state);

    let timestamp = Utc::now().to_rfc3339();

    // 16 bytes instead of 32
    let short_key = hex::encode([0u8; 16]);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, STANDARD.encode([0u8; 64]))
        .header(PUBLIC_KEY_HEADER, &short_key)
        .header(TIMESTAMP_HEADER, &timestamp)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Wrong length public key should return 400"
    );
}

/// Validates: Malformed timestamp is rejected
#[tokio::test]
async fn test_malformed_timestamp_returns_400() {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, STANDARD.encode([0u8; 64]))
        .header(PUBLIC_KEY_HEADER, hex::encode(signer.public_key()))
        .header(TIMESTAMP_HEADER, "not-a-valid-timestamp")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Malformed timestamp should return 400"
    );
}

// ============================================================================
// Test 4: Expired Timestamp Returns 401
// ============================================================================

/// Validates: Old timestamps are rejected to prevent replay attacks
///
/// Security Invariant: Signatures older than MAX_SIGNATURE_AGE_SECONDS
/// must be rejected to limit the window for replay attacks.
#[tokio::test]
async fn test_expired_timestamp_returns_401() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let body = b"test".to_vec();

    // Create a timestamp 10 minutes in the past (beyond 5 minute limit)
    let old_timestamp = (Utc::now() - Duration::minutes(10)).to_rfc3339();

    let (signature, public_key, ts) =
        sign_request(&signer, "POST", "/claims", &body, &old_timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Expired timestamp should return 401"
    );
}

/// Validates: Future timestamps are rejected
///
/// Security Invariant: Timestamps too far in the future indicate
/// either clock skew manipulation or pre-computed attack signatures.
#[tokio::test]
async fn test_future_timestamp_returns_401() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let body = b"test".to_vec();

    // Create a timestamp 5 minutes in the future (beyond 30s tolerance)
    let future_timestamp = (Utc::now() + Duration::minutes(5)).to_rfc3339();

    let (signature, public_key, ts) =
        sign_request(&signer, "POST", "/claims", &body, &future_timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Future timestamp should return 401"
    );
}

/// Validates: Timestamps within acceptable window are accepted
#[tokio::test]
async fn test_recent_timestamp_is_accepted() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let body = b"test".to_vec();

    // Create a timestamp 1 minute in the past (within 5 minute limit)
    let recent_timestamp = (Utc::now() - Duration::minutes(1)).to_rfc3339();

    let (signature, public_key, ts) =
        sign_request(&signer, "POST", "/claims", &body, &recent_timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Recent timestamp should be accepted"
    );
}

// ============================================================================
// Test 5: Unknown Agent Returns 403
// ============================================================================

/// Validates: Signatures from unregistered agents are rejected
///
/// Security Invariant: Only registered agents can submit claims.
/// This prevents arbitrary key generation for sybil attacks.
#[tokio::test]
async fn test_unknown_agent_returns_403() {
    let state = SignatureVerificationState::new();
    // Create signer but DO NOT register it
    let unregistered_signer = AgentSigner::generate();
    let router = build_test_router(state);

    let body = b"test".to_vec();
    let timestamp = Utc::now().to_rfc3339();

    let (signature, public_key, ts) =
        sign_request(&unregistered_signer, "POST", "/claims", &body, &timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Unknown agent should return 403"
    );
}

// ============================================================================
// Test 6: Replay Attack Prevention
// ============================================================================

/// Validates: Same signature cannot be used twice
///
/// Security Invariant: Each request must be unique. Capturing and
/// replaying a valid request must fail.
#[tokio::test]
async fn test_replay_attack_prevention() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);

    let body = b"test claim".to_vec();
    let timestamp = Utc::now().to_rfc3339();

    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    // First request should succeed
    {
        let router = build_test_router(state.clone());
        let request = create_signed_request(
            Method::POST,
            "/claims",
            body.clone(),
            &signature,
            &public_key,
            &ts,
        );

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "First request should succeed"
        );
    }

    // Second request with same signature should fail
    {
        let router = build_test_router(state.clone());
        let request = create_signed_request(
            Method::POST,
            "/claims",
            body.clone(),
            &signature,
            &public_key,
            &ts,
        );

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Replay should be detected"
        );

        // Verify error indicates replay
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let error = json.get("error").and_then(|e| e.as_str()).unwrap_or("");
        assert!(
            error.contains("Replay"),
            "Error should indicate replay attack"
        );
    }
}

/// Validates: Different timestamps create different signatures (can't replay)
#[tokio::test]
async fn test_different_timestamps_create_different_nonces() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);

    let body = b"test claim".to_vec();

    // First request
    let timestamp1 = Utc::now().to_rfc3339();
    let (sig1, pk1, ts1) = sign_request(&signer, "POST", "/claims", &body, &timestamp1);

    // Brief delay to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Second request with different timestamp
    let timestamp2 = Utc::now().to_rfc3339();
    let (sig2, pk2, ts2) = sign_request(&signer, "POST", "/claims", &body, &timestamp2);

    // Both should succeed (different timestamps = different nonces)
    {
        let router = build_test_router(state.clone());
        let request =
            create_signed_request(Method::POST, "/claims", body.clone(), &sig1, &pk1, &ts1);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    {
        let router = build_test_router(state.clone());
        let request =
            create_signed_request(Method::POST, "/claims", body.clone(), &sig2, &pk2, &ts2);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

// ============================================================================
// Test 7: Signature Covers Correct Request Body
// ============================================================================

/// Validates: Tampered body is detected
///
/// Security Invariant: The signature must cover the request body.
/// Any modification to the body after signing must invalidate the signature.
#[tokio::test]
async fn test_tampered_body_is_rejected() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    let original_body = serde_json::to_vec(&TestClaimPayload {
        content: "Original claim".to_string(),
        truth_value: 0.5,
    })
    .unwrap();

    let tampered_body = serde_json::to_vec(&TestClaimPayload {
        content: "Tampered claim!".to_string(),
        truth_value: 1.0, // Attacker tries to set max truth
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();

    // Sign with original body
    let (signature, public_key, ts) =
        sign_request(&signer, "POST", "/claims", &original_body, &timestamp);

    // But send tampered body
    let request = create_signed_request(
        Method::POST,
        "/claims",
        tampered_body,
        &signature,
        &public_key,
        &ts,
    );

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Tampered body should be rejected"
    );
}

/// Validates: Signature covers HTTP method
#[tokio::test]
async fn test_signature_covers_http_method() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);

    // Build router with both POST and GET on same path for testing
    let router = Router::new()
        .route("/protected", post(protected_handler))
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            signature_verification_middleware,
        ))
        .with_state(state.clone());

    let body = b"".to_vec();
    let timestamp = Utc::now().to_rfc3339();

    // Sign for POST
    let (signature, public_key, ts) =
        sign_request(&signer, "POST", "/protected", &body, &timestamp);

    // But send as GET
    let request = Request::builder()
        .method(Method::GET)
        .uri("/protected")
        .header(SIGNATURE_HEADER, &signature)
        .header(PUBLIC_KEY_HEADER, &public_key)
        .header(TIMESTAMP_HEADER, &ts)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Method mismatch should be rejected"
    );
}

/// Validates: Signature covers request path
#[tokio::test]
async fn test_signature_covers_request_path() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);

    let router = Router::new()
        .route("/claims", post(protected_handler))
        .route("/other", post(protected_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            signature_verification_middleware,
        ))
        .with_state(state.clone());

    let body = b"test".to_vec();
    let timestamp = Utc::now().to_rfc3339();

    // Sign for /claims
    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    // But send to /other
    let request = create_signed_request(Method::POST, "/other", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Path mismatch should be rejected"
    );
}

// ============================================================================
// Test 8: Constant-Time Comparison Security
// ============================================================================

/// Validates: Signature verification uses constant-time comparison
///
/// Security Invariant: Timing attacks must not be possible.
/// The verification time should not correlate with how many bytes match.
///
/// Note: This is a statistical test that may have some variance.
/// We verify that the underlying SignatureVerifier uses constant-time ops.
#[tokio::test]
async fn test_constant_time_comparison_is_used() {
    // This test verifies that SignatureVerifier::constant_time_eq is used
    // by checking that comparison times are similar regardless of match position

    let a = [1u8; 64];
    let mut b_early_diff = [1u8; 64];
    let mut b_late_diff = [1u8; 64];

    b_early_diff[0] = 0xFF; // Differs in first byte
    b_late_diff[63] = 0xFF; // Differs in last byte

    // Time many iterations to reduce variance
    const ITERATIONS: u32 = 10_000;

    let start_early = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = SignatureVerifier::constant_time_eq(&a, &b_early_diff);
    }
    let early_time = start_early.elapsed();

    let start_late = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = SignatureVerifier::constant_time_eq(&a, &b_late_diff);
    }
    let late_time = start_late.elapsed();

    // The times should be very similar (within 50% of each other)
    // Non-constant-time comparison would be much faster for early differences
    let ratio = early_time.as_nanos() as f64 / late_time.as_nanos() as f64;

    assert!(
        ratio > 0.5 && ratio < 2.0,
        "Constant-time comparison expected, got timing ratio: {ratio}"
    );
}

/// Validates: Direct test of constant_time_eq function correctness
#[tokio::test]
async fn test_constant_time_eq_correctness() {
    // Equal arrays
    assert!(SignatureVerifier::constant_time_eq(
        &[1u8, 2, 3],
        &[1u8, 2, 3]
    ));

    // Different arrays
    assert!(!SignatureVerifier::constant_time_eq(
        &[1u8, 2, 3],
        &[1u8, 2, 4]
    ));

    // Different lengths
    assert!(!SignatureVerifier::constant_time_eq(
        &[1u8, 2, 3],
        &[1u8, 2]
    ));

    // Empty arrays
    assert!(SignatureVerifier::constant_time_eq(&[], &[]));
}

// ============================================================================
// Test 9: Middleware Extracts Agent ID for Downstream Handlers
// ============================================================================

/// Validates: Verified agent info is available to route handlers
///
/// Security Invariant: After verification, handlers must be able to
/// identify which agent made the request without re-verification.
#[tokio::test]
async fn test_middleware_extracts_agent_id() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let expected_public_key = signer.public_key();

    let router = build_test_router(state);

    let body = b"test".to_vec();
    let timestamp = Utc::now().to_rfc3339();

    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Parse response to verify agent info was extracted
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let response_pk = json.get("public_key").and_then(|p| p.as_str()).unwrap();
    assert_eq!(
        response_pk,
        hex::encode(expected_public_key),
        "Public key should be extracted correctly"
    );

    // Verify agent_id was created
    assert!(json.get("agent_id").is_some());
}

/// Validates: Handler without Extension fails gracefully when middleware bypassed
#[tokio::test]
async fn test_handler_without_agent_extension_on_protected_route() {
    // This test verifies that if someone accidentally misconfigures routing
    // and a protected handler is reached without verification, it fails safely

    // Create a router WITHOUT the middleware
    let router = Router::new().route("/claims", post(protected_handler));

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    // Should fail because Extension<VerifiedAgent> is missing
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Missing extension should cause 500, not silent pass"
    );
}

// ============================================================================
// Test 10: OPTIONS/Health Routes Bypass Signature Check
// ============================================================================

/// Validates: Health endpoint bypasses signature verification
///
/// Security Invariant: Monitoring and health check endpoints must be
/// accessible without authentication for operational visibility.
#[tokio::test]
async fn test_health_route_bypasses_signature_check() {
    let state = SignatureVerificationState::new();
    let router = build_test_router(state);

    // Request without ANY authentication headers
    let request = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Health endpoint should bypass auth"
    );

    // Verify response content
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.get("status").and_then(|s| s.as_str()), Some("healthy"));
}

/// Validates: OPTIONS requests bypass signature verification (CORS preflight)
///
/// Security Invariant: CORS preflight requests must not require authentication
/// as browsers send them automatically without credentials.
#[tokio::test]
async fn test_options_method_bypasses_signature_check() {
    let state = SignatureVerificationState::new();

    // Custom handler that returns 200 for OPTIONS
    async fn options_handler() -> impl IntoResponse {
        StatusCode::NO_CONTENT
    }

    let router = Router::new()
        .route("/claims", post(protected_handler))
        // Add explicit OPTIONS handler
        .route("/claims", axum::routing::options(options_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            signature_verification_middleware,
        ))
        .with_state(state);

    // OPTIONS request without authentication
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/claims")
        .header("Origin", "http://example.com")
        .header("Access-Control-Request-Method", "POST")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert!(
        response.status().is_success(),
        "OPTIONS should bypass auth, got status: {}",
        response.status()
    );
}

/// Validates: Multiple bypass routes can be configured
#[tokio::test]
async fn test_multiple_bypass_routes() {
    let mut state = SignatureVerificationState::new();
    state.bypass_routes.push("/metrics".to_string());
    state.bypass_routes.push("/readiness".to_string());

    async fn metrics_handler() -> impl IntoResponse {
        "metrics data"
    }

    let router = Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/readiness", get(health_handler))
        .route("/claims", post(protected_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            signature_verification_middleware,
        ))
        .with_state(state);

    // All bypass routes should work without auth
    for path in &["/health", "/metrics", "/readiness"] {
        let request = Request::builder()
            .method(Method::GET)
            .uri(*path)
            .body(Body::empty())
            .unwrap();

        let response = router.clone().oneshot(request).await.unwrap();
        assert!(
            response.status().is_success(),
            "{} should bypass auth",
            path
        );
    }
}

// ============================================================================
// Additional Security Tests
// ============================================================================

/// Validates: Wrong key signature is rejected
///
/// Security Invariant: A valid signature from a different agent's key
/// must not authenticate as the claimed agent.
#[tokio::test]
async fn test_wrong_agent_key_rejected() {
    let state = SignatureVerificationState::new();

    let signer1 = create_registered_signer(&state);
    let signer2 = create_registered_signer(&state);

    let router = build_test_router(state);

    let body = b"test".to_vec();
    let timestamp = Utc::now().to_rfc3339();

    // Sign with signer1
    let message = SignedMessage {
        method: "POST",
        path: "/claims",
        body: &body,
        timestamp: &timestamp,
    };
    let message_bytes = serde_json::to_vec(&message).unwrap();
    let signature = signer1.sign(&message_bytes);

    use base64::{engine::general_purpose::STANDARD, Engine};

    // But claim to be signer2 (send signer2's public key)
    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, STANDARD.encode(signature))
        .header(PUBLIC_KEY_HEADER, hex::encode(signer2.public_key()))
        .header(TIMESTAMP_HEADER, &timestamp)
        .body(Body::from(body))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Wrong key should be rejected"
    );
}

/// Validates: Empty body requests work correctly
#[tokio::test]
async fn test_empty_body_request() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);

    let router = Router::new()
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            signature_verification_middleware,
        ))
        .with_state(state);

    let body = Vec::new();
    let timestamp = Utc::now().to_rfc3339();

    let (signature, public_key, ts) = sign_request(&signer, "GET", "/protected", &body, &timestamp);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/protected")
        .header(SIGNATURE_HEADER, &signature)
        .header(PUBLIC_KEY_HEADER, &public_key)
        .header(TIMESTAMP_HEADER, &ts)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Empty body should be handled correctly"
    );
}

/// Validates: Large body requests are handled
#[tokio::test]
async fn test_large_body_request() {
    let state = SignatureVerificationState::new();
    let signer = create_registered_signer(&state);
    let router = build_test_router(state);

    // Create a 100KB body
    let large_content = "x".repeat(100_000);
    let body = serde_json::to_vec(&TestClaimPayload {
        content: large_content,
        truth_value: 0.5,
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();

    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Large body should be handled correctly"
    );
}

// ============================================================================
// Integration with epigraph-crypto verification
// ============================================================================

/// Validates: SignatureVerifier from epigraph-crypto correctly verifies
#[tokio::test]
async fn test_epigraph_crypto_integration() {
    let signer = AgentSigner::generate();
    let public_key = signer.public_key();

    let message = b"Test message for signing";
    let signature = signer.sign(message);

    // Verify using SignatureVerifier
    let is_valid = SignatureVerifier::verify(&public_key, message, &signature).unwrap();
    assert!(is_valid, "Valid signature should verify");

    // Tampered message should fail
    let tampered = b"Tampered message";
    let is_valid = SignatureVerifier::verify(&public_key, tampered, &signature).unwrap();
    assert!(!is_valid, "Tampered message should fail verification");
}

/// Validates: Canonical serialization works correctly with middleware
#[tokio::test]
async fn test_canonical_serialization_in_signing() {
    let signer = AgentSigner::generate();

    // Sign a JSON object using canonical serialization
    let payload = serde_json::json!({
        "z_field": 1,
        "a_field": 2,
        "m_field": 3,
    });

    let signature = signer.sign_canonical(&payload).unwrap();

    // Verify with reordered keys (should work due to canonicalization)
    let reordered = serde_json::json!({
        "a_field": 2,
        "m_field": 3,
        "z_field": 1,
    });

    let is_valid =
        SignatureVerifier::verify_canonical(&signer.public_key(), &reordered, &signature).unwrap();

    assert!(
        is_valid,
        "Canonical serialization should handle key reordering"
    );
}

// ============================================================================
// Test: Agent ID is correctly extracted from registration
// ============================================================================

/// Validates: The extracted agent ID matches the registered agent ID
///
/// Security Invariant: CRITICAL - The middleware must return the actual
/// registered agent ID, not a random UUID. Random UUIDs would allow
/// identity spoofing.
#[tokio::test]
async fn test_correct_agent_id_is_extracted() {
    let state = SignatureVerificationState::new();
    let signer = AgentSigner::generate();
    let expected_agent_id = AgentId::new();

    // Register the signer with a specific agent ID
    state.register_agent(signer.public_key(), expected_agent_id);

    // Custom handler that returns the actual agent_id from the extension
    async fn agent_id_handler(Extension(agent): Extension<VerifiedAgent>) -> impl IntoResponse {
        Json(serde_json::json!({
            "agent_id": agent.agent_id.to_string(),
        }))
    }

    let router = Router::new()
        .route("/claims", post(agent_id_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            signature_verification_middleware,
        ))
        .with_state(state);

    let body = b"test claim".to_vec();
    let timestamp = Utc::now().to_rfc3339();
    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Parse response and verify the agent ID matches
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let returned_agent_id = json.get("agent_id").and_then(|id| id.as_str()).unwrap();

    assert_eq!(
        returned_agent_id,
        expected_agent_id.to_string(),
        "The extracted agent ID must match the registered agent ID. \
         Random UUIDs would allow identity spoofing!"
    );
}
