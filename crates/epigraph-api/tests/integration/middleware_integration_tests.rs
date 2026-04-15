//! Middleware Route Integration Tests
//!
//! # Purpose
//!
//! Validates that the signature verification middleware is correctly applied
//! to protected routes while allowing public routes to bypass authentication.
//!
//! # Security Invariants Tested
//!
//! 1. **Write Protection**: All mutating endpoints (POST /claims, POST /agents,
//!    POST /api/v1/submit/packet) require valid Ed25519 signatures
//! 2. **Read Access**: Read-only endpoints (GET /claims/:id, GET /health)
//!    bypass signature verification for public accessibility
//! 3. **Signature Integrity**: Tampering with body, method, or path invalidates
//!    the signature
//! 4. **Replay Prevention**: Same signature+timestamp cannot be used twice
//! 5. **Agent Verification**: Only registered agents can submit claims
//! 6. **Context Injection**: Verified agent ID is available to handlers
//!
//! # Test Categories
//!
//! - Protected Route Tests (tests 1-6): Verify middleware enforcement
//! - Public Route Tests (tests 7-8): Verify middleware bypass
//! - Context Injection Tests (test 9): Verify agent extraction
//! - Security Tests (tests 10-14): Verify attack prevention

use axum::{
    body::Body,
    extract::{Extension, Path, State},
    http::{header, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use epigraph_core::domain::ids::AgentId;
use epigraph_crypto::{AgentSigner, SignatureVerifier, SIGNATURE_SIZE};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tower::ServiceExt;
use uuid::Uuid;

// ============================================================================
// Constants
// ============================================================================

/// Header name for the Ed25519 signature (base64-encoded)
const SIGNATURE_HEADER: &str = "X-Signature";

/// Header name for the agent's public key (hex-encoded)
const PUBLIC_KEY_HEADER: &str = "X-Public-Key";

/// Header name for the request timestamp (ISO 8601)
const TIMESTAMP_HEADER: &str = "X-Timestamp";

/// Maximum age of a valid signature (5 minutes)
const MAX_SIGNATURE_AGE_SECONDS: i64 = 300;

/// Clock skew tolerance (30 seconds)
const CLOCK_SKEW_TOLERANCE_SECONDS: i64 = 30;

// ============================================================================
// Test Infrastructure: Types
// ============================================================================

/// Used nonces for replay attack prevention
type NonceStore = Arc<RwLock<std::collections::HashSet<String>>>;

/// Agent registry mapping public keys to agent IDs
type AgentRegistry = Arc<RwLock<HashMap<[u8; 32], AgentId>>>;

/// Errors that can occur during signature verification
#[derive(Debug, Clone)]
pub enum SignatureError {
    MissingHeader(&'static str),
    MalformedData(String),
    InvalidSignature,
    ExpiredTimestamp,
    UnknownAgent,
    ReplayDetected,
}

impl IntoResponse for SignatureError {
    fn into_response(self) -> Response {
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

/// Extracted agent identity after signature verification
#[derive(Clone, Debug)]
pub struct VerifiedAgent {
    pub agent_id: AgentId,
    pub public_key: [u8; 32],
}

/// Application state for signature verification middleware
#[derive(Clone)]
pub struct TestAppState {
    pub nonce_store: NonceStore,
    pub agent_registry: AgentRegistry,
    pub bypass_routes: Vec<String>,
}

impl TestAppState {
    pub fn new() -> Self {
        Self {
            nonce_store: Arc::new(RwLock::new(std::collections::HashSet::new())),
            agent_registry: Arc::new(RwLock::new(HashMap::new())),
            bypass_routes: vec![
                "/health".to_string(),
                "/claims/".to_string(), // GET /claims/:id bypasses
            ],
        }
    }

    /// Register an agent's public key and return their agent ID
    pub fn register_agent(&self, public_key: [u8; 32]) -> AgentId {
        let agent_id = AgentId::new();
        self.agent_registry
            .write()
            .unwrap()
            .insert(public_key, agent_id);
        agent_id
    }

    /// Look up agent by public key
    pub fn get_agent_by_public_key(&self, public_key: &[u8; 32]) -> Option<AgentId> {
        self.agent_registry.read().unwrap().get(public_key).cloned()
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
        // GET requests to /claims/:id bypass (read-only)
        if method == Method::GET && path.starts_with("/claims/") {
            return true;
        }
        // GET requests to /health bypass
        if method == Method::GET && path.starts_with("/health") {
            return true;
        }
        // All other routes require authentication
        false
    }
}

impl Default for TestAppState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Test Infrastructure: Helpers
// ============================================================================

/// The signed message format that gets hashed and signed
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

    if age < Duration::seconds(-CLOCK_SKEW_TOLERANCE_SECONDS) {
        return Err(SignatureError::ExpiredTimestamp);
    }

    if age > Duration::seconds(MAX_SIGNATURE_AGE_SECONDS) {
        return Err(SignatureError::ExpiredTimestamp);
    }

    Ok(())
}

// ============================================================================
// Test Infrastructure: Middleware Implementation
// ============================================================================

/// Signature verification middleware for integration testing
///
/// This middleware:
/// 1. Checks if route should bypass verification
/// 2. Extracts and validates signature headers
/// 3. Verifies timestamp freshness
/// 4. Looks up agent from database by public key
/// 5. Verifies Ed25519 signature
/// 6. Detects replay attacks
/// 7. Injects VerifiedAgent into request extensions
pub async fn require_signature_middleware(
    State(state): State<TestAppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, SignatureError> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Check if route should bypass verification
    if state.should_bypass(&path, &method) {
        return Ok(next.run(request).await);
    }

    // Extract headers
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

    // Look up agent from database by public key (authorization)
    let agent_id = state
        .get_agent_by_public_key(&public_key)
        .ok_or(SignatureError::UnknownAgent)?;

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

    // Verify signature
    let is_valid = SignatureVerifier::verify(&public_key, &message_bytes, &signature)
        .map_err(|_| SignatureError::InvalidSignature)?;

    if !is_valid {
        return Err(SignatureError::InvalidSignature);
    }

    // Create nonce from signature to prevent replay
    let nonce = format!("{}-{}", hex::encode(&signature[..16]), timestamp_header);
    if !state.record_nonce(&nonce) {
        return Err(SignatureError::ReplayDetected);
    }

    // Create verified agent extension with agent ID from database
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
// Test Infrastructure: Handlers
// ============================================================================

/// Protected handler that requires authentication
async fn protected_claims_handler(
    Extension(agent): Extension<VerifiedAgent>,
    Json(payload): Json<CreateClaimRequest>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "id": Uuid::new_v4(),
        "content": payload.content,
        "agent_id": agent.agent_id.to_string(),
        "public_key": hex::encode(agent.public_key),
        "created_at": Utc::now().to_rfc3339(),
    }))
}

/// Protected handler for agent creation
async fn protected_agents_handler(
    Extension(agent): Extension<VerifiedAgent>,
    Json(payload): Json<CreateAgentRequest>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "id": Uuid::new_v4(),
        "public_key": payload.public_key,
        "display_name": payload.display_name,
        "created_by_agent_id": agent.agent_id.to_string(),
    }))
}

/// Protected handler for packet submission
async fn protected_submit_packet_handler(
    Extension(agent): Extension<VerifiedAgent>,
    Json(payload): Json<SubmitPacketRequest>,
) -> impl IntoResponse {
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "claim_id": Uuid::new_v4(),
            "agent_id": agent.agent_id.to_string(),
            "content": payload.claim_content,
        })),
    )
}

/// Public handler for claim retrieval (no auth required)
async fn public_get_claim_handler(Path(id): Path<Uuid>) -> impl IntoResponse {
    Json(serde_json::json!({
        "id": id,
        "content": "Test claim content",
        "truth_value": 0.75,
    }))
}

/// Public health check handler (no auth required)
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "version": "1.0.0",
    }))
}

// ============================================================================
// Test Infrastructure: Request/Response Types
// ============================================================================

#[derive(Serialize, Deserialize, Debug)]
struct CreateClaimRequest {
    content: String,
    truth_value: Option<f64>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CreateAgentRequest {
    public_key: String,
    display_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SubmitPacketRequest {
    claim_content: String,
    evidence: Vec<String>,
}

// ============================================================================
// Test Infrastructure: Router Builder
// ============================================================================

/// Build test router with middleware applied correctly
///
/// Expected Pattern:
/// - POST /claims - requires signature
/// - POST /agents - requires signature
/// - POST /api/v1/submit/packet - requires signature
/// - GET /claims/:id - public read (no signature)
/// - GET /health - public (no signature)
fn build_protected_router(state: TestAppState) -> Router {
    Router::new()
        // Protected write endpoints
        .route("/claims", post(protected_claims_handler))
        .route("/agents", post(protected_agents_handler))
        .route(
            "/api/v1/submit/packet",
            post(protected_submit_packet_handler),
        )
        // Public read endpoints
        .route("/claims/:id", get(public_get_claim_handler))
        .route("/health", get(health_handler))
        // Apply middleware to all routes - it will bypass based on method/path
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_signature_middleware,
        ))
        .with_state(state)
}

/// Create a test signer and register it with the state
fn create_registered_signer(state: &TestAppState) -> (AgentSigner, AgentId) {
    let signer = AgentSigner::generate();
    let agent_id = state.register_agent(signer.public_key());
    (signer, agent_id)
}

/// Sign a request and return (signature_base64, public_key_hex, timestamp)
fn sign_request(
    signer: &AgentSigner,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: &str,
) -> (String, String, String) {
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

// ============================================================================
// Test 1: POST /claims requires valid signature header
// ============================================================================

/// Validates: POST /claims with valid signature is accepted
///
/// Security Invariant: Properly signed requests from registered agents
/// should be authenticated and allowed to submit claims.
#[tokio::test]
async fn test_post_claims_requires_valid_signature() {
    let state = TestAppState::new();
    let (signer, expected_agent_id) = create_registered_signer(&state);
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test claim content".to_string(),
        truth_value: Some(0.8),
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

    // Verify the agent_id was correctly extracted and injected
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let response_agent_id = json.get("agent_id").and_then(|a| a.as_str()).unwrap();
    assert_eq!(
        response_agent_id,
        expected_agent_id.to_string(),
        "Agent ID should match registered agent"
    );
}

// ============================================================================
// Test 2: POST /claims with missing signature returns 401
// ============================================================================

/// Validates: Requests without signature header are rejected
///
/// Security Invariant: Anonymous requests must not be able to submit claims.
#[tokio::test]
async fn test_post_claims_missing_signature_returns_401() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test claim".to_string(),
        truth_value: None,
    })
    .unwrap();

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
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let message = json.get("message").and_then(|m| m.as_str()).unwrap_or("");
    assert!(
        message.contains(SIGNATURE_HEADER),
        "Error should mention missing signature header, got: {}",
        message
    );
}

// ============================================================================
// Test 3: POST /claims with invalid signature returns 401
// ============================================================================

/// Validates: Requests with invalid signature are rejected
///
/// Security Invariant: Forged or corrupted signatures must be rejected.
#[tokio::test]
async fn test_post_claims_invalid_signature_returns_401() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test claim".to_string(),
        truth_value: None,
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();

    // Create a valid-looking but WRONG signature (64 bytes of zeros)
    let fake_signature = STANDARD.encode([0u8; 64]);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, &fake_signature)
        .header(PUBLIC_KEY_HEADER, hex::encode(signer.public_key()))
        .header(TIMESTAMP_HEADER, &timestamp)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Invalid signature should return 401"
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let error = json.get("error").and_then(|e| e.as_str()).unwrap_or("");
    assert!(
        error.contains("InvalidSignature"),
        "Error should indicate invalid signature, got: {}",
        error
    );
}

// ============================================================================
// Test 4: POST /claims with expired timestamp returns 401
// ============================================================================

/// Validates: Old timestamps are rejected to prevent replay attacks
///
/// Security Invariant: Signatures older than MAX_SIGNATURE_AGE_SECONDS
/// must be rejected to limit the window for replay attacks.
#[tokio::test]
async fn test_post_claims_expired_timestamp_returns_401() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test claim".to_string(),
        truth_value: None,
    })
    .unwrap();

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

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let error = json.get("error").and_then(|e| e.as_str()).unwrap_or("");
    assert!(
        error.contains("ExpiredTimestamp"),
        "Error should indicate expired timestamp, got: {}",
        error
    );
}

// ============================================================================
// Test 5: POST /agents requires valid signature
// ============================================================================

/// Validates: POST /agents endpoint requires valid signature
///
/// Security Invariant: Agent registration is a privileged operation
/// that requires authentication.
#[tokio::test]
async fn test_post_agents_requires_valid_signature() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);
    let router = build_protected_router(state);

    let new_agent_key = AgentSigner::generate();
    let body = serde_json::to_vec(&CreateAgentRequest {
        public_key: hex::encode(new_agent_key.public_key()),
        display_name: Some("New Agent".to_string()),
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();
    let (signature, public_key, ts) = sign_request(&signer, "POST", "/agents", &body, &timestamp);

    let request =
        create_signed_request(Method::POST, "/agents", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Valid signature should allow agent creation"
    );
}

/// Validates: POST /agents without signature is rejected
#[tokio::test]
async fn test_post_agents_missing_signature_returns_401() {
    let state = TestAppState::new();
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateAgentRequest {
        public_key: hex::encode([0u8; 32]),
        display_name: None,
    })
    .unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/agents")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "POST /agents without signature should return 401"
    );
}

// ============================================================================
// Test 6: POST /api/v1/submit/packet requires valid signature
// ============================================================================

/// Validates: POST /api/v1/submit/packet requires valid signature
///
/// Security Invariant: Packet submission is a critical write operation
/// that must be authenticated.
#[tokio::test]
async fn test_post_submit_packet_requires_valid_signature() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&SubmitPacketRequest {
        claim_content: "Test epistemic claim".to_string(),
        evidence: vec!["Evidence 1".to_string()],
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();
    let (signature, public_key, ts) =
        sign_request(&signer, "POST", "/api/v1/submit/packet", &body, &timestamp);

    let request = create_signed_request(
        Method::POST,
        "/api/v1/submit/packet",
        body,
        &signature,
        &public_key,
        &ts,
    );

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "Valid signature should allow packet submission"
    );
}

/// Validates: POST /api/v1/submit/packet without signature is rejected
#[tokio::test]
async fn test_post_submit_packet_missing_signature_returns_401() {
    let state = TestAppState::new();
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&SubmitPacketRequest {
        claim_content: "Test claim".to_string(),
        evidence: vec![],
    })
    .unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "POST /api/v1/submit/packet without signature should return 401"
    );
}

// ============================================================================
// Test 7: GET /claims/:id does NOT require signature (read-only)
// ============================================================================

/// Validates: GET /claims/:id bypasses signature verification
///
/// Security Invariant: Read-only operations on public claims should be
/// accessible without authentication for transparency.
#[tokio::test]
async fn test_get_claim_does_not_require_signature() {
    let state = TestAppState::new();
    let router = build_protected_router(state);

    let claim_id = Uuid::new_v4();

    // Request without ANY authentication headers
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/claims/{}", claim_id))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /claims/:id should not require signature"
    );

    // Verify we got the claim data
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(json.get("id").is_some());
    assert!(json.get("content").is_some());
}

// ============================================================================
// Test 8: GET /health does NOT require signature
// ============================================================================

/// Validates: Health endpoint bypasses signature verification
///
/// Security Invariant: Monitoring and health check endpoints must be
/// accessible without authentication for operational visibility.
#[tokio::test]
async fn test_get_health_does_not_require_signature() {
    let state = TestAppState::new();
    let router = build_protected_router(state);

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
        "GET /health should not require signature"
    );

    // Verify health response
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json.get("status").and_then(|s| s.as_str()), Some("healthy"));
}

// ============================================================================
// Test 9: Verified agent_id is injected into handler context
// ============================================================================

/// Validates: Verified agent info is available to route handlers
///
/// Security Invariant: After verification, handlers must be able to
/// identify which agent made the request without re-verification.
#[tokio::test]
async fn test_verified_agent_id_is_injected_into_handler() {
    let state = TestAppState::new();
    let (signer, expected_agent_id) = create_registered_signer(&state);
    let expected_public_key = signer.public_key();
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test claim for agent verification".to_string(),
        truth_value: Some(0.9),
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();
    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Parse response to verify agent info was extracted
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Verify agent_id matches registered agent
    let response_agent_id = json.get("agent_id").and_then(|a| a.as_str()).unwrap();
    assert_eq!(
        response_agent_id,
        expected_agent_id.to_string(),
        "Injected agent_id should match registered agent"
    );

    // Verify public_key matches
    let response_pk = json.get("public_key").and_then(|p| p.as_str()).unwrap();
    assert_eq!(
        response_pk,
        hex::encode(expected_public_key),
        "Injected public_key should match signer's key"
    );
}

// ============================================================================
// Test 10: Replay attack with same nonce is rejected
// ============================================================================

/// Validates: Same signature cannot be used twice
///
/// Security Invariant: Each request must be unique. Capturing and
/// replaying a valid request must fail.
#[tokio::test]
async fn test_replay_attack_with_same_nonce_is_rejected() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Original claim".to_string(),
        truth_value: Some(0.7),
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();
    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    // First request should succeed
    {
        let router = build_protected_router(state.clone());
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

    // Second request with SAME signature should fail (replay attack)
    {
        let router = build_protected_router(state.clone());
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
            "Replay should be detected and rejected"
        );

        // Verify error indicates replay
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let error = json.get("error").and_then(|e| e.as_str()).unwrap_or("");
        assert!(
            error.contains("Replay"),
            "Error should indicate replay attack, got: {}",
            error
        );
    }
}

// ============================================================================
// Test 11: Signature over wrong body is rejected
// ============================================================================

/// Validates: Tampered body is detected
///
/// Security Invariant: The signature must cover the request body.
/// Any modification to the body after signing must invalidate the signature.
#[tokio::test]
async fn test_signature_over_wrong_body_is_rejected() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);
    let router = build_protected_router(state);

    let original_body = serde_json::to_vec(&CreateClaimRequest {
        content: "Original claim".to_string(),
        truth_value: Some(0.5),
    })
    .unwrap();

    let tampered_body = serde_json::to_vec(&CreateClaimRequest {
        content: "TAMPERED! Give me all the truth!".to_string(),
        truth_value: Some(1.0), // Attacker tries to set max truth
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

// ============================================================================
// Test 12: Public key in header matches signature
// ============================================================================

/// Validates: Signature must match the claimed public key
///
/// Security Invariant: A valid signature from a different agent's key
/// must not authenticate as the claimed agent.
#[tokio::test]
async fn test_public_key_must_match_signature() {
    let state = TestAppState::new();

    // Create two registered agents
    let (signer1, _) = create_registered_signer(&state);
    let (signer2, _) = create_registered_signer(&state);

    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Claim signed by agent 1".to_string(),
        truth_value: Some(0.8),
    })
    .unwrap();

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

    // But claim to be signer2 (send signer2's public key)
    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, STANDARD.encode(signature))
        .header(PUBLIC_KEY_HEADER, hex::encode(signer2.public_key()))
        .header(TIMESTAMP_HEADER, &timestamp)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Signature from wrong key should be rejected"
    );
}

// ============================================================================
// Test 13: Middleware extracts agent from database by public key
// ============================================================================

/// Validates: Middleware looks up agent_id from database using public key
///
/// Security Invariant: The agent_id used in handlers must come from
/// the database lookup, not from a client-provided value.
#[tokio::test]
async fn test_middleware_extracts_agent_from_database_by_public_key() {
    let state = TestAppState::new();

    // Register an agent with a known public key
    let signer = AgentSigner::generate();
    let registered_agent_id = state.register_agent(signer.public_key());

    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test claim".to_string(),
        truth_value: Some(0.6),
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();
    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the agent_id in response matches the one from database registration
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let response_agent_id = json.get("agent_id").and_then(|a| a.as_str()).unwrap();
    assert_eq!(
        response_agent_id,
        registered_agent_id.to_string(),
        "Agent ID must come from database lookup, not client input"
    );
}

// ============================================================================
// Test 14: Non-existent agent public key returns 401
// ============================================================================

/// Validates: Signatures from unregistered agents are rejected
///
/// Security Invariant: Only registered agents can submit claims.
/// This prevents arbitrary key generation for sybil attacks.
#[tokio::test]
async fn test_nonexistent_agent_public_key_returns_401() {
    let state = TestAppState::new();
    // Create signer but DO NOT register it
    let unregistered_signer = AgentSigner::generate();
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Claim from unregistered agent".to_string(),
        truth_value: Some(0.5),
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();
    let (signature, public_key, ts) =
        sign_request(&unregistered_signer, "POST", "/claims", &body, &timestamp);

    let request =
        create_signed_request(Method::POST, "/claims", body, &signature, &public_key, &ts);

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Unregistered agent should return 401"
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let error = json.get("error").and_then(|e| e.as_str()).unwrap_or("");
    assert!(
        error.contains("UnknownAgent"),
        "Error should indicate unknown agent, got: {}",
        error
    );
}

// ============================================================================
// Additional Tests: Edge Cases and Security Hardening
// ============================================================================

/// Validates: Future timestamps beyond tolerance are rejected
#[tokio::test]
async fn test_future_timestamp_beyond_tolerance_returns_401() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Future claim".to_string(),
        truth_value: None,
    })
    .unwrap();

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

/// Validates: Signature covers HTTP method
#[tokio::test]
async fn test_signature_covers_http_method() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);

    // Build a custom router that accepts both POST and PUT on same path
    let custom_router = Router::new()
        .route("/claims", post(protected_claims_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_signature_middleware,
        ))
        .with_state(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test claim".to_string(),
        truth_value: None,
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();

    // Sign for PUT method
    let (signature, public_key, ts) = sign_request(&signer, "PUT", "/claims", &body, &timestamp);

    // But send as POST
    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, &signature)
        .header(PUBLIC_KEY_HEADER, &public_key)
        .header(TIMESTAMP_HEADER, &ts)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = custom_router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Method mismatch should be rejected"
    );
}

/// Validates: Signature covers request path
#[tokio::test]
async fn test_signature_covers_request_path() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);

    // Build router with two protected endpoints
    let custom_router = Router::new()
        .route("/claims", post(protected_claims_handler))
        .route("/other", post(protected_claims_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_signature_middleware,
        ))
        .with_state(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test claim".to_string(),
        truth_value: None,
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();

    // Sign for /claims
    let (signature, public_key, ts) = sign_request(&signer, "POST", "/claims", &body, &timestamp);

    // But send to /other
    let request = create_signed_request(Method::POST, "/other", body, &signature, &public_key, &ts);

    let response = custom_router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Path mismatch should be rejected"
    );
}

/// Validates: Different timestamps allow same body to be submitted again
#[tokio::test]
async fn test_different_timestamps_create_unique_nonces() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Repeatable claim".to_string(),
        truth_value: Some(0.5),
    })
    .unwrap();

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
        let router = build_protected_router(state.clone());
        let request =
            create_signed_request(Method::POST, "/claims", body.clone(), &sig1, &pk1, &ts1);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "First request should succeed"
        );
    }

    {
        let router = build_protected_router(state.clone());
        let request =
            create_signed_request(Method::POST, "/claims", body.clone(), &sig2, &pk2, &ts2);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Second request with different timestamp should also succeed"
        );
    }
}

/// Validates: Malformed base64 signature returns 400 (bad request)
#[tokio::test]
async fn test_malformed_base64_signature_returns_400() {
    let state = TestAppState::new();
    let (signer, _) = create_registered_signer(&state);
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test".to_string(),
        truth_value: None,
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, "not-valid-base64!@#$")
        .header(PUBLIC_KEY_HEADER, hex::encode(signer.public_key()))
        .header(TIMESTAMP_HEADER, &timestamp)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Malformed base64 signature should return 400"
    );
}

/// Validates: Malformed hex public key returns 400
#[tokio::test]
async fn test_malformed_hex_public_key_returns_400() {
    let state = TestAppState::new();
    let router = build_protected_router(state);

    let body = serde_json::to_vec(&CreateClaimRequest {
        content: "Test".to_string(),
        truth_value: None,
    })
    .unwrap();

    let timestamp = Utc::now().to_rfc3339();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/claims")
        .header(SIGNATURE_HEADER, STANDARD.encode([0u8; 64]))
        .header(PUBLIC_KEY_HEADER, "not-valid-hex-gggg")
        .header(TIMESTAMP_HEADER, &timestamp)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Malformed hex public key should return 400"
    );
}

/// Validates: OPTIONS requests bypass signature check (CORS preflight)
#[tokio::test]
async fn test_options_request_bypasses_signature_check() {
    let state = TestAppState::new();

    // Custom handler for OPTIONS
    async fn options_handler() -> impl IntoResponse {
        StatusCode::NO_CONTENT
    }

    let router = Router::new()
        .route("/claims", post(protected_claims_handler))
        .route("/claims", axum::routing::options(options_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_signature_middleware,
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
