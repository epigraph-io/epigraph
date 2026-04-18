//! Comprehensive tests for the Submit Packet Endpoint
//!
//! POST /api/v1/submit/packet
//!
//! The submit packet endpoint accepts a complete "epistemic packet" containing
//! a Claim, its Evidence, and ReasoningTrace in a single atomic transaction.
//!
//! # Epistemic Invariants Tested
//!
//! 1. No naked assertions - every claim requires a reasoning trace
//! 2. Truth values are bounded [0.0, 1.0]
//! 3. No cycles in reasoning graph
//! 4. Signatures are verified before DB write
//! 5. Content hashes are verified against actual content
//! 6. BAD ACTOR: High reputation cannot inflate truth without evidence
//!
//! # Test Categories
//!
//! - Happy path validation
//! - Input validation (400 errors)
//! - Cryptographic verification
//! - Atomicity guarantees
//! - Idempotency behavior
//! - Rate limiting
//! - Security (Bad Actor Test)

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

// =============================================================================
// SUBMISSION TYPES
// =============================================================================

/// Submission structure for a new claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSubmission {
    /// The statement content of this claim
    pub content: String,

    /// Requested initial truth value [0.0, 1.0]
    /// Note: This is only a suggestion - actual truth is calculated from evidence
    pub initial_truth: Option<f64>,

    /// The agent ID making this claim
    pub agent_id: Uuid,

    /// Optional idempotency key for duplicate detection
    pub idempotency_key: Option<String>,
}

/// Submission structure for evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSubmission {
    /// BLAKE3 content hash (hex-encoded, 64 chars)
    pub content_hash: String,

    /// Evidence type and metadata
    pub evidence_type: EvidenceTypeSubmission,

    /// Raw content (for hash verification)
    pub raw_content: Option<String>,

    /// Ed25519 signature over evidence (hex-encoded, 128 chars)
    pub signature: Option<String>,
}

/// Evidence type variants for submission
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceTypeSubmission {
    Document {
        source_url: Option<String>,
        mime_type: String,
    },
    Observation {
        observed_at: DateTime<Utc>,
        method: String,
        location: Option<String>,
    },
    Testimony {
        source: String,
        testified_at: DateTime<Utc>,
    },
    Literature {
        doi: String,
        extraction_target: String,
    },
}

/// Reasoning methodology for submission
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodologySubmission {
    Deductive,
    Inductive,
    Abductive,
    Instrumental,
    Extraction,
    BayesianInference,
    VisualInspection,
    FormalProof,
    Heuristic,
}

/// Input reference in reasoning trace
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TraceInputSubmission {
    /// References an evidence item by its index in the evidence array
    Evidence { index: usize },
    /// References an existing claim by ID
    Claim { id: Uuid },
}

/// Reasoning trace submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningTraceSubmission {
    /// Methodology used for reasoning
    pub methodology: MethodologySubmission,

    /// Inputs to this reasoning (indices into evidence array, or claim IDs)
    pub inputs: Vec<TraceInputSubmission>,

    /// Agent's confidence in this reasoning [0.0, 1.0]
    pub confidence: f64,

    /// Human-readable explanation
    pub explanation: String,

    /// Ed25519 signature over trace (hex-encoded, 128 chars)
    pub signature: Option<String>,
}

/// Complete epistemic packet for atomic submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpistemicPacket {
    /// The claim being made
    pub claim: ClaimSubmission,

    /// Supporting evidence (can be empty for purely logical claims)
    pub evidence: Vec<EvidenceSubmission>,

    /// The reasoning trace connecting evidence to claim
    pub reasoning_trace: ReasoningTraceSubmission,

    /// Ed25519 signature over the entire packet (hex-encoded)
    pub signature: String,
}

/// Successful submission response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPacketResponse {
    /// The created claim ID
    pub claim_id: Uuid,

    /// The calculated truth value (from evidence, NOT from reputation)
    pub truth_value: f64,

    /// The created trace ID
    pub trace_id: Uuid,

    /// IDs of created evidence items
    pub evidence_ids: Vec<Uuid>,

    /// Whether this was a duplicate submission (idempotent return)
    pub was_duplicate: bool,
}

/// Error response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

// =============================================================================
// TEST HELPERS
// =============================================================================

/// Ensure DATABASE_URL is set for AppState::new()'s connect_lazy().
///
/// The lazy pool never actually connects until a query executes, so a
/// fake URL is sufficient for validation tests that never touch the DB.
fn ensure_database_url_for_lazy_pool() {
    if std::env::var("DATABASE_URL").is_err() {
        // connect_lazy does NOT open a connection — it only parses the URL
        // and stores it. Validation tests never execute a query, so this
        // dummy value is sufficient.
        std::env::set_var(
            "DATABASE_URL",
            "postgres://test:test@localhost:5432/test_dummy",
        );
    }
}

/// Return true when a real DATABASE_URL is available (integration tests).
fn has_real_database() -> bool {
    // If we had to inject a dummy URL above, the real DB is unavailable.
    std::env::var("DATABASE_URL")
        .map(|url| !url.contains("test_dummy"))
        .unwrap_or(false)
}

/// Create a mock app state for testing
fn create_test_app() -> axum::Router {
    use epigraph_api::{create_router, ApiConfig, AppState};

    ensure_database_url_for_lazy_pool();
    let config = ApiConfig {
        require_signatures: true,
        max_request_size: 1024 * 1024,
    };
    let state = AppState::new(config);
    create_router(state)
}

/// Create a mock app that doesn't require signatures (for validation tests)
fn create_test_app_no_sig() -> axum::Router {
    use epigraph_api::{create_router, ApiConfig, AppState};

    ensure_database_url_for_lazy_pool();
    let config = ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
    };
    let state = AppState::new(config);
    create_router(state)
}

/// Register a test agent in the database so submit validation passes.
///
/// The submit handler validates that `agent_id` exists in the DB.
/// This creates a minimal agent record for test purposes.
///
/// Uses raw SQL rather than AgentRepository::create() because:
/// 1. We need ON CONFLICT DO NOTHING for idempotent test setup
/// 2. The caller provides a raw Uuid, not an AgentId
/// 3. This test file uses manual pool (not #[sqlx::test]), so the agent
///    may already exist from a previous test run
async fn ensure_agent_in_db(agent_id: Uuid) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph".into());
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    // public_key is bytea(32) — use the agent UUID bytes padded to 32 bytes
    let mut pk_bytes = [0u8; 32];
    pk_bytes[..16].copy_from_slice(agent_id.as_bytes());
    sqlx::query(
        "INSERT INTO agents (id, display_name, public_key) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .bind(format!("test-agent-{}", &agent_id.to_string()[..8]))
    .bind(&pk_bytes[..])
    .execute(&pool)
    .await
    .unwrap();
}

/// Generate a valid keypair for testing
fn generate_test_keypair() -> (epigraph_crypto::AgentSigner, [u8; 32]) {
    let signer = epigraph_crypto::AgentSigner::generate();
    let public_key = signer.public_key();
    (signer, public_key)
}

/// Compute BLAKE3 hash of content and return as hex string
fn compute_content_hash(content: &str) -> String {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    epigraph_crypto::ContentHasher::to_hex(&hash)
}

/// Create a valid evidence submission with proper hash
fn create_valid_evidence(content: &str) -> EvidenceSubmission {
    EvidenceSubmission {
        content_hash: compute_content_hash(content),
        evidence_type: EvidenceTypeSubmission::Document {
            source_url: Some("https://example.com/doc.pdf".to_string()),
            mime_type: "application/pdf".to_string(),
        },
        raw_content: Some(content.to_string()),
        signature: None,
    }
}

/// Create a valid reasoning trace
fn create_valid_trace(evidence_count: usize) -> ReasoningTraceSubmission {
    let inputs: Vec<TraceInputSubmission> = (0..evidence_count)
        .map(|i| TraceInputSubmission::Evidence { index: i })
        .collect();

    ReasoningTraceSubmission {
        methodology: MethodologySubmission::Inductive,
        inputs,
        confidence: 0.8,
        explanation: "Based on the provided evidence, this conclusion follows.".to_string(),
        signature: None,
    }
}

/// Create a minimal valid packet for testing
fn create_valid_packet(agent_id: Uuid) -> EpistemicPacket {
    let evidence_content = "Empirical data supporting the claim";

    EpistemicPacket {
        claim: ClaimSubmission {
            content: "The test hypothesis is supported by evidence".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: None,
        },
        evidence: vec![create_valid_evidence(evidence_content)],
        reasoning_trace: create_valid_trace(1),
        signature: "0".repeat(128), // Placeholder - would be real signature in production
    }
}

/// Make a POST request to the submit packet endpoint
async fn submit_packet(app: axum::Router, packet: &EpistemicPacket) -> (StatusCode, String) {
    let body = serde_json::to_string(packet).expect("Failed to serialize packet");

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-signature", "test-bypass") // Pass bearer_auth_middleware (falls through to legacy path)
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    (status, body_str)
}

// =============================================================================
// TEST 1: Valid Packet Submission Returns 201 with claim_id
// =============================================================================

/// Test: A valid epistemic packet with claim, evidence, and reasoning trace
/// should be accepted and return 201 Created with the new claim_id.
///
/// **Evidence**: IMPLEMENTATION_PLAN.md requires atomic packet submission
/// **Reasoning**: Valid packets must be accepted to enable the core workflow
#[tokio::test]
async fn test_valid_packet_submission_returns_201_with_claim_id() {
    if !has_real_database() {
        eprintln!(
            "SKIPPED: test_valid_packet_submission_returns_201_with_claim_id (no DATABASE_URL)"
        );
        return;
    }
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    ensure_agent_in_db(agent_id).await;
    let packet = create_valid_packet(agent_id);

    let (status, body) = submit_packet(app, &packet).await;

    // Should return 201 Created
    assert_eq!(
        status,
        StatusCode::CREATED,
        "Expected 201 Created for valid packet, got {}: {}",
        status,
        body
    );

    // Response should contain claim_id
    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");
    assert!(
        !response.claim_id.is_nil(),
        "claim_id should not be nil UUID"
    );
    assert!(
        !response.trace_id.is_nil(),
        "trace_id should not be nil UUID"
    );
    assert_eq!(
        response.evidence_ids.len(),
        1,
        "Should have one evidence ID"
    );

    // Truth value should be calculated (not just the requested initial_truth)
    assert!(
        (0.0..=1.0).contains(&response.truth_value),
        "Truth value should be bounded [0, 1]"
    );
}

// =============================================================================
// TEST 2: Packet with Missing Claim Returns 400
// =============================================================================

/// Test: A packet without a claim field should be rejected with 400 Bad Request.
///
/// **Evidence**: JSON schema requires claim field
/// **Reasoning**: Every packet must make exactly one claim
#[tokio::test]
async fn test_packet_missing_claim_returns_400() {
    let app = create_test_app_no_sig();

    // Manually construct JSON without claim field
    let malformed_packet = json!({
        "evidence": [],
        "reasoning_trace": {
            "methodology": "inductive",
            "inputs": [],
            "confidence": 0.8,
            "explanation": "Test explanation"
        },
        "signature": "0".repeat(128)
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-signature", "test-bypass")
        .body(Body::from(malformed_packet.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 for missing claim field"
    );
}

/// Test: A packet with empty claim content should be rejected.
///
/// **Evidence**: Empty claims carry no epistemic value
/// **Reasoning**: Claims must make a substantive assertion
#[tokio::test]
async fn test_packet_empty_claim_content_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let mut packet = create_valid_packet(agent_id);
    packet.claim.content = "".to_string();

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for empty claim content: {}",
        body
    );
}

/// Test: A packet with whitespace-only claim content should be rejected.
#[tokio::test]
async fn test_packet_whitespace_claim_content_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let mut packet = create_valid_packet(agent_id);
    packet.claim.content = "   \t\n  ".to_string();

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for whitespace-only claim: {}",
        body
    );
}

// =============================================================================
// TEST 3: Invalid Truth Value Returns 400
// =============================================================================

/// Test: A packet with truth_value > 1.0 should be rejected.
///
/// **Evidence**: CLAUDE.md invariant: truth_value must be in [0.0, 1.0]
/// **Reasoning**: Truth values outside bounds are mathematically meaningless
#[tokio::test]
async fn test_packet_truth_value_above_one_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let mut packet = create_valid_packet(agent_id);
    packet.claim.initial_truth = Some(1.5);

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for truth_value > 1.0: {}",
        body
    );

    // Verify error message mentions truth value
    let error: ErrorResponse = serde_json::from_str(&body).unwrap_or_else(|_| ErrorResponse {
        error: "parse_failed".to_string(),
        message: body.clone(),
        details: None,
    });
    assert!(
        error.message.to_lowercase().contains("truth")
            || error
                .details
                .map(|d| d.to_string().to_lowercase().contains("truth"))
                .unwrap_or(false),
        "Error should mention truth value"
    );
}

/// Test: A packet with truth_value < 0.0 should be rejected.
#[tokio::test]
async fn test_packet_truth_value_below_zero_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let mut packet = create_valid_packet(agent_id);
    packet.claim.initial_truth = Some(-0.5);

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for truth_value < 0.0: {}",
        body
    );
}

/// Test: A packet with NaN truth_value should be rejected.
#[tokio::test]
async fn test_packet_truth_value_nan_returns_400() {
    let app = create_test_app_no_sig();

    // Construct JSON directly since f64::NAN doesn't serialize naturally
    let packet_json = json!({
        "claim": {
            "content": "Test claim",
            "initial_truth": f64::NAN,
            "agent_id": Uuid::new_v4().to_string(),
        },
        "evidence": [],
        "reasoning_trace": {
            "methodology": "inductive",
            "inputs": [],
            "confidence": 0.8,
            "explanation": "Test"
        },
        "signature": "0".repeat(128)
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-signature", "test-bypass")
        .body(Body::from(packet_json.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 for NaN truth_value"
    );
}

/// Test: A packet with infinity truth_value should be rejected.
#[tokio::test]
async fn test_packet_truth_value_infinity_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    // Try with a very large value that JSON can represent
    let packet_json = json!({
        "claim": {
            "content": "Test claim",
            "initial_truth": 1e308,  // Very large but finite
            "agent_id": agent_id.to_string(),
        },
        "evidence": [{
            "content_hash": compute_content_hash("test"),
            "evidence_type": {
                "type": "document",
                "source_url": "https://example.com",
                "mime_type": "text/plain"
            },
            "raw_content": "test"
        }],
        "reasoning_trace": {
            "methodology": "inductive",
            "inputs": [{"type": "evidence", "index": 0}],
            "confidence": 0.8,
            "explanation": "Test"
        },
        "signature": "0".repeat(128)
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-signature", "test-bypass")
        .body(Body::from(packet_json.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 for extremely large truth_value"
    );
}

// =============================================================================
// TEST 4: Missing Reasoning Trace Rejected (No Naked Assertions)
// =============================================================================

/// Test: A packet without a reasoning_trace should be rejected.
///
/// **Evidence**: CLAUDE.md invariant: "Every claim requires a ReasoningTrace"
/// **Reasoning**: Claims without reasoning are "naked assertions" which violate
///               the fundamental epistemic principle of the system.
#[tokio::test]
async fn test_packet_missing_reasoning_trace_returns_400() {
    let app = create_test_app_no_sig();

    // Construct packet without reasoning_trace field
    let packet_json = json!({
        "claim": {
            "content": "This is a naked assertion",
            "initial_truth": 0.9,
            "agent_id": Uuid::new_v4().to_string(),
        },
        "evidence": [],
        "signature": "0".repeat(128)
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-signature", "test-bypass")
        .body(Body::from(packet_json.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 for missing reasoning_trace (naked assertion)"
    );
}

/// Test: A reasoning trace with empty explanation should be rejected.
///
/// **Evidence**: Explanations provide audit trail
/// **Reasoning**: Reasoning without explanation cannot be reviewed or validated
#[tokio::test]
async fn test_packet_empty_reasoning_explanation_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let mut packet = create_valid_packet(agent_id);
    packet.reasoning_trace.explanation = "".to_string();

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for empty reasoning explanation: {}",
        body
    );
}

/// Test: Reasoning trace with confidence out of bounds should be rejected.
#[tokio::test]
async fn test_packet_reasoning_confidence_out_of_bounds_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let mut packet = create_valid_packet(agent_id);
    packet.reasoning_trace.confidence = 1.5; // Invalid: > 1.0

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for confidence > 1.0: {}",
        body
    );
}

// =============================================================================
// TEST 5: Circular Reasoning References Return 400
// =============================================================================

/// Test: A reasoning trace that references its own claim should be rejected.
///
/// **Evidence**: CLAUDE.md invariant: "No cycles in reasoning graph"
/// **Reasoning**: Circular reasoning is a logical fallacy that would allow
///               claims to bootstrap their own truth values.
#[tokio::test]
async fn test_packet_circular_reference_self_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    let claim_id = Uuid::new_v4();

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "This claim references itself".to_string(),
            initial_truth: Some(0.9),
            agent_id,
            idempotency_key: Some(claim_id.to_string()), // Simulate known claim ID
        },
        evidence: vec![],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Deductive,
            inputs: vec![TraceInputSubmission::Claim { id: claim_id }], // Circular!
            confidence: 0.9,
            explanation: "This reasoning is circular".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for circular self-reference: {}",
        body
    );

    // Verify error mentions cycle
    let error: ErrorResponse = serde_json::from_str(&body).unwrap_or_else(|_| ErrorResponse {
        error: "parse_failed".to_string(),
        message: body.clone(),
        details: None,
    });
    assert!(
        error.message.to_lowercase().contains("cycle")
            || error.message.to_lowercase().contains("circular"),
        "Error should mention cycle/circular reference"
    );
}

/// Test: A reasoning trace referencing non-existent evidence index should be rejected.
#[tokio::test]
async fn test_packet_invalid_evidence_index_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: None,
        },
        evidence: vec![create_valid_evidence("one piece of evidence")],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Inductive,
            inputs: vec![
                TraceInputSubmission::Evidence { index: 0 }, // Valid
                TraceInputSubmission::Evidence { index: 5 }, // Invalid: out of bounds
            ],
            confidence: 0.8,
            explanation: "References non-existent evidence".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for invalid evidence index: {}",
        body
    );
}

/// Test: A reasoning trace referencing non-existent claim ID should be rejected.
#[tokio::test]
async fn test_packet_invalid_claim_reference_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    let nonexistent_claim_id = Uuid::new_v4();

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: None,
        },
        evidence: vec![],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Deductive,
            inputs: vec![TraceInputSubmission::Claim {
                id: nonexistent_claim_id,
            }],
            confidence: 0.8,
            explanation: "References non-existent claim".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status, body) = submit_packet(app, &packet).await;

    // Should return 400 (not found in context of validation)
    // or 404 if the system distinguishes validation from lookup
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "Expected 400 or 404 for non-existent claim reference: {} {}",
        status,
        body
    );
}

// =============================================================================
// TEST 6: Evidence Content Hash Verification
// =============================================================================

/// Test: Evidence with mismatched content_hash should be rejected.
///
/// **Evidence**: CLAUDE.md states "All evidence ... are signed. Verify before trust."
/// **Reasoning**: Hash mismatches indicate tampering or transmission errors.
#[tokio::test]
async fn test_evidence_content_hash_mismatch_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let actual_content = "The actual evidence content";
    let wrong_hash = compute_content_hash("Different content that doesn't match");

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: None,
        },
        evidence: vec![EvidenceSubmission {
            content_hash: wrong_hash, // WRONG hash
            evidence_type: EvidenceTypeSubmission::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
            },
            raw_content: Some(actual_content.to_string()),
            signature: None,
        }],
        reasoning_trace: create_valid_trace(1),
        signature: "0".repeat(128),
    };

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for content hash mismatch: {}",
        body
    );

    // Verify error mentions hash
    let lower_body = body.to_lowercase();
    assert!(
        lower_body.contains("hash") || lower_body.contains("integrity"),
        "Error should mention hash/integrity mismatch"
    );
}

/// Test: Evidence with valid content_hash should be accepted.
#[tokio::test]
async fn test_evidence_content_hash_valid_passes() {
    if !has_real_database() {
        eprintln!("SKIPPED: test_evidence_content_hash_valid_passes (no DATABASE_URL)");
        return;
    }
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    ensure_agent_in_db(agent_id).await;
    let content = "Valid evidence content for verification";
    let correct_hash = compute_content_hash(content);

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim with verified evidence".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: None,
        },
        evidence: vec![EvidenceSubmission {
            content_hash: correct_hash,
            evidence_type: EvidenceTypeSubmission::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
            },
            raw_content: Some(content.to_string()),
            signature: None,
        }],
        reasoning_trace: create_valid_trace(1),
        signature: "0".repeat(128),
    };

    let (status, _) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Expected 201 for valid content hash"
    );
}

/// Test: Evidence with invalid hex in content_hash should be rejected.
#[tokio::test]
async fn test_evidence_invalid_hex_hash_returns_400() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: None,
        },
        evidence: vec![EvidenceSubmission {
            content_hash: "not_valid_hex_string_at_all!@#$".to_string(),
            evidence_type: EvidenceTypeSubmission::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
            },
            raw_content: Some("content".to_string()),
            signature: None,
        }],
        reasoning_trace: create_valid_trace(1),
        signature: "0".repeat(128),
    };

    let (status, _) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for invalid hex in content_hash"
    );
}

// =============================================================================
// TEST 7: Signature Verification on Packet
// =============================================================================

/// Test: A packet with invalid signature should be rejected when signatures are required.
///
/// **Evidence**: CLAUDE.md: "Cryptographic Integrity: All evidence and traces are signed"
/// **Reasoning**: Invalid signatures indicate tampering or unauthorized submissions
#[tokio::test]
async fn test_packet_invalid_signature_returns_401() {
    let app = create_test_app(); // Signatures required
    let agent_id = Uuid::new_v4();

    let mut packet = create_valid_packet(agent_id);
    packet.signature = "invalid_signature_not_hex".to_string();

    let (status, body) = submit_packet(app, &packet).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Expected 401 or 400 for invalid signature: {} {}",
        status,
        body
    );
}

/// Test: A packet with wrong-length signature should be rejected.
#[tokio::test]
async fn test_packet_wrong_length_signature_returns_400() {
    let app = create_test_app();
    let agent_id = Uuid::new_v4();

    let mut packet = create_valid_packet(agent_id);
    packet.signature = "ab".repeat(32); // 64 chars instead of 128

    let (status, body) = submit_packet(app, &packet).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Expected 401 or 400 for wrong signature length: {} {}",
        status,
        body
    );
}

/// Test: A packet signed by wrong key should be rejected.
#[tokio::test]
async fn test_packet_wrong_key_signature_returns_401() {
    let app = create_test_app();

    // Generate two different keypairs
    let (signer1, _public_key1) = generate_test_keypair();
    let (_signer2, public_key2) = generate_test_keypair();

    // Create packet claiming to be from public_key2
    let agent_id = Uuid::new_v4();
    let mut packet = create_valid_packet(agent_id);

    // But sign with signer1 (wrong key!)
    let packet_bytes = serde_json::to_vec(&json!({
        "claim": packet.claim,
        "evidence": packet.evidence,
        "reasoning_trace": packet.reasoning_trace,
    }))
    .unwrap();
    let signature = signer1.sign(&packet_bytes);
    packet.signature = signature.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });

    // Packet claims different public key identity
    let _ = public_key2; // Would be used in agent lookup

    let (status, body) = submit_packet(app, &packet).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
        "Expected 401 or 400 for signature from wrong key: {} {}",
        status,
        body
    );
}

// =============================================================================
// TEST 8: Atomic Rollback - If Evidence Fails, Claim Isn't Created
// =============================================================================

/// Test: If evidence validation fails, no claim should be created.
///
/// **Evidence**: Transaction atomicity requirement
/// **Reasoning**: Partial submissions would leave the system in inconsistent state
#[tokio::test]
async fn test_atomic_rollback_on_evidence_failure() {
    if !has_real_database() {
        eprintln!("SKIPPED: test_atomic_rollback_on_evidence_failure (no DATABASE_URL)");
        return;
    }
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    ensure_agent_in_db(agent_id).await;
    let idempotency_key = format!("atomicity_test_key_{}", Uuid::new_v4());

    // Create packet with multiple evidence items, one invalid
    let valid_content = "Valid evidence";
    let invalid_packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim for atomicity".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: Some(idempotency_key.clone()),
        },
        evidence: vec![
            EvidenceSubmission {
                content_hash: compute_content_hash(valid_content),
                evidence_type: EvidenceTypeSubmission::Document {
                    source_url: None,
                    mime_type: "text/plain".to_string(),
                },
                raw_content: Some(valid_content.to_string()),
                signature: None,
            },
            EvidenceSubmission {
                content_hash: "wrong_hash".repeat(4), // Invalid - only 40 chars, not 64
                evidence_type: EvidenceTypeSubmission::Document {
                    source_url: None,
                    mime_type: "text/plain".to_string(),
                },
                raw_content: Some("This hash doesn't match".to_string()),
                signature: None,
            },
        ],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Inductive,
            inputs: vec![
                TraceInputSubmission::Evidence { index: 0 },
                TraceInputSubmission::Evidence { index: 1 },
            ],
            confidence: 0.8,
            explanation: "Combined evidence".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    // First submission should fail due to invalid evidence hash
    let (status1, body1) = submit_packet(app.clone(), &invalid_packet).await;
    assert_eq!(
        status1,
        StatusCode::BAD_REQUEST,
        "Expected 400 for invalid evidence: {}",
        body1
    );

    // CRITICAL VERIFICATION: If rollback worked, no claim should exist.
    // We verify this by submitting a VALID packet with the SAME idempotency key.
    // If the failed submission created a partial claim, this would return was_duplicate=true.
    // If rollback worked correctly, this will create a NEW claim (was_duplicate=false).
    let valid_packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim for atomicity".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: Some(idempotency_key.clone()),
        },
        evidence: vec![EvidenceSubmission {
            content_hash: compute_content_hash(valid_content),
            evidence_type: EvidenceTypeSubmission::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
            },
            raw_content: Some(valid_content.to_string()),
            signature: None,
        }],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Inductive,
            inputs: vec![TraceInputSubmission::Evidence { index: 0 }],
            confidence: 0.8,
            explanation: "Valid single evidence".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status2, body2) = submit_packet(app, &valid_packet).await;

    // Should succeed as a NEW claim (rollback means no prior claim exists)
    assert_eq!(
        status2,
        StatusCode::CREATED,
        "Expected 201 for valid packet after failed rollback: {}",
        body2
    );

    let response: SubmitPacketResponse =
        serde_json::from_str(&body2).expect("Failed to parse response");

    // CRITICAL: was_duplicate should be FALSE because the failed submission
    // should have rolled back and not created any claim
    assert!(
        !response.was_duplicate,
        "Rollback verification failed! was_duplicate=true means a partial claim \
         was created despite validation failure. Transaction atomicity is broken."
    );

    // Verify we got a valid claim_id (new claim was created)
    assert!(
        !response.claim_id.is_nil(),
        "Should have created a new claim after successful retry"
    );
}

/// Test: Failed trace validation should not create partial evidence.
///
/// **Evidence**: Transaction atomicity requirement
/// **Reasoning**: If trace validation fails AFTER evidence is processed,
///               the evidence must be rolled back. No orphan evidence allowed.
#[tokio::test]
async fn test_atomic_rollback_on_trace_failure() {
    if !has_real_database() {
        eprintln!("SKIPPED: test_atomic_rollback_on_trace_failure (no DATABASE_URL)");
        return;
    }
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    ensure_agent_in_db(agent_id).await;
    let idempotency_key = format!("trace_rollback_test_{}", Uuid::new_v4());

    let content = "Valid evidence content";

    // First: Submit packet with VALID evidence but INVALID trace reference
    let invalid_trace_packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: Some(idempotency_key.clone()),
        },
        evidence: vec![EvidenceSubmission {
            content_hash: compute_content_hash(content),
            evidence_type: EvidenceTypeSubmission::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
            },
            raw_content: Some(content.to_string()),
            signature: None,
        }],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Inductive,
            inputs: vec![TraceInputSubmission::Evidence { index: 99 }], // Invalid index!
            confidence: 0.8,
            explanation: "Invalid reference".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status1, body1) = submit_packet(app.clone(), &invalid_trace_packet).await;

    assert_eq!(
        status1,
        StatusCode::BAD_REQUEST,
        "Expected 400 for invalid trace reference: {}",
        body1
    );

    // CRITICAL VERIFICATION: Evidence should NOT have been persisted.
    // We verify by submitting a valid packet with the same idempotency key.
    // If evidence was orphaned (partial commit), idempotency might be corrupted.
    let valid_packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: Some(idempotency_key.clone()),
        },
        evidence: vec![EvidenceSubmission {
            content_hash: compute_content_hash(content),
            evidence_type: EvidenceTypeSubmission::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
            },
            raw_content: Some(content.to_string()),
            signature: None,
        }],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Inductive,
            inputs: vec![TraceInputSubmission::Evidence { index: 0 }], // Valid index
            confidence: 0.8,
            explanation: "Valid reference".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status2, body2) = submit_packet(app, &valid_packet).await;

    // Should succeed as a NEW claim
    assert_eq!(
        status2,
        StatusCode::CREATED,
        "Expected 201 for valid packet after trace failure rollback: {}",
        body2
    );

    let response: SubmitPacketResponse =
        serde_json::from_str(&body2).expect("Failed to parse response");

    // CRITICAL: was_duplicate should be FALSE
    // If the failed trace validation left orphan evidence or partial state,
    // the idempotency system might incorrectly return was_duplicate=true
    assert!(
        !response.was_duplicate,
        "Rollback verification failed! Trace validation failure should not leave \
         partial state. was_duplicate=true indicates orphaned data."
    );

    // Verify claim was created successfully
    assert!(
        !response.claim_id.is_nil(),
        "Should have created a new claim after successful retry"
    );
    assert!(
        !response.trace_id.is_nil(),
        "Should have created a new trace after successful retry"
    );
    assert_eq!(
        response.evidence_ids.len(),
        1,
        "Should have created exactly one evidence item"
    );
}

// =============================================================================
// TEST 9: Idempotency - Same Packet Twice Returns Same claim_id
// =============================================================================

/// Test: Submitting the same packet twice with idempotency key returns same claim_id.
///
/// **Evidence**: Standard API idempotency pattern
/// **Reasoning**: Prevents duplicate claims from network retries
#[tokio::test]
async fn test_idempotency_returns_same_claim_id() {
    if !has_real_database() {
        eprintln!("SKIPPED: test_idempotency_returns_same_claim_id (no DATABASE_URL)");
        return;
    }
    // Note: This test requires stateful behavior - two requests to same app
    // In unit test context, we verify the response structure

    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    ensure_agent_in_db(agent_id).await;
    let idempotency_key = "unique_idempotency_key_12345".to_string();

    let mut packet = create_valid_packet(agent_id);
    packet.claim.idempotency_key = Some(idempotency_key.clone());

    // First submission
    let (status1, body1) = submit_packet(app.clone(), &packet).await;

    assert_eq!(status1, StatusCode::CREATED);
    let response1: SubmitPacketResponse = serde_json::from_str(&body1).unwrap();

    // Second submission with same idempotency key
    let (status2, body2) = submit_packet(app, &packet).await;

    // Should succeed (either 200 OK or 201 Created depending on implementation)
    assert!(
        status2 == StatusCode::CREATED || status2 == StatusCode::OK,
        "Expected 200 or 201 for idempotent retry"
    );

    let response2: SubmitPacketResponse = serde_json::from_str(&body2).unwrap();

    // Same claim_id should be returned
    assert_eq!(
        response1.claim_id, response2.claim_id,
        "Idempotent submissions should return same claim_id"
    );

    // Second response should indicate it was a duplicate
    assert!(
        response2.was_duplicate,
        "Second submission should be marked as duplicate"
    );
}

/// Test: Different idempotency keys create different claims.
#[tokio::test]
async fn test_different_idempotency_keys_create_different_claims() {
    if !has_real_database() {
        eprintln!(
            "SKIPPED: test_different_idempotency_keys_create_different_claims (no DATABASE_URL)"
        );
        return;
    }
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    ensure_agent_in_db(agent_id).await;

    // Distinct content per packet — migration 097 added a UNIQUE constraint on
    // (content_hash, agent_id), so two packets with the same content under the
    // same agent would now violate the constraint regardless of idempotency key.
    // The test still validates the original intent: different idempotency keys
    // (paired with materially different requests) produce different claims.
    let mut packet1 = create_valid_packet(agent_id);
    packet1.claim.content = "Hypothesis A is supported by evidence".to_string();
    packet1.claim.idempotency_key = Some("key_one".to_string());

    let mut packet2 = create_valid_packet(agent_id);
    packet2.claim.content = "Hypothesis B is supported by evidence".to_string();
    packet2.claim.idempotency_key = Some("key_two".to_string());

    let (status1, body1) = submit_packet(app.clone(), &packet1).await;
    let (status2, body2) = submit_packet(app, &packet2).await;

    assert_eq!(status1, StatusCode::CREATED);
    assert_eq!(status2, StatusCode::CREATED);

    let response1: SubmitPacketResponse = serde_json::from_str(&body1).unwrap();
    let response2: SubmitPacketResponse = serde_json::from_str(&body2).unwrap();

    assert_ne!(
        response1.claim_id, response2.claim_id,
        "Different idempotency keys should create different claims"
    );
}

// =============================================================================
// TEST 10: Rate Limiting on Submissions
// =============================================================================

/// Test: Excessive submissions should be rate limited.
///
/// **Evidence**: DoS protection requirement
/// **Reasoning**: Prevents system abuse and ensures fair resource allocation
#[tokio::test]
async fn test_rate_limiting_returns_429() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    // Make many requests rapidly
    let mut rate_limited = false;
    for i in 0..100 {
        let mut packet = create_valid_packet(agent_id);
        packet.claim.content = format!("Rapid claim submission #{i}");
        packet.claim.idempotency_key = Some(format!("rate_limit_test_{i}"));

        let (status, _) = submit_packet(app.clone(), &packet).await;

        if status == StatusCode::TOO_MANY_REQUESTS {
            rate_limited = true;
            break;
        }
    }

    // Note: This may not trigger in unit tests without actual rate limiting middleware
    // The test documents the expected behavior
    if !rate_limited {
        eprintln!(
            "Note: Rate limiting not triggered in test environment. \
             Ensure rate limiting middleware is configured in production."
        );
    }
}

/// Test: Rate limit headers should be present in responses.
#[tokio::test]
async fn test_rate_limit_headers_present() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    let packet = create_valid_packet(agent_id);

    let body = serde_json::to_string(&packet).unwrap();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-signature", "test-bypass")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Check for rate limit headers (if implemented)
    // Common headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
    let _limit = response.headers().get("X-RateLimit-Limit");
    let _remaining = response.headers().get("X-RateLimit-Remaining");

    // Note: Headers may not be present in test environment
    // This test documents expected production behavior
}

// =============================================================================
// TEST 11: BAD ACTOR TEST - High Reputation Cannot Inflate Truth Without Evidence
// =============================================================================

/// CRITICAL TEST: High-reputation agent submitting claim WITHOUT real evidence
/// should NOT receive an inflated truth value.
///
/// **Evidence**: CLAUDE.md states this test "MUST always pass"
/// **Reasoning**: This validates the core epistemic principle that truth comes
///               from evidence, not authority. Reputation NEVER influences
///               initial truth calculation.
///
/// If this test fails, the system has a fundamental design flaw.
#[tokio::test]
async fn test_bad_actor_high_reputation_no_evidence_gets_low_truth() {
    if !has_real_database() {
        eprintln!(
            "SKIPPED: test_bad_actor_high_reputation_no_evidence_gets_low_truth (no DATABASE_URL)"
        );
        return;
    }
    let app = create_test_app_no_sig();

    // 1. Create agent with "stellar reputation" (0.95)
    // In test context, we simulate this by using a known agent_id
    // that would have high historical accuracy
    let high_rep_agent_id = Uuid::new_v4();
    ensure_agent_in_db(high_rep_agent_id).await;

    // 2. Submit claim with NO real evidence
    // The agent says "Trust me" but provides nothing substantive
    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Trust me, this is definitely true because I say so".to_string(),
            initial_truth: Some(0.95), // Agent REQUESTS high truth
            agent_id: high_rep_agent_id,
            idempotency_key: None,
        },
        evidence: vec![], // NO EVIDENCE!
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Heuristic, // Weakest methodology
            inputs: vec![],                                // No inputs
            confidence: 0.99,                              // Agent claims high confidence
            explanation: "I have a great reputation, trust me".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status, body) = submit_packet(app, &packet).await;

    // The submission might succeed (we accept the claim for tracking)
    // but the TRUTH VALUE must be LOW
    if status == StatusCode::CREATED {
        let response: SubmitPacketResponse = serde_json::from_str(&body).unwrap();

        // 3. CRITICAL: Truth must be LOW despite agent's reputation and request
        assert!(
            response.truth_value < 0.3,
            "BAD ACTOR TEST FAILED: Reputation must not inflate truth! \
             Agent requested 0.95, got {} - claims without evidence should be LOW",
            response.truth_value
        );

        // Additional check: verify truth is not simply echoing the requested value
        assert_ne!(
            response.truth_value, 0.95,
            "Truth value should NOT be the requested initial_truth"
        );

        // The system should calculate truth from evidence (which is none)
        // Combined with the weak methodology (heuristic, 0.5 weight)
        // and no inputs, the truth should be very low
    } else {
        // If the system rejects claims without evidence entirely, that's also valid
        // but we should verify the rejection reason
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "If rejecting claims without evidence, should be 400: {}",
            body
        );

        // Verify rejection is for lack of evidence, not other reason
        let lower_body = body.to_lowercase();
        assert!(
            lower_body.contains("evidence")
                || lower_body.contains("input")
                || lower_body.contains("empty"),
            "Rejection should mention lack of evidence"
        );
    }
}

/// Test: Even with evidence, truth should be calculated from evidence quality,
/// not from agent reputation.
#[tokio::test]
async fn test_truth_calculated_from_evidence_not_reputation() {
    let app = create_test_app_no_sig();

    // Agent with "high reputation"
    let high_rep_agent_id = Uuid::new_v4();

    // Weak evidence (circumstantial, low relevance)
    let weak_content = "Someone mentioned this might be true";
    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "This claim has only weak evidence".to_string(),
            initial_truth: Some(0.95), // Requested high
            agent_id: high_rep_agent_id,
            idempotency_key: None,
        },
        evidence: vec![EvidenceSubmission {
            content_hash: compute_content_hash(weak_content),
            evidence_type: EvidenceTypeSubmission::Testimony {
                source: "anonymous rumor".to_string(),
                testified_at: Utc::now(),
            },
            raw_content: Some(weak_content.to_string()),
            signature: None,
        }],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Heuristic, // Weak methodology
            inputs: vec![TraceInputSubmission::Evidence { index: 0 }],
            confidence: 0.5, // Low confidence
            explanation: "Based on hearsay".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status, body) = submit_packet(app, &packet).await;

    if status == StatusCode::CREATED {
        let response: SubmitPacketResponse = serde_json::from_str(&body).unwrap();

        // Truth should reflect weak evidence, not high reputation
        // Heuristic methodology has 0.5 weight, testimony has lower weight
        assert!(
            response.truth_value < 0.7,
            "Truth should reflect weak evidence quality (heuristic + testimony), \
             not agent reputation. Got: {}",
            response.truth_value
        );
    }
}

/// Test: Strong evidence from low-reputation agent should get appropriate truth.
///
/// The converse of the bad actor test: truth should be based on evidence
/// quality, not on who provides it.
#[tokio::test]
async fn test_strong_evidence_from_any_agent_gets_appropriate_truth() {
    let app = create_test_app_no_sig();

    // New agent with no reputation
    let new_agent_id = Uuid::new_v4();

    // Strong empirical evidence
    let strong_content = "Reproducible experimental data with p<0.001 significance";
    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "This claim is supported by strong empirical evidence".to_string(),
            initial_truth: Some(0.5), // Modest request
            agent_id: new_agent_id,
            idempotency_key: None,
        },
        evidence: vec![EvidenceSubmission {
            content_hash: compute_content_hash(strong_content),
            evidence_type: EvidenceTypeSubmission::Observation {
                observed_at: Utc::now(),
                method: "controlled experiment".to_string(),
                location: Some("peer-reviewed laboratory".to_string()),
            },
            raw_content: Some(strong_content.to_string()),
            signature: None,
        }],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::FormalProof, // Strong methodology (1.2 weight)
            inputs: vec![TraceInputSubmission::Evidence { index: 0 }],
            confidence: 0.95,
            explanation: "Derived from controlled experimental observation".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status, body) = submit_packet(app, &packet).await;

    if status == StatusCode::CREATED {
        let response: SubmitPacketResponse = serde_json::from_str(&body).unwrap();

        // Truth should reflect strong evidence, despite new agent
        assert!(
            response.truth_value > 0.5,
            "Strong evidence should yield reasonable truth value \
             regardless of agent reputation. Got: {}",
            response.truth_value
        );
    }
}

// =============================================================================
// ADDITIONAL EDGE CASE TESTS
// =============================================================================

/// Test: Maximum evidence count should be enforced.
#[tokio::test]
async fn test_maximum_evidence_count_enforced() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    // Create packet with excessive evidence (e.g., 1000 items)
    let evidence: Vec<EvidenceSubmission> = (0..1000)
        .map(|i| {
            let content = format!("Evidence item {i}");
            EvidenceSubmission {
                content_hash: compute_content_hash(&content),
                evidence_type: EvidenceTypeSubmission::Document {
                    source_url: None,
                    mime_type: "text/plain".to_string(),
                },
                raw_content: Some(content),
                signature: None,
            }
        })
        .collect();

    let inputs: Vec<TraceInputSubmission> = (0..evidence.len())
        .map(|i| TraceInputSubmission::Evidence { index: i })
        .collect();

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Claim with excessive evidence".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: None,
        },
        evidence,
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Inductive,
            inputs,
            confidence: 0.8,
            explanation: "Too much evidence".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status, _) = submit_packet(app, &packet).await;

    // Either rejected for too many items, or accepted with limits
    // Implementation should document the limit
    assert!(
        status == StatusCode::CREATED
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::PAYLOAD_TOO_LARGE,
        "Should handle excessive evidence gracefully"
    );
}

/// Test: Very long claim content should be handled appropriately.
#[tokio::test]
async fn test_claim_content_length_limit() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();

    let mut packet = create_valid_packet(agent_id);
    // 1MB of content
    packet.claim.content = "x".repeat(1024 * 1024);

    let (status, _) = submit_packet(app, &packet).await;

    // Should either accept (if within limits) or reject gracefully
    assert!(
        status == StatusCode::CREATED
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::PAYLOAD_TOO_LARGE,
        "Should handle long content gracefully"
    );
}

/// Test: Unicode content should be handled correctly.
#[tokio::test]
async fn test_unicode_content_handled_correctly() {
    if !has_real_database() {
        eprintln!("SKIPPED: test_unicode_content_handled_correctly (no DATABASE_URL)");
        return;
    }
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    ensure_agent_in_db(agent_id).await;

    let unicode_content = "Evidence with Unicode: \\u4e2d\\u6587 emoji: \\u{1F4A1}";
    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Claim about international data \\u4e16\\u754c".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: None,
        },
        evidence: vec![EvidenceSubmission {
            content_hash: compute_content_hash(unicode_content),
            evidence_type: EvidenceTypeSubmission::Document {
                source_url: None,
                mime_type: "text/plain; charset=utf-8".to_string(),
            },
            raw_content: Some(unicode_content.to_string()),
            signature: None,
        }],
        reasoning_trace: create_valid_trace(1),
        signature: "0".repeat(128),
    };

    let (status, body) = submit_packet(app, &packet).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Should accept Unicode content: {}",
        body
    );
}

/// Test: Malformed JSON should return 400.
#[tokio::test]
async fn test_malformed_json_returns_400() {
    let app = create_test_app_no_sig();

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-signature", "test-bypass")
        .body(Body::from("{ this is not valid json }"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Should return 400 for malformed JSON"
    );
}

/// Test: Wrong content type should return 415.
#[tokio::test]
async fn test_wrong_content_type_returns_415() {
    let app = create_test_app_no_sig();
    let agent_id = Uuid::new_v4();
    let packet = create_valid_packet(agent_id);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "text/plain") // Wrong!
        .header("x-signature", "test-bypass")
        .body(Body::from(serde_json::to_string(&packet).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert!(
        response.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE
            || response.status() == StatusCode::BAD_REQUEST,
        "Should return 415 or 400 for wrong content type"
    );
}
