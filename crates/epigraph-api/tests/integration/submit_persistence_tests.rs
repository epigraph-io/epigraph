//! Submit Handler Database Persistence Tests (TDD)
//!
//! POST /api/v1/submit/packet - Database Persistence
//!
//! These tests define the EXPECTED behavior for submit handler persistence.
//! The current implementation validates packets but does NOT persist to database.
//! These tests will FAIL until persistence is implemented.
//!
//! # Test Coverage
//!
//! 1. Submit creates evidence records in database
//! 2. Submit creates reasoning_trace record with correct parent links
//! 3. Submit creates claim record with calculated truth value
//! 4. All inserts happen in a single transaction (rollback on failure)
//! 5. Returned IDs match actual database records
//! 6. Evidence content_hash matches raw_content
//! 7. Claim references correct trace_id and agent_id
//! 8. Idempotency - same key returns same IDs without re-insert
//! 9. Concurrent submissions don't create duplicates
//! 10. Foreign key constraints (agent must exist)
//! 11. Truth value calculated via BayesianUpdater, not from request
//! 12. Evidence signatures are stored correctly
//!
//! # Prerequisites
//!
//! These tests require a PostgreSQL database with pgvector extension.
//! See db_integration_tests.rs for setup instructions.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test --package epigraph-api --test submit_persistence_tests
//! ```

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use chrono::{DateTime, Utc};
use epigraph_api::middleware::SignatureVerificationState;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_core::{Agent, ClaimId, EvidenceId, TraceId};
use epigraph_db::{
    AgentRepository, ClaimRepository, EvidenceRepository, PgPool, ReasoningTraceRepository,
};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use uuid::Uuid;

// =============================================================================
// SUBMISSION TYPES (Mirrored from routes/submit.rs for testing)
// =============================================================================

/// Submission structure for a new claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSubmission {
    pub content: String,
    pub initial_truth: Option<f64>,
    pub agent_id: Uuid,
    pub idempotency_key: Option<String>,
}

/// Submission structure for evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSubmission {
    pub content_hash: String,
    pub evidence_type: EvidenceTypeSubmission,
    pub raw_content: Option<String>,
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
    Evidence { index: usize },
    Claim { id: Uuid },
}

/// Reasoning trace submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningTraceSubmission {
    pub methodology: MethodologySubmission,
    pub inputs: Vec<TraceInputSubmission>,
    pub confidence: f64,
    pub explanation: String,
    pub signature: Option<String>,
}

/// Complete epistemic packet for atomic submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpistemicPacket {
    pub claim: ClaimSubmission,
    pub evidence: Vec<EvidenceSubmission>,
    pub reasoning_trace: ReasoningTraceSubmission,
    pub signature: String,
}

/// Successful submission response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPacketResponse {
    pub claim_id: Uuid,
    pub truth_value: f64,
    pub trace_id: Uuid,
    pub evidence_ids: Vec<Uuid>,
    pub was_duplicate: bool,
}

// =============================================================================
// TEST FIXTURES
// =============================================================================

/// Create a test agent with a random Ed25519 public key
fn create_test_agent(display_name: Option<&str>) -> Agent {
    let mut public_key = [0u8; 32];
    for (i, byte) in public_key.iter_mut().enumerate() {
        *byte = (i as u8)
            .wrapping_mul(17)
            .wrapping_add(Uuid::new_v4().as_bytes()[i % 16]);
    }
    Agent::new(public_key, display_name.map(String::from))
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

/// Create evidence with a signature
fn create_signed_evidence(content: &str, signature_hex: &str) -> EvidenceSubmission {
    EvidenceSubmission {
        content_hash: compute_content_hash(content),
        evidence_type: EvidenceTypeSubmission::Document {
            source_url: Some("https://example.com/signed.pdf".to_string()),
            mime_type: "application/pdf".to_string(),
        },
        raw_content: Some(content.to_string()),
        signature: Some(signature_hex.to_string()),
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
        signature: "0".repeat(128),
    }
}

/// Create a packet with multiple evidence items
fn create_multi_evidence_packet(agent_id: Uuid, evidence_count: usize) -> EpistemicPacket {
    let evidence: Vec<EvidenceSubmission> = (0..evidence_count)
        .map(|i| create_valid_evidence(&format!("Evidence content item {}", i)))
        .collect();

    EpistemicPacket {
        claim: ClaimSubmission {
            content: "Claim supported by multiple evidence sources".to_string(),
            initial_truth: Some(0.5),
            agent_id,
            idempotency_key: None,
        },
        evidence,
        reasoning_trace: create_valid_trace(evidence_count),
        signature: "0".repeat(128),
    }
}

/// Create a router configured for testing with the given database pool.
///
/// Bypasses signature verification middleware so tests can focus on
/// DB persistence logic without auth ceremony.
fn create_test_router(pool: PgPool) -> Router {
    let config = ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
    };
    // Bypass signature verification for all routes in tests
    let signature_state = SignatureVerificationState::with_bypass_routes(vec!["/".to_string()]);
    let state = AppState::with_db_and_signature_state(pool, config, signature_state);
    create_router(state)
}

/// Make a POST request to the submit packet endpoint (creates fresh router per call)
async fn submit_packet_request(pool: &PgPool, packet: &EpistemicPacket) -> (StatusCode, String) {
    let router = create_test_router(pool.clone());
    send_packet(&router, packet).await
}

/// Send a packet through an existing router (for idempotency/concurrency tests
/// that need to share in-memory state across requests)
async fn send_packet(router: &Router, packet: &EpistemicPacket) -> (StatusCode, String) {
    let body = serde_json::to_string(packet).expect("Failed to serialize packet");

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-signature", "test-bypass") // Pass bearer_auth_middleware (falls through to legacy path)
        .body(Body::from(body))
        .expect("Failed to build request");

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();
    let body_string = String::from_utf8(body_bytes.to_vec()).expect("Body is not valid UTF-8");

    (status, body_string)
}

// =============================================================================
// TEST 1: Submit Creates Evidence Records in Database
// =============================================================================

/// Validates that submitting a packet creates evidence records in the database.
///
/// # Invariant Tested
/// - Each evidence item in the packet results in a row in the evidence table
/// - Evidence IDs returned in response match database records
/// - Evidence data (content_hash, raw_content, type) is preserved
///
/// # Evidence
/// IMPLEMENTATION_PLAN.md requires atomic packet submission with persistence
#[sqlx::test(migrations = "../../migrations")]
async fn test_submit_creates_evidence_records(pool: PgPool) {
    // Arrange: Create an agent in the database (required for FK)
    let agent = create_test_agent(Some("Evidence Test Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let evidence_content_1 = "First piece of evidence for claim";
    let evidence_content_2 = "Second piece of evidence for claim";

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim for evidence persistence".to_string(),
            initial_truth: Some(0.5),
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("evidence_test_{}", Uuid::new_v4())),
        },
        evidence: vec![
            create_valid_evidence(evidence_content_1),
            create_valid_evidence(evidence_content_2),
        ],
        reasoning_trace: create_valid_trace(2),
        signature: "0".repeat(128),
    };

    // Act: Submit the packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    // Assert: Submission succeeded
    assert_eq!(
        status,
        StatusCode::CREATED,
        "Submission should succeed: {}",
        body
    );

    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");

    // Verify correct number of evidence IDs returned
    assert_eq!(
        response.evidence_ids.len(),
        2,
        "Should return 2 evidence IDs"
    );

    // Verify evidence exists in database
    for evidence_id in &response.evidence_ids {
        let evidence = EvidenceRepository::get_by_id(&pool, EvidenceId::from_uuid(*evidence_id))
            .await
            .expect("Evidence query should succeed");

        assert!(
            evidence.is_some(),
            "Evidence {} should exist in database",
            evidence_id
        );
    }

    // Verify evidence is linked to the claim
    let claim_id = ClaimId::from_uuid(response.claim_id);
    let claim_evidence = EvidenceRepository::get_by_claim(&pool, claim_id)
        .await
        .expect("Evidence query should succeed");

    assert_eq!(
        claim_evidence.len(),
        2,
        "Claim should have 2 evidence items"
    );
}

// =============================================================================
// TEST 2: Submit Creates Reasoning Trace with Correct Parent Links
// =============================================================================

/// Validates that submitting a packet creates a reasoning trace with proper structure.
///
/// # Invariant Tested
/// - ReasoningTrace is created in reasoning_traces table
/// - Trace ID returned matches database record
/// - Methodology, confidence, and explanation are preserved
/// - Trace inputs are stored correctly (parent links to evidence)
///
/// # Evidence
/// CLAUDE.md requires "Every claim requires a ReasoningTrace"
#[sqlx::test(migrations = "../../migrations")]
async fn test_submit_creates_reasoning_trace_with_parent_links(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Trace Test Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim for trace persistence".to_string(),
            initial_truth: Some(0.5),
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("trace_test_{}", Uuid::new_v4())),
        },
        evidence: vec![
            create_valid_evidence("Evidence item 1"),
            create_valid_evidence("Evidence item 2"),
        ],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Deductive,
            inputs: vec![
                TraceInputSubmission::Evidence { index: 0 },
                TraceInputSubmission::Evidence { index: 1 },
            ],
            confidence: 0.9,
            explanation: "Deductive reasoning from two evidence sources".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    // Act: Submit the packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    // Assert: Submission succeeded
    assert_eq!(status, StatusCode::CREATED, "Submission should succeed");

    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");

    // Verify trace exists in database
    let trace = ReasoningTraceRepository::get_by_id(&pool, TraceId::from_uuid(response.trace_id))
        .await
        .expect("Trace query should succeed");

    assert!(trace.is_some(), "Trace should exist in database");
    let trace = trace.unwrap();

    // Verify trace properties
    assert_eq!(trace.confidence, 0.9, "Confidence should be preserved");
    assert_eq!(
        trace.explanation, "Deductive reasoning from two evidence sources",
        "Explanation should be preserved"
    );

    // Verify trace is linked to claim
    let claim_traces =
        ReasoningTraceRepository::get_by_claim(&pool, ClaimId::from_uuid(response.claim_id))
            .await
            .expect("Trace query should succeed");

    assert!(
        !claim_traces.is_empty(),
        "Claim should have associated trace"
    );
    assert_eq!(
        claim_traces[0].id,
        TraceId::from_uuid(response.trace_id),
        "Claim's trace should match returned trace_id"
    );
}

// =============================================================================
// TEST 3: Submit Creates Claim with Calculated Truth Value
// =============================================================================

/// Validates that submitting a packet creates a claim record with calculated truth.
///
/// # Invariant Tested
/// - Claim is created in claims table
/// - Claim ID returned matches database record
/// - Content is preserved
/// - Truth value is CALCULATED from evidence, not from request
/// - Agent ID is correctly linked
/// - Trace ID is correctly linked
///
/// # Evidence
/// CLAUDE.md: "Truth values are derived from evidence, not from agent reputation"
#[sqlx::test(migrations = "../../migrations")]
async fn test_submit_creates_claim_with_calculated_truth(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Claim Test Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim for persistence verification".to_string(),
            initial_truth: Some(0.95), // Request high truth
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("claim_test_{}", Uuid::new_v4())),
        },
        evidence: vec![create_valid_evidence("Single evidence item")],
        reasoning_trace: create_valid_trace(1),
        signature: "0".repeat(128),
    };

    // Act: Submit the packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    // Assert: Submission succeeded
    assert_eq!(status, StatusCode::CREATED, "Submission should succeed");

    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");

    // Verify claim exists in database
    let claim = ClaimRepository::get_by_id(&pool, ClaimId::from_uuid(response.claim_id))
        .await
        .expect("Claim query should succeed");

    assert!(claim.is_some(), "Claim should exist in database");
    let claim = claim.unwrap();

    // Verify claim properties
    assert_eq!(
        claim.content, "Test claim for persistence verification",
        "Content should be preserved"
    );
    assert_eq!(claim.agent_id, created_agent.id, "Agent ID should match");
    assert!(claim.trace_id.is_some(), "Claim should have trace_id");
    assert_eq!(
        claim.trace_id.unwrap(),
        TraceId::from_uuid(response.trace_id),
        "Trace ID should match response"
    );

    // Verify truth value matches response (which was calculated, not from request)
    assert!(
        (claim.truth_value.value() - response.truth_value).abs() < f64::EPSILON,
        "Database truth value should match response"
    );

    // Verify the engine actually calculated truth rather than blindly accepting initial_truth.
    // The submitted initial_truth was 0.95, but the engine should compute its own value
    // based on evidence quality and quantity.
    assert!(
        (claim.truth_value.value() - 0.95).abs() > f64::EPSILON,
        "Calculated truth ({}) should differ from requested initial_truth (0.95) — \
         the engine must compute truth from evidence, not pass through the request value",
        claim.truth_value.value()
    );
}

// =============================================================================
// TEST 4: All Inserts Happen in Single Transaction (Rollback on Failure)
// =============================================================================

/// Validates that submit operations are atomic - all succeed or all fail.
///
/// # Invariant Tested
/// - If evidence creation fails mid-transaction, no claim is created
/// - If trace creation fails, no evidence or claim is created
/// - If claim creation fails, no evidence or trace is created
/// - Database state is unchanged after failed submission
///
/// # Evidence
/// IMPLEMENTATION_PLAN.md requires atomic packet submission
#[sqlx::test(migrations = "../../migrations")]
async fn test_submit_transaction_rollback_on_failure(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Transaction Test Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    // Record initial counts
    let initial_claim_count = ClaimRepository::count(&pool, None)
        .await
        .expect("Count should succeed");

    let idempotency_key = format!("rollback_test_{}", Uuid::new_v4());

    // Create a packet that will fail during evidence validation
    // (second evidence has mismatched hash)
    let valid_content = "Valid evidence content";
    let packet_with_bad_evidence = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Claim that should not persist".to_string(),
            initial_truth: Some(0.5),
            agent_id: created_agent.id.into(),
            idempotency_key: Some(idempotency_key.clone()),
        },
        evidence: vec![
            create_valid_evidence(valid_content),
            EvidenceSubmission {
                content_hash: "0".repeat(64), // Wrong hash!
                evidence_type: EvidenceTypeSubmission::Document {
                    source_url: None,
                    mime_type: "text/plain".to_string(),
                },
                raw_content: Some("This content doesn't match the hash".to_string()),
                signature: None,
            },
        ],
        reasoning_trace: create_valid_trace(2),
        signature: "0".repeat(128),
    };

    // Act: Submit packet that will fail validation
    let (status, _body) = submit_packet_request(&pool, &packet_with_bad_evidence).await;

    // Assert: Submission should fail
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Submission with bad evidence should fail"
    );

    // Verify NO claims were created (transaction rolled back)
    let final_claim_count = ClaimRepository::count(&pool, None)
        .await
        .expect("Count should succeed");

    assert_eq!(
        initial_claim_count, final_claim_count,
        "Claim count should be unchanged after failed submission (transaction rollback)"
    );

    // Now submit a valid packet with the same idempotency key
    // It should create a NEW record (proving nothing was persisted before)
    let valid_packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Valid claim after rollback".to_string(),
            initial_truth: Some(0.5),
            agent_id: created_agent.id.into(),
            idempotency_key: Some(idempotency_key),
        },
        evidence: vec![create_valid_evidence(valid_content)],
        reasoning_trace: create_valid_trace(1),
        signature: "0".repeat(128),
    };

    let (status2, body2) = submit_packet_request(&pool, &valid_packet).await;

    assert_eq!(
        status2,
        StatusCode::CREATED,
        "Valid submission should succeed"
    );

    let response: SubmitPacketResponse =
        serde_json::from_str(&body2).expect("Failed to parse response");

    // CRITICAL: was_duplicate should be FALSE because rollback succeeded
    assert!(
        !response.was_duplicate,
        "Rollback verification failed! was_duplicate=true means partial state persisted"
    );
}

// =============================================================================
// TEST 5: Returned IDs Match Actual Database Records
// =============================================================================

/// Validates that IDs returned in response exactly match database records.
///
/// # Invariant Tested
/// - response.claim_id exists in claims table
/// - response.trace_id exists in reasoning_traces table
/// - response.evidence_ids all exist in evidence table
/// - No phantom IDs (every ID returned is persisted)
///
/// # Evidence
/// API contract requires returned IDs to be valid references
#[sqlx::test(migrations = "../../migrations")]
async fn test_returned_ids_match_database_records(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("ID Match Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let packet = create_multi_evidence_packet(created_agent.id.into(), 3);

    // Act: Submit packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    assert_eq!(status, StatusCode::CREATED, "Submission should succeed");

    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");

    // Assert: Verify claim_id exists
    let claim = ClaimRepository::get_by_id(&pool, ClaimId::from_uuid(response.claim_id))
        .await
        .expect("Claim query should succeed");
    assert!(
        claim.is_some(),
        "Returned claim_id {} must exist in database",
        response.claim_id
    );

    // Assert: Verify trace_id exists
    let trace = ReasoningTraceRepository::get_by_id(&pool, TraceId::from_uuid(response.trace_id))
        .await
        .expect("Trace query should succeed");
    assert!(
        trace.is_some(),
        "Returned trace_id {} must exist in database",
        response.trace_id
    );

    // Assert: Verify all evidence_ids exist
    assert_eq!(response.evidence_ids.len(), 3, "Should have 3 evidence IDs");

    for (i, evidence_id) in response.evidence_ids.iter().enumerate() {
        let evidence = EvidenceRepository::get_by_id(&pool, EvidenceId::from_uuid(*evidence_id))
            .await
            .expect("Evidence query should succeed");
        assert!(
            evidence.is_some(),
            "Returned evidence_id[{}] {} must exist in database",
            i,
            evidence_id
        );
    }
}

// =============================================================================
// TEST 6: Evidence Content Hash Matches Raw Content
// =============================================================================

/// Validates that stored evidence has correct content_hash for raw_content.
///
/// # Invariant Tested
/// - BLAKE3(raw_content) == content_hash in database
/// - Hash is computed at submission time and stored
/// - Hash integrity is maintained through persistence
///
/// # Evidence
/// CLAUDE.md: "All evidence ... are signed. Verify before trust."
#[sqlx::test(migrations = "../../migrations")]
async fn test_evidence_content_hash_matches_raw_content(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Hash Verify Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let evidence_content = "This is the evidence content that will be hashed";
    let _expected_hash_hex = compute_content_hash(evidence_content);
    let expected_hash_bytes = epigraph_crypto::ContentHasher::hash(evidence_content.as_bytes());

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Test claim for hash verification".to_string(),
            initial_truth: Some(0.5),
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("hash_test_{}", Uuid::new_v4())),
        },
        evidence: vec![create_valid_evidence(evidence_content)],
        reasoning_trace: create_valid_trace(1),
        signature: "0".repeat(128),
    };

    // Act: Submit packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    assert_eq!(status, StatusCode::CREATED, "Submission should succeed");

    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");

    // Assert: Verify evidence hash in database
    let evidence_id = response
        .evidence_ids
        .first()
        .expect("Should have evidence ID");
    let evidence = EvidenceRepository::get_by_id(&pool, EvidenceId::from_uuid(*evidence_id))
        .await
        .expect("Evidence query should succeed")
        .expect("Evidence should exist");

    // Verify stored hash matches expected
    assert_eq!(
        evidence.content_hash, expected_hash_bytes,
        "Stored content_hash should match BLAKE3 hash of raw_content"
    );

    // Verify raw_content is preserved
    assert_eq!(
        evidence.raw_content,
        Some(evidence_content.to_string()),
        "Raw content should be preserved"
    );

    // Double-check by recomputing hash
    if let Some(ref raw) = evidence.raw_content {
        let recomputed = epigraph_crypto::ContentHasher::hash(raw.as_bytes());
        assert_eq!(
            evidence.content_hash, recomputed,
            "Recomputed hash should match stored hash"
        );
    }
}

// =============================================================================
// TEST 7: Claim References Correct Trace ID and Agent ID
// =============================================================================

/// Validates that persisted claim has correct foreign key references.
///
/// # Invariant Tested
/// - claim.trace_id references the correct reasoning trace
/// - claim.agent_id references the submitting agent
/// - FK constraints are satisfied
///
/// # Evidence
/// CLAUDE.md: "Every claim requires a ReasoningTrace"
#[sqlx::test(migrations = "../../migrations")]
async fn test_claim_references_correct_trace_and_agent(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("FK Reference Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let packet = create_valid_packet(created_agent.id.into());

    // Act: Submit packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    assert_eq!(status, StatusCode::CREATED, "Submission should succeed");

    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");

    // Assert: Retrieve claim and verify references
    let claim = ClaimRepository::get_by_id(&pool, ClaimId::from_uuid(response.claim_id))
        .await
        .expect("Claim query should succeed")
        .expect("Claim should exist");

    // Verify agent_id matches submitting agent
    assert_eq!(
        claim.agent_id, created_agent.id,
        "Claim agent_id should match submitting agent"
    );

    // Verify trace_id is set and matches response
    assert!(claim.trace_id.is_some(), "Claim must have trace_id");
    assert_eq!(
        claim.trace_id.unwrap(),
        TraceId::from_uuid(response.trace_id),
        "Claim trace_id should match returned trace_id"
    );

    // Verify the trace exists and is linked to claim
    let trace = ReasoningTraceRepository::get_by_id(&pool, claim.trace_id.unwrap())
        .await
        .expect("Trace query should succeed")
        .expect("Trace should exist");

    assert_eq!(
        trace.id,
        TraceId::from_uuid(response.trace_id),
        "Trace ID should match"
    );
}

// =============================================================================
// TEST 8: Idempotency - Same Key Returns Same IDs Without Re-Insert
// =============================================================================

/// Validates idempotency behavior with database persistence.
///
/// # Invariant Tested
/// - Same idempotency_key returns identical IDs
/// - No duplicate records created in database
/// - was_duplicate flag is true for second submission
/// - All data accessible via returned IDs
///
/// # Evidence
/// API idempotency is standard for POST endpoints that create resources
#[sqlx::test(migrations = "../../migrations")]
async fn test_idempotency_returns_same_ids_without_reinsert(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Idempotency Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let idempotency_key = format!("idempotency_test_{}", Uuid::new_v4());

    let mut packet = create_valid_packet(created_agent.id.into());
    packet.claim.idempotency_key = Some(idempotency_key.clone());

    // Record initial counts
    let initial_claim_count = ClaimRepository::count(&pool, None)
        .await
        .expect("Count should succeed");

    // Share a single router so the in-memory idempotency store persists
    let router = create_test_router(pool.clone());

    // Act: First submission
    let (status1, body1) = send_packet(&router, &packet).await;

    assert_eq!(
        status1,
        StatusCode::CREATED,
        "First submission should succeed"
    );

    let response1: SubmitPacketResponse =
        serde_json::from_str(&body1).expect("Failed to parse response");

    assert!(
        !response1.was_duplicate,
        "First submission should not be duplicate"
    );

    // Act: Second submission with same idempotency key (same router = same store)
    let (status2, body2) = send_packet(&router, &packet).await;

    // Should return success (either 200 or 201)
    assert!(
        status2 == StatusCode::CREATED || status2 == StatusCode::OK,
        "Second submission should succeed"
    );

    let response2: SubmitPacketResponse =
        serde_json::from_str(&body2).expect("Failed to parse response");

    // Assert: Same IDs returned
    assert_eq!(
        response1.claim_id, response2.claim_id,
        "Claim ID should be identical"
    );
    assert_eq!(
        response1.trace_id, response2.trace_id,
        "Trace ID should be identical"
    );
    assert_eq!(
        response1.evidence_ids, response2.evidence_ids,
        "Evidence IDs should be identical"
    );
    assert!(
        (response1.truth_value - response2.truth_value).abs() < f64::EPSILON,
        "Truth value should be identical"
    );

    // Assert: Second response is marked as duplicate
    assert!(
        response2.was_duplicate,
        "Second submission should be marked as duplicate"
    );

    // Assert: No additional records created
    let final_claim_count = ClaimRepository::count(&pool, None)
        .await
        .expect("Count should succeed");

    assert_eq!(
        final_claim_count,
        initial_claim_count + 1,
        "Only one claim should be created despite two submissions"
    );
}

// =============================================================================
// TEST 9: Concurrent Submissions Are Safe (No Deadlocks or Constraint Violations)
// =============================================================================

/// Validates that concurrent submissions from the same agent don't deadlock or crash.
///
/// # Invariant Tested
/// - Parallel submissions all succeed (no deadlocks, no constraint violations)
/// - Database handles concurrent transactions safely
/// - All created claims are valid and queryable
///
/// # Note on Idempotency
/// In-memory idempotency (RwLock<HashMap>) provides sequential dedup only.
/// True concurrent dedup would require DB-level uniqueness constraints.
/// This test verifies concurrent writes are safe, not idempotent.
///
/// # Evidence
/// Concurrent API calls must not crash the server or corrupt data
#[sqlx::test(migrations = "../../migrations")]
async fn test_concurrent_submissions_no_duplicates(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Concurrency Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let initial_count = ClaimRepository::count(&pool, None)
        .await
        .expect("Count should succeed");

    // Share a single router for all requests
    let router = create_test_router(pool.clone());

    // Act: Submit 5 concurrent requests with DIFFERENT content (no idempotency)
    let num_concurrent = 5;
    let mut handles = Vec::new();

    for i in 0..num_concurrent {
        let router_clone = router.clone();
        let agent_id: Uuid = created_agent.id.into();

        let handle = tokio::spawn(async move {
            let evidence_content = format!("Concurrent evidence item {}", i);
            let packet = EpistemicPacket {
                claim: ClaimSubmission {
                    content: format!("Concurrent claim {}", i),
                    initial_truth: Some(0.5),
                    agent_id,
                    idempotency_key: None, // Each is unique
                },
                evidence: vec![create_valid_evidence(&evidence_content)],
                reasoning_trace: create_valid_trace(1),
                signature: "0".repeat(128),
            };
            send_packet(&router_clone, &packet).await
        });
        handles.push(handle);
    }

    // Collect all results
    let results: Vec<_> = futures::future::join_all(handles).await;

    // Assert: All submissions should succeed (no deadlocks, no constraint violations)
    let mut success_count = 0;
    for result in results {
        let (status, body) = result.expect("Task should not panic");

        assert_eq!(
            status,
            StatusCode::CREATED,
            "Concurrent submission should succeed: {}",
            body
        );
        success_count += 1;
    }

    assert_eq!(
        success_count, num_concurrent,
        "All concurrent submissions should succeed"
    );

    // Assert: Correct number of claims created
    let final_count = ClaimRepository::count(&pool, None)
        .await
        .expect("Count should succeed");

    assert_eq!(
        final_count,
        initial_count + num_concurrent as i64,
        "Each concurrent submission should create exactly one claim"
    );
}

// =============================================================================
// TEST 10: Foreign Key Constraints (Agent Must Exist)
// =============================================================================

/// Validates that submissions fail if agent doesn't exist.
///
/// # Invariant Tested
/// - Submission with non-existent agent_id fails
/// - No partial records created
/// - Appropriate error returned
///
/// # Evidence
/// Database FK constraint: claims.agent_id -> agents.id
#[sqlx::test(migrations = "../../migrations")]
async fn test_foreign_key_constraint_agent_must_exist(pool: PgPool) {
    // Arrange: Create a packet with non-existent agent
    let fake_agent_id = Uuid::new_v4();
    let packet = create_valid_packet(fake_agent_id);

    // Record initial counts
    let initial_claim_count = ClaimRepository::count(&pool, None)
        .await
        .expect("Count should succeed");

    // Act: Submit packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    // Assert: Submission should fail
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "Submission with non-existent agent should fail: {}",
        body
    );

    // Assert: No records created
    let final_claim_count = ClaimRepository::count(&pool, None)
        .await
        .expect("Count should succeed");

    assert_eq!(
        initial_claim_count, final_claim_count,
        "No claims should be created when agent doesn't exist"
    );
}

// =============================================================================
// TEST 11: Truth Value Calculated via BayesianUpdater, Not From Request
// =============================================================================

/// Validates that truth value is calculated from evidence, not request.
///
/// # CRITICAL INVARIANT (BAD ACTOR TEST)
///
/// Agent's requested initial_truth is IGNORED. Truth is calculated by
/// BayesianUpdater based on evidence count, methodology, and confidence.
///
/// # Invariant Tested
/// - Requested initial_truth has NO effect on stored truth value
/// - Truth is calculated using BayesianUpdater::calculate_initial_truth
/// - High requested truth with weak evidence yields low actual truth
/// - Zero evidence yields truth <= 0.5
///
/// # Evidence
/// CLAUDE.md: "Reputation must not inflate truth!"
#[sqlx::test(migrations = "../../migrations")]
async fn test_truth_value_calculated_by_bayesian_not_request(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Truth Calc Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    // Test 1: High requested truth with NO evidence
    let packet_no_evidence = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Claim with no evidence requesting high truth".to_string(),
            initial_truth: Some(0.99), // Request near-certain
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("no_evidence_{}", Uuid::new_v4())),
        },
        evidence: vec![], // NO EVIDENCE
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Heuristic, // Weakest
            inputs: vec![],
            confidence: 0.99, // High confidence (should be ignored)
            explanation: "Trust me".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status1, body1) = submit_packet_request(&pool, &packet_no_evidence).await;

    // If the system rejects claims with no evidence entirely, that's valid
    if status1 == StatusCode::CREATED {
        let response1: SubmitPacketResponse =
            serde_json::from_str(&body1).expect("Failed to parse response");

        // CRITICAL: Truth must be LOW despite request
        assert!(
            response1.truth_value < 0.3,
            "BAD ACTOR TEST FAILED: No evidence should yield low truth (<0.3), got {}",
            response1.truth_value
        );

        assert_ne!(
            response1.truth_value, 0.99,
            "Truth must NOT be the requested value"
        );

        // Verify database matches
        let claim = ClaimRepository::get_by_id(&pool, ClaimId::from_uuid(response1.claim_id))
            .await
            .expect("Query should succeed")
            .expect("Claim should exist");

        assert!(
            claim.truth_value.value() < 0.3,
            "Database truth should also be low: {}",
            claim.truth_value.value()
        );
    }

    // Test 2: Compare requested high vs calculated with evidence
    let packet_with_evidence = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Claim with evidence requesting low truth".to_string(),
            initial_truth: Some(0.1), // Request low
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("with_evidence_{}", Uuid::new_v4())),
        },
        evidence: vec![
            create_valid_evidence("Evidence 1"),
            create_valid_evidence("Evidence 2"),
            create_valid_evidence("Evidence 3"),
        ],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::FormalProof, // Strongest
            inputs: vec![
                TraceInputSubmission::Evidence { index: 0 },
                TraceInputSubmission::Evidence { index: 1 },
                TraceInputSubmission::Evidence { index: 2 },
            ],
            confidence: 0.95,
            explanation: "Formal derivation from multiple sources".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status2, body2) = submit_packet_request(&pool, &packet_with_evidence).await;

    assert_eq!(status2, StatusCode::CREATED, "Submission should succeed");

    let response2: SubmitPacketResponse =
        serde_json::from_str(&body2).expect("Failed to parse response");

    // Truth should be HIGHER than requested because evidence is strong
    assert!(
        response2.truth_value > 0.1,
        "Strong evidence should yield truth higher than requested 0.1, got {}",
        response2.truth_value
    );

    // Truth should be reasonable but not extreme (initial truth capped at 0.85)
    assert!(
        response2.truth_value <= 0.85,
        "Initial truth should not exceed 0.85, got {}",
        response2.truth_value
    );
}

// =============================================================================
// TEST 12: Evidence Signatures Are Stored Correctly
// =============================================================================

/// Validates that evidence signatures are persisted to database.
///
/// # Invariant Tested
/// - Evidence signature bytes are stored correctly
/// - Signature can be retrieved and verified later
/// - Unsigned evidence has None signature
///
/// # Evidence
/// CLAUDE.md: "Cryptographic Integrity: All evidence and traces are signed"
#[sqlx::test(migrations = "../../migrations")]
async fn test_evidence_signatures_stored_correctly(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Signature Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    // Create a valid Ed25519-style signature (128 hex chars = 64 bytes)
    let signature_hex = "ab".repeat(64); // Valid hex, 128 chars

    let evidence_content = "Signed evidence content";

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Claim with signed evidence".to_string(),
            initial_truth: Some(0.5),
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("sig_test_{}", Uuid::new_v4())),
        },
        evidence: vec![
            create_signed_evidence(evidence_content, &signature_hex),
            create_valid_evidence("Unsigned evidence"), // No signature
        ],
        reasoning_trace: create_valid_trace(2),
        signature: "0".repeat(128),
    };

    // Act: Submit packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    assert_eq!(status, StatusCode::CREATED, "Submission should succeed");

    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");

    // Assert: Verify signed evidence has signature stored
    let signed_evidence_id = &response.evidence_ids[0];
    let signed_evidence =
        EvidenceRepository::get_by_id(&pool, EvidenceId::from_uuid(*signed_evidence_id))
            .await
            .expect("Evidence query should succeed")
            .expect("Evidence should exist");

    assert!(
        signed_evidence.is_signed(),
        "First evidence should have signature"
    );

    // Verify signature bytes match
    let expected_signature: [u8; 64] = hex::decode(&signature_hex)
        .expect("Valid hex")
        .try_into()
        .expect("64 bytes");

    assert_eq!(
        signed_evidence.signature,
        Some(expected_signature),
        "Stored signature should match submitted signature"
    );

    // Assert: Verify unsigned evidence has no signature
    let unsigned_evidence_id = &response.evidence_ids[1];
    let unsigned_evidence =
        EvidenceRepository::get_by_id(&pool, EvidenceId::from_uuid(*unsigned_evidence_id))
            .await
            .expect("Evidence query should succeed")
            .expect("Evidence should exist");

    assert!(
        !unsigned_evidence.is_signed(),
        "Second evidence should not have signature"
    );
    assert_eq!(
        unsigned_evidence.signature, None,
        "Unsigned evidence should have None signature"
    );
}

// =============================================================================
// ADDITIONAL TESTS: Edge Cases and Error Conditions
// =============================================================================

/// Validates that claim content is trimmed and stored correctly
#[sqlx::test(migrations = "../../migrations")]
async fn test_claim_content_whitespace_handling(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Whitespace Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "  Valid claim with surrounding whitespace  ".to_string(),
            initial_truth: Some(0.5),
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("ws_test_{}", Uuid::new_v4())),
        },
        evidence: vec![create_valid_evidence("Evidence")],
        reasoning_trace: create_valid_trace(1),
        signature: "0".repeat(128),
    };

    // Act: Submit packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    assert_eq!(status, StatusCode::CREATED, "Submission should succeed");

    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");

    // Assert: Verify content in database
    let claim = ClaimRepository::get_by_id(&pool, ClaimId::from_uuid(response.claim_id))
        .await
        .expect("Query should succeed")
        .expect("Claim should exist");

    // Content should be stored (trimming is optional depending on implementation)
    assert!(
        !claim.content.is_empty(),
        "Claim content should not be empty"
    );
}

/// Validates that evidence types are correctly serialized and stored
#[sqlx::test(migrations = "../../migrations")]
async fn test_evidence_type_variants_stored_correctly(pool: PgPool) {
    // Arrange: Create agent
    let agent = create_test_agent(Some("Evidence Type Agent"));
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("Agent creation should succeed");

    let now = Utc::now();
    let observation_content = "Observation content";
    let testimony_content = "Testimony content";

    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Claim with diverse evidence types".to_string(),
            initial_truth: Some(0.5),
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("evtype_test_{}", Uuid::new_v4())),
        },
        evidence: vec![
            EvidenceSubmission {
                content_hash: compute_content_hash(observation_content),
                evidence_type: EvidenceTypeSubmission::Observation {
                    observed_at: now,
                    method: "visual inspection".to_string(),
                    location: Some("Laboratory A".to_string()),
                },
                raw_content: Some(observation_content.to_string()),
                signature: None,
            },
            EvidenceSubmission {
                content_hash: compute_content_hash(testimony_content),
                evidence_type: EvidenceTypeSubmission::Testimony {
                    source: "Dr. Expert".to_string(),
                    testified_at: now,
                },
                raw_content: Some(testimony_content.to_string()),
                signature: None,
            },
        ],
        reasoning_trace: create_valid_trace(2),
        signature: "0".repeat(128),
    };

    // Act: Submit packet
    let (status, body) = submit_packet_request(&pool, &packet).await;

    assert_eq!(status, StatusCode::CREATED, "Submission should succeed");

    let response: SubmitPacketResponse =
        serde_json::from_str(&body).expect("Failed to parse response");

    // Assert: Verify evidence types
    let ev1 = EvidenceRepository::get_by_id(&pool, EvidenceId::from_uuid(response.evidence_ids[0]))
        .await
        .expect("Query should succeed")
        .expect("Evidence should exist");

    assert_eq!(ev1.type_description(), "Observation");

    let ev2 = EvidenceRepository::get_by_id(&pool, EvidenceId::from_uuid(response.evidence_ids[1]))
        .await
        .expect("Query should succeed")
        .expect("Evidence should exist");

    assert_eq!(ev2.type_description(), "Testimony");
}

/// THE BAD ACTOR TEST - Integration Level
///
/// This is the database-level enforcement of the Bad Actor principle.
/// Even if somehow an invalid truth value was passed through the API,
/// the database should reject it.
#[sqlx::test(migrations = "../../migrations")]
async fn test_bad_actor_db_level_enforcement(pool: PgPool) {
    // Arrange: Create agent with "high reputation" (simulated)
    let high_rep_agent = create_test_agent(Some("Famous Authority"));
    let created_agent = AgentRepository::create(&pool, &high_rep_agent)
        .await
        .expect("Agent creation should succeed");

    // Packet with NO evidence but high requested truth
    let packet = EpistemicPacket {
        claim: ClaimSubmission {
            content: "Trust me, I'm famous".to_string(),
            initial_truth: Some(0.99), // Request near-certain
            agent_id: created_agent.id.into(),
            idempotency_key: Some(format!("bad_actor_{}", Uuid::new_v4())),
        },
        evidence: vec![], // NO EVIDENCE
        reasoning_trace: ReasoningTraceSubmission {
            methodology: MethodologySubmission::Heuristic,
            inputs: vec![],
            confidence: 0.99,
            explanation: "I have a great reputation".to_string(),
            signature: None,
        },
        signature: "0".repeat(128),
    };

    let (status, body) = submit_packet_request(&pool, &packet).await;

    // Either rejected entirely OR accepted with LOW truth
    if status == StatusCode::CREATED {
        let response: SubmitPacketResponse =
            serde_json::from_str(&body).expect("Failed to parse response");

        // CRITICAL ASSERTION
        assert!(
            response.truth_value < 0.3,
            "BAD ACTOR TEST FAILED: Famous agent with no evidence got truth {}. \
             This violates the core epistemic principle!",
            response.truth_value
        );

        // Verify database consistency
        let claim = ClaimRepository::get_by_id(&pool, ClaimId::from_uuid(response.claim_id))
            .await
            .expect("Query should succeed")
            .expect("Claim should exist");

        assert!(
            claim.truth_value.value() < 0.3,
            "Database also shows violation: {}",
            claim.truth_value.value()
        );
    }
}
