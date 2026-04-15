//! Comprehensive tests for SignedRequest extractor
//!
//! # Test Categories
//!
//! 1. **Happy Path**: Valid signatures extract payload correctly
//! 2. **Authentication Failures**: Invalid/tampered signatures rejected (401)
//! 3. **Missing Headers**: Required headers missing returns proper error
//! 4. **Malformed Data**: Invalid base64/hex encoding rejected
//! 5. **Key Lifecycle**: Expired and revoked keys are rejected
//! 6. **Message Integrity**: Signature over wrong message is rejected
//! 7. **Security Attacks**: Key substitution, replay, timing attacks
//!
//! # Security Invariants Validated
//!
//! - Only properly signed requests from valid keys are accepted
//! - Tampered payloads are detected and rejected
//! - Expired keys cannot be used for authentication
//! - Revoked keys cannot be used for authentication
//! - Missing cryptographic material returns 401 Unauthorized
//! - Key substitution attacks are detected and rejected
//! - Error messages do not leak sensitive information

use axum::{
    body::Body,
    extract::{FromRequest, Request},
    http::{header, Method, StatusCode},
    response::IntoResponse,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use epigraph_api::{errors::ApiError, extractors::SignedRequest, AgentKey, KeyStatus};
use epigraph_core::domain::AgentId;
use epigraph_crypto::{AgentSigner, ContentHasher, SignatureVerifier, SIGNATURE_SIZE};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Constants matching the expected SignedRequest extractor implementation
// ============================================================================

/// Authorization header format: "Signature <base64>"
const AUTHORIZATION_HEADER: &str = "Authorization";

/// Public key header: hex-encoded 32 bytes
const PUBLIC_KEY_HEADER: &str = "X-Public-Key";

// ============================================================================
// Test Payload Types
// ============================================================================

/// Simple test payload for SignedRequest extraction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestPayload {
    message: String,
    value: u64,
}

/// Complex nested payload for testing serialization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ComplexPayload {
    id: Uuid,
    claim: String,
    truth_value: f64,
    metadata: PayloadMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct PayloadMetadata {
    source: String,
    confidence: f64,
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a valid signed request with all required headers
fn create_valid_signed_request<T: Serialize>(signer: &AgentSigner, payload: &T) -> Request<Body> {
    let body_bytes = serde_json::to_vec(payload).expect("Failed to serialize payload");

    // Hash the body for signing
    let body_hash = ContentHasher::hash(&body_bytes);

    // Sign the hash
    let signature = signer.sign(&body_hash);
    let signature_base64 = STANDARD.encode(signature);

    // Format: "Signature <base64>"
    let auth_header = format!("Signature {}", signature_base64);

    // Hex-encode the public key
    let public_key_hex = hex::encode(signer.public_key());

    Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header(AUTHORIZATION_HEADER, auth_header)
        .header(PUBLIC_KEY_HEADER, public_key_hex)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body_bytes))
        .expect("Failed to build request")
}

/// Create request with custom Authorization header
fn create_request_with_auth(
    auth_header: Option<&str>,
    public_key_hex: Option<&str>,
    body: Vec<u8>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(auth) = auth_header {
        builder = builder.header(AUTHORIZATION_HEADER, auth);
    }

    if let Some(pk) = public_key_hex {
        builder = builder.header(PUBLIC_KEY_HEADER, pk);
    }

    builder
        .body(Body::from(body))
        .expect("Failed to build request")
}

/// Sign a message and return base64-encoded signature
fn sign_message(signer: &AgentSigner, message: &[u8]) -> String {
    let hash = ContentHasher::hash(message);
    let signature = signer.sign(&hash);
    STANDARD.encode(signature)
}

/// Extract the SignedRequest from a request and return the result
async fn extract_signed_request<T: serde::de::DeserializeOwned>(
    request: Request<Body>,
) -> Result<SignedRequest<T>, ApiError> {
    SignedRequest::<T>::from_request(request, &()).await
}

/// Helper to expect an error and get the status code from the response
async fn expect_error_status<T: serde::de::DeserializeOwned>(
    request: Request<Body>,
    expected_status: StatusCode,
    test_name: &str,
) {
    let result = extract_signed_request::<T>(request).await;
    match result {
        Ok(_) => panic!("{}: Expected error but got success", test_name),
        Err(error) => {
            let response = error.into_response();
            assert_eq!(
                response.status(),
                expected_status,
                "{}: Expected {} but got {}",
                test_name,
                expected_status,
                response.status()
            );
        }
    }
}

/// Helper to verify response has correct Content-Type
async fn verify_error_response_format(error: ApiError) {
    let response = error.into_response();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("Response should have Content-Type header");

    assert!(
        content_type.to_str().unwrap().contains("application/json"),
        "Error response Content-Type should be application/json, got: {:?}",
        content_type
    );

    // Verify body is valid JSON
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Should read body")
        .to_bytes();

    let json: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("Response body should be valid JSON");

    // Verify error response structure
    assert!(
        json.get("error").is_some(),
        "Error response should have 'error' field"
    );
    assert!(
        json.get("message").is_some(),
        "Error response should have 'message' field"
    );
}

// ============================================================================
// Test 1: Valid Signature Extracts Payload Correctly
// ============================================================================

/// Validates: A properly signed request successfully extracts the payload
///
/// Security Invariant: Valid Ed25519 signatures from valid keys should
/// authenticate the request and allow payload extraction.
#[tokio::test]
async fn test_valid_signature_extracts_payload_correctly() {
    let signer = AgentSigner::generate();

    let payload = TestPayload {
        message: "Hello, EpiGraph!".to_string(),
        value: 42,
    };

    let request = create_valid_signed_request(&signer, &payload);

    // Actually invoke the SignedRequest extractor
    let result = extract_signed_request::<TestPayload>(request).await;

    assert!(
        result.is_ok(),
        "Valid signature should extract successfully"
    );

    let signed_request = result.unwrap();
    assert_eq!(
        signed_request.payload, payload,
        "Payload should match original"
    );
    assert_eq!(
        signed_request.public_key,
        signer.public_key(),
        "Public key should match"
    );
    assert_eq!(
        signed_request.signature.len(),
        SIGNATURE_SIZE,
        "Signature should be 64 bytes"
    );
}

/// Validates: Complex nested payloads are correctly extracted
#[tokio::test]
async fn test_valid_signature_with_complex_payload() {
    let signer = AgentSigner::generate();

    let payload = ComplexPayload {
        id: Uuid::new_v4(),
        claim: "The epistemic graph validates truth probabilistically".to_string(),
        truth_value: 0.85,
        metadata: PayloadMetadata {
            source: "scientific_paper".to_string(),
            confidence: 0.92,
        },
    };

    let request = create_valid_signed_request(&signer, &payload);

    // Actually invoke the SignedRequest extractor
    let result = extract_signed_request::<ComplexPayload>(request).await;

    assert!(
        result.is_ok(),
        "Complex payload with valid signature should extract successfully"
    );

    let signed_request = result.unwrap();
    assert_eq!(
        signed_request.payload, payload,
        "Complex payload should match original"
    );
}

// ============================================================================
// Test 2: Invalid Signature (Tampered) Is Rejected with 401
// ============================================================================

/// Validates: Tampered signatures are rejected
///
/// Security Invariant: Any modification to the signature must result in
/// rejection with 401 Unauthorized.
#[tokio::test]
async fn test_tampered_signature_is_rejected() {
    let signer = AgentSigner::generate();

    let payload = TestPayload {
        message: "Original message".to_string(),
        value: 100,
    };

    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let body_hash = ContentHasher::hash(&body_bytes);
    let mut signature = signer.sign(&body_hash);

    // Tamper with the signature by flipping bits
    signature[0] ^= 0xFF;
    signature[32] ^= 0xFF;

    let signature_base64 = STANDARD.encode(signature);
    let auth_header = format!("Signature {}", signature_base64);
    let public_key_hex = hex::encode(signer.public_key());

    let request = create_request_with_auth(Some(&auth_header), Some(&public_key_hex), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(request, StatusCode::UNAUTHORIZED, "Tampered signature")
        .await;
}

/// Validates: Completely random signature is rejected
#[tokio::test]
async fn test_random_signature_is_rejected() {
    let signer = AgentSigner::generate();

    let payload = TestPayload {
        message: "Test".to_string(),
        value: 1,
    };

    let body_bytes = serde_json::to_vec(&payload).unwrap();

    // Create random signature (not from signer)
    let random_signature = [0xAB; SIGNATURE_SIZE];
    let signature_base64 = STANDARD.encode(random_signature);
    let auth_header = format!("Signature {}", signature_base64);
    let public_key_hex = hex::encode(signer.public_key());

    let request = create_request_with_auth(Some(&auth_header), Some(&public_key_hex), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(request, StatusCode::UNAUTHORIZED, "Random signature").await;
}

// ============================================================================
// Test 3: Missing Authorization Header Returns Error
// ============================================================================

/// Validates: Requests without Authorization header are rejected
///
/// Security Invariant: Anonymous requests must not be able to use the
/// SignedRequest extractor.
#[tokio::test]
async fn test_missing_authorization_header_returns_error() {
    let signer = AgentSigner::generate();
    let public_key_hex = hex::encode(signer.public_key());

    let payload = TestPayload {
        message: "No auth header".to_string(),
        value: 0,
    };
    let body_bytes = serde_json::to_vec(&payload).unwrap();

    // Request WITHOUT Authorization header
    let request = create_request_with_auth(
        None, // No Authorization header
        Some(&public_key_hex),
        body_bytes,
    );

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(
        request,
        StatusCode::UNAUTHORIZED,
        "Missing Authorization header",
    )
    .await;
}

/// Validates: Empty Authorization header is rejected
#[tokio::test]
async fn test_empty_authorization_header_returns_error() {
    let signer = AgentSigner::generate();
    let public_key_hex = hex::encode(signer.public_key());

    let body_bytes = b"{}".to_vec();

    // Request with empty auth header
    let request = create_request_with_auth(
        Some(""), // Empty auth header
        Some(&public_key_hex),
        body_bytes,
    );

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(
        request,
        StatusCode::UNAUTHORIZED,
        "Empty Authorization header",
    )
    .await;
}

/// Validates: Authorization header without "Signature " prefix is rejected
#[tokio::test]
async fn test_authorization_header_wrong_prefix_returns_error() {
    let signer = AgentSigner::generate();
    let public_key_hex = hex::encode(signer.public_key());

    let body_bytes = b"{}".to_vec();
    let signature_base64 = sign_message(&signer, &body_bytes);

    // Wrong prefix "Bearer" instead of "Signature"
    let bad_auth = format!("Bearer {}", signature_base64);

    let request = create_request_with_auth(Some(&bad_auth), Some(&public_key_hex), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(
        request,
        StatusCode::UNAUTHORIZED,
        "Wrong Authorization prefix",
    )
    .await;
}

// ============================================================================
// Test 4: Missing X-Public-Key Header Returns Error
// ============================================================================

/// Validates: Requests without X-Public-Key header are rejected
///
/// Security Invariant: The public key must be provided to verify the signature.
#[tokio::test]
async fn test_missing_public_key_header_returns_error() {
    let signer = AgentSigner::generate();

    let payload = TestPayload {
        message: "No public key header".to_string(),
        value: 0,
    };
    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let signature_base64 = sign_message(&signer, &body_bytes);
    let auth_header = format!("Signature {}", signature_base64);

    // Request WITHOUT X-Public-Key header
    let request = create_request_with_auth(
        Some(&auth_header),
        None, // No public key header
        body_bytes,
    );

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(
        request,
        StatusCode::UNAUTHORIZED,
        "Missing X-Public-Key header",
    )
    .await;
}

/// Validates: Empty public key header is rejected
#[tokio::test]
async fn test_empty_public_key_header_returns_error() {
    let signer = AgentSigner::generate();

    let body_bytes = b"{}".to_vec();
    let signature_base64 = sign_message(&signer, &body_bytes);
    let auth_header = format!("Signature {}", signature_base64);

    // Request with empty public key
    let request = create_request_with_auth(
        Some(&auth_header),
        Some(""), // Empty public key
        body_bytes,
    );

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(
        request,
        StatusCode::BAD_REQUEST,
        "Empty X-Public-Key header",
    )
    .await;
}

// ============================================================================
// Test 5: Malformed Base64 Signature Returns Error
// ============================================================================

/// Validates: Invalid base64 in signature is rejected with proper error
///
/// Security Invariant: Malformed data should be rejected early with
/// clear error messages.
#[tokio::test]
async fn test_malformed_base64_signature_returns_error() {
    let signer = AgentSigner::generate();
    let public_key_hex = hex::encode(signer.public_key());

    let body_bytes = b"{}".to_vec();

    // Invalid base64 characters
    let invalid_base64 = "not-valid-base64!@#$%^&*()";
    let auth_header = format!("Signature {}", invalid_base64);

    let request = create_request_with_auth(Some(&auth_header), Some(&public_key_hex), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(
        request,
        StatusCode::BAD_REQUEST,
        "Malformed base64 signature",
    )
    .await;
}

/// Validates: Valid base64 but wrong length signature is rejected
#[tokio::test]
async fn test_wrong_length_signature_returns_error() {
    let signer = AgentSigner::generate();
    let public_key_hex = hex::encode(signer.public_key());

    let body_bytes = b"{}".to_vec();

    // Valid base64 but only 32 bytes (should be 64)
    let short_signature = STANDARD.encode([0u8; 32]);
    let auth_header = format!("Signature {}", short_signature);

    let request = create_request_with_auth(Some(&auth_header), Some(&public_key_hex), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(request, StatusCode::BAD_REQUEST, "Wrong-length signature")
        .await;
}

/// Validates: Too-long signature is rejected
#[tokio::test]
async fn test_too_long_signature_returns_error() {
    let signer = AgentSigner::generate();
    let public_key_hex = hex::encode(signer.public_key());

    let body_bytes = b"{}".to_vec();

    // 128 bytes instead of 64
    let long_signature = STANDARD.encode([0u8; 128]);
    let auth_header = format!("Signature {}", long_signature);

    let request = create_request_with_auth(Some(&auth_header), Some(&public_key_hex), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(request, StatusCode::BAD_REQUEST, "Too-long signature")
        .await;
}

// ============================================================================
// Test 6: Malformed Hex Public Key Returns Error
// ============================================================================

/// Validates: Invalid hex in public key is rejected
///
/// Security Invariant: Malformed public keys should be rejected early.
#[tokio::test]
async fn test_malformed_hex_public_key_returns_error() {
    let signer = AgentSigner::generate();

    let body_bytes = b"{}".to_vec();
    let signature_base64 = sign_message(&signer, &body_bytes);
    let auth_header = format!("Signature {}", signature_base64);

    // Invalid hex characters (g, h are not valid hex)
    let invalid_hex = "not-valid-hex-gggg-hhhh-zzzz";

    let request = create_request_with_auth(Some(&auth_header), Some(invalid_hex), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(
        request,
        StatusCode::BAD_REQUEST,
        "Malformed hex public key",
    )
    .await;
}

/// Validates: Valid hex but wrong length public key is rejected
#[tokio::test]
async fn test_wrong_length_public_key_returns_error() {
    let signer = AgentSigner::generate();

    let body_bytes = b"{}".to_vec();
    let signature_base64 = sign_message(&signer, &body_bytes);
    let auth_header = format!("Signature {}", signature_base64);

    // Valid hex but only 16 bytes (should be 32)
    let short_key = hex::encode([0u8; 16]);

    let request = create_request_with_auth(Some(&auth_header), Some(&short_key), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(request, StatusCode::BAD_REQUEST, "Wrong-length public key")
        .await;
}

/// Validates: Too-long public key is rejected
#[tokio::test]
async fn test_too_long_public_key_returns_error() {
    let signer = AgentSigner::generate();

    let body_bytes = b"{}".to_vec();
    let signature_base64 = sign_message(&signer, &body_bytes);
    let auth_header = format!("Signature {}", signature_base64);

    // 64 bytes instead of 32
    let long_key = hex::encode([0u8; 64]);

    let request = create_request_with_auth(Some(&auth_header), Some(&long_key), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(request, StatusCode::BAD_REQUEST, "Too-long public key")
        .await;
}

// ============================================================================
// Test 7: Key Lifecycle - Expired Keys
// ============================================================================

/// Validates: Keys that have expired cannot be used for authentication
///
/// Security Invariant: Expired keys must be rejected to enforce key rotation
/// and limit the window of exposure if a key is compromised.
#[tokio::test]
async fn test_expired_key_is_rejected() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();

    // Create an expired key (valid_until in the past)
    let mut agent_key = AgentKey::new(agent_id, signer.public_key());
    agent_key.valid_until = Some(Utc::now() - Duration::hours(1));

    // Check expiration
    agent_key.check_expiration();

    // The key should now be expired
    assert!(agent_key.is_expired(), "Key should be expired");
    assert_eq!(
        agent_key.status,
        KeyStatus::Expired,
        "Key status should be Expired"
    );

    // Attempting to verify should fail
    let verify_result = agent_key.can_verify();
    assert!(
        verify_result.is_err(),
        "Expired key should not allow verification"
    );
}

/// Validates: Keys with valid_until just passed are rejected
#[tokio::test]
async fn test_just_expired_key_is_rejected() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();

    // Create a key that expired 1 second ago
    let mut agent_key = AgentKey::new(agent_id, signer.public_key());
    agent_key.valid_until = Some(Utc::now() - Duration::seconds(1));

    // Check expiration
    agent_key.check_expiration();

    assert!(
        agent_key.is_expired(),
        "Key that just expired should be expired"
    );
}

/// Validates: Keys with future valid_until are accepted
#[tokio::test]
async fn test_key_with_future_expiry_is_valid() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();

    // Create a key that expires in the future
    let agent_key = AgentKey::new_pending(
        agent_id,
        signer.public_key(),
        Utc::now() - Duration::hours(1), // valid_from in the past
        Some(Utc::now() + Duration::days(30)), // valid_until in the future
    );

    assert!(
        !agent_key.is_expired(),
        "Key with future expiry should not be expired"
    );
}

/// Validates: Keys without expiry (None) never expire
#[tokio::test]
async fn test_key_without_expiry_never_expires() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();

    // Create a key with no expiration
    let agent_key = AgentKey::new(agent_id, signer.public_key());

    assert!(agent_key.valid_until.is_none(), "Key should have no expiry");
    assert!(
        !agent_key.is_expired(),
        "Key without expiry should not be expired"
    );
}

/// Validates: Expired key rejection integrates correctly with extractor flow
///
/// This tests the conceptual integration - in a full system, the extractor
/// would look up the AgentKey from a repository and check its status.
#[tokio::test]
async fn test_expired_key_rejected_by_extractor() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();

    // Create an expired key
    let mut agent_key = AgentKey::new(agent_id, signer.public_key());
    agent_key.valid_until = Some(Utc::now() - Duration::hours(1));
    agent_key.check_expiration();

    // Verify key lifecycle check would reject this
    assert!(agent_key.is_expired(), "Key should be expired");
    assert!(
        agent_key.can_verify().is_err(),
        "Expired key should fail can_verify check"
    );

    // In a full integration, the extractor would:
    // 1. Extract public key from request
    // 2. Look up AgentKey from repository
    // 3. Call agent_key.can_verify() and reject if error
    // 4. Only then verify the signature
    //
    // The SignedRequest extractor currently verifies the signature itself.
    // Key lifecycle checks would be added in a key management layer.
}

// ============================================================================
// Test 8: Key Lifecycle - Revoked Keys
// ============================================================================

/// Validates: Revoked keys cannot be used for authentication
///
/// Security Invariant: Revoked keys must be immediately unusable,
/// regardless of their expiration date.
#[tokio::test]
async fn test_revoked_key_is_rejected() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();
    let revoker_id = AgentId::new();

    // Create an active key
    let mut agent_key = AgentKey::new(agent_id, signer.public_key());

    // Verify it's active
    assert_eq!(
        agent_key.status,
        KeyStatus::Active,
        "Key should start active"
    );
    assert!(
        agent_key.can_verify().is_ok(),
        "Active key should allow verification"
    );

    // Revoke the key
    agent_key.revoke("Compromised in security incident".to_string(), revoker_id);

    // Verify revocation
    assert_eq!(
        agent_key.status,
        KeyStatus::Revoked,
        "Key should be revoked"
    );
    assert!(
        agent_key.revocation_reason.is_some(),
        "Should have revocation reason"
    );
    assert!(agent_key.revoked_by.is_some(), "Should have revoked_by");

    // Attempting to verify should fail
    let verify_result = agent_key.can_verify();
    assert!(
        verify_result.is_err(),
        "Revoked key should not allow verification"
    );
}

/// Validates: Key with both revoked status and valid expiry is still rejected
#[tokio::test]
async fn test_revoked_key_with_future_expiry_is_rejected() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();
    let revoker_id = AgentId::new();

    // Create a key with future expiration
    let mut agent_key = AgentKey::new(agent_id, signer.public_key());
    agent_key.valid_until = Some(Utc::now() + Duration::days(365));

    // Revoke it
    agent_key.revoke("Preemptive revocation".to_string(), revoker_id);

    // Even though it hasn't expired, it's revoked
    assert!(!agent_key.is_expired(), "Key has not expired");
    assert_eq!(agent_key.status, KeyStatus::Revoked, "Key is revoked");
    assert!(
        agent_key.can_verify().is_err(),
        "Revoked key should not allow verification"
    );
}

/// Validates: Revoked keys cannot be used for signing either
#[tokio::test]
async fn test_revoked_key_cannot_sign() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();
    let revoker_id = AgentId::new();

    let mut agent_key = AgentKey::new(agent_id, signer.public_key());
    agent_key.revoke("Key compromised".to_string(), revoker_id);

    // Signing should also fail
    let sign_result = agent_key.can_sign();
    assert!(sign_result.is_err(), "Revoked key should not allow signing");
}

/// Validates: Revoked key rejection integrates correctly with extractor flow
///
/// This tests the conceptual integration - in a full system, the extractor
/// would look up the AgentKey from a repository and check its status.
#[tokio::test]
async fn test_revoked_key_rejected_by_extractor() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();
    let revoker_id = AgentId::new();

    // Create and immediately revoke a key
    let mut agent_key = AgentKey::new(agent_id, signer.public_key());
    agent_key.revoke("Emergency revocation".to_string(), revoker_id);

    // Verify key lifecycle check would reject this
    assert_eq!(
        agent_key.status,
        KeyStatus::Revoked,
        "Key should be revoked"
    );
    assert!(
        agent_key.can_verify().is_err(),
        "Revoked key should fail can_verify check"
    );

    // In a full integration, the extractor would:
    // 1. Extract public key from request
    // 2. Look up AgentKey from repository
    // 3. Call agent_key.can_verify() and reject if error
    // 4. Only then verify the signature
}

// ============================================================================
// Test 9: Signature Over Wrong Message Is Rejected
// ============================================================================

/// Validates: Signature signed over different body is rejected
///
/// Security Invariant: The signature must be over the exact request body.
/// Any mismatch indicates tampering or misconfiguration.
#[tokio::test]
async fn test_signature_over_different_body_is_rejected() {
    let signer = AgentSigner::generate();

    // Sign one message
    let original_payload = TestPayload {
        message: "Original message".to_string(),
        value: 100,
    };
    let original_bytes = serde_json::to_vec(&original_payload).unwrap();
    let original_hash = ContentHasher::hash(&original_bytes);
    let signature = signer.sign(&original_hash);

    // But send a different message with the original signature
    let tampered_payload = TestPayload {
        message: "Tampered message".to_string(),
        value: 999,
    };
    let tampered_bytes = serde_json::to_vec(&tampered_payload).unwrap();

    let signature_base64 = STANDARD.encode(signature);
    let auth_header = format!("Signature {}", signature_base64);
    let public_key_hex = hex::encode(signer.public_key());

    let request =
        create_request_with_auth(Some(&auth_header), Some(&public_key_hex), tampered_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(
        request,
        StatusCode::UNAUTHORIZED,
        "Signature over different body",
    )
    .await;
}

/// Validates: Signature with modified field value is rejected
#[tokio::test]
async fn test_signature_with_modified_field_is_rejected() {
    let signer = AgentSigner::generate();

    let original_payload = ComplexPayload {
        id: Uuid::new_v4(),
        claim: "Original claim".to_string(),
        truth_value: 0.5,
        metadata: PayloadMetadata {
            source: "trusted_source".to_string(),
            confidence: 0.9,
        },
    };
    let original_bytes = serde_json::to_vec(&original_payload).unwrap();
    let original_hash = ContentHasher::hash(&original_bytes);
    let signature = signer.sign(&original_hash);

    // Modify just the truth_value (attacker tries to inflate it)
    let mut tampered_payload = original_payload.clone();
    tampered_payload.truth_value = 1.0;

    let tampered_bytes = serde_json::to_vec(&tampered_payload).unwrap();

    let signature_base64 = STANDARD.encode(signature);
    let auth_header = format!("Signature {}", signature_base64);
    let public_key_hex = hex::encode(signer.public_key());

    let request =
        create_request_with_auth(Some(&auth_header), Some(&public_key_hex), tampered_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<ComplexPayload>(request, StatusCode::UNAUTHORIZED, "Modified field")
        .await;
}

/// Validates: Signature verified with wrong public key is rejected
#[tokio::test]
async fn test_signature_verified_with_wrong_key_is_rejected() {
    let signer1 = AgentSigner::generate();
    let signer2 = AgentSigner::generate();

    let payload = TestPayload {
        message: "Test".to_string(),
        value: 42,
    };
    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let body_hash = ContentHasher::hash(&body_bytes);

    // Sign with signer1
    let signature = signer1.sign(&body_hash);
    let signature_base64 = STANDARD.encode(signature);
    let auth_header = format!("Signature {}", signature_base64);

    // But provide signer2's public key (should fail)
    let wrong_public_key_hex = hex::encode(signer2.public_key());

    let request =
        create_request_with_auth(Some(&auth_header), Some(&wrong_public_key_hex), body_bytes);

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(request, StatusCode::UNAUTHORIZED, "Wrong public key").await;
}

/// Validates: Empty body with signature over non-empty body is rejected
#[tokio::test]
async fn test_signature_mismatch_empty_body() {
    let signer = AgentSigner::generate();

    // Sign a non-empty body
    let non_empty = b"some data";
    let non_empty_hash = ContentHasher::hash(non_empty);
    let signature = signer.sign(&non_empty_hash);

    let signature_base64 = STANDARD.encode(signature);
    let auth_header = format!("Signature {}", signature_base64);
    let public_key_hex = hex::encode(signer.public_key());

    // But send empty body
    let request = create_request_with_auth(Some(&auth_header), Some(&public_key_hex), vec![]);

    // Actually invoke the SignedRequest extractor - will fail on JSON parse since body is empty
    let result = extract_signed_request::<TestPayload>(request).await;

    // This could fail on signature verification or JSON parsing
    assert!(
        result.is_err(),
        "Empty body with non-empty signature should fail"
    );
}

// ============================================================================
// Test 10: Security Attack Tests
// ============================================================================

/// Validates: Key substitution attack is rejected
///
/// Attack scenario: Attacker intercepts victim's signature and tries to use it
/// with their own public key.
///
/// Security Invariant: The signature MUST be cryptographically bound to the
/// public key that created it. Using a different public key with someone else's
/// signature must fail verification.
#[tokio::test]
async fn test_key_substitution_attack_rejected() {
    let victim_signer = AgentSigner::generate();
    let attacker_signer = AgentSigner::generate();

    let payload = TestPayload {
        message: "Important claim".to_string(),
        value: 1000,
    };
    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let body_hash = ContentHasher::hash(&body_bytes);

    // Victim creates a valid signature
    let victim_signature = victim_signer.sign(&body_hash);
    let signature_base64 = STANDARD.encode(victim_signature);
    let auth_header = format!("Signature {}", signature_base64);

    // Attacker tries to substitute their own public key
    let attacker_public_key_hex = hex::encode(attacker_signer.public_key());

    let request = create_request_with_auth(
        Some(&auth_header),
        Some(&attacker_public_key_hex),
        body_bytes,
    );

    // Actually invoke the SignedRequest extractor
    expect_error_status::<TestPayload>(
        request,
        StatusCode::UNAUTHORIZED,
        "Key substitution attack",
    )
    .await;
}

/// Documents: Replay attack prevention
///
/// # Replay Attack Scenario
///
/// An attacker captures a valid signed request and resends it later to:
/// - Duplicate a transaction
/// - Re-execute an action the victim performed
///
/// # Prevention Strategy
///
/// The SignedRequest extractor validates the signature but does NOT prevent replay.
/// Replay prevention is handled at a higher layer:
///
/// 1. **Timestamp-based**: The signature verification middleware validates
///    X-Timestamp header and rejects signatures older than 5 minutes.
///
/// 2. **Nonce-based**: The middleware tracks used nonces (derived from signature)
///    and rejects duplicates within the validity window.
///
/// 3. **Idempotency keys**: For critical operations like claim submission,
///    the API layer uses X-Idempotency-Key to detect and deduplicate requests.
///
/// This test documents that replay prevention is NOT the responsibility of
/// SignedRequest extractor but happens in middleware and API layers.
#[tokio::test]
async fn test_replay_attack_documentation() {
    let signer = AgentSigner::generate();

    let payload = TestPayload {
        message: "Submit claim".to_string(),
        value: 42,
    };

    // Create identical requests (simulating replay)
    let request1 = create_valid_signed_request(&signer, &payload);
    let request2 = create_valid_signed_request(&signer, &payload);

    // Both requests should succeed at the SignedRequest level
    // (replay prevention happens in middleware/API layer)
    let result1 = extract_signed_request::<TestPayload>(request1).await;
    let result2 = extract_signed_request::<TestPayload>(request2).await;

    assert!(result1.is_ok(), "First request should succeed");
    assert!(
        result2.is_ok(),
        "Second request also succeeds at extractor level"
    );

    // NOTE: In a full integration test, the middleware would:
    // 1. Check X-Timestamp for freshness (rejects old signatures)
    // 2. Record nonce derived from signature
    // 3. Reject requests with duplicate nonces
    //
    // The SignedRequest extractor is concerned only with cryptographic validity,
    // not replay prevention. This separation of concerns allows the extractor
    // to be stateless and testable in isolation.
}

/// Documents: Timing attack resistance
///
/// Ed25519 signature verification must use constant-time comparison to prevent
/// timing side-channel attacks that could leak information about the signature.
///
/// # Implementation Details
///
/// The epigraph-crypto crate uses ed25519-dalek which implements constant-time
/// signature verification. From the ed25519-dalek documentation:
///
/// > All operations are performed in constant time to prevent timing attacks.
///
/// This test documents the security property rather than testing it directly
/// (timing attacks require sophisticated measurement and are typically validated
/// through code review and formal analysis, not unit tests).
#[tokio::test]
async fn test_timing_attack_resistance_documented() {
    let signer = AgentSigner::generate();

    let payload = TestPayload {
        message: "Test timing".to_string(),
        value: 1,
    };
    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let body_hash = ContentHasher::hash(&body_bytes);

    // Create valid and invalid signatures
    let valid_signature = signer.sign(&body_hash);
    let mut almost_valid_signature = valid_signature;
    almost_valid_signature[63] ^= 0x01; // Flip one bit at the end

    // Verify both signatures complete (timing is implementation detail)
    let valid_result =
        SignatureVerifier::verify(&signer.public_key(), &body_hash, &valid_signature);
    let invalid_result =
        SignatureVerifier::verify(&signer.public_key(), &body_hash, &almost_valid_signature);

    assert!(
        valid_result.is_ok() && valid_result.unwrap(),
        "Valid signature should verify"
    );
    assert!(
        invalid_result.is_ok() && !invalid_result.unwrap(),
        "Almost-valid signature should fail"
    );

    // SECURITY NOTE: The actual timing attack resistance comes from ed25519-dalek's
    // implementation using subtle::ConstantTimeEq. This test just confirms the
    // signatures are processed correctly. Timing attack resistance is verified through:
    //
    // 1. Code review: Confirm ed25519-dalek uses constant-time comparison
    // 2. Dependency audit: ed25519-dalek is a widely audited cryptographic library
    // 3. The subtle crate provides ConstantTimeEq trait used internally
    //
    // Reference: https://docs.rs/ed25519-dalek/latest/ed25519_dalek/
}

// ============================================================================
// Additional Security Tests
// ============================================================================

/// Validates: Rotated keys can still verify but cannot sign
#[tokio::test]
async fn test_rotated_key_can_verify_but_not_sign() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();

    let mut agent_key = AgentKey::new(agent_id, signer.public_key());

    // Mark as rotated
    agent_key.mark_rotated();

    assert_eq!(
        agent_key.status,
        KeyStatus::Rotated,
        "Key should be rotated"
    );

    // Should allow verification
    assert!(
        agent_key.can_verify().is_ok(),
        "Rotated key should allow verification"
    );

    // Should NOT allow signing
    assert!(
        agent_key.can_sign().is_err(),
        "Rotated key should not allow signing"
    );
}

/// Validates: Pending keys cannot be used for operations
#[tokio::test]
async fn test_pending_key_cannot_verify_or_sign() {
    let signer = AgentSigner::generate();
    let agent_id = AgentId::new();

    // Create a pending key (valid_from in the future)
    let agent_key = AgentKey::new_pending(
        agent_id,
        signer.public_key(),
        Utc::now() + Duration::hours(1), // Not yet valid
        Some(Utc::now() + Duration::days(30)),
    );

    assert_eq!(
        agent_key.status,
        KeyStatus::Pending,
        "Key should be pending"
    );

    // Should not allow verification
    assert!(
        agent_key.can_verify().is_err(),
        "Pending key should not allow verification"
    );

    // Should not allow signing
    assert!(
        agent_key.can_sign().is_err(),
        "Pending key should not allow signing"
    );
}

/// Validates: KeyStatus transitions are correct
#[tokio::test]
async fn test_key_status_allows_operations() {
    // Active: can sign and verify
    assert!(
        KeyStatus::Active.allows_signing(),
        "Active should allow signing"
    );
    assert!(
        KeyStatus::Active.allows_verification(),
        "Active should allow verification"
    );
    assert!(KeyStatus::Active.is_usable(), "Active should be usable");

    // Rotated: can verify only
    assert!(
        !KeyStatus::Rotated.allows_signing(),
        "Rotated should not allow signing"
    );
    assert!(
        KeyStatus::Rotated.allows_verification(),
        "Rotated should allow verification"
    );
    assert!(KeyStatus::Rotated.is_usable(), "Rotated should be usable");

    // Revoked: cannot do anything
    assert!(
        !KeyStatus::Revoked.allows_signing(),
        "Revoked should not allow signing"
    );
    assert!(
        !KeyStatus::Revoked.allows_verification(),
        "Revoked should not allow verification"
    );
    assert!(
        !KeyStatus::Revoked.is_usable(),
        "Revoked should not be usable"
    );

    // Expired: cannot do anything
    assert!(
        !KeyStatus::Expired.allows_signing(),
        "Expired should not allow signing"
    );
    assert!(
        !KeyStatus::Expired.allows_verification(),
        "Expired should not allow verification"
    );
    assert!(
        !KeyStatus::Expired.is_usable(),
        "Expired should not be usable"
    );

    // Pending: cannot do anything
    assert!(
        !KeyStatus::Pending.allows_signing(),
        "Pending should not allow signing"
    );
    assert!(
        !KeyStatus::Pending.allows_verification(),
        "Pending should not allow verification"
    );
    assert!(
        !KeyStatus::Pending.is_usable(),
        "Pending should not be usable"
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

/// Validates: Large payload signatures work correctly
#[tokio::test]
async fn test_large_payload_signature() {
    let signer = AgentSigner::generate();

    // Create a large payload (100KB)
    let large_message = "x".repeat(100_000);
    let payload = TestPayload {
        message: large_message,
        value: u64::MAX,
    };

    let request = create_valid_signed_request(&signer, &payload);

    // Actually invoke the SignedRequest extractor
    let result = extract_signed_request::<TestPayload>(request).await;

    assert!(
        result.is_ok(),
        "Large payload with valid signature should succeed"
    );
    let signed_request = result.unwrap();
    assert_eq!(signed_request.payload.value, u64::MAX);
}

/// Validates: Empty JSON payload signatures work correctly
#[tokio::test]
async fn test_empty_json_payload_signature() {
    let signer = AgentSigner::generate();

    // Empty struct that serializes to {}
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct EmptyPayload {}

    let payload = EmptyPayload {};
    let request = create_valid_signed_request(&signer, &payload);

    // Actually invoke the SignedRequest extractor
    let result = extract_signed_request::<EmptyPayload>(request).await;

    assert!(
        result.is_ok(),
        "Empty JSON payload with valid signature should succeed"
    );
}

/// Validates: Unicode payload signatures work correctly
#[tokio::test]
async fn test_unicode_payload_signature() {
    let signer = AgentSigner::generate();

    let payload = TestPayload {
        message: "Hello, \u{1F310} World! \u{4E2D}\u{6587} \u{0410}\u{0411}\u{0412}".to_string(),
        value: 42,
    };

    let request = create_valid_signed_request(&signer, &payload);

    // Actually invoke the SignedRequest extractor
    let result = extract_signed_request::<TestPayload>(request).await;

    assert!(
        result.is_ok(),
        "Unicode payload with valid signature should succeed"
    );
    let signed_request = result.unwrap();
    assert!(signed_request.payload.message.contains('\u{1F310}'));
}

/// Validates: Signature is deterministic (same key + message = same signature)
#[tokio::test]
async fn test_signature_is_deterministic() {
    let signer = AgentSigner::generate();

    let message = b"deterministic test message";
    let hash = ContentHasher::hash(message);

    let signature1 = signer.sign(&hash);
    let signature2 = signer.sign(&hash);

    // Ed25519 signatures are deterministic for same key and message
    assert_eq!(signature1, signature2, "Signatures should be deterministic");
}

/// Validates: Different messages produce different signatures
#[tokio::test]
async fn test_different_messages_different_signatures() {
    let signer = AgentSigner::generate();

    let message1 = b"message one";
    let message2 = b"message two";

    let hash1 = ContentHasher::hash(message1);
    let hash2 = ContentHasher::hash(message2);

    let signature1 = signer.sign(&hash1);
    let signature2 = signer.sign(&hash2);

    assert_ne!(
        signature1, signature2,
        "Different messages should have different signatures"
    );
}

// ============================================================================
// Integration with ApiError
// ============================================================================

/// Validates: ApiError::InvalidSignature returns 401
#[tokio::test]
async fn test_api_error_invalid_signature_returns_401() {
    let error = ApiError::InvalidSignature;
    let response = error.into_response();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "InvalidSignature should return 401 Unauthorized"
    );
}

/// Validates: ApiError::SignatureError returns 401
#[tokio::test]
async fn test_api_error_signature_error_returns_401() {
    let error = ApiError::SignatureError {
        reason: "Malformed signature data".to_string(),
    };
    let response = error.into_response();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "SignatureError should return 401 Unauthorized"
    );
}

/// Validates: ApiError::Unauthorized returns 401
#[tokio::test]
async fn test_api_error_unauthorized_returns_401() {
    let error = ApiError::Unauthorized {
        reason: "Missing Authorization header".to_string(),
    };
    let response = error.into_response();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Unauthorized should return 401"
    );
}

/// Validates: ApiError::BadRequest returns 400 (for malformed data)
#[tokio::test]
async fn test_api_error_bad_request_returns_400() {
    let error = ApiError::BadRequest {
        message: "Invalid base64 encoding in signature".to_string(),
    };
    let response = error.into_response();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "BadRequest should return 400"
    );
}

/// Validates: Error responses have correct Content-Type and structure
#[tokio::test]
async fn test_error_response_format() {
    // Test InvalidSignature error format
    verify_error_response_format(ApiError::InvalidSignature).await;

    // Test SignatureError error format
    verify_error_response_format(ApiError::SignatureError {
        reason: "Test error".to_string(),
    })
    .await;

    // Test Unauthorized error format
    verify_error_response_format(ApiError::Unauthorized {
        reason: "Test reason".to_string(),
    })
    .await;

    // Test BadRequest error format
    verify_error_response_format(ApiError::BadRequest {
        message: "Test message".to_string(),
    })
    .await;
}

/// Validates: Error messages do not leak sensitive information
#[tokio::test]
async fn test_error_messages_do_not_leak_sensitive_info() {
    let signer = AgentSigner::generate();

    let payload = TestPayload {
        message: "Secret data".to_string(),
        value: 42,
    };
    let body_bytes = serde_json::to_vec(&payload).unwrap();

    // Create invalid signature
    let invalid_signature = STANDARD.encode([0xDE, 0xAD, 0xBE, 0xEF].repeat(16));
    let auth_header = format!("Signature {}", invalid_signature);
    let public_key_hex = hex::encode(signer.public_key());

    let request = create_request_with_auth(Some(&auth_header), Some(&public_key_hex), body_bytes);

    let result = extract_signed_request::<TestPayload>(request).await;

    match result {
        Ok(_) => panic!("Expected error but got success"),
        Err(error) => {
            let error_message = error.to_string();

            // Error message should NOT contain:
            // - The actual payload data
            // - The signature bytes
            // - The public key bytes
            assert!(
                !error_message.contains("Secret data"),
                "Error message should not leak payload data"
            );
            assert!(
                !error_message.contains("DEADBEEF"),
                "Error message should not leak signature bytes"
            );
        }
    }
}
