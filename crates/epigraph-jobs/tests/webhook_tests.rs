//! TDD Tests for `WebhookNotificationHandler`
//!
//! These tests define the expected behavior of the webhook notification job handler.
//! Webhooks must be reliable, handle failures gracefully, and implement proper retry logic.
//!
//! # Test Categories
//!
//! 1. Success cases: HTTP POST with correct payload
//! 2. Security: HMAC-SHA256 signatures, SSRF protection
//! 3. Retry logic: Exponential backoff, permanent vs transient failures
//! 4. Timeout handling: Slow endpoints should not block indefinitely
//! 5. Error responses: Proper categorization of HTTP status codes
//! 6. Payload validation: Correct serialization format

use epigraph_jobs::{
    async_trait, compute_hmac_signature, extract_host_from_url, is_internal_ip,
    verify_hmac_signature, ConfigurableWebhookHandler, EpiGraphJob, HttpClient, HttpError,
    HttpResponse, InMemoryJobQueue, Job, JobError, JobHandler, JobRunner, WebhookConfig,
    WebhookNotificationHandler, WebhookRepository,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

// ============================================================================
// Mock HTTP Client for Testing
// ============================================================================

/// Represents an HTTP request captured by the mock client
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub timestamp: Instant,
}

/// Configuration for mock HTTP response behavior
#[derive(Debug, Clone)]
pub struct MockResponseConfig {
    /// HTTP status code to return
    pub status_code: u16,
    /// Response body
    pub body: String,
    /// Simulated latency before responding
    pub latency: Duration,
    /// Number of times to fail before succeeding (for retry testing)
    pub fail_count: u32,
    /// Optional Retry-After header value for 429 responses
    pub retry_after: Option<u64>,
}

impl Default for MockResponseConfig {
    fn default() -> Self {
        Self {
            status_code: 200,
            body: r#"{"status": "ok"}"#.to_string(),
            latency: Duration::from_millis(10),
            fail_count: 0,
            retry_after: None,
        }
    }
}

/// Mock HTTP client that captures requests and returns configured responses
pub struct MockHttpClient {
    requests: RwLock<Vec<CapturedRequest>>,
    response_config: RwLock<MockResponseConfig>,
    call_count: AtomicU32,
    total_latency_ms: AtomicU64,
}

impl Default for MockHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MockHttpClient {
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: RwLock::new(Vec::new()),
            response_config: RwLock::new(MockResponseConfig::default()),
            call_count: AtomicU32::new(0),
            total_latency_ms: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub const fn with_config(config: MockResponseConfig) -> Self {
        Self {
            requests: RwLock::new(Vec::new()),
            response_config: RwLock::new(config),
            call_count: AtomicU32::new(0),
            total_latency_ms: AtomicU64::new(0),
        }
    }

    pub fn set_response_config(&self, config: MockResponseConfig) {
        *self.response_config.write().unwrap() = config;
    }

    pub fn get_requests(&self) -> Vec<CapturedRequest> {
        self.requests.read().unwrap().clone()
    }

    pub fn get_call_count(&self) -> u32 {
        self.call_count.load(Ordering::SeqCst)
    }

    pub fn get_last_request(&self) -> Option<CapturedRequest> {
        self.requests.read().unwrap().last().cloned()
    }

    pub fn clear_requests(&self) {
        self.requests.write().unwrap().clear();
        self.call_count.store(0, Ordering::SeqCst);
    }
}

#[async_trait]
impl HttpClient for MockHttpClient {
    async fn post(
        &self,
        url: &str,
        headers: HashMap<String, String>,
        body: &str,
    ) -> Result<HttpResponse, HttpError> {
        let config = self.response_config.read().unwrap().clone();
        let current_call = self.call_count.fetch_add(1, Ordering::SeqCst);

        // Capture the request
        self.requests.write().unwrap().push(CapturedRequest {
            url: url.to_string(),
            method: "POST".to_string(),
            headers,
            body: body.to_string(),
            timestamp: Instant::now(),
        });

        // Simulate latency
        tokio::time::sleep(config.latency).await;
        self.total_latency_ms
            .fetch_add(config.latency.as_millis() as u64, Ordering::SeqCst);

        // Simulate transient failures for retry testing
        if current_call < config.fail_count {
            return Err(HttpError::TransientFailure {
                message: format!("Simulated failure #{}", current_call + 1),
            });
        }

        // Return configured response
        Ok(HttpResponse {
            status_code: config.status_code,
            body: config.body.clone(),
        })
    }
}

// ============================================================================
// Mock Webhook Repository
// ============================================================================

/// Mock repository for webhook configurations
pub struct MockWebhookRepository {
    configs: RwLock<HashMap<Uuid, WebhookConfig>>,
}

impl MockWebhookRepository {
    #[must_use]
    pub fn new() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_webhook(&self, config: WebhookConfig) {
        self.configs.write().unwrap().insert(config.id, config);
    }
}

impl Default for MockWebhookRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WebhookRepository for MockWebhookRepository {
    async fn get_webhook(&self, id: Uuid) -> Option<WebhookConfig> {
        self.configs.read().unwrap().get(&id).cloned()
    }
}

// ============================================================================
// Helper to create a standard test handler
// ============================================================================

fn create_test_handler(
    http_client: Arc<MockHttpClient>,
    webhook_repo: Arc<MockWebhookRepository>,
) -> ConfigurableWebhookHandler {
    ConfigurableWebhookHandler::new(http_client, webhook_repo)
}

// ============================================================================
// Test: HMAC Signature Generation and Verification (SECURITY CRITICAL)
// ============================================================================

/// HMAC signature should be cryptographically secure and verifiable
#[test]
fn test_hmac_signature_can_be_verified_by_receiver() {
    let secret = "webhook-secret-key-12345";
    let payload = r#"{"event":"claim_verified","claim_id":"abc123"}"#;

    // Generate signature
    let signature = compute_hmac_signature(secret, payload);

    // Signature should be prefixed with sha256=
    assert!(
        signature.starts_with("sha256="),
        "Signature should be prefixed with sha256="
    );

    // Signature should be hex-encoded (64 chars for SHA-256)
    let sig_hex = signature.strip_prefix("sha256=").unwrap();
    assert_eq!(
        sig_hex.len(),
        64,
        "SHA-256 hex should be 64 characters, got {}",
        sig_hex.len()
    );

    // Verify the signature is valid hex
    assert!(
        hex::decode(sig_hex).is_ok(),
        "Signature should be valid hex"
    );

    // Verify signature using verification function
    assert!(
        verify_hmac_signature(secret, payload, &signature),
        "Signature should be verifiable with same secret and payload"
    );

    // Verify without prefix also works
    assert!(
        verify_hmac_signature(secret, payload, sig_hex),
        "Signature should be verifiable without sha256= prefix"
    );
}

/// Tampered payload should break signature verification
#[test]
fn test_tampered_payload_breaks_signature() {
    let secret = "webhook-secret-key-12345";
    let original_payload = r#"{"event":"claim_verified","claim_id":"abc123"}"#;
    let tampered_payload = r#"{"event":"claim_verified","claim_id":"HACKED"}"#;

    // Generate signature for original payload
    let signature = compute_hmac_signature(secret, original_payload);

    // Verify original passes
    assert!(
        verify_hmac_signature(secret, original_payload, &signature),
        "Original payload should verify"
    );

    // Verify tampered payload fails
    assert!(
        !verify_hmac_signature(secret, tampered_payload, &signature),
        "Tampered payload should NOT verify"
    );
}

/// Wrong secret should fail verification
#[test]
fn test_wrong_secret_fails_verification() {
    let correct_secret = "correct-secret";
    let wrong_secret = "wrong-secret";
    let payload = r#"{"event":"test"}"#;

    let signature = compute_hmac_signature(correct_secret, payload);

    assert!(
        verify_hmac_signature(correct_secret, payload, &signature),
        "Correct secret should verify"
    );
    assert!(
        !verify_hmac_signature(wrong_secret, payload, &signature),
        "Wrong secret should NOT verify"
    );
}

/// Different payloads should produce different signatures
#[test]
fn test_different_payloads_different_signatures() {
    let secret = "test-secret";
    let payload1 = r#"{"event":"event1"}"#;
    let payload2 = r#"{"event":"event2"}"#;

    let sig1 = compute_hmac_signature(secret, payload1);
    let sig2 = compute_hmac_signature(secret, payload2);

    assert_ne!(
        sig1, sig2,
        "Different payloads should produce different signatures"
    );
}

/// Same payload and secret should produce deterministic signature
#[test]
fn test_signature_is_deterministic() {
    let secret = "test-secret";
    let payload = r#"{"event":"test"}"#;

    let sig1 = compute_hmac_signature(secret, payload);
    let sig2 = compute_hmac_signature(secret, payload);

    assert_eq!(sig1, sig2, "Same inputs should produce same signature");
}

// ============================================================================
// Test: SSRF Protection (SECURITY CRITICAL)
// ============================================================================

/// Internal IP addresses should be blocked (loopback)
#[test]
fn test_ssrf_blocks_loopback_addresses() {
    assert!(is_internal_ip("127.0.0.1"), "127.0.0.1 should be blocked");
    assert!(is_internal_ip("127.0.0.2"), "127.0.0.2 should be blocked");
    assert!(
        is_internal_ip("127.255.255.255"),
        "127.255.255.255 should be blocked"
    );
    assert!(is_internal_ip("localhost"), "localhost should be blocked");
    assert!(
        is_internal_ip("sub.localhost"),
        "sub.localhost should be blocked"
    );
}

/// Internal IP addresses should be blocked (private ranges)
#[test]
fn test_ssrf_blocks_private_addresses() {
    // 10.0.0.0/8
    assert!(is_internal_ip("10.0.0.1"), "10.0.0.1 should be blocked");
    assert!(
        is_internal_ip("10.255.255.255"),
        "10.255.255.255 should be blocked"
    );

    // 172.16.0.0/12
    assert!(is_internal_ip("172.16.0.1"), "172.16.0.1 should be blocked");
    assert!(
        is_internal_ip("172.31.255.255"),
        "172.31.255.255 should be blocked"
    );
    assert!(
        !is_internal_ip("172.15.0.1"),
        "172.15.0.1 should NOT be blocked"
    );
    assert!(
        !is_internal_ip("172.32.0.1"),
        "172.32.0.1 should NOT be blocked"
    );

    // 192.168.0.0/16
    assert!(
        is_internal_ip("192.168.0.1"),
        "192.168.0.1 should be blocked"
    );
    assert!(
        is_internal_ip("192.168.255.255"),
        "192.168.255.255 should be blocked"
    );
}

/// Link-local addresses should be blocked
#[test]
fn test_ssrf_blocks_link_local_addresses() {
    assert!(
        is_internal_ip("169.254.0.1"),
        "169.254.0.1 should be blocked"
    );
    assert!(
        is_internal_ip("169.254.169.254"),
        "AWS metadata endpoint should be blocked"
    );
    assert!(
        is_internal_ip("169.254.255.255"),
        "169.254.255.255 should be blocked"
    );
}

/// External/public IP addresses should be allowed
#[test]
fn test_ssrf_allows_external_addresses() {
    assert!(!is_internal_ip("8.8.8.8"), "8.8.8.8 should be allowed");
    assert!(!is_internal_ip("1.1.1.1"), "1.1.1.1 should be allowed");
    assert!(
        !is_internal_ip("93.184.216.34"),
        "example.com IP should be allowed"
    );
    assert!(
        !is_internal_ip("203.0.113.1"),
        "203.0.113.1 should be allowed"
    );
}

/// URL host extraction should work correctly
#[test]
fn test_extract_host_from_url() {
    assert_eq!(
        extract_host_from_url("https://example.com/webhook"),
        Some("example.com".to_string())
    );
    assert_eq!(
        extract_host_from_url("http://192.168.1.1:8080/api"),
        Some("192.168.1.1".to_string())
    );
    assert_eq!(
        extract_host_from_url("https://localhost/test"),
        Some("localhost".to_string())
    );
    assert_eq!(
        extract_host_from_url("https://127.0.0.1:3000"),
        Some("127.0.0.1".to_string())
    );
}

/// Webhook to internal IP should be rejected
#[tokio::test]
async fn test_ssrf_internal_ip_rejected() {
    let http_client = Arc::new(MockHttpClient::new());
    let webhook_repo = Arc::new(MockWebhookRepository::new());

    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "http://192.168.1.1:8080/internal".to_string(), // Internal IP!
        secret: None,
        enabled: true,
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client.clone(), webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({"event": "test"}),
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await;

    assert!(result.is_err(), "Internal IP should be rejected");
    match result {
        Err(JobError::SsrfBlocked { address }) => {
            assert!(
                address.contains("192.168"),
                "Error should mention blocked address: {address}"
            );
        }
        Err(e) => panic!("Expected SsrfBlocked error, got: {e:?}"),
        Ok(_) => panic!("Should have failed for internal IP"),
    }

    // Verify NO HTTP request was made
    assert_eq!(
        http_client.get_call_count(),
        0,
        "No HTTP request should be made for internal IPs"
    );
}

/// Webhook to localhost should be rejected
#[tokio::test]
async fn test_ssrf_localhost_rejected() {
    let http_client = Arc::new(MockHttpClient::new());
    let webhook_repo = Arc::new(MockWebhookRepository::new());

    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "http://localhost:3000/webhook".to_string(),
        secret: None,
        enabled: true,
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client.clone(), webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({"event": "test"}),
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await;

    assert!(result.is_err(), "localhost should be rejected");
    matches!(result, Err(JobError::SsrfBlocked { .. }));
}

// ============================================================================
// Test: Webhook Sends HTTP POST with Payload
// ============================================================================

/// Webhook handler should send HTTP POST to configured URL with correct payload
#[tokio::test]
async fn test_webhook_sends_http_post_with_payload() {
    let http_client = Arc::new(MockHttpClient::new());
    let webhook_repo = Arc::new(MockWebhookRepository::new());

    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "https://example.com/webhook".to_string(),
        secret: Some("test-secret".to_string()),
        enabled: true,
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client.clone(), webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({
            "event": "claim_verified",
            "claim_id": "12345",
            "truth_value": 0.95
        }),
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await;

    assert!(result.is_ok(), "Webhook notification should succeed");

    // Verify the request was made
    let requests = http_client.get_requests();
    assert_eq!(requests.len(), 1, "Should have made exactly one request");

    let request = &requests[0];
    assert_eq!(request.url, "https://example.com/webhook");

    // Verify headers
    assert_eq!(
        request.headers.get("Content-Type").unwrap(),
        "application/json"
    );
    assert!(request.headers.contains_key("X-Webhook-Signature"));
    assert!(request.headers.contains_key("X-Webhook-ID"));

    // Verify payload was serialized correctly
    let sent_payload: serde_json::Value = serde_json::from_str(&request.body).unwrap();
    assert_eq!(sent_payload["event"], "claim_verified");
    assert_eq!(sent_payload["claim_id"], "12345");
    assert_eq!(sent_payload["truth_value"], 0.95);
}

/// Webhook signature in header should be verifiable
#[tokio::test]
async fn test_webhook_signature_is_verifiable() {
    let http_client = Arc::new(MockHttpClient::new());
    let webhook_repo = Arc::new(MockWebhookRepository::new());
    let secret = "my-webhook-secret";

    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "https://example.com/webhook".to_string(),
        secret: Some(secret.to_string()),
        enabled: true,
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client.clone(), webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({"event": "test_event"}),
    }
    .into_job()
    .unwrap();

    let _ = handler.handle(&job).await;

    let request = http_client.get_last_request().unwrap();
    let signature = request.headers.get("X-Webhook-Signature").unwrap();

    // The receiver should be able to verify this signature
    assert!(
        verify_hmac_signature(secret, &request.body, signature),
        "Receiver should be able to verify the signature"
    );
}

/// Webhook without secret should not include signature header
#[tokio::test]
async fn test_webhook_without_secret_no_signature() {
    let http_client = Arc::new(MockHttpClient::new());
    let webhook_repo = Arc::new(MockWebhookRepository::new());

    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "https://example.com/public-webhook".to_string(),
        secret: None, // No secret configured
        enabled: true,
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client.clone(), webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({"event": "test"}),
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await;
    assert!(result.is_ok());

    let request = http_client.get_last_request().unwrap();
    assert!(
        !request.headers.contains_key("X-Webhook-Signature"),
        "Should not include signature when no secret is configured"
    );
}

// ============================================================================
// Test: Exponential Backoff (Deterministic Tests)
// ============================================================================

/// Handler should implement exponential backoff with cap at 16 seconds
#[test]
fn test_exponential_backoff_formula() {
    let handler = WebhookNotificationHandler;

    // Verify exponential backoff: 2^attempt seconds, capped at 16
    assert_eq!(handler.backoff(0), Duration::from_secs(1)); // 2^0 = 1
    assert_eq!(handler.backoff(1), Duration::from_secs(2)); // 2^1 = 2
    assert_eq!(handler.backoff(2), Duration::from_secs(4)); // 2^2 = 4
    assert_eq!(handler.backoff(3), Duration::from_secs(8)); // 2^3 = 8
    assert_eq!(handler.backoff(4), Duration::from_secs(16)); // 2^4 = 16 (cap)
}

/// Backoff should be capped at 16 seconds
#[test]
fn test_backoff_capped_at_16_seconds() {
    let handler = WebhookNotificationHandler;

    // All attempts >= 4 should be capped at 16 seconds
    assert_eq!(handler.backoff(4), Duration::from_secs(16));
    assert_eq!(handler.backoff(5), Duration::from_secs(16));
    assert_eq!(handler.backoff(10), Duration::from_secs(16));
    assert_eq!(handler.backoff(100), Duration::from_secs(16));
}

/// Handler should have `max_retries` set appropriately
#[test]
fn test_max_retries_configured() {
    let handler = WebhookNotificationHandler;
    assert_eq!(handler.max_retries(), 5, "Should allow up to 5 retries");
}

/// Deterministic backoff timing test (no actual sleeping)
#[test]
fn test_retry_timing_with_backoff_deterministic() {
    let handler = WebhookNotificationHandler;

    // Calculate total expected backoff time for all retries
    let mut total_backoff = Duration::ZERO;
    for attempt in 0..handler.max_retries() {
        total_backoff += handler.backoff(attempt);
    }

    // 1 + 2 + 4 + 8 + 16 = 31 seconds
    assert_eq!(total_backoff, Duration::from_secs(31));
}

// ============================================================================
// Test: Permanent vs Transient Failure (4xx vs 5xx)
// ============================================================================

/// 4xx errors (except 429) should be permanent failures and not retry
#[tokio::test]
async fn test_permanent_failure_no_retry() {
    let permanent_error_codes = [400, 401, 403, 404, 405, 410, 422];

    for status_code in permanent_error_codes {
        let http_client = Arc::new(MockHttpClient::with_config(MockResponseConfig {
            status_code,
            body: format!(r#"{{"error": "Client error {status_code}"}}"#),
            latency: Duration::from_millis(10),
            fail_count: 0,
            retry_after: None,
        }));

        let webhook_repo = Arc::new(MockWebhookRepository::new());
        let webhook_id = Uuid::new_v4();
        webhook_repo.add_webhook(WebhookConfig {
            id: webhook_id,
            url: "https://example.com/webhook".to_string(),
            secret: None,
            enabled: true,
            retry_count: 3,
            timeout_seconds: 30,
        });

        let handler = create_test_handler(http_client, webhook_repo);

        let job = EpiGraphJob::WebhookNotification {
            webhook_id,
            payload: json!({"event": "test"}),
        }
        .into_job()
        .unwrap();

        let result = handler.handle(&job).await;

        match result {
            Err(JobError::PermanentFailure { message }) => {
                assert!(
                    message.contains(&status_code.to_string()),
                    "Error should include status code {status_code}: {message}"
                );
                // Verify should_retry returns false
                assert!(
                    !JobError::PermanentFailure {
                        message: message.clone()
                    }
                    .should_retry(),
                    "PermanentFailure should not retry"
                );
            }
            Err(e) => panic!("Expected PermanentFailure for {status_code}, got: {e:?}"),
            Ok(_) => panic!("Status {status_code} should not succeed"),
        }
    }
}

/// 5xx errors should be transient and trigger retry
#[tokio::test]
async fn test_transient_failure_5xx_retries() {
    let transient_error_codes = [500, 502, 503, 504];

    for status_code in transient_error_codes {
        let http_client = Arc::new(MockHttpClient::with_config(MockResponseConfig {
            status_code,
            body: format!(r#"{{"error": "Server error {status_code}"}}"#),
            latency: Duration::from_millis(10),
            fail_count: 0,
            retry_after: None,
        }));

        let webhook_repo = Arc::new(MockWebhookRepository::new());
        let webhook_id = Uuid::new_v4();
        webhook_repo.add_webhook(WebhookConfig {
            id: webhook_id,
            url: "https://example.com/webhook".to_string(),
            secret: None,
            enabled: true,
            retry_count: 3,
            timeout_seconds: 30,
        });

        let handler = create_test_handler(http_client, webhook_repo);

        let job = EpiGraphJob::WebhookNotification {
            webhook_id,
            payload: json!({"event": "test"}),
        }
        .into_job()
        .unwrap();

        let result = handler.handle(&job).await;

        match result {
            Err(JobError::ProcessingFailed { message }) => {
                assert!(
                    message.contains(&status_code.to_string()),
                    "Error should include status code {status_code}: {message}"
                );
                // Verify should_retry returns true
                assert!(
                    JobError::ProcessingFailed {
                        message: message.clone()
                    }
                    .should_retry(),
                    "ProcessingFailed (5xx) should retry"
                );
            }
            Err(e) => panic!("Expected ProcessingFailed for {status_code}, got: {e:?}"),
            Ok(_) => panic!("Status {status_code} should not succeed"),
        }
    }
}

// ============================================================================
// Test: Rate Limiting (429)
// ============================================================================

/// 429 responses should trigger `RateLimited` error
#[tokio::test]
async fn test_rate_limit_429_with_retry_after() {
    let http_client = Arc::new(MockHttpClient::with_config(MockResponseConfig {
        status_code: 429,
        body: r#"{"error": "Too Many Requests"}"#.to_string(),
        latency: Duration::from_millis(10),
        fail_count: 0,
        retry_after: Some(60),
    }));

    let webhook_repo = Arc::new(MockWebhookRepository::new());
    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "https://example.com/webhook".to_string(),
        secret: None,
        enabled: true,
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client, webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({"event": "test"}),
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await;

    match result {
        Err(JobError::RateLimited { retry_after_secs }) => {
            assert!(
                retry_after_secs > 0,
                "Retry-After should be positive: {retry_after_secs}"
            );
            // Verify should_retry returns true for rate limits
            assert!(
                JobError::RateLimited { retry_after_secs }.should_retry(),
                "RateLimited should retry"
            );
        }
        Err(e) => panic!("Expected RateLimited error, got: {e:?}"),
        Ok(_) => panic!("429 should not succeed"),
    }
}

// ============================================================================
// Test: Redirect Handling (3xx)
// ============================================================================

/// 3xx redirects should be handled (treated as success since client follows)
#[tokio::test]
async fn test_redirect_handling() {
    let redirect_codes = [301, 302, 307, 308];

    for status_code in redirect_codes {
        let http_client = Arc::new(MockHttpClient::with_config(MockResponseConfig {
            status_code,
            body: String::new(),
            latency: Duration::from_millis(10),
            fail_count: 0,
            retry_after: None,
        }));

        let webhook_repo = Arc::new(MockWebhookRepository::new());
        let webhook_id = Uuid::new_v4();
        webhook_repo.add_webhook(WebhookConfig {
            id: webhook_id,
            url: "https://example.com/webhook".to_string(),
            secret: None,
            enabled: true,
            retry_count: 3,
            timeout_seconds: 30,
        });

        let handler = create_test_handler(http_client, webhook_repo);

        let job = EpiGraphJob::WebhookNotification {
            webhook_id,
            payload: json!({"event": "test"}),
        }
        .into_job()
        .unwrap();

        let result = handler.handle(&job).await;

        // Redirects are treated as success (client should follow redirects)
        assert!(
            result.is_ok(),
            "Redirect {status_code} should be treated as success: {result:?}"
        );

        let job_result = result.unwrap();
        assert_eq!(job_result.output["status_code"], status_code);
        assert_eq!(job_result.output["redirect"], true);
    }
}

// ============================================================================
// Test: Timeout Handling
// ============================================================================

/// Handler should timeout on slow endpoints
#[tokio::test]
async fn test_timeout_on_slow_endpoint() {
    let http_client = Arc::new(MockHttpClient::with_config(MockResponseConfig {
        status_code: 200,
        body: "ok".to_string(),
        latency: Duration::from_secs(5), // Simulates slow endpoint
        fail_count: 0,
        retry_after: None,
    }));

    let webhook_repo = Arc::new(MockWebhookRepository::new());
    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "https://slow.example.com/webhook".to_string(),
        secret: None,
        enabled: true,
        retry_count: 3,
        timeout_seconds: 1, // 1 second timeout
    });

    let handler = create_test_handler(http_client.clone(), webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({"event": "test"}),
    }
    .into_job()
    .unwrap();

    let start = Instant::now();
    let result = handler.handle(&job).await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "Should timeout on slow endpoint");
    match result {
        Err(JobError::Timeout { timeout }) => {
            assert!(
                timeout <= Duration::from_secs(2),
                "Timeout should be around 1 second"
            );
        }
        Err(e) => panic!("Expected Timeout error, got: {e:?}"),
        Ok(_) => panic!("Should have timed out"),
    }

    // Should have returned quickly (timeout + small overhead)
    assert!(
        elapsed < Duration::from_secs(3),
        "Should not wait for full endpoint latency"
    );
}

/// Fast endpoints should complete well within timeout
#[tokio::test]
async fn test_fast_endpoint_succeeds_within_timeout() {
    let http_client = Arc::new(MockHttpClient::with_config(MockResponseConfig {
        status_code: 200,
        body: r#"{"received": true}"#.to_string(),
        latency: Duration::from_millis(50),
        fail_count: 0,
        retry_after: None,
    }));

    let webhook_repo = Arc::new(MockWebhookRepository::new());
    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "https://fast.example.com/webhook".to_string(),
        secret: None,
        enabled: true,
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client, webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({"event": "fast_event"}),
    }
    .into_job()
    .unwrap();

    let start = Instant::now();
    let result = handler.handle(&job).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "Fast endpoint should succeed");
    assert!(
        elapsed < Duration::from_secs(1),
        "Should complete quickly: {elapsed:?}"
    );
}

// ============================================================================
// Test: JobError.should_retry() behavior
// ============================================================================

/// Verify `should_retry` returns correct values for all error types
#[test]
fn test_job_error_should_retry() {
    // Should retry
    assert!(JobError::ProcessingFailed {
        message: "test".into()
    }
    .should_retry());
    assert!(JobError::Timeout {
        timeout: Duration::from_secs(1)
    }
    .should_retry());
    assert!(JobError::RateLimited {
        retry_after_secs: 60
    }
    .should_retry());

    // Should NOT retry
    assert!(!JobError::PermanentFailure {
        message: "test".into()
    }
    .should_retry());
    assert!(!JobError::SsrfBlocked {
        address: "127.0.0.1".into()
    }
    .should_retry());
    assert!(!JobError::NoHandler {
        job_type: "test".into()
    }
    .should_retry());
    assert!(!JobError::PayloadError {
        message: "test".into()
    }
    .should_retry());
    assert!(!JobError::Cancelled.should_retry());
    assert!(!JobError::MaxRetriesExceeded { max_retries: 5 }.should_retry());
}

// ============================================================================
// Test: 2xx Status Codes
// ============================================================================

/// 2xx status codes should succeed
#[tokio::test]
async fn test_2xx_variants_succeed() {
    let success_codes = [200, 201, 202, 204];

    for status_code in success_codes {
        let http_client = Arc::new(MockHttpClient::with_config(MockResponseConfig {
            status_code,
            body: String::new(),
            latency: Duration::from_millis(10),
            fail_count: 0,
            retry_after: None,
        }));

        let webhook_repo = Arc::new(MockWebhookRepository::new());
        let webhook_id = Uuid::new_v4();
        webhook_repo.add_webhook(WebhookConfig {
            id: webhook_id,
            url: "https://example.com/webhook".to_string(),
            secret: None,
            enabled: true,
            retry_count: 3,
            timeout_seconds: 30,
        });

        let handler = create_test_handler(http_client, webhook_repo);

        let job = EpiGraphJob::WebhookNotification {
            webhook_id,
            payload: json!({"event": "test"}),
        }
        .into_job()
        .unwrap();

        let result = handler.handle(&job).await;

        assert!(
            result.is_ok(),
            "Status {status_code} should succeed, got: {result:?}"
        );
    }
}

// ============================================================================
// Test: Error Cases
// ============================================================================

/// Missing webhook configuration should return error
#[tokio::test]
async fn test_missing_webhook_config_returns_error() {
    let http_client = Arc::new(MockHttpClient::new());
    let webhook_repo = Arc::new(MockWebhookRepository::new());
    // Note: No webhook added to repository

    let handler = create_test_handler(http_client, webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id: Uuid::new_v4(), // Unknown webhook ID
        payload: json!({"event": "test"}),
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await;

    assert!(result.is_err());
    match result {
        Err(JobError::ProcessingFailed { message }) => {
            assert!(message.contains("not found"), "Error: {message}");
        }
        Err(e) => panic!("Expected ProcessingFailed, got: {e:?}"),
        Ok(_) => panic!("Should fail for missing webhook"),
    }
}

/// Disabled webhook should return error
#[tokio::test]
async fn test_disabled_webhook_returns_error() {
    let http_client = Arc::new(MockHttpClient::new());
    let webhook_repo = Arc::new(MockWebhookRepository::new());

    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "https://example.com/webhook".to_string(),
        secret: None,
        enabled: false, // Disabled
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client, webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({"event": "test"}),
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await;

    assert!(result.is_err());
    match result {
        Err(JobError::ProcessingFailed { message }) => {
            assert!(message.contains("disabled"), "Error: {message}");
        }
        Err(e) => panic!("Expected ProcessingFailed, got: {e:?}"),
        Ok(_) => panic!("Should fail for disabled webhook"),
    }
}

/// Invalid `webhook_id` format should return `PayloadError`
#[tokio::test]
async fn test_invalid_webhook_id_format() {
    let http_client = Arc::new(MockHttpClient::new());
    let webhook_repo = Arc::new(MockWebhookRepository::new());
    let handler = create_test_handler(http_client, webhook_repo);

    let job = Job::new(
        "webhook_notification",
        json!({
            "WebhookNotification": {
                "webhook_id": "not-a-uuid",
                "payload": {}
            }
        }),
    );

    let result = handler.handle(&job).await;

    assert!(result.is_err());
    match result {
        Err(JobError::PayloadError { message }) => {
            assert!(message.contains("Invalid webhook_id"), "Error: {message}");
        }
        Err(e) => panic!("Expected PayloadError, got: {e:?}"),
        Ok(_) => panic!("Should fail for invalid webhook_id"),
    }
}

// ============================================================================
// Test: Payload Serialization
// ============================================================================

/// Complex payloads should be serialized correctly as JSON
#[tokio::test]
async fn test_payload_serialization_complex_object() {
    let http_client = Arc::new(MockHttpClient::new());
    let webhook_repo = Arc::new(MockWebhookRepository::new());

    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "https://example.com/webhook".to_string(),
        secret: None,
        enabled: true,
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client.clone(), webhook_repo);

    // Complex nested payload
    let complex_payload = json!({
        "event": "claim_updated",
        "timestamp": "2024-01-15T10:30:00Z",
        "data": {
            "claim": {
                "id": "claim-12345",
                "content": "Test claim with special chars: <>&\"'",
                "truth_value": 0.856,
                "agent": {
                    "id": "agent-67890",
                    "reputation": 0.92
                }
            },
            "evidence_ids": ["ev-1", "ev-2", "ev-3"],
            "metadata": {
                "source": "harvester",
                "version": 2,
                "flags": [true, false, true]
            }
        }
    });

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: complex_payload.clone(),
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await;
    assert!(result.is_ok());

    let request = http_client.get_last_request().unwrap();
    let sent_payload: serde_json::Value = serde_json::from_str(&request.body).unwrap();

    // Verify structure is preserved
    assert_eq!(sent_payload["event"], "claim_updated");
    assert_eq!(sent_payload["data"]["claim"]["id"], "claim-12345");
    assert_eq!(
        sent_payload["data"]["evidence_ids"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(sent_payload["data"]["metadata"]["version"], 2);
}

// ============================================================================
// Test: Built-in Handler Registration
// ============================================================================

/// The built-in `WebhookNotificationHandler` should have correct job type
#[test]
fn test_builtin_handler_has_correct_job_type() {
    let handler = WebhookNotificationHandler;
    assert_eq!(
        handler.job_type(),
        "webhook_notification",
        "Built-in handler should have job_type 'webhook_notification'"
    );
}

/// Built-in handler should be registrable with `JobRunner`
#[test]
fn test_builtin_handler_is_registrable() {
    let queue = Arc::new(InMemoryJobQueue::new());
    let mut runner = JobRunner::new(1, queue);

    runner.register_handler(Arc::new(WebhookNotificationHandler));

    let registered = runner.registered_job_types();
    assert!(
        registered.contains(&"webhook_notification".to_string()),
        "webhook_notification should be registered"
    );
}

// ============================================================================
// Test: JobResult Contains Expected Data
// ============================================================================

/// Successful webhook should return detailed result
#[tokio::test]
async fn test_successful_webhook_result_contains_details() {
    let http_client = Arc::new(MockHttpClient::with_config(MockResponseConfig {
        status_code: 200,
        body: r#"{"acknowledged": true, "id": "resp-123"}"#.to_string(),
        latency: Duration::from_millis(25),
        fail_count: 0,
        retry_after: None,
    }));

    let webhook_repo = Arc::new(MockWebhookRepository::new());
    let webhook_id = Uuid::new_v4();
    webhook_repo.add_webhook(WebhookConfig {
        id: webhook_id,
        url: "https://api.example.com/events".to_string(),
        secret: Some("secret123".to_string()),
        enabled: true,
        retry_count: 3,
        timeout_seconds: 30,
    });

    let handler = create_test_handler(http_client, webhook_repo);

    let job = EpiGraphJob::WebhookNotification {
        webhook_id,
        payload: json!({"event": "claim_created"}),
    }
    .into_job()
    .unwrap();

    let result = handler.handle(&job).await.unwrap();

    // Verify output contains expected fields
    assert_eq!(result.output["webhook_id"], webhook_id.to_string());
    assert_eq!(result.output["url"], "https://api.example.com/events");
    assert_eq!(result.output["status_code"], 200);
    assert!(result.output["response_body"]
        .as_str()
        .unwrap()
        .contains("acknowledged"));

    // Verify metadata
    assert!(result.metadata.worker_id.is_some());
    assert_eq!(result.metadata.items_processed, Some(1));

    // Verify execution duration is tracked
    assert!(result.execution_duration >= Duration::from_millis(20));
}
