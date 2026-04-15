//! Webhook subscription management endpoints
//!
//! POST   /api/v1/webhooks     - Register a new webhook subscription (protected)
//! GET    /api/v1/webhooks     - List all active webhook subscriptions (protected)
//! GET    /api/v1/webhooks/:id - Get a single webhook subscription (protected)
//! DELETE /api/v1/webhooks/:id - Remove a webhook subscription (protected)
//!
//! Webhooks enable external systems to receive real-time notifications when
//! epistemic events occur (claims submitted, truth updated, etc.). Payload
//! integrity is ensured via HMAC-SHA256 signing with a per-subscription secret.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::{AppState, WebhookSubscription};

// =============================================================================
// REQUEST TYPES
// =============================================================================

/// Request body for registering a new webhook subscription
#[derive(Debug, Deserialize)]
pub struct WebhookRegistration {
    /// Target URL for webhook delivery
    pub url: String,
    /// Filter: which event types to send (empty = all)
    pub event_types: Vec<String>,
    /// HMAC-SHA256 secret for payload signing (minimum 32 characters)
    pub secret: String,
}

// =============================================================================
// SECURITY CONSTANTS
// =============================================================================

/// Minimum length of the webhook secret in characters.
/// A 32-character secret provides adequate entropy for HMAC-SHA256 signing.
const MIN_SECRET_LENGTH: usize = 32;

// =============================================================================
// HMAC-SHA256 PAYLOAD SIGNING
// =============================================================================

/// Sign a webhook payload using HMAC-SHA256
///
/// Returns the hex-encoded signature string that recipients can use
/// to verify payload integrity and authenticity.
///
/// # Arguments
/// * `secret` - The shared secret for this webhook subscription
/// * `payload` - The raw payload bytes to sign
pub fn sign_webhook_payload(secret: &str, payload: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Register a new webhook subscription
///
/// POST /api/v1/webhooks
///
/// This is a protected endpoint requiring Ed25519 signature verification.
/// The caller must provide a valid URL, event type filters, and a secret
/// of at least 32 characters for HMAC-SHA256 payload signing.
///
/// # Errors
///
/// - 400 Bad Request: Empty URL or secret shorter than 32 characters
/// - 401 Unauthorized: Missing or invalid signature (handled by middleware)
/// - 201 Created: Webhook subscription registered successfully
pub async fn register_webhook(
    State(state): State<AppState>,
    Json(registration): Json<WebhookRegistration>,
) -> Result<(StatusCode, Json<WebhookSubscription>), ApiError> {
    // 1. Validate URL is not empty
    if registration.url.trim().is_empty() {
        return Err(ApiError::BadRequest {
            message: "Webhook URL must not be empty".to_string(),
        });
    }

    // 2. Validate secret length (minimum 32 characters for adequate entropy)
    if registration.secret.len() < MIN_SECRET_LENGTH {
        return Err(ApiError::BadRequest {
            message: format!(
                "Webhook secret must be at least {} characters, got {}",
                MIN_SECRET_LENGTH,
                registration.secret.len()
            ),
        });
    }

    // 3. Create the subscription
    let subscription = WebhookSubscription {
        id: Uuid::new_v4(),
        url: registration.url,
        event_types: registration.event_types,
        created_at: Utc::now(),
        active: true,
        secret: registration.secret,
    };

    // 4. Store the subscription
    {
        let mut store = state.webhook_store.write().await;
        store.insert(subscription.id, subscription.clone());
    }

    Ok((StatusCode::CREATED, Json(subscription)))
}

/// List all active webhook subscriptions
///
/// GET /api/v1/webhooks
///
/// This is a protected endpoint requiring Ed25519 signature verification.
/// Returns all active webhook subscriptions with secrets redacted.
pub async fn list_webhooks(State(state): State<AppState>) -> Json<Vec<WebhookSubscription>> {
    let store = state.webhook_store.read().await;
    let subscriptions: Vec<WebhookSubscription> =
        store.values().filter(|sub| sub.active).cloned().collect();
    Json(subscriptions)
}

/// Get a single webhook subscription by ID
///
/// GET /api/v1/webhooks/:id
///
/// This is a protected endpoint requiring Ed25519 signature verification.
/// Returns the webhook subscription with the secret redacted.
///
/// # Errors
///
/// - 404 Not Found: No subscription with the given ID
pub async fn get_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<WebhookSubscription>, ApiError> {
    let store = state.webhook_store.read().await;
    store.get(&id).cloned().map(Json).ok_or(ApiError::NotFound {
        entity: "Webhook".to_string(),
        id: id.to_string(),
    })
}

/// Remove a webhook subscription
///
/// DELETE /api/v1/webhooks/:id
///
/// This is a protected endpoint requiring Ed25519 signature verification.
/// Removes the subscription entirely from the store.
///
/// # Errors
///
/// - 404 Not Found: No subscription with the given ID
pub async fn delete_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let mut store = state.webhook_store.write().await;
    if store.remove(&id).is_some() {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound {
            entity: "Webhook".to_string(),
            id: id.to_string(),
        })
    }
}

// =============================================================================
// WEBHOOK DELIVERY
// =============================================================================

/// Configuration for webhook delivery behavior
#[derive(Debug, Clone)]
pub struct WebhookDeliveryConfig {
    /// Request timeout for webhook delivery
    pub timeout: std::time::Duration,
    /// Maximum number of retry attempts for failed deliveries
    pub max_retries: u32,
}

impl Default for WebhookDeliveryConfig {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(10),
            max_retries: 3,
        }
    }
}

/// Deliver a single event to all matching webhook subscriptions
///
/// For each active webhook subscription whose event type filter matches
/// the event, this function:
/// 1. Serializes the event payload as JSON
/// 2. Signs the payload with the subscription's HMAC-SHA256 secret
/// 3. POSTs the payload to the subscription's URL
///
/// Delivery failures are logged but do not block the caller. Each
/// subscription is attempted independently.
///
/// # Arguments
/// * `client` - HTTP client for making requests
/// * `webhook_store` - The shared webhook subscription store
/// * `event` - The event to deliver
/// * `config` - Delivery configuration (timeout, retries)
pub async fn deliver_event(
    client: &reqwest::Client,
    webhook_store: &crate::state::WebhookStore,
    event: &epigraph_events::EpiGraphEvent,
    config: &WebhookDeliveryConfig,
) -> Vec<WebhookDeliveryResult> {
    let event_type = event.event_type();

    // Read subscriptions snapshot
    let subscriptions: Vec<crate::state::WebhookSubscription> = {
        let store = webhook_store.read().await;
        store
            .values()
            .filter(|sub| sub.active)
            .filter(|sub| sub.event_types.is_empty() || sub.event_types.contains(&event_type))
            .cloned()
            .collect()
    };

    let payload = serde_json::json!({
        "event_type": event_type,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": event,
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();

    let mut results = Vec::with_capacity(subscriptions.len());

    for sub in &subscriptions {
        let signature = sign_webhook_payload(&sub.secret, &payload_bytes);
        let result = deliver_to_subscription(client, sub, &payload_bytes, &signature, config).await;
        results.push(result);
    }

    results
}

/// Result of attempting to deliver a webhook to a single subscription
#[derive(Debug)]
pub struct WebhookDeliveryResult {
    /// The subscription ID this delivery was for
    pub subscription_id: Uuid,
    /// Whether the delivery succeeded
    pub success: bool,
    /// HTTP status code if a response was received
    pub status_code: Option<u16>,
    /// Number of attempts made
    pub attempts: u32,
    /// Error message if delivery failed
    pub error: Option<String>,
}

/// Deliver a payload to a single webhook subscription with retry logic
async fn deliver_to_subscription(
    client: &reqwest::Client,
    subscription: &crate::state::WebhookSubscription,
    payload: &[u8],
    signature: &str,
    config: &WebhookDeliveryConfig,
) -> WebhookDeliveryResult {
    let mut last_error = None;

    for attempt in 0..=config.max_retries {
        match client
            .post(&subscription.url)
            .header("Content-Type", "application/json")
            .header("X-EpiGraph-Signature", signature)
            .header("X-EpiGraph-Event", "webhook")
            .timeout(config.timeout)
            .body(payload.to_vec())
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                if response.status().is_success() {
                    return WebhookDeliveryResult {
                        subscription_id: subscription.id,
                        success: true,
                        status_code: Some(status),
                        attempts: attempt + 1,
                        error: None,
                    };
                }
                last_error = Some(format!("HTTP {status}"));
            }
            Err(e) => {
                last_error = Some(e.to_string());
            }
        }

        // Exponential backoff before retry (skip on last attempt)
        if attempt < config.max_retries {
            let delay = std::time::Duration::from_millis(100 * 2u64.pow(attempt));
            tokio::time::sleep(delay).await;
        }
    }

    WebhookDeliveryResult {
        subscription_id: subscription.id,
        success: false,
        status_code: None,
        attempts: config.max_retries + 1,
        error: last_error,
    }
}

/// Start the webhook dispatcher background task
///
/// This function subscribes to the event bus and spawns a background
/// task that delivers events to registered webhook subscriptions.
/// The task runs until the event bus is dropped.
///
/// # Arguments
/// * `event_bus` - The shared event bus to subscribe to
/// * `webhook_store` - The shared webhook subscription store
/// * `config` - Delivery configuration
///
/// # Returns
/// The subscription ID for the webhook dispatcher (can be used to unsubscribe)
pub fn start_webhook_dispatcher(
    event_bus: &crate::state::SharedEventBus,
    webhook_store: crate::state::WebhookStore,
    config: WebhookDeliveryConfig,
) -> epigraph_events::SubscriptionId {
    let client = reqwest::Client::builder()
        .timeout(config.timeout)
        .build()
        .unwrap_or_default();

    let store = webhook_store;
    let cfg = std::sync::Arc::new(config);

    event_bus.subscribe(vec![], move |event| {
        let client = client.clone();
        let store = store.clone();
        let cfg = std::sync::Arc::clone(&cfg);

        tokio::spawn(async move {
            let results = deliver_event(&client, &store, &event, &cfg).await;
            for result in &results {
                if !result.success {
                    tracing::warn!(
                        subscription_id = %result.subscription_id,
                        attempts = result.attempts,
                        error = result.error.as_deref().unwrap_or("unknown"),
                        "Webhook delivery failed"
                    );
                }
            }
        });
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Unit tests (no AppState needed, always run) ----

    #[test]
    fn test_sign_webhook_payload_produces_hex_string() {
        let secret = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s";
        let payload = b"test payload";

        let signature = sign_webhook_payload(secret, payload);

        // HMAC-SHA256 produces a 32-byte hash, hex-encoded to 64 characters
        assert_eq!(signature.len(), 64, "Signature should be 64 hex characters");
        assert!(
            signature.chars().all(|c| c.is_ascii_hexdigit()),
            "Signature should contain only hex characters"
        );
    }

    #[test]
    fn test_sign_webhook_payload_deterministic() {
        let secret = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s";
        let payload = b"deterministic test";

        let sig1 = sign_webhook_payload(secret, payload);
        let sig2 = sign_webhook_payload(secret, payload);

        assert_eq!(
            sig1, sig2,
            "Same secret + payload should produce same signature"
        );
    }

    #[test]
    fn test_sign_webhook_payload_different_secrets_differ() {
        let payload = b"same payload";
        let sig1 = sign_webhook_payload("Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s", payload);
        let sig2 = sign_webhook_payload("Ym8nQ3rK6wL9xCjG4dS1zBfH7eT0pA2u", payload);

        assert_ne!(
            sig1, sig2,
            "Different secrets should produce different signatures"
        );
    }

    #[test]
    fn test_sign_webhook_payload_different_payloads_differ() {
        let secret = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s";
        let sig1 = sign_webhook_payload(secret, b"payload one");
        let sig2 = sign_webhook_payload(secret, b"payload two");

        assert_ne!(
            sig1, sig2,
            "Different payloads should produce different signatures"
        );
    }

    #[test]
    fn test_webhook_subscription_secret_not_serialized() {
        let sub = WebhookSubscription {
            id: Uuid::new_v4(),
            url: "https://example.com/hook".to_string(),
            event_types: vec!["ClaimSubmitted".to_string()],
            created_at: Utc::now(),
            active: true,
            secret: "this-should-not-appear-in-json-output-ever".to_string(),
        };

        let json = serde_json::to_string(&sub).unwrap();
        assert!(
            !json.contains("this-should-not-appear"),
            "Secret must not appear in serialized JSON output"
        );
    }

    #[test]
    fn test_webhook_registration_deserializes() {
        let json = serde_json::json!({
            "url": "https://example.com/hook",
            "event_types": ["ClaimSubmitted", "TruthUpdated"],
            "secret": "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"
        });

        let reg: WebhookRegistration = serde_json::from_value(json).unwrap();
        assert_eq!(reg.url, "https://example.com/hook");
        assert_eq!(reg.event_types.len(), 2);
        assert_eq!(reg.secret.len(), 32);
    }

    #[test]
    fn test_webhook_payload_format() {
        // Verify that a JSON payload can be signed and the signature is valid hex
        let payload = serde_json::json!({
            "event_type": "ClaimSubmitted",
            "claim_id": Uuid::new_v4(),
            "timestamp": Utc::now().to_rfc3339()
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let secret = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s";

        let signature = sign_webhook_payload(secret, &payload_bytes);
        assert_eq!(signature.len(), 64);

        // Verify the signature can be decoded back to bytes
        let decoded = hex::decode(&signature).unwrap();
        assert_eq!(decoded.len(), 32, "HMAC-SHA256 should produce 32 bytes");
    }

    #[test]
    fn test_event_type_filtering_logic() {
        // Verify the event type filtering concept:
        // empty event_types means "all events", non-empty means "only these"
        let sub_all = WebhookSubscription {
            id: Uuid::new_v4(),
            url: "https://example.com/all".to_string(),
            event_types: vec![],
            created_at: Utc::now(),
            active: true,
            secret: "x".repeat(32),
        };

        let sub_filtered = WebhookSubscription {
            id: Uuid::new_v4(),
            url: "https://example.com/filtered".to_string(),
            event_types: vec!["ClaimSubmitted".to_string()],
            created_at: Utc::now(),
            active: true,
            secret: "x".repeat(32),
        };

        // Empty event_types matches all
        assert!(
            sub_all.event_types.is_empty(),
            "Subscription with no filters should match all events"
        );

        // Non-empty event_types matches only specific ones
        assert!(
            sub_filtered
                .event_types
                .contains(&"ClaimSubmitted".to_string()),
            "Subscription should match configured event type"
        );
        assert!(
            !sub_filtered
                .event_types
                .contains(&"TruthUpdated".to_string()),
            "Subscription should not match unconfigured event type"
        );
    }

    // ---- Webhook delivery unit tests ----

    #[test]
    fn test_default_delivery_config() {
        let config = WebhookDeliveryConfig::default();
        assert_eq!(config.timeout, std::time::Duration::from_secs(10));
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_delivery_result_debug() {
        let result = WebhookDeliveryResult {
            subscription_id: Uuid::new_v4(),
            success: true,
            status_code: Some(200),
            attempts: 1,
            error: None,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("success: true"));
    }

    #[test]
    fn test_delivery_result_failure() {
        let result = WebhookDeliveryResult {
            subscription_id: Uuid::new_v4(),
            success: false,
            status_code: None,
            attempts: 4,
            error: Some("connection refused".to_string()),
        };
        assert!(!result.success);
        assert_eq!(result.attempts, 4);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("connection refused"));
    }

    #[tokio::test]
    async fn test_deliver_event_with_no_subscriptions() {
        let client = reqwest::Client::new();
        let store: crate::state::WebhookStore =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
        let event = epigraph_events::EpiGraphEvent::ClaimSubmitted {
            claim_id: epigraph_core::ClaimId::new(),
            agent_id: epigraph_core::AgentId::new(),
            initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
        };
        let config = WebhookDeliveryConfig::default();

        let results = deliver_event(&client, &store, &event, &config).await;
        assert!(
            results.is_empty(),
            "No subscriptions means no delivery results"
        );
    }

    #[tokio::test]
    async fn test_deliver_event_filters_by_event_type() {
        let client = reqwest::Client::new();
        let store: crate::state::WebhookStore =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));

        // Register a subscription that only wants TruthUpdated events
        {
            let mut s = store.write().await;
            s.insert(
                Uuid::new_v4(),
                WebhookSubscription {
                    id: Uuid::new_v4(),
                    url: "http://127.0.0.1:1/nonexistent".to_string(),
                    event_types: vec!["TruthUpdated".to_string()],
                    created_at: Utc::now(),
                    active: true,
                    secret: "x".repeat(32),
                },
            );
        }

        // Publish a ClaimSubmitted event (should NOT match)
        let event = epigraph_events::EpiGraphEvent::ClaimSubmitted {
            claim_id: epigraph_core::ClaimId::new(),
            agent_id: epigraph_core::AgentId::new(),
            initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
        };
        let config = WebhookDeliveryConfig {
            timeout: std::time::Duration::from_millis(100),
            max_retries: 0,
        };

        let results = deliver_event(&client, &store, &event, &config).await;
        assert!(
            results.is_empty(),
            "ClaimSubmitted should not match TruthUpdated filter"
        );
    }

    #[tokio::test]
    async fn test_deliver_event_empty_filter_matches_all() {
        let client = reqwest::Client::new();
        let store: crate::state::WebhookStore =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));

        let sub_id = Uuid::new_v4();
        {
            let mut s = store.write().await;
            s.insert(
                sub_id,
                WebhookSubscription {
                    id: sub_id,
                    url: "http://127.0.0.1:1/nonexistent".to_string(),
                    event_types: vec![], // empty = all events
                    created_at: Utc::now(),
                    active: true,
                    secret: "x".repeat(32),
                },
            );
        }

        let event = epigraph_events::EpiGraphEvent::ClaimSubmitted {
            claim_id: epigraph_core::ClaimId::new(),
            agent_id: epigraph_core::AgentId::new(),
            initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
        };
        let config = WebhookDeliveryConfig {
            timeout: std::time::Duration::from_millis(100),
            max_retries: 0,
        };

        let results = deliver_event(&client, &store, &event, &config).await;
        assert_eq!(results.len(), 1, "Empty filter should match all events");
        // Will fail because the URL is unreachable, but the attempt should be made
        assert!(!results[0].success);
        assert_eq!(results[0].subscription_id, sub_id);
    }

    #[tokio::test]
    async fn test_deliver_event_skips_inactive_subscriptions() {
        let client = reqwest::Client::new();
        let store: crate::state::WebhookStore =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));

        let sub_id = Uuid::new_v4();
        {
            let mut s = store.write().await;
            s.insert(
                sub_id,
                WebhookSubscription {
                    id: sub_id,
                    url: "http://127.0.0.1:1/nonexistent".to_string(),
                    event_types: vec![],
                    created_at: Utc::now(),
                    active: false, // INACTIVE
                    secret: "x".repeat(32),
                },
            );
        }

        let event = epigraph_events::EpiGraphEvent::ClaimSubmitted {
            claim_id: epigraph_core::ClaimId::new(),
            agent_id: epigraph_core::AgentId::new(),
            initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
        };
        let config = WebhookDeliveryConfig {
            timeout: std::time::Duration::from_millis(100),
            max_retries: 0,
        };

        let results = deliver_event(&client, &store, &event, &config).await;
        assert!(
            results.is_empty(),
            "Inactive subscriptions should be skipped"
        );
    }

    // ---- Handler integration tests (need AppState without DB) ----

    #[cfg(not(feature = "db"))]
    mod handler_tests {
        use super::super::*;
        use crate::state::{ApiConfig, AppState, WebhookSubscription};
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::{delete, get, post};
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        /// Create a test router with webhook endpoints (no auth middleware for unit tests)
        fn test_router() -> Router {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });

            Router::new()
                .route("/api/v1/webhooks", post(register_webhook))
                .route("/api/v1/webhooks", get(list_webhooks))
                .route("/api/v1/webhooks/:id", get(get_webhook))
                .route("/api/v1/webhooks/:id", delete(delete_webhook))
                .with_state(state)
        }

        /// Create a test router with shared state for multi-request tests
        fn test_router_with_state(state: AppState) -> Router {
            Router::new()
                .route("/api/v1/webhooks", post(register_webhook))
                .route("/api/v1/webhooks", get(list_webhooks))
                .route("/api/v1/webhooks/:id", get(get_webhook))
                .route("/api/v1/webhooks/:id", delete(delete_webhook))
                .with_state(state)
        }

        /// Helper to parse JSON response body
        async fn parse_body<T: serde::de::DeserializeOwned>(
            response: axum::http::Response<Body>,
        ) -> T {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice(&body).unwrap()
        }

        fn valid_registration_json() -> serde_json::Value {
            serde_json::json!({
                "url": "https://example.com/webhook",
                "event_types": ["ClaimSubmitted"],
                "secret": "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"
            })
        }

        #[tokio::test]
        async fn test_register_webhook_valid() {
            let router = test_router();

            let body = valid_registration_json();

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            let sub: WebhookSubscription = parse_body(response).await;
            assert_eq!(sub.url, "https://example.com/webhook");
            assert_eq!(sub.event_types, vec!["ClaimSubmitted"]);
            assert!(sub.active);
        }

        #[tokio::test]
        async fn test_register_webhook_rejects_empty_url() {
            let router = test_router();

            let body = serde_json::json!({
                "url": "",
                "event_types": [],
                "secret": "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"
            });

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_register_webhook_rejects_whitespace_url() {
            let router = test_router();

            let body = serde_json::json!({
                "url": "   ",
                "event_types": [],
                "secret": "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"
            });

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_register_webhook_rejects_short_secret() {
            let router = test_router();

            let body = serde_json::json!({
                "url": "https://example.com/webhook",
                "event_types": [],
                "secret": "too-short"
            });

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_list_webhooks_returns_registered() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });
            let router = test_router_with_state(state);

            // Register a webhook first
            let body = valid_registration_json();

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            // Now list webhooks
            let request = Request::builder()
                .method("GET")
                .uri("/api/v1/webhooks")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let subs: Vec<WebhookSubscription> = parse_body(response).await;
            assert_eq!(subs.len(), 1);
            assert_eq!(subs[0].url, "https://example.com/webhook");
        }

        #[tokio::test]
        async fn test_list_webhooks_empty() {
            let router = test_router();

            let request = Request::builder()
                .method("GET")
                .uri("/api/v1/webhooks")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let subs: Vec<WebhookSubscription> = parse_body(response).await;
            assert!(subs.is_empty());
        }

        #[tokio::test]
        async fn test_get_webhook_by_id() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });
            let router = test_router_with_state(state);

            // Register a webhook
            let body = valid_registration_json();

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            let created: WebhookSubscription = parse_body(response).await;

            // Get by ID
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/webhooks/{}", created.id))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let fetched: WebhookSubscription = parse_body(response).await;
            assert_eq!(fetched.id, created.id);
            assert_eq!(fetched.url, "https://example.com/webhook");
        }

        #[tokio::test]
        async fn test_get_nonexistent_webhook_returns_404() {
            let router = test_router();
            let fake_id = Uuid::new_v4();

            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/webhooks/{fake_id}"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_delete_webhook_removes_it() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });
            let router = test_router_with_state(state);

            // Register a webhook
            let body = valid_registration_json();

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            let created: WebhookSubscription = parse_body(response).await;

            // Delete it
            let request = Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/webhooks/{}", created.id))
                .body(Body::empty())
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            // Verify it's gone
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/webhooks/{}", created.id))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_delete_nonexistent_webhook_returns_404() {
            let router = test_router();
            let fake_id = Uuid::new_v4();

            let request = Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/webhooks/{fake_id}"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        // ---- Full CRUD lifecycle test ----

        #[tokio::test]
        async fn test_full_crud_lifecycle() {
            // Single end-to-end test: register -> list -> get -> delete -> verify gone
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });
            let router = test_router_with_state(state);

            // 1. Register a webhook
            let body = valid_registration_json();
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::CREATED,
                "Register should return 201"
            );
            let created: WebhookSubscription = parse_body(response).await;
            assert_eq!(created.url, "https://example.com/webhook");
            assert!(created.active, "Newly created webhook should be active");

            // 2. List webhooks - should contain exactly the one we created
            let request = Request::builder()
                .method("GET")
                .uri("/api/v1/webhooks")
                .body(Body::empty())
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let listed: Vec<WebhookSubscription> = parse_body(response).await;
            assert_eq!(listed.len(), 1, "List should return exactly 1 webhook");
            assert_eq!(
                listed[0].id, created.id,
                "Listed webhook ID should match created ID"
            );

            // 3. Get webhook by ID
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/webhooks/{}", created.id))
                .body(Body::empty())
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let fetched: WebhookSubscription = parse_body(response).await;
            assert_eq!(fetched.id, created.id);
            assert_eq!(fetched.url, created.url);
            assert_eq!(fetched.event_types, created.event_types);

            // 4. Delete the webhook
            let request = Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/webhooks/{}", created.id))
                .body(Body::empty())
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NO_CONTENT,
                "Delete should return 204"
            );

            // 5. Verify it's gone - GET returns 404
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/webhooks/{}", created.id))
                .body(Body::empty())
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Deleted webhook should return 404"
            );

            // 6. Verify list is now empty
            let request = Request::builder()
                .method("GET")
                .uri("/api/v1/webhooks")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let listed: Vec<WebhookSubscription> = parse_body(response).await;
            assert!(listed.is_empty(), "List should be empty after deletion");
        }

        // ---- Auth / 401 tests (using full router with signature middleware) ----

        #[tokio::test]
        async fn test_register_webhook_without_signature_returns_401() {
            // Use the full router which applies require_signature middleware
            let state = AppState::new(ApiConfig {
                require_signatures: true,
                ..ApiConfig::default()
            });
            let router = crate::routes::create_router(state);

            let body = valid_registration_json();
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "POST without signature headers should return 401"
            );
        }

        #[tokio::test]
        async fn test_list_webhooks_without_signature_returns_401() {
            let state = AppState::new(ApiConfig {
                require_signatures: true,
                ..ApiConfig::default()
            });
            let router = crate::routes::create_router(state);

            let request = Request::builder()
                .method("GET")
                .uri("/api/v1/webhooks")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "GET list without signature headers should return 401"
            );
        }

        #[tokio::test]
        async fn test_get_webhook_without_signature_returns_401() {
            let state = AppState::new(ApiConfig {
                require_signatures: true,
                ..ApiConfig::default()
            });
            let router = crate::routes::create_router(state);

            let fake_id = Uuid::new_v4();
            let request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/webhooks/{fake_id}"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "GET single webhook without signature headers should return 401"
            );
        }

        #[tokio::test]
        async fn test_delete_webhook_without_signature_returns_401() {
            let state = AppState::new(ApiConfig {
                require_signatures: true,
                ..ApiConfig::default()
            });
            let router = crate::routes::create_router(state);

            let fake_id = Uuid::new_v4();
            let request = Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/webhooks/{fake_id}"))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "DELETE without signature headers should return 401"
            );
        }

        // ---- Additional edge case tests ----

        #[tokio::test]
        async fn test_register_webhook_secret_at_boundary_length() {
            let router = test_router();

            // 31 characters - one below minimum, should be rejected
            let body = serde_json::json!({
                "url": "https://example.com/webhook",
                "event_types": [],
                "secret": "a]9bK2mN5pQ8rT1wX4yZ7cE0fH3jL6o"  // 31 chars
            });

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "Secret with 31 characters should be rejected"
            );
        }

        #[tokio::test]
        async fn test_register_webhook_secret_exactly_at_minimum() {
            let router = test_router();

            // Exactly 32 characters - should be accepted
            let body = serde_json::json!({
                "url": "https://example.com/webhook",
                "event_types": [],
                "secret": "a]9bK2mN5pQ8rT1wX4yZ7cE0fH3jL6oV"  // 32 chars
            });

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::CREATED,
                "Secret with exactly 32 characters should be accepted"
            );
        }

        #[tokio::test]
        async fn test_register_multiple_webhooks_then_list_all() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });
            let router = test_router_with_state(state);

            let urls = [
                "https://example.com/hook1",
                "https://example.com/hook2",
                "https://example.com/hook3",
            ];

            // Register 3 webhooks
            for url in &urls {
                let body = serde_json::json!({
                    "url": url,
                    "event_types": [],
                    "secret": "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"
                });

                let request = Request::builder()
                    .method("POST")
                    .uri("/api/v1/webhooks")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap();

                let response = router.clone().oneshot(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::CREATED);
            }

            // List all webhooks
            let request = Request::builder()
                .method("GET")
                .uri("/api/v1/webhooks")
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let listed: Vec<WebhookSubscription> = parse_body(response).await;
            assert_eq!(listed.len(), 3, "Should list all 3 registered webhooks");

            // Verify all URLs are present (order may vary due to HashMap)
            let listed_urls: Vec<&str> = listed.iter().map(|s| s.url.as_str()).collect();
            for url in &urls {
                assert!(
                    listed_urls.contains(url),
                    "Listed webhooks should contain URL: {url}"
                );
            }
        }

        #[tokio::test]
        async fn test_register_webhook_with_empty_event_types() {
            let router = test_router();

            // Empty event_types means "subscribe to all events"
            let body = serde_json::json!({
                "url": "https://example.com/all-events",
                "event_types": [],
                "secret": "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"
            });

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);

            let sub: WebhookSubscription = parse_body(response).await;
            assert!(
                sub.event_types.is_empty(),
                "Empty event_types should be preserved (wildcard subscription)"
            );
        }

        #[tokio::test]
        async fn test_register_webhook_missing_content_type_returns_415() {
            let router = test_router();

            let body = valid_registration_json();

            // Send POST without content-type header
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            // Axum rejects JSON body without proper content-type with 415
            assert_eq!(
                response.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Missing content-type should return 415"
            );
        }

        #[tokio::test]
        async fn test_register_webhook_malformed_json_returns_400() {
            let router = test_router();

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from("{not valid json"))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "Malformed JSON body should return 400"
            );
        }

        #[tokio::test]
        async fn test_register_webhook_missing_required_fields_returns_422() {
            let router = test_router();

            // JSON object missing the 'secret' field
            let body = serde_json::json!({
                "url": "https://example.com/webhook",
                "event_types": ["ClaimSubmitted"]
            });

            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            // Axum returns 422 Unprocessable Entity when JSON structure doesn't match
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Missing required field should return 422"
            );
        }

        #[tokio::test]
        async fn test_delete_webhook_is_idempotent_returns_404_on_second_delete() {
            let state = AppState::new(ApiConfig {
                require_signatures: false,
                ..ApiConfig::default()
            });
            let router = test_router_with_state(state);

            // Register a webhook
            let body = valid_registration_json();
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/webhooks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            let created: WebhookSubscription = parse_body(response).await;

            // First delete succeeds
            let request = Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/webhooks/{}", created.id))
                .body(Body::empty())
                .unwrap();

            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            // Second delete returns 404
            let request = Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/webhooks/{}", created.id))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "Second delete of same webhook should return 404"
            );
        }
    }
}
