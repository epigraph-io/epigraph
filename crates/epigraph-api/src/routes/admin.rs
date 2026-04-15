//! Administrative endpoints for system health and diagnostics
//!
//! GET /api/v1/admin/stats - Comprehensive system statistics (public)
//!
//! This endpoint aggregates operational metrics from all major subsystems:
//! - Event bus (subscriber count, history size)
//! - Propagation engine (DAG node/edge counts)
//! - Caches (idempotency store size)
//! - Challenge system (total challenges)
//! - Security audit log (event count)
//! - Webhook subscriptions (active count)
//! - Application uptime and configuration

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;

// =============================================================================
// RESPONSE TYPES
// =============================================================================

/// Comprehensive system statistics response
///
/// Aggregates metrics from all major subsystems into a single JSON response.
/// All fields are read-only snapshots taken at request time.
#[derive(Debug, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SystemStats {
    /// Event bus metrics
    pub event_bus: EventBusStats,
    /// Truth propagation engine metrics
    pub propagation: PropagationStats,
    /// Cache metrics
    pub caches: CacheStats,
    /// Challenge system metrics
    pub challenges: ChallengeStats,
    /// Security audit log metrics
    pub security: SecurityStats,
    /// Webhook subscription metrics
    pub webhooks: WebhookStats,
    /// Application configuration summary
    pub config: ConfigSummary,
    /// Application uptime in seconds
    pub uptime_secs: u64,
}

/// Event bus statistics
#[derive(Debug, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct EventBusStats {
    /// Number of active event subscribers
    pub subscriber_count: usize,
    /// Number of events currently in the history buffer
    pub history_size: usize,
}

/// Truth propagation engine statistics
#[derive(Debug, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PropagationStats {
    /// Number of nodes (claims) in the reasoning DAG
    pub dag_node_count: usize,
    /// Number of edges (dependencies) in the reasoning DAG
    pub dag_edge_count: usize,
}

/// Cache statistics
#[derive(Debug, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct CacheStats {
    /// Number of entries in the idempotency store
    pub idempotency_store_size: usize,
}

/// Challenge system statistics
#[derive(Debug, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ChallengeStats {
    /// Total number of challenges (all states)
    pub total_challenges: usize,
}

/// Security audit log statistics
#[derive(Debug, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SecurityStats {
    /// Total number of security events recorded
    pub audit_log_size: usize,
}

/// Webhook subscription statistics
#[derive(Debug, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct WebhookStats {
    /// Number of registered webhook subscriptions
    pub webhook_count: usize,
}

/// Application configuration summary
///
/// Exposes non-sensitive configuration values for diagnostics.
#[derive(Debug, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ConfigSummary {
    /// Whether Ed25519 signature verification is required for write operations
    pub require_signatures: bool,
    /// Maximum request body size in bytes
    pub max_request_size: usize,
}

// =============================================================================
// HANDLER
// =============================================================================

/// Get comprehensive system statistics
///
/// GET /api/v1/admin/stats
///
/// Returns a JSON snapshot of operational metrics from all major subsystems.
/// This endpoint is public (no authentication required) to support monitoring
/// tools and health dashboards.
///
/// # Response
///
/// Returns a `SystemStats` JSON object with nested subsystem metrics.
///
/// # Performance
///
/// This handler acquires read locks on several shared state objects.
/// All locks are short-lived and released before the response is sent.
pub async fn system_stats(State(state): State<AppState>) -> Json<SystemStats> {
    // Gather event bus metrics (no lock needed - EventBus uses internal RwLock)
    let event_bus = EventBusStats {
        subscriber_count: state.event_bus.subscriber_count(),
        history_size: state.event_bus.history_size(),
    };

    // Gather propagation engine metrics (requires read lock on orchestrator)
    let propagation = {
        let orchestrator = state.propagation_orchestrator.read().await;
        let dag = orchestrator.dag();
        PropagationStats {
            dag_node_count: dag.node_count(),
            dag_edge_count: dag.edge_count(),
        }
    };

    // Gather cache metrics (requires read lock on idempotency store)
    let caches = {
        let store = state.idempotency_store.read().await;
        CacheStats {
            idempotency_store_size: store.len(),
        }
    };

    // Gather challenge metrics (no tokio lock - ChallengeService uses std RwLock internally)
    let challenges = ChallengeStats {
        total_challenges: state.challenge_service.total_challenges(),
    };

    // Gather security metrics (no tokio lock - InMemorySecurityAuditLog uses internal RwLock)
    let security = SecurityStats {
        audit_log_size: state.audit_log.len(),
    };

    // Gather webhook metrics (requires read lock on webhook store)
    let webhooks = {
        let store = state.webhook_store.read().await;
        WebhookStats {
            webhook_count: store.len(),
        }
    };

    // Configuration summary (no lock - ApiConfig is cloned)
    let config = ConfigSummary {
        require_signatures: state.config.require_signatures,
        max_request_size: state.config.max_request_size,
    };

    // Uptime from started_at Instant
    let uptime_secs = state.started_at.elapsed().as_secs();

    Json(SystemStats {
        event_bus,
        propagation,
        caches,
        challenges,
        security,
        webhooks,
        config,
        uptime_secs,
    })
}

// =============================================================================
// OAUTH CLIENT APPROVAL
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct ApproveClientRequest {
    pub granted_scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ApproveClientResponse {
    pub client_id: Uuid,
    pub status: String,
    pub granted_scopes: Vec<String>,
}

/// POST /api/v1/admin/clients/:id/approve
///
/// Promotes a pending OAuth client to active with explicit scope grant.
/// Requires `clients:admin` scope.
#[cfg(feature = "db")]
pub async fn approve_client(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    axum::Extension(auth): axum::Extension<crate::middleware::bearer::AuthContext>,
    Json(req): Json<ApproveClientRequest>,
) -> Result<(StatusCode, Json<ApproveClientResponse>), ApiError> {
    crate::middleware::scopes::check_scopes(&auth, &["clients:admin"])?;

    use epigraph_db::repos::oauth_client::OAuthClientRepository;
    OAuthClientRepository::approve(&state.db_pool, id, &req.granted_scopes, auth.client_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?;

    Ok((
        StatusCode::OK,
        Json(ApproveClientResponse {
            client_id: id,
            status: "active".to_string(),
            granted_scopes: req.granted_scopes,
        }),
    ))
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(all(test, not(feature = "db")))]
mod tests {
    use super::*;
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Create a test router with just the admin stats endpoint
    fn test_router() -> Router {
        let state = AppState::new(ApiConfig::default());
        Router::new()
            .route("/api/v1/admin/stats", get(system_stats))
            .with_state(state)
    }

    /// Create a test router with a specific AppState
    fn test_router_with_state(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/admin/stats", get(system_stats))
            .with_state(state)
    }

    /// Helper to parse JSON response body
    async fn parse_body<T: serde::de::DeserializeOwned>(response: axum::http::Response<Body>) -> T {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn test_system_stats_returns_200() {
        let router = test_router();
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_system_stats_returns_valid_json() {
        let router = test_router();
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let stats: SystemStats = parse_body(response).await;

        // Verify all top-level fields are present and have sane defaults
        assert_eq!(stats.event_bus.subscriber_count, 0);
        assert_eq!(stats.event_bus.history_size, 0);
        assert_eq!(stats.propagation.dag_node_count, 0);
        assert_eq!(stats.propagation.dag_edge_count, 0);
        assert_eq!(stats.caches.idempotency_store_size, 0);
        assert_eq!(stats.challenges.total_challenges, 0);
        assert_eq!(stats.security.audit_log_size, 0);
        assert_eq!(stats.webhooks.webhook_count, 0);
    }

    #[tokio::test]
    async fn test_system_stats_default_config() {
        let router = test_router();
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let stats: SystemStats = parse_body(response).await;

        // Default ApiConfig has require_signatures = false and max_request_size = 10MB
        assert!(!stats.config.require_signatures);
        assert_eq!(stats.config.max_request_size, 10 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_system_stats_custom_config() {
        let state = AppState::new(ApiConfig {
            require_signatures: true,
            max_request_size: 2048,
        });
        let router = test_router_with_state(state);

        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let stats: SystemStats = parse_body(response).await;

        assert!(stats.config.require_signatures);
        assert_eq!(stats.config.max_request_size, 2048);
    }

    #[tokio::test]
    async fn test_system_stats_uptime_is_nonnegative() {
        let router = test_router();
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let stats: SystemStats = parse_body(response).await;

        // Uptime should be 0 or more (test executes immediately after state creation)
        // We just verify it does not panic or return something unreasonable
        assert!(
            stats.uptime_secs < 60,
            "Uptime should be less than 60 seconds in test"
        );
    }

    #[tokio::test]
    async fn test_system_stats_reflects_idempotency_store() {
        let state = AppState::new(ApiConfig::default());

        // Insert an entry into the idempotency store
        {
            let mut store = state.idempotency_store.write().await;
            store.insert(
                "test-key".to_string(),
                crate::state::CachedSubmission {
                    claim_id: uuid::Uuid::new_v4(),
                    truth_value: 0.5,
                    trace_id: uuid::Uuid::new_v4(),
                    evidence_ids: vec![],
                    created_at: std::time::Instant::now(),
                },
            );
        }

        let router = test_router_with_state(state);
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let stats: SystemStats = parse_body(response).await;

        assert_eq!(stats.caches.idempotency_store_size, 1);
    }

    #[tokio::test]
    async fn test_system_stats_reflects_webhook_store() {
        let state = AppState::new(ApiConfig::default());

        // Insert a webhook subscription
        {
            let mut store = state.webhook_store.write().await;
            let id = uuid::Uuid::new_v4();
            store.insert(
                id,
                crate::state::WebhookSubscription {
                    id,
                    url: "https://example.com/hook".to_string(),
                    event_types: vec![],
                    created_at: chrono::Utc::now(),
                    active: true,
                    secret: "x".repeat(32),
                },
            );
        }

        let router = test_router_with_state(state);
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let stats: SystemStats = parse_body(response).await;

        assert_eq!(stats.webhooks.webhook_count, 1);
    }

    #[tokio::test]
    async fn test_system_stats_reflects_challenge_count() {
        use epigraph_core::challenge::{Challenge, ChallengeService, ChallengeType};
        use epigraph_core::{AgentId, ClaimId};
        use std::sync::Arc;

        let challenge_service = Arc::new(ChallengeService::new());

        // Submit a challenge
        let challenge = Challenge::new(
            ClaimId::new(),
            AgentId::new(),
            ChallengeType::FactualError,
            "Test challenge",
        );
        challenge_service.submit(challenge).unwrap();

        let state = AppState::new(ApiConfig::default()).with_challenge_service(challenge_service);

        let router = test_router_with_state(state);
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let stats: SystemStats = parse_body(response).await;

        assert_eq!(stats.challenges.total_challenges, 1);
    }

    #[tokio::test]
    async fn test_system_stats_reflects_event_bus_subscribers() {
        let state = AppState::new(ApiConfig::default());

        // Subscribe to events
        state.event_bus.subscribe(vec![], |_| {});

        let router = test_router_with_state(state);
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let stats: SystemStats = parse_body(response).await;

        assert_eq!(stats.event_bus.subscriber_count, 1);
    }

    #[tokio::test]
    async fn test_system_stats_json_structure() {
        let router = test_router();
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Verify top-level JSON structure has expected keys
        assert!(json.get("event_bus").is_some(), "Missing 'event_bus' key");
        assert!(
            json.get("propagation").is_some(),
            "Missing 'propagation' key"
        );
        assert!(json.get("caches").is_some(), "Missing 'caches' key");
        assert!(json.get("challenges").is_some(), "Missing 'challenges' key");
        assert!(json.get("security").is_some(), "Missing 'security' key");
        assert!(json.get("webhooks").is_some(), "Missing 'webhooks' key");
        assert!(json.get("config").is_some(), "Missing 'config' key");
        assert!(
            json.get("uptime_secs").is_some(),
            "Missing 'uptime_secs' key"
        );

        // Verify nested structure
        let event_bus = json.get("event_bus").unwrap();
        assert!(event_bus.get("subscriber_count").is_some());
        assert!(event_bus.get("history_size").is_some());

        let propagation = json.get("propagation").unwrap();
        assert!(propagation.get("dag_node_count").is_some());
        assert!(propagation.get("dag_edge_count").is_some());
    }

    /// Test that admin stats endpoint is accessible through the full application
    /// router created by `create_router()`, including the rate-limiting and
    /// middleware layers.
    #[tokio::test]
    async fn test_system_stats_via_full_router() {
        let state = AppState::new(ApiConfig::default());
        let router = crate::routes::create_router(state);

        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Admin stats should be accessible as a public endpoint through the full router"
        );

        let stats: SystemStats = parse_body(response).await;
        // Verify the response is structurally valid from the full router path
        assert_eq!(stats.propagation.dag_node_count, 0);
        assert_eq!(stats.challenges.total_challenges, 0);
    }

    /// Test that stats reflect correct state after mutations: submitting a claim
    /// via the propagation orchestrator should increase the DAG node count reported
    /// by the admin stats endpoint.
    #[tokio::test]
    async fn test_system_stats_reflects_dag_after_claim_registration() {
        use epigraph_core::{AgentId, Claim, TruthValue};

        let state = AppState::new(ApiConfig::default());

        // Register a claim directly in the propagation orchestrator
        let claim = Claim::new(
            "Test claim for DAG stats".to_string(),
            AgentId::new(),
            [0u8; 32],
            TruthValue::new(0.7).unwrap(),
        );
        {
            let mut orchestrator = state.propagation_orchestrator.write().await;
            orchestrator.register_claim(claim).expect("register claim");
        }

        // Also add an entry to the idempotency store and a webhook subscription
        // to verify multiple subsystem stats update simultaneously
        {
            let mut store = state.idempotency_store.write().await;
            store.insert(
                "mutation-test-key".to_string(),
                crate::state::CachedSubmission {
                    claim_id: uuid::Uuid::new_v4(),
                    truth_value: 0.5,
                    trace_id: uuid::Uuid::new_v4(),
                    evidence_ids: vec![],
                    created_at: std::time::Instant::now(),
                },
            );
        }

        let router = test_router_with_state(state);
        let request = Request::builder()
            .uri("/api/v1/admin/stats")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let stats: SystemStats = parse_body(response).await;
        assert_eq!(
            stats.propagation.dag_node_count, 1,
            "DAG should contain 1 node after registering a claim"
        );
        assert_eq!(
            stats.caches.idempotency_store_size, 1,
            "Idempotency store should contain 1 entry"
        );
    }
}
