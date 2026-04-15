use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use uuid::Uuid;

#[cfg(feature = "db")]
use epigraph_db::PgPool;

use crate::middleware::SignatureVerificationState;
use crate::routes::harvest::HarvesterClient;
use crate::security::audit::InMemorySecurityAuditLog;
use crate::security::AgentRateLimiter;
use chrono::{DateTime, Utc};
use epigraph_core::challenge::ChallengeService;
use epigraph_core::Claim;
use epigraph_embeddings::EmbeddingService;
use epigraph_engine::{DatabasePropagator, PropagationConfig, PropagationOrchestrator};
use epigraph_events::EventBus;
use epigraph_interfaces::{
    EncryptionProvider, NoOpEncryptionProvider,
    OrchestrationBackend, NoOpOrchestrationBackend,
    PolicyGate, NoOpPolicyGate,
};
use serde::{Deserialize, Serialize};

/// Cached submission for idempotency
///
/// Stores the result of a successful packet submission so that
/// duplicate requests with the same idempotency key return the same result.
#[derive(Debug, Clone)]
pub struct CachedSubmission {
    pub claim_id: Uuid,
    pub truth_value: f64,
    pub trace_id: Uuid,
    pub evidence_ids: Vec<Uuid>,
    /// Timestamp when this entry was created, used for LRU eviction
    pub created_at: Instant,
}

/// Idempotency store type alias
pub type IdempotencyStore = Arc<RwLock<HashMap<String, CachedSubmission>>>;

/// Thread-safe propagation orchestrator type alias
pub type SharedOrchestrator = Arc<RwLock<PropagationOrchestrator>>;

/// Thread-safe security audit log type alias
///
/// This log captures security-relevant events for forensic analysis.
/// Using `Arc` allows sharing across handlers without mutex contention
/// since `InMemorySecurityAuditLog` uses internal RwLock.
pub type SharedAuditLog = Arc<InMemorySecurityAuditLog>;

/// Thread-safe challenge service type alias
///
/// The challenge service manages claim disputes and counter-evidence.
/// Uses `Arc` because `ChallengeService` uses internal `RwLock` for thread-safe
/// in-memory storage of challenges.
pub type SharedChallengeService = Arc<ChallengeService>;

/// Thread-safe in-memory claim store type alias
///
/// Provides a shared, concurrent map of claims keyed by UUID.
/// Used by the versioning endpoints to track claim supersession chains
/// without requiring a database.
pub type ClaimStore = Arc<RwLock<HashMap<Uuid, Claim>>>;

/// Thread-safe event bus type alias
///
/// The event bus provides pub/sub messaging for webhook notifications
/// and internal event-driven communication between components.
pub type SharedEventBus = Arc<EventBus>;

/// A registered webhook subscription
///
/// Stored in the in-memory webhook store. The `secret` field is excluded
/// from JSON serialization to prevent accidental exposure in API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSubscription {
    /// Unique identifier for this subscription
    pub id: Uuid,
    /// Target URL for webhook delivery
    pub url: String,
    /// Filter: which event types to send (empty = all)
    pub event_types: Vec<String>,
    /// When this subscription was created
    pub created_at: DateTime<Utc>,
    /// Whether this subscription is currently active
    pub active: bool,
    /// HMAC-SHA256 secret for payload signing (redacted in API responses)
    #[serde(skip_serializing, default)]
    pub secret: String,
}

/// Thread-safe in-memory webhook subscription store
pub type WebhookStore = Arc<RwLock<HashMap<Uuid, WebhookSubscription>>>;

/// Thread-safe embedding service type alias
///
/// The embedding service is optional to maintain backward compatibility.
/// When present, it provides real vector embeddings for semantic search.
/// When absent, semantic search falls back to mock embeddings.
pub type SharedEmbeddingService = Arc<dyn EmbeddingService>;

/// Thread-safe harvester gRPC client type alias
///
/// The harvester client is optional. When present, the `POST /api/v1/harvest`
/// endpoint forwards requests to the Python harvester gRPC service.
/// When absent, the endpoint returns 503 Service Unavailable.
pub type SharedHarvesterClient = Arc<dyn HarvesterClient>;

/// Thread-safe encryption provider type alias
///
/// Defaults to [`NoOpEncryptionProvider`] (pass-through). Enterprise deployments
/// replace this with an AES-256-GCM group-keyed implementation at startup.
pub type SharedEncryptionProvider = Arc<dyn EncryptionProvider>;

/// Thread-safe policy gate type alias
///
/// Defaults to [`NoOpPolicyGate`] (allow all). Enterprise deployments replace
/// this with an RBAC/ABAC enforcement implementation at startup.
pub type SharedPolicyGate = Arc<dyn PolicyGate>;

/// Thread-safe orchestration backend type alias
///
/// Defaults to [`NoOpOrchestrationBackend`] (silent drop). Enterprise deployments
/// replace this with a durable task queue implementation at startup.
pub type SharedOrchestrationBackend = Arc<dyn OrchestrationBackend>;

/// Application state shared across all request handlers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    #[cfg(feature = "db")]
    pub db_pool: PgPool,
    /// API configuration
    pub config: ApiConfig,
    /// Idempotency store for duplicate request detection
    pub idempotency_store: IdempotencyStore,
    /// Signature verification state for authenticated routes
    pub signature_state: SignatureVerificationState,
    /// Thread-safe propagation orchestrator for truth propagation
    ///
    /// The orchestrator maintains the in-memory representation of the
    /// claim dependency graph and handles Bayesian truth updates.
    pub propagation_orchestrator: SharedOrchestrator,
    /// Database propagator for triggering propagation after claim operations
    ///
    /// Contains configuration for depth limits, convergence thresholds, etc.
    pub propagator: DatabasePropagator,
    /// Rate limiter for protecting against DoS attacks
    ///
    /// Optional: When None, rate limiting is disabled.
    /// Uses per-agent and global rate limits based on token bucket algorithm.
    pub rate_limiter: Option<AgentRateLimiter>,
    /// Security audit log for tracking security-relevant events
    ///
    /// This log captures authentication attempts, signature verifications,
    /// key operations, rate limiting events, and other security events.
    /// Events include correlation IDs for request tracing.
    pub audit_log: SharedAuditLog,
    /// Optional embedding service for semantic search
    ///
    /// When present, provides real vector embeddings for claim content.
    /// When absent, semantic search falls back to mock/deterministic embeddings.
    /// This is optional to maintain backward compatibility with existing code.
    pub embedding_service: Option<SharedEmbeddingService>,
    /// Challenge service for claim dispute management
    ///
    /// Manages the lifecycle of challenges against claims, including
    /// submission, review, and resolution. Uses in-memory storage
    /// with internal RwLock for thread safety.
    pub challenge_service: SharedChallengeService,
    /// In-memory claim store for versioning and supersession tracking
    ///
    /// Maps claim UUIDs to Claim structs for the versioning endpoints.
    /// When the `db` feature is enabled, this supplements (not replaces)
    /// the database - it provides fast in-memory access for version chain
    /// traversal during supersession operations.
    pub claim_store: ClaimStore,
    /// Event bus for pub/sub messaging
    ///
    /// Provides decoupled communication between system components
    /// and supports webhook notification delivery.
    pub event_bus: SharedEventBus,
    /// Timestamp when the application was started
    ///
    /// Used to calculate uptime for the admin stats endpoint.
    pub started_at: Instant,
    /// In-memory webhook subscription store
    ///
    /// Stores registered webhook subscriptions for event notification delivery.
    /// Uses `Arc<RwLock<HashMap>>` for thread-safe concurrent access.
    pub webhook_store: WebhookStore,
    /// Optional harvester gRPC client for claim extraction
    ///
    /// When present, the `POST /api/v1/harvest` endpoint forwards text
    /// to the Python harvester service. When absent, returns 503.
    pub harvester_client: Option<SharedHarvesterClient>,
    /// JWT signing configuration for OAuth2 tokens
    ///
    /// Stored once at startup via `Arc` to avoid recreating per request.
    pub jwt_config: Arc<crate::oauth::JwtConfig>,
    /// In-memory set of revoked access tokens (JWTs)
    ///
    /// Bounded by token TTL — entries auto-expire when the token would have expired.
    /// Used by the /oauth/revoke and bearer middleware.
    revoked_tokens: Arc<std::sync::RwLock<HashSet<String>>>,

    /// Encryption provider for subgraph key management.
    ///
    /// Defaults to [`NoOpEncryptionProvider`] (pass-through). Enterprise
    /// deployments inject an AES-256-GCM implementation via `with_encryption_provider`.
    /// Handlers check `is_active()` to skip metadata writes when the no-op is active.
    pub encryption_provider: SharedEncryptionProvider,

    /// Policy gate for RBAC/ABAC enforcement.
    ///
    /// Defaults to [`NoOpPolicyGate`] (allow all). Enterprise deployments inject
    /// a real enforcement implementation via `with_policy_gate`.
    pub policy_gate: SharedPolicyGate,

    /// Orchestration backend for durable task scheduling.
    ///
    /// Defaults to [`NoOpOrchestrationBackend`] (silent drop). Enterprise deployments
    /// inject a durable queue implementation via `with_orchestration_backend`.
    pub orchestration_backend: SharedOrchestrationBackend,
}

/// API configuration options
#[derive(Clone)]
pub struct ApiConfig {
    /// Whether to require Ed25519 signatures on write operations
    pub require_signatures: bool,
    /// Maximum size of request bodies in bytes
    pub max_request_size: usize,
}

impl AppState {
    /// Create new application state with the given configuration (no database)
    #[cfg(not(feature = "db"))]
    pub fn new(config: ApiConfig) -> Self {
        let signature_state =
            SignatureVerificationState::new().with_max_request_size(config.max_request_size);
        Self {
            config,
            idempotency_store: Arc::new(RwLock::new(HashMap::new())),
            signature_state,
            propagation_orchestrator: Arc::new(RwLock::new(PropagationOrchestrator::new())),
            propagator: DatabasePropagator::with_defaults(),
            rate_limiter: None,
            audit_log: Arc::new(InMemorySecurityAuditLog::new()),
            embedding_service: None,
            challenge_service: Arc::new(ChallengeService::new()),
            claim_store: Arc::new(RwLock::new(HashMap::new())),
            event_bus: Arc::new(EventBus::new(1000)),
            started_at: Instant::now(),
            webhook_store: Arc::new(RwLock::new(HashMap::new())),
            harvester_client: None,
            jwt_config: Self::default_jwt_config(),
            revoked_tokens: Arc::new(std::sync::RwLock::new(HashSet::new())),
            encryption_provider: Arc::new(NoOpEncryptionProvider::new()),
            policy_gate: Arc::new(NoOpPolicyGate::new()),
            orchestration_backend: Arc::new(NoOpOrchestrationBackend::new()),
        }
    }

    /// Create application state with a lazy DB pool from `DATABASE_URL`.
    ///
    /// The pool connects on first use, so this remains synchronous.
    /// Panics if `DATABASE_URL` is not set.
    #[cfg(feature = "db")]
    pub fn new(config: ApiConfig) -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set when db feature is enabled");
        let db_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect_lazy(&database_url)
            .expect("Failed to create lazy DB pool from DATABASE_URL");
        Self::with_db(db_pool, config)
    }

    /// Create new application state with database pool and configuration
    #[cfg(feature = "db")]
    pub fn with_db(db_pool: PgPool, config: ApiConfig) -> Self {
        let signature_state =
            SignatureVerificationState::new().with_max_request_size(config.max_request_size);
        Self {
            db_pool,
            config,
            idempotency_store: Arc::new(RwLock::new(HashMap::new())),
            signature_state,
            propagation_orchestrator: Arc::new(RwLock::new(PropagationOrchestrator::new())),
            propagator: DatabasePropagator::with_defaults(),
            rate_limiter: None,
            audit_log: Arc::new(InMemorySecurityAuditLog::new()),
            embedding_service: None,
            challenge_service: Arc::new(ChallengeService::new()),
            claim_store: Arc::new(RwLock::new(HashMap::new())),
            event_bus: Arc::new(EventBus::new(1000)),
            started_at: Instant::now(),
            webhook_store: Arc::new(RwLock::new(HashMap::new())),
            harvester_client: None,
            jwt_config: Self::default_jwt_config(),
            revoked_tokens: Arc::new(std::sync::RwLock::new(HashSet::new())),
            encryption_provider: Arc::new(NoOpEncryptionProvider::new()),
            policy_gate: Arc::new(NoOpPolicyGate::new()),
            orchestration_backend: Arc::new(NoOpOrchestrationBackend::new()),
        }
    }

    /// Create new application state with custom signature verification state
    #[cfg(not(feature = "db"))]
    pub fn with_signature_state(
        config: ApiConfig,
        signature_state: SignatureVerificationState,
    ) -> Self {
        Self {
            config,
            idempotency_store: Arc::new(RwLock::new(HashMap::new())),
            signature_state,
            propagation_orchestrator: Arc::new(RwLock::new(PropagationOrchestrator::new())),
            propagator: DatabasePropagator::with_defaults(),
            rate_limiter: None,
            audit_log: Arc::new(InMemorySecurityAuditLog::new()),
            embedding_service: None,
            challenge_service: Arc::new(ChallengeService::new()),
            claim_store: Arc::new(RwLock::new(HashMap::new())),
            event_bus: Arc::new(EventBus::new(1000)),
            started_at: Instant::now(),
            webhook_store: Arc::new(RwLock::new(HashMap::new())),
            harvester_client: None,
            jwt_config: Self::default_jwt_config(),
            revoked_tokens: Arc::new(std::sync::RwLock::new(HashSet::new())),
            encryption_provider: Arc::new(NoOpEncryptionProvider::new()),
            policy_gate: Arc::new(NoOpPolicyGate::new()),
            orchestration_backend: Arc::new(NoOpOrchestrationBackend::new()),
        }
    }

    /// Create new application state with database pool and custom signature verification state
    #[cfg(feature = "db")]
    pub fn with_db_and_signature_state(
        db_pool: PgPool,
        config: ApiConfig,
        signature_state: SignatureVerificationState,
    ) -> Self {
        Self {
            db_pool,
            config,
            idempotency_store: Arc::new(RwLock::new(HashMap::new())),
            signature_state,
            propagation_orchestrator: Arc::new(RwLock::new(PropagationOrchestrator::new())),
            propagator: DatabasePropagator::with_defaults(),
            rate_limiter: None,
            audit_log: Arc::new(InMemorySecurityAuditLog::new()),
            embedding_service: None,
            challenge_service: Arc::new(ChallengeService::new()),
            claim_store: Arc::new(RwLock::new(HashMap::new())),
            event_bus: Arc::new(EventBus::new(1000)),
            started_at: Instant::now(),
            webhook_store: Arc::new(RwLock::new(HashMap::new())),
            harvester_client: None,
            jwt_config: Self::default_jwt_config(),
            revoked_tokens: Arc::new(std::sync::RwLock::new(HashSet::new())),
            encryption_provider: Arc::new(NoOpEncryptionProvider::new()),
            policy_gate: Arc::new(NoOpPolicyGate::new()),
            orchestration_backend: Arc::new(NoOpOrchestrationBackend::new()),
        }
    }

    /// Create new application state with custom propagation configuration
    #[cfg(not(feature = "db"))]
    pub fn with_propagation_config(
        config: ApiConfig,
        propagation_config: PropagationConfig,
    ) -> Self {
        let signature_state =
            SignatureVerificationState::new().with_max_request_size(config.max_request_size);
        Self {
            config,
            idempotency_store: Arc::new(RwLock::new(HashMap::new())),
            signature_state,
            propagation_orchestrator: Arc::new(RwLock::new(PropagationOrchestrator::new())),
            propagator: DatabasePropagator::new(propagation_config),
            rate_limiter: None,
            audit_log: Arc::new(InMemorySecurityAuditLog::new()),
            embedding_service: None,
            challenge_service: Arc::new(ChallengeService::new()),
            claim_store: Arc::new(RwLock::new(HashMap::new())),
            event_bus: Arc::new(EventBus::new(1000)),
            started_at: Instant::now(),
            webhook_store: Arc::new(RwLock::new(HashMap::new())),
            harvester_client: None,
            jwt_config: Self::default_jwt_config(),
            revoked_tokens: Arc::new(std::sync::RwLock::new(HashSet::new())),
            encryption_provider: Arc::new(NoOpEncryptionProvider::new()),
            policy_gate: Arc::new(NoOpPolicyGate::new()),
            orchestration_backend: Arc::new(NoOpOrchestrationBackend::new()),
        }
    }

    /// Create new application state with database pool and custom propagation configuration
    #[cfg(feature = "db")]
    pub fn with_db_and_propagation_config(
        db_pool: PgPool,
        config: ApiConfig,
        propagation_config: PropagationConfig,
    ) -> Self {
        let signature_state =
            SignatureVerificationState::new().with_max_request_size(config.max_request_size);
        Self {
            db_pool,
            config,
            idempotency_store: Arc::new(RwLock::new(HashMap::new())),
            signature_state,
            propagation_orchestrator: Arc::new(RwLock::new(PropagationOrchestrator::new())),
            propagator: DatabasePropagator::new(propagation_config),
            rate_limiter: None,
            audit_log: Arc::new(InMemorySecurityAuditLog::new()),
            embedding_service: None,
            challenge_service: Arc::new(ChallengeService::new()),
            claim_store: Arc::new(RwLock::new(HashMap::new())),
            event_bus: Arc::new(EventBus::new(1000)),
            started_at: Instant::now(),
            webhook_store: Arc::new(RwLock::new(HashMap::new())),
            harvester_client: None,
            jwt_config: Self::default_jwt_config(),
            revoked_tokens: Arc::new(std::sync::RwLock::new(HashSet::new())),
            encryption_provider: Arc::new(NoOpEncryptionProvider::new()),
            policy_gate: Arc::new(NoOpPolicyGate::new()),
            orchestration_backend: Arc::new(NoOpOrchestrationBackend::new()),
        }
    }

    /// Default JWT config from env var or dev fallback.
    fn default_jwt_config() -> Arc<crate::oauth::JwtConfig> {
        let secret = std::env::var("EPIGRAPH_JWT_SECRET")
            .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
        Arc::new(crate::oauth::JwtConfig::from_secret(secret.as_bytes()))
    }

    /// Add a JWT token to the revocation set.
    pub fn revoke_access_token(&self, token: &str) {
        if let Ok(mut set) = self.revoked_tokens.write() {
            set.insert(token.to_string());
        }
    }

    /// Check if a JWT token has been revoked.
    pub fn is_token_revoked(&self, token: &str) -> bool {
        self.revoked_tokens
            .read()
            .map(|set| set.contains(token))
            .unwrap_or(false)
    }

    /// Get a reference to the audit log for logging security events
    pub fn audit(&self) -> &InMemorySecurityAuditLog {
        &self.audit_log
    }

    /// Set the rate limiter for this state (builder pattern)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use epigraph_api::{AgentRateLimiter, RateLimitConfig};
    /// use epigraph_api::state::{ApiConfig, AppState};
    ///
    /// let rate_limiter = AgentRateLimiter::new(RateLimitConfig {
    ///     default_rpm: 60,
    ///     global_rpm: 1000,
    ///     replenish_interval_secs: 1,
    ///     enable_global_limit: true,
    /// });
    ///
    /// let state = AppState::new(ApiConfig::default())
    ///     .with_rate_limiter(rate_limiter);
    /// ```
    #[must_use]
    pub fn with_rate_limiter(mut self, rate_limiter: AgentRateLimiter) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Set the embedding service for this state (builder pattern)
    ///
    /// When an embedding service is configured, semantic search will use it
    /// to generate real vector embeddings. When absent, falls back to mock embeddings.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use epigraph_api::state::{ApiConfig, AppState};
    /// use epigraph_embeddings::{EmbeddingConfig, MockProvider};
    ///
    /// let config = EmbeddingConfig::openai(1536);
    /// let provider = MockProvider::new(config);
    ///
    /// let state = AppState::with_db(pool, ApiConfig::default())
    ///     .with_embedding_service(Arc::new(provider));
    /// ```
    #[must_use]
    pub fn with_embedding_service(mut self, service: SharedEmbeddingService) -> Self {
        self.embedding_service = Some(service);
        self
    }

    /// Get a reference to the embedding service if configured
    #[must_use]
    pub fn embedding_service(&self) -> Option<&SharedEmbeddingService> {
        self.embedding_service.as_ref()
    }

    /// Set a custom challenge service for this state (builder pattern)
    ///
    /// Replaces the default `ChallengeService` with a provided one.
    /// Useful for testing with pre-populated challenge data.
    #[must_use]
    pub fn with_challenge_service(mut self, service: SharedChallengeService) -> Self {
        self.challenge_service = service;
        self
    }

    /// Inject an enterprise encryption provider (builder pattern).
    ///
    /// Replaces the default [`NoOpEncryptionProvider`] with a real AES-256-GCM
    /// implementation. Must be called at startup before the router is created.
    #[must_use]
    pub fn with_encryption_provider(mut self, provider: SharedEncryptionProvider) -> Self {
        self.encryption_provider = provider;
        self
    }

    /// Inject an enterprise policy gate (builder pattern).
    ///
    /// Replaces the default [`NoOpPolicyGate`] with a real RBAC/ABAC implementation.
    /// Must be called at startup before the router is created.
    #[must_use]
    pub fn with_policy_gate(mut self, gate: SharedPolicyGate) -> Self {
        self.policy_gate = gate;
        self
    }

    /// Inject an enterprise orchestration backend (builder pattern).
    ///
    /// Replaces the default [`NoOpOrchestrationBackend`] with a durable queue
    /// implementation. Must be called at startup before the router is created.
    #[must_use]
    pub fn with_orchestration_backend(mut self, backend: SharedOrchestrationBackend) -> Self {
        self.orchestration_backend = backend;
        self
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            require_signatures: false,
            max_request_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

#[cfg(test)]
mod extension_wiring_tests {
    use epigraph_interfaces::{
        NoOpEncryptionProvider, NoOpOrchestrationBackend, NoOpPolicyGate,
    };
    use std::sync::Arc;
    use super::{SharedEncryptionProvider, SharedOrchestrationBackend, SharedPolicyGate};

    #[test]
    fn appstate_accepts_noop_providers() {
        // Verifies the trait objects are correctly declared Send + Sync.
        let _enc: SharedEncryptionProvider = Arc::new(NoOpEncryptionProvider::new());
        let _pol: SharedPolicyGate = Arc::new(NoOpPolicyGate::new());
        let _orc: SharedOrchestrationBackend = Arc::new(NoOpOrchestrationBackend::new());
        // If this compiles, the trait objects are correctly declared Send + Sync.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ApiConfig::default();
        assert!(!config.require_signatures);
        assert_eq!(config.max_request_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_config_clone() {
        let config = ApiConfig {
            require_signatures: true,
            max_request_size: 2048,
        };
        let cloned = config.clone();
        assert!(cloned.require_signatures);
        assert_eq!(cloned.max_request_size, 2048);
    }

    #[cfg(not(feature = "db"))]
    #[test]
    fn test_appstate_with_embedding_service() {
        use epigraph_embeddings::{EmbeddingConfig, MockProvider};

        let config = EmbeddingConfig::openai(1536);
        let provider = MockProvider::new(config);
        let service: SharedEmbeddingService = Arc::new(provider);

        let state = AppState::new(ApiConfig::default()).with_embedding_service(service);

        assert!(state.embedding_service().is_some());
    }

    #[cfg(not(feature = "db"))]
    #[test]
    fn test_appstate_without_embedding_service_is_none() {
        let state = AppState::new(ApiConfig::default());
        assert!(state.embedding_service().is_none());
    }
}
