use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use uuid::Uuid;

#[cfg(feature = "db")]
use epigraph_db::PgPool;

use crate::middleware::SignatureVerificationState;
use crate::oauth::providers::ProviderRegistry;
use crate::routes::harvest::HarvesterClient;
use crate::security::audit::InMemorySecurityAuditLog;
use crate::security::AgentRateLimiter;
use chrono::{DateTime, Utc};
use epigraph_core::challenge::ChallengeService;
use epigraph_core::Claim;
use epigraph_embeddings::EmbeddingService;
use epigraph_engine::{DatabasePropagator, PropagationConfig, PropagationOrchestrator};
use epigraph_events::EventBus;
use epigraph_interfaces::PolicyGate;
use serde::{Deserialize, Serialize};

/// Cached submission for idempotency
///
/// Stores the result of a successful packet submission so that
/// duplicate requests with the same idempotency key return the same result.
#[derive(Debug, Clone)]
pub struct CachedSubmission {
    pub claim_id: Uuid,
    pub truth_value: f64,
    /// The trace bound to the canonical claim, or `None` when the deduped claim
    /// has no trace (`trace_id IS NULL`). Mirrors `SubmitPacketResponse::trace_id`
    /// so a cache hit replays the exact (non-phantom) response.
    pub trace_id: Option<Uuid>,
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
/// Held in [`WebhookStore`], a per-process cache of `webhook_subscriptions`
/// (migration 085). The `secret` field is excluded from JSON serialization to
/// prevent accidental exposure in API responses.
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
    /// The `agents.id` that registered this subscription.
    ///
    /// **PR-10 re-pointed this field.** It was `owner_id`, set to
    /// `auth.owner_id.unwrap_or(auth.client_id)` — an `oauth_clients.id`. That
    /// value is a fine equality token for an ownership check and a useless one
    /// for anything else: `epigraph_db::Viewer::resolve` takes an `agents.id`,
    /// so an `oauth_clients.id` cannot be turned into reading authority, and
    /// the fan-out had no way to ask "may this subscriber see this event?".
    /// `AuthContext.agent_id` has been non-null on every authenticated request
    /// since PR-02, so the correct principal was available at registration time
    /// all along.
    ///
    /// `Option` only because `Deserialize` must have an answer for a row that
    /// carries no principal. Every path that acts on it — ownership checks in
    /// `routes/webhooks.rs`, viewer resolution in `deliver_event` — treats
    /// `None` as REFUSE, never as "skip the check". The `agent_id` column in
    /// migration 085 is `NOT NULL`, so no persisted row can produce one.
    #[serde(skip_serializing, default)]
    pub agent_id: Option<Uuid>,
}

/// Thread-safe in-memory webhook subscription store.
///
/// A per-process cache of `public.webhook_subscriptions` (migration 085), not
/// the system of record. `bin/server.rs` hydrates it at boot via
/// `WebhookSubscriptionRepository::list_active`; `register_webhook` and
/// `delete_webhook` write through to the table before touching it, so a process
/// restart no longer silently unsubscribes everyone.
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

/// Thread-safe write-authorization gate.
///
/// Defaults to [`epigraph_authz::GroupPolicyGate`] — **fail-closed**. Before
/// PR-11 this defaulted to an allow-all no-op that nothing ever called;
/// `with_policy_gate` replaces it for a deployment with its own policy.
pub type SharedPolicyGate = Arc<dyn PolicyGate>;

/// Application state shared across all request handlers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    #[cfg(feature = "db")]
    pub db_pool: PgPool,
    /// The tenancy-aware pool, when this process built one.
    ///
    /// `Option` on purpose. `ScopedPool::connect` owns pool construction —
    /// `PgPoolOptions::after_release`, the release scrub that stands between a
    /// recycled connection and a cross-tenant read, can only be installed at
    /// BUILD time — so a `ScopedPool` cannot be wrapped around a `PgPool`
    /// someone else made. `AppState`'s three existing constructors are
    /// synchronous and receive a possibly-lazy `PgPool`, so they cannot build
    /// one; only [`Self::with_scoped_pool`] (which `bin/server.rs` calls) can.
    ///
    /// The consequence is deliberate: a process that never built a `ScopedPool`
    /// cannot mint a [`epigraph_db::visibility::MaintenanceLease`], and
    /// therefore cannot construct a bypass `Viewer` at all. Fixtures and unit
    /// tests get `None` and a clear error rather than a silent bypass.
    #[cfg(feature = "db")]
    pub scoped: Option<epigraph_db::ScopedPool>,
    /// API configuration
    pub config: ApiConfig,
    /// Idempotency store for duplicate request detection
    pub idempotency_store: IdempotencyStore,
    /// Signature verification state for the Ed25519 request-signing middleware.
    ///
    /// **Test-only as of PR-03, and left in place deliberately.** Its sole
    /// production consumer was `middleware::require_signature`, which was
    /// unreachable through either `create_router` and has been deleted; the
    /// remaining constructors (`with_signature_state`,
    /// `with_db_and_signature_state`) and every reader of this field now live
    /// under `tests/`. `SecurityEvent::signature_verification` and
    /// `::auth_attempt` are consequently never written any more — `deploy.md`
    /// §5 tells operators their dashboards for those two event types will read
    /// empty.
    ///
    /// Not deleted here because removing it means touching `AppState`'s two
    /// non-db constructors, and the `not(feature = "db")` configuration does
    /// not compile today (28 pre-existing errors), so the change could not be
    /// verified. It is dead weight, not a hazard: nothing reads it on a request
    /// path.
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

    /// Write-authorization gate.
    ///
    /// Defaults to [`epigraph_authz::GroupPolicyGate`], which denies unless the
    /// principal owns the resource or holds `admin`/`writer` in its owning
    /// group. `with_policy_gate` replaces it.
    ///
    /// Unlike the pre-PR-11 field, this one is **consulted**: see
    /// `routes/ownership.rs::assign_ownership` / `::update_partition`.
    pub policy_gate: SharedPolicyGate,

    /// External identity provider registry. Built once at startup from `providers.toml`.
    /// Empty by default — server still works for agent/service auth and existing tokens,
    /// but external `grant_type=*` requests return 400 unsupported_grant_type.
    pub providers: Arc<ProviderRegistry>,

    /// entity_types registry cache: `type_name` -> resolved [`EntityTypeEntry`].
    ///
    /// The single source of truth (in-process) for BOTH edge entity-type
    /// validity (`is_valid_entity_type` = `contains_key`) and existence
    /// checking (`entity_exists`). Uses a `std::sync::RwLock` (like
    /// `revoked_tokens`) so reads stay synchronous on the hot path.
    ///
    /// Primed by [`AppState::load_entity_type_cache`] at startup (the sync
    /// `with_db` constructors can't `SELECT`, so it starts empty and is loaded
    /// just after the pool connects — see server.rs). Also self-heals via
    /// read-through-on-miss in `entity_exists` / the admin write-through.
    #[cfg(feature = "db")]
    pub entity_type_cache: Arc<std::sync::RwLock<HashMap<String, epigraph_db::EntityTypeEntry>>>,
}

/// API configuration options
#[derive(Clone)]
pub struct ApiConfig {
    /// Whether to require Ed25519 signatures on write operations
    pub require_packet_signatures: bool,
    /// Maximum size of request bodies in bytes
    pub max_request_size: usize,
    /// Public HTTPS base URL this API is reachable at externally (no trailing slash),
    /// used to build OAuth discovery documents and consent/redirect links.
    /// e.g. "https://5-78-124-36.nip.io"
    pub public_base_url: String,
    /// Re-open the pre-PR-02 identity posture: permit an external IdP to
    /// provision (and to refresh) an identity even when the provider configures
    /// NO `allowed_emails`/`allowed_domains` allowlist.
    ///
    /// Defaults to `false` — an empty allowlist DENIES. Setting it true is an
    /// explicit operator declaration that "any identity this IdP authenticates
    /// may have an account here", which is exactly what the old empty-list
    /// default meant silently. Read from `EPIGRAPH_ALLOW_ALL_IDENTITIES` in
    /// `bin/server.rs`; also consulted by
    /// `oauth::providers::build_registry`, which refuses to boot under
    /// `EPIGRAPH_ENV=production` with an empty allowlist and this false.
    pub allow_all_identities: bool,
}

impl ApiConfig {
    /// The RFC 9728 protected-resource-metadata document URL for this
    /// deployment.
    ///
    /// A **method**, not a field, on purpose. `ApiConfig` is not
    /// `#[non_exhaustive]` and ~70 struct literals in this workspace name every
    /// field explicitly, five of them without a `..Default::default()` spread;
    /// a new field would break all five and add a value that is derivable from
    /// one already present.
    ///
    /// It derives the same document URL that
    /// `oauth::metadata::protected_resource_metadata` already serves from
    /// `public_base_url`, so the URL named in a `WWW-Authenticate` challenge
    /// and the URL that actually answers cannot drift.
    ///
    /// Operators who front the API with a different metadata host override the
    /// derived value with `EPIGRAPH_RESOURCE_METADATA_URL` in `bin/server.rs`.
    #[must_use]
    pub fn resource_metadata_url(&self) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource",
            self.public_base_url.trim_end_matches('/')
        )
    }
}

/// The tenancy triggers **migration 070** installs, as `(relation, trigger)`.
///
/// Transcribed from `migrations/070_tenancy_write_path.sql`: arm (c)'s
/// 17-element `inheritors` array, plus `claims_require_tenancy` (arm a),
/// `edges_tenancy` (arm b) and `claims_propagate_tenancy` (arm d).
///
/// Required unconditionally by [`AppState::assert_tenancy_triggers_armed`],
/// because every database from 070 onward has them — including one sitting at
/// plan §9.2 step (i) with 074 not yet applied.
#[cfg(feature = "db")]
const TENANCY_TRIGGERS_070: &[(&str, &str)] = &[
    ("claims", "claims_require_tenancy"),
    ("claims", "claims_propagate_tenancy"),
    ("edges", "edges_tenancy"),
    ("evidence", "evidence_inherit_tenancy"),
    ("triples", "triples_inherit_tenancy"),
    ("entity_mentions", "entity_mentions_inherit_tenancy"),
    ("claim_versions", "claim_versions_inherit_tenancy"),
    ("mass_functions", "mass_functions_inherit_tenancy"),
    ("ds_combined_beliefs", "ds_combined_beliefs_inherit_tenancy"),
    (
        "ds_bayesian_divergence",
        "ds_bayesian_divergence_inherit_tenancy",
    ),
    ("claim_frames", "claim_frames_inherit_tenancy"),
    (
        "harvester_claim_provenance",
        "harvester_claim_provenance_inherit_tenancy",
    ),
    ("challenges", "challenges_inherit_tenancy"),
    ("reasoning_traces", "reasoning_traces_inherit_tenancy"),
    ("experiment_triples", "experiment_triples_inherit_tenancy"),
    (
        "experiment_entity_mentions",
        "experiment_entity_mentions_inherit_tenancy",
    ),
    ("claim_clusters", "claim_clusters_inherit_tenancy"),
    (
        "claim_cluster_membership",
        "claim_cluster_membership_inherit_tenancy",
    ),
    (
        "claim_neighborhood_membership",
        "claim_neighborhood_membership_inherit_tenancy",
    ),
    (
        "claim_signature_revocations",
        "claim_signature_revocations_inherit_tenancy",
    ),
];

/// The tenancy triggers **migration 074** ADDS, as `(relation, trigger)`.
///
/// Transcribed from `migrations/074_tenancy_required.sql`: section 2's
/// 17 derived-table `*_require_tenancy` triggers (the same 17 relations as
/// 070's `inheritors`, on the BEFORE INSERT side), section 3's 6 roots, and
/// section 4's `claims_block_widening`.
///
/// Required by [`AppState::assert_tenancy_triggers_armed`] **only when
/// `claims_block_widening` is present**, which is the marker that 074 ran.
/// See that function's doc for why a flat required set would refuse to boot at
/// plan §9.2 step (i) and cause the outage it exists to prevent.
#[cfg(feature = "db")]
const TENANCY_TRIGGERS_074: &[(&str, &str)] = &[
    ("claims", "claims_block_widening"),
    ("evidence", "evidence_require_tenancy"),
    ("triples", "triples_require_tenancy"),
    ("entity_mentions", "entity_mentions_require_tenancy"),
    ("claim_versions", "claim_versions_require_tenancy"),
    ("mass_functions", "mass_functions_require_tenancy"),
    ("ds_combined_beliefs", "ds_combined_beliefs_require_tenancy"),
    (
        "ds_bayesian_divergence",
        "ds_bayesian_divergence_require_tenancy",
    ),
    ("claim_frames", "claim_frames_require_tenancy"),
    (
        "harvester_claim_provenance",
        "harvester_claim_provenance_require_tenancy",
    ),
    ("challenges", "challenges_require_tenancy"),
    ("reasoning_traces", "reasoning_traces_require_tenancy"),
    ("experiment_triples", "experiment_triples_require_tenancy"),
    (
        "experiment_entity_mentions",
        "experiment_entity_mentions_require_tenancy",
    ),
    ("claim_clusters", "claim_clusters_require_tenancy"),
    (
        "claim_cluster_membership",
        "claim_cluster_membership_require_tenancy",
    ),
    (
        "claim_neighborhood_membership",
        "claim_neighborhood_membership_require_tenancy",
    ),
    (
        "claim_signature_revocations",
        "claim_signature_revocations_require_tenancy",
    ),
    ("frames", "frames_require_tenancy"),
    ("contexts", "contexts_require_tenancy"),
    ("perspectives", "perspectives_require_tenancy"),
    ("communities", "communities_require_tenancy"),
    ("harvester_fragments", "harvester_fragments_require_tenancy"),
    ("recall_events", "recall_events_require_tenancy"),
];

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
            policy_gate: Arc::new(epigraph_authz::GroupPolicyGate::new()),
            providers: Arc::new(ProviderRegistry::empty()),
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
            scoped: None,
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
            policy_gate: Arc::new(epigraph_authz::GroupPolicyGate::new()),
            providers: Arc::new(ProviderRegistry::empty()),
            entity_type_cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
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
            policy_gate: Arc::new(epigraph_authz::GroupPolicyGate::new()),
            providers: Arc::new(ProviderRegistry::empty()),
        }
    }

    /// Create application state from a [`epigraph_db::ScopedPool`].
    ///
    /// The only constructor that can populate [`Self::scoped`], and therefore
    /// the only one after which [`Self::maintenance_viewer`] can succeed.
    /// `bin/server.rs` uses it; it keeps the inner `PgPool` in `db_pool` so no
    /// existing handler changes shape.
    #[cfg(feature = "db")]
    #[must_use]
    pub fn with_scoped_pool(scoped: epigraph_db::ScopedPool, config: ApiConfig) -> Self {
        let db_pool = scoped.inner().clone();
        let mut st = Self::with_db(db_pool, config);
        st.scoped = Some(scoped);
        st
    }

    /// A bypass viewer plus the maintenance connection it is inseparable from.
    ///
    /// This lives in `state.rs` and NOT under `routes/` on purpose:
    /// `crates/epigraph-api/tests/no_bypass_in_handlers.rs` (PR-03) fails the
    /// build on the literals `Viewer::system(` or `MaintenanceLease` anywhere
    /// under `crates/epigraph-api/src/routes/`. That lint is right — a bypass
    /// inside a request handler is the bug it exists to prevent — and the three
    /// genuine maintenance routes (`find_claims_needing_embeddings` is the one
    /// PR-06 converts) reach their bypass through here instead, where a reviewer
    /// looking for "who can bypass" will actually find it.
    ///
    /// The returned `MaintenanceConn` must be held for as long as the viewer is
    /// used, and from PR-15 on it must also be the thing the statements RUN on:
    /// the maintenance connection is the privileged one, so a caller that holds
    /// it and then queries `db_pool` gets a bypass viewer on an unprivileged
    /// connection — an empty result and a 200. `routes/claims.rs::find_claims_needing_embeddings`
    /// is the one call site and it passes `&mut *maint_conn`.
    ///
    /// The coupling is NOT enforced by the type: the `Viewer` is owned and the
    /// `MaintenanceLease` it was minted from drops at return, so dropping the
    /// connection leaves a usable viewer behind. Making that structural is
    /// `D-PR17-maintenance-lease-coupling-is-a-convention`.
    ///
    /// # Errors
    /// `DbError::InvalidData` when this `AppState` was not built from a
    /// `ScopedPool` (see [`Self::scoped`]); `DbError::ConnectionFailed` on the
    /// acquire.
    #[cfg(feature = "db")]
    pub async fn maintenance_viewer(
        &self,
        reason: epigraph_db::visibility::SystemReason,
    ) -> Result<
        (
            epigraph_db::MaintenanceConn<'_>,
            epigraph_db::visibility::Viewer,
        ),
        epigraph_db::DbError,
    > {
        let scoped = self
            .scoped
            .as_ref()
            .ok_or_else(|| epigraph_db::DbError::InvalidData {
                reason: "AppState was not built from a ScopedPool, so no maintenance \
                         lease can be minted; use AppState::with_scoped_pool"
                    .to_string(),
            })?;
        let (conn, lease) = scoped.unscoped_for_maintenance(reason).await?;
        let viewer = epigraph_db::visibility::Viewer::system(&lease, reason);
        Ok((conn, viewer))
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
            scoped: None,
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
            policy_gate: Arc::new(epigraph_authz::GroupPolicyGate::new()),
            providers: Arc::new(ProviderRegistry::empty()),
            entity_type_cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
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
            policy_gate: Arc::new(epigraph_authz::GroupPolicyGate::new()),
            providers: Arc::new(ProviderRegistry::empty()),
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
            scoped: None,
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
            policy_gate: Arc::new(epigraph_authz::GroupPolicyGate::new()),
            providers: Arc::new(ProviderRegistry::empty()),
            entity_type_cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Default JWT config from env var or dev fallback.
    fn default_jwt_config() -> Arc<crate::oauth::JwtConfig> {
        // NOTE: intentionally NOT fail-closed. This is called by test/builder
        // constructors; the production gate lives in bin/server.rs::main behind
        // EPIGRAPH_ALLOW_INSECURE_SECRET. See epigraph_auth::assert_production_secret.
        let secret = std::env::var("EPIGRAPH_JWT_SECRET").unwrap_or_else(|_| {
            String::from_utf8(epigraph_auth::DEV_JWT_SECRET.to_vec())
                .expect("DEV_JWT_SECRET is valid UTF-8")
        });
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

    /// Prime the `entity_type_cache` from the `entity_types` registry.
    ///
    /// The sync `with_db*` constructors cannot `SELECT` (they receive a
    /// possibly-lazy pool), so the cache starts empty and this loader is called
    /// once at startup right after the pool connects (see server.rs), and by
    /// tests right after `with_db`. Owned-table (`is_optional=false`) absence is
    /// a loud `tracing::error!` — an epigraph-owned backing table that failed
    /// `to_regclass` means the schema is broken.
    ///
    /// # Errors
    /// Returns the underlying `DbError` if the registry query fails.
    #[cfg(feature = "db")]
    pub async fn load_entity_type_cache(&self) -> Result<(), epigraph_db::DbError> {
        let entries = epigraph_db::EntityTypeRepository::list_all(&self.db_pool).await?;
        let mut map = HashMap::with_capacity(entries.len());
        for (name, entry) in entries {
            if !entry.is_optional && entry.table.is_some() && !entry.table_present {
                tracing::error!(
                    entity_type = %name,
                    schema = %entry.schema,
                    table = ?entry.table,
                    "Owned entity-type backing table absent at cache load — edges of this type will fail loud"
                );
            }
            map.insert(name, entry);
        }
        if let Ok(mut cache) = self.entity_type_cache.write() {
            *cache = map;
        }
        Ok(())
    }

    /// PR-16 boot assertion: **the tenancy triggers are armed.**
    ///
    /// Plan §8.2 A5, checked at startup rather than only in the test suite.
    /// `ALTER TABLE … DISABLE TRIGGER` and `SET session_replication_role =
    /// 'replica'` are the two ways to revert D1's whole write-side enforcement
    /// with no diff and no migration, and migration 074's own header names them
    /// as the residual it cannot close. Both need table ownership, which the
    /// application role does not have — but a database restored from a dump, or
    /// one an operator "fixed" during an incident, can arrive with a trigger
    /// disabled and nothing would say so.
    ///
    /// **This one refuses to serve.** A disabled require-tenancy trigger is
    /// indistinguishable at the row level from an absent one: writes succeed
    /// and land on nothing, because migration 074 also removed the DEFAULT that
    /// used to catch them. Serving in that state produces rows with a `NOT
    /// NULL` violation waiting to happen and, worse, a corpus whose tenancy
    /// nobody declared.
    ///
    /// Placed here, not in `with_db`: that constructor is sync and cannot
    /// `SELECT`. [`Self::load_entity_type_cache`] is the existing precedent for
    /// a post-connect async boot step, and `bin/server.rs` calls both together.
    ///
    /// # The set is checked by NAME, not by count — and it is STAGED
    ///
    /// A "non-empty, none disabled" probe passes on a database that is missing
    /// `claims_require_tenancy` and nothing else, because the other 43 matching
    /// triggers are still there. That is the case that matters: it is D1's
    /// primary enforcement, and after 074 there is no `DEFAULT` left behind it.
    /// So the expected `(relation, trigger)` pairs are enumerated below, the
    /// same way `visibility_lint.rs::EXPECTED_EXEMPTIONS` and
    /// `viewer_route_table_lint.rs::FAIL_OPEN_SCOPE_SITES` enumerate theirs.
    ///
    /// **It is staged on purpose, and transcribing 074's arrays as one flat
    /// required set would brick plan §9.2 step (i).** That step deploys these
    /// binaries with 074 NOT YET APPLIED, to watch PR-12's
    /// `tenancy_undeclared_writes` counter sit at zero for 24 hours before the
    /// migration commits. On such a database 074's 23 additional
    /// `*_require_tenancy` triggers and `claims_block_widening` do not exist,
    /// and a flat assertion would refuse to boot — turning the control that
    /// prevents the outage into the outage.
    ///
    /// Hence two tiers:
    ///   * [`TENANCY_TRIGGERS_070`] is required unconditionally. Every database
    ///     that has applied 070 has it, before and after 074.
    ///   * [`TENANCY_TRIGGERS_074`] is required only once `claims_block_widening`
    ///     is present, which is the marker that 074 has run. A half-applied 074
    ///     (some roots armed, `claims_block_widening` created) is therefore
    ///     still caught, because that trigger is created in section 4, before
    ///     section 5 drops the defaults.
    ///
    /// A trigger whose *table* does not exist is not required — 070 and 074
    /// both guard their `CREATE TRIGGER` with `IF EXISTS (… relkind = 'r')`, so
    /// requiring it would refuse on exactly the databases those guards exist
    /// for. Missing-table is reported as a warning, not a refusal.
    ///
    /// # Errors
    /// Returns `DbError::InvalidData` if an expected trigger is absent on a
    /// table that exists, or if any matching trigger is not `tgenabled = 'O'`.
    #[cfg(feature = "db")]
    pub async fn assert_tenancy_triggers_armed(&self) -> Result<(), epigraph_db::DbError> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT c.relname, t.tgname, t.tgenabled::text \
               FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
              WHERE NOT t.tgisinternal \
                AND (t.tgname LIKE '%\\_require\\_tenancy' \
                     OR t.tgname LIKE '%\\_inherit\\_tenancy' \
                     OR t.tgname IN ('edges_tenancy','claims_propagate_tenancy', \
                                     'claims_block_widening')) \
              ORDER BY c.relname, t.tgname",
        )
        .fetch_all(&self.db_pool)
        .await?;

        let present: std::collections::HashSet<(&str, &str)> = rows
            .iter()
            .map(|(rel, tg, _)| (rel.as_str(), tg.as_str()))
            .collect();

        // Which of the expected tables actually exist. `relkind = 'r'` matches
        // the guard 070/074 use, so a VIEW or an absent relation is excluded
        // here for the same reason no trigger was created on it there.
        let existing_tables: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY($1)",
        )
        .bind(
            TENANCY_TRIGGERS_070
                .iter()
                .chain(TENANCY_TRIGGERS_074.iter())
                .map(|(rel, _)| (*rel).to_string())
                .collect::<Vec<_>>(),
        )
        .fetch_all(&self.db_pool)
        .await?;
        let existing: std::collections::HashSet<&str> =
            existing_tables.iter().map(String::as_str).collect();

        // 074 ran iff `claims_block_widening` is installed. It is created in
        // section 4, ahead of section 5's `DROP DEFAULT`, so this marker cannot
        // be true on a database that still has the defaults to fall back on.
        let migration_074_applied = present.contains(&("claims", "claims_block_widening"));

        let mut required: Vec<(&str, &str)> = TENANCY_TRIGGERS_070.to_vec();
        if migration_074_applied {
            required.extend_from_slice(TENANCY_TRIGGERS_074);
        }

        let mut missing: Vec<String> = Vec::new();
        let mut table_absent: Vec<&str> = Vec::new();
        for (rel, tg) in required {
            if !existing.contains(rel) {
                table_absent.push(rel);
                continue;
            }
            if !present.contains(&(rel, tg)) {
                missing.push(format!("{rel}.{tg}"));
            }
        }
        if !table_absent.is_empty() {
            table_absent.sort_unstable();
            table_absent.dedup();
            tracing::warn!(
                tables = ?table_absent,
                "tenancy-trigger tables absent; their triggers are not required on this database"
            );
        }
        if !missing.is_empty() {
            return Err(epigraph_db::DbError::InvalidData {
                reason: format!(
                    "refusing to serve: {} expected tenancy trigger(s) are MISSING: {}. \
                     Migration 070 installs the first tier and 074 the second; a database \
                     without them accepts writes that declare no owner, and after 074 there \
                     is no DEFAULT left to catch them. Re-run epigraph-migrate, then restart.",
                    missing.len(),
                    missing.join(", ")
                ),
            });
        }

        let disabled: Vec<String> = rows
            .iter()
            .filter(|(_, _, e)| e != "O")
            .map(|(rel, tg, e)| format!("{rel}.{tg}={e}"))
            .collect();
        if !disabled.is_empty() {
            return Err(epigraph_db::DbError::InvalidData {
                reason: format!(
                    "refusing to serve: {} tenancy trigger(s) are not ENABLED \
                     (tgenabled <> 'O'): {}. Re-enable them with ALTER TABLE … ENABLE \
                     TRIGGER as the table owner, then restart.",
                    disabled.len(),
                    disabled.join(", ")
                ),
            });
        }

        tracing::info!(
            triggers = rows.len(),
            migration_074_applied,
            "tenancy triggers armed"
        );
        Ok(())
    }

    /// PR-16 boot posture check: **is this process connecting as the
    /// application role, and can it take the seed escape hatch?**
    ///
    /// # Why this WARNS and does not refuse — a correction to the plan
    ///
    /// PR-16's *Files* line says the boot assertions gain, alongside
    /// `tgenabled='O'`, "not-a-member-of-`epigraph_seed`" and
    /// `current_user = 'epigraph_app'`. Measured on this tree: the connecting
    /// role is `epigraph`, which is `rolsuper` and therefore satisfies
    /// `pg_has_role(session_user, 'epigraph_seed', 'MEMBER')` for free, and
    /// `current_user` is `epigraph`, not `epigraph_app`. Making either a hard
    /// refusal would stop the API booting in CI and in every development
    /// environment **today**, before anything has gone wrong — a self-inflicted
    /// outage in service of a posture nothing yet establishes.
    ///
    /// The credential split is plan §9.2's week 11d, and PR-17 owns it by name:
    /// its *Acceptance* line already reads "the process refuses to serve as a
    /// superuser or `BYPASSRLS` holder … refuses if `current_user <>
    /// 'epigraph_app'`". So the two checks are duplicated across PR-16 and
    /// PR-17's *Files* lines, and PR-17 is where they can be armed, because
    /// that is the PR that repoints `DATABASE_URL`.
    ///
    /// Shipping them as WARNs now is not a no-op: it puts the measurement in
    /// the boot log of every environment, so week 11d's flip is a change whose
    /// blast radius is already known rather than discovered on the day.
    ///
    /// # Errors
    /// Returns the underlying `DbError` if the catalog probe itself fails. The
    /// posture findings are logged, not returned.
    #[cfg(feature = "db")]
    pub async fn warn_on_privileged_connection(&self) -> Result<(), epigraph_db::DbError> {
        let (current_user, is_seed_member, is_super): (String, bool, bool) = sqlx::query_as(
            "SELECT current_user::text, \
                    EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_seed') \
                      AND pg_has_role(session_user, 'epigraph_seed', 'MEMBER'), \
                    (SELECT rolsuper FROM pg_roles WHERE rolname = session_user)",
        )
        .fetch_one(&self.db_pool)
        .await?;

        if current_user != "epigraph_app" {
            tracing::warn!(
                current_user = %current_user,
                "connecting as a role other than epigraph_app. PR-17 (plan §9.2 week 11d) \
                 turns this into a refusal; until then it is a posture note."
            );
        }
        if is_seed_member {
            tracing::warn!(
                current_user = %current_user,
                superuser = is_super,
                "this connection can take migration 074's epigraph_seed escape hatch, so an \
                 undeclared write is STAMPED ('public', <seed group>) instead of raising \
                 23502. Audit with: SELECT count(*) FROM claims WHERE owner_group_id = \
                 '00000000-0000-0000-0000-00000000dead'. \
                 Arming this as a refusal is D-PR16-seed-membership-refusal-downgraded, \
                 owned by PR-17."
            );
        }
        Ok(())
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

    /// Inject a deployment's own policy gate (builder pattern).
    ///
    /// Replaces the default [`epigraph_authz::GroupPolicyGate`] with a
    /// deployment's own implementation.
    /// Must be called at startup before the router is created.
    #[must_use]
    pub fn with_policy_gate(mut self, gate: SharedPolicyGate) -> Self {
        self.policy_gate = gate;
        self
    }

    /// Replace the external-provider registry (builder pattern).
    ///
    /// Call at startup after loading `providers.toml`. When omitted, the registry
    /// is empty — agent/service/refresh auth still works; external grant types
    /// return 400 unsupported_grant_type.
    #[must_use]
    pub fn with_providers(mut self, providers: Arc<ProviderRegistry>) -> Self {
        self.providers = providers;
        self
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            require_packet_signatures: false,
            max_request_size: 10 * 1024 * 1024, // 10MB
            public_base_url: "http://localhost:8080".to_string(),
            // Fail closed. An operator who wants the old allow-all posture must
            // say so with EPIGRAPH_ALLOW_ALL_IDENTITIES=true.
            allow_all_identities: false,
        }
    }
}

/// PR-11's second acceptance criterion: *a fresh `AppState` denies by default*.
///
/// Before PR-11 this module held `appstate_accepts_noop_providers`, which
/// asserted the three `Shared*` aliases were `Send + Sync` by constructing a
/// no-op for each. Two of the three traits are gone; the surviving one changed
/// from a compile-only assertion to a behavioural one, because "the field
/// accepts a trait object" was exactly the property that was true while the
/// gate was never called.
///
/// # Why this does not build an `AppState`
///
/// Every `AppState` constructor needs a live `PgPool` (or, in the no-db arm,
/// the whole set of embedding/event/challenge services). What is under test is
/// the *default the constructors install*, and all six install the identical
/// expression `Arc::new(epigraph_authz::GroupPolicyGate::new())`. Asserting
/// against that value directly keeps this a unit test;
/// [`the_default_gate_is_installed_at_every_constructor`] pins that the six
/// sites and the value here have not drifted apart, by reading this file.
#[cfg(test)]
mod extension_wiring_tests {
    use super::SharedPolicyGate;
    use epigraph_interfaces::{Action, Principal, ResourceKind, ResourceRef};
    use std::sync::Arc;
    use uuid::Uuid;

    /// The value every `AppState` constructor assigns to `policy_gate`.
    fn default_gate() -> SharedPolicyGate {
        Arc::new(epigraph_authz::GroupPolicyGate::new())
    }

    #[tokio::test]
    async fn a_fresh_appstates_gate_denies_a_principal_with_no_writable_group() {
        let decision = default_gate()
            .authorize(
                &Principal::without_groups(Uuid::new_v4()),
                &Action::Create,
                &ResourceRef::new(ResourceKind::Claim, Uuid::new_v4())
                    .owned_by_group(Uuid::new_v4()),
            )
            .await;
        assert!(!decision.is_allowed(), "got {decision:?}");
    }

    /// The undeclared-resource case, at the state layer: a write whose resource
    /// names no owner at all is refused rather than waved through.
    #[tokio::test]
    async fn a_fresh_appstates_gate_denies_an_undeclared_resource() {
        let group = Uuid::new_v4();
        let decision = default_gate()
            .authorize(
                &Principal::new(Uuid::new_v4(), vec![group]),
                &Action::Create,
                &ResourceRef::new(ResourceKind::Claim, Uuid::new_v4()),
            )
            .await;
        assert!(!decision.is_allowed(), "got {decision:?}");
    }

    #[tokio::test]
    async fn a_fresh_appstates_gate_allows_a_group_writer() {
        let group = Uuid::new_v4();
        let decision = default_gate()
            .authorize(
                &Principal::new(Uuid::new_v4(), vec![group]),
                &Action::Create,
                &ResourceRef::new(ResourceKind::Claim, Uuid::new_v4()).owned_by_group(group),
            )
            .await;
        assert!(decision.is_allowed(), "got {decision:?}");
    }

    /// Six assignment sites cover eight public entry points: `AppState::new`
    /// (db) and `with_scoped_pool` delegate to `with_db` rather than assigning
    /// their own. Counting the literal is how the three tests above stay
    /// connected to the constructors they claim to describe — a seventh
    /// constructor that installed something else would show up here.
    #[test]
    fn the_default_gate_is_installed_at_every_constructor() {
        let src = include_str!("state.rs");
        // Split so the needle itself is not a seventh occurrence of the thing
        // being counted.
        let needle = concat!(
            "policy_gate: Arc::new(epigraph_authz::",
            "GroupPolicyGate::new())"
        );
        let installs = src.matches(needle).count();
        assert_eq!(
            installs, 6,
            "expected the fail-closed default at all six `policy_gate:` \
             assignment sites (AppState::new(no-db), with_db, \
             with_signature_state, with_db_and_signature_state, \
             with_propagation_config, with_db_and_propagation_config), found \
             {installs}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ApiConfig::default();
        assert!(!config.require_packet_signatures);
        assert_eq!(config.max_request_size, 10 * 1024 * 1024);
        // PR-02 decision Q4: fail closed. Flipping this default silently
        // restores allow-all external provisioning on every deployment.
        assert!(
            !config.allow_all_identities,
            "allow_all_identities must default to false"
        );
    }

    #[test]
    fn test_config_clone() {
        let config = ApiConfig {
            require_packet_signatures: true,
            max_request_size: 2048,
            ..ApiConfig::default()
        };
        let cloned = config.clone();
        assert!(cloned.require_packet_signatures);
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
