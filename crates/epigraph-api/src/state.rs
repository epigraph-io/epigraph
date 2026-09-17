// UNSCOPED-POOL-EXEMPT: Boot and observability, including the session-GUC probe itself. `probe_session_gucs`,
// the entity-type cache load, the tenancy-trigger and RLS-posture assertions and the
// maintenance-viewer path all run at startup or on the maintenance connection. Scoping the probe
// to a Viewer would make it prove a property of that viewer instead of the pool.
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
/// the system of record. `hydrate_webhook_store` (below) holds the row-to-cache
/// mapping and `bin/server.rs::main` calls it once at boot — named here rather
/// than naming the repository function directly, because the mapping is where
/// the fields the fan-out reads are decided and that is what a reader following
/// this sentence wants. `register_webhook` and `delete_webhook` write through to
/// the table before touching it, so a process restart no longer silently
/// unsubscribes everyone.
pub type WebhookStore = Arc<RwLock<HashMap<Uuid, WebhookSubscription>>>;

/// Fill a process's [`WebhookStore`] from the durable table, at boot.
///
/// # Why this is a function and not eight lines inside `bin/server.rs::main`
///
/// It was those eight lines until now, and that is exactly why
/// `D-PR-webhook-dispatcher-behavioural-test`'s sibling obligation
/// (`D-PR-bin-server-boot-hydration-test`) could be raised: the whole durability
/// half of migration 085 rests on this mapping, and a block inside `main` can be
/// read and reviewed but never executed by a test. Extracting it changes no
/// behaviour — `main` calls it under the `#[cfg(feature = "db")]` the block
/// already carried — and makes the mapping reachable from
/// `tests/webhook_boot_hydration.rs`.
///
/// # Boot only, and that is now enforced rather than asserted
///
/// The extraction has a cost that a doc heading alone does not pay for. Inside
/// `main` this mapping was structurally unreachable from request-serving code;
/// as a `pub fn` on `epigraph_api::state` it is reachable from any handler, and
/// it is an authority-free corpus-wide read — every principal's subscriptions,
/// no `&Viewer`, by construction (see below). No `.db_pool` counter sees it,
/// because the pool arrives as a parameter. So
/// `epigraph-api/tests/no_bypass_in_handlers.rs` carries a needle for it: a call
/// from `epigraph-api/src/routes` or `epigraph-mcp/src/tools` fails that lint.
/// Nothing in either root calls it today; the needle exists so that the boot-only
/// constraint survives the next author who needs "just this one map".
///
/// # The mapping is the load-bearing part
///
/// `agent_id: Some(row.agent_id)` in particular. `list_webhooks`, `get_webhook`
/// and `deliver_event` all compare `agent_id == Some(principal)`, so a hydrated
/// subscription that lost its principal on the way into the cache is not a
/// cosmetic defect: it is invisible to its owner and undeliverable, while the
/// row on disk looks healthy. The column is `NOT NULL` in migration 085, so the
/// `Option` is a wire-format concession and never an absent principal here.
///
/// # It MERGES. It is not a reconciler, and calling it twice does not make it one
///
/// The loop below takes the write guard and inserts; it never clears and never
/// removes. So the contract is *fill a store*, not *make the store equal the
/// table*: a second call yields the UNION of what the store already held and
/// what `list_active` returned this time, not the table's current set. That is
/// the right shape for the one call site there is — an empty store at boot —
/// and it is the reason the returned `usize` is the number of rows `list_active`
/// returned rather than the size of the store afterwards.
///
/// This is stated because the obvious next use is not boot. Anything that wants
/// the store to track the table over time needs a mechanism that can also drop
/// an entry, which this function deliberately does not have; the conditions on
/// that are recorded under `D-PR-webhook-store-invalidation` in
/// `docs/tenancy/progress.json` and are not restated here.
/// `tests/webhook_boot_hydration.rs::hydration_merges_into_the_store_and_never_evicts`
/// pins the merge behaviour, so turning this into a reconciling function forces
/// that assertion to change in the same commit.
///
/// # No `&Viewer`, deliberately
///
/// See `epigraph_db::repos::webhook`'s module doc. This is a corpus-wide boot
/// enumerator; hydrating "as some viewer" would drop every other principal's
/// subscriptions, and the symptom — webhooks that stop firing after a deploy —
/// is indistinguishable from an idle corpus. Tenancy for webhooks is applied to
/// the EVENT against the subscriber's viewer, one level up, in `deliver_event`.
///
/// # Errors
/// Propagates [`epigraph_db::DbError`] from
/// [`epigraph_db::WebhookSubscriptionRepository::list_active`]. The caller
/// decides what a failure means; `bin/server.rs` logs it and boots anyway,
/// because an empty store delivers nothing and a degraded feature is not an
/// outage.
#[cfg(feature = "db")]
pub async fn hydrate_webhook_store(
    pool: &sqlx::PgPool,
    store: &WebhookStore,
) -> Result<usize, epigraph_db::DbError> {
    let rows = epigraph_db::WebhookSubscriptionRepository::list_active(pool).await?;
    let mut guard = store.write().await;
    for row in &rows {
        guard.insert(
            row.id,
            WebhookSubscription {
                id: row.id,
                url: row.url.clone(),
                event_types: row.event_types.clone(),
                created_at: row.created_at,
                active: row.active,
                secret: row.secret.clone(),
                agent_id: Some(row.agent_id),
            },
        );
    }
    Ok(rows.len())
}

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
    /// therefore cannot construct a bypass `Viewer` at all. Such a process gets
    /// `None` and a clear error rather than a silent bypass.
    ///
    /// # WHICH TEST FIXTURES ARE STILL SUCH A PROCESS — AND WHICH IS NOT
    ///
    /// Until conversion shard 4 that sentence read "fixtures and unit tests",
    /// full stop. It no longer does, and the change is recorded here rather
    /// than left to be discovered. [`crate::build_app_for_tests`] — which
    /// `epigraph-api/tests/common`'s `spawn_app` uses, and through it roughly
    /// sixty integration binaries — now builds through
    /// [`Self::with_scoped_pool`], because a handler converted onto
    /// [`Self::read_as`] REFUSES on a `None` and would otherwise answer 500 for
    /// a reason unrelated to the route.
    ///
    /// So the bypass mint IS reachable from `spawn_app` today, and the three
    /// route-layer consumers of it — `routes/privatization.rs::create_plan`,
    /// `routes/privatization.rs::maintenance` and the embedding-backfill site
    /// in `routes/claims.rs` — can now execute their bypass path there instead
    /// of erroring. MEASURED, because the size of that blast radius is the
    /// whole question: **no** `epigraph-api` integration binary reaches any of
    /// the three over HTTP. `privatization_routes.rs` is the only binary that
    /// names them and it invokes the handlers DIRECTLY, on its own `split_state`
    /// fixture, for a reason its module doc gives. The reachability is
    /// therefore latent rather than exercised, and it is not a production
    /// change at all: `bin/server.rs` has built through `with_scoped_pool`
    /// since PR-17.
    ///
    /// The residual a future author should know: `spawn_app` attaches no
    /// maintenance pool, so `ScopedPool::maintenance_inner()` falls back to the
    /// application pool — the fallback `unscoped_for_maintenance`'s own doc
    /// calls unsound. A test written against that path would be measuring the
    /// fallback, not the lease.
    ///
    /// Unit tests and every other non-`spawn_app` constructor are unchanged:
    /// [`Self::with_db`] still leaves this `None`, which is what the
    /// direct-invocation proofs in `epigraph-api/tests/` rely on — they set
    /// `state.scoped` by hand precisely so the two arms are DIFFERENT pools.
    /// `tests/common/mod.rs::spawn_app_with_mock_embedding` was moved onto
    /// `with_scoped_pool` in the same change, because its doc claims to mirror
    /// `build_app_for_tests` and a silent divergence there would surface as a
    /// 500 in whichever shard next converts a route reachable through it.
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
    /// e.g. "https://mcp.example.com"
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

/// Every relation the migrations FORCE, transcribed.
///
/// 062's `tier_a` (25) ∪ the ten group/identity/encryption control tables ∪ the
/// four privatization tables. Duplicated here rather than derived from the
/// catalog on purpose: a probe that asked "which tables are FORCEd" and then
/// checked that they are all FORCEd would pass whatever the migration did.
///
/// `rls_canary` is deliberately absent — migration 078 FORCEs it at creation and
/// 079's array omits it for the same reason.
///
/// # `079_rls_force.sql` IS NOT THE ONLY SOURCE, AND IT MUST NOT BE EDITED
///
/// An earlier revision of this comment said PR-18 "adds them to 079's array, to
/// this constant and to `locked_decisions.rs::FORCE_PROTECTED_SET` in one
/// commit". **The first of those three is impossible.** 079 is applied on every
/// database that has run this branch, and `migrations/README.md` states the
/// governing rule: editing an applied file changes its checksum and
/// `sqlx migrate run` then refuses to start, which panics the api binary on
/// restart. 079's own header carries the same wrong instruction and cannot be
/// corrected either, for exactly that reason.
///
/// The instrument is the one 078 established and 079's header names: **a table
/// added from 080 onward FORCEs itself at creation.** Migrations 080–083 each
/// issue `ENABLE` + `FORCE ROW LEVEL SECURITY` on the table they create. So a
/// table added to this constant must be FORCEd by ITS OWN migration, never by
/// 079.
///
/// # Adding a name here without the DDL is a self-inflicted outage
///
/// [`rls_verdict`] refuses to serve when `0 < forced_count < protected_count`,
/// and that refusal is unconditional and identity-independent. Both counts are
/// computed over relations that EXIST, so naming a not-yet-created table here is
/// inert — but naming a table that exists and is NOT FORCEd makes the process
/// refuse to start on every database that has run the migration. The DDL and
/// this constant are one decision.
#[cfg(feature = "db")]
pub const FORCE_PROTECTED_SET: &[&str] = &[
    "claims",
    "evidence",
    "edges",
    "triples",
    "entity_mentions",
    "claim_versions",
    "mass_functions",
    "ds_combined_beliefs",
    "ds_bayesian_divergence",
    "claim_frames",
    "harvester_claim_provenance",
    "challenges",
    "reasoning_traces",
    "experiment_triples",
    "experiment_entity_mentions",
    "claim_clusters",
    "claim_cluster_membership",
    "claim_neighborhood_membership",
    "claim_signature_revocations",
    "harvester_fragments",
    "frames",
    "contexts",
    "perspectives",
    "communities",
    "recall_events",
    "groups",
    "group_memberships",
    "group_key_epochs",
    "agents",
    "jobs",
    "security_events",
    "claim_encryption",
    "claim_version_encryption",
    "evidence_encryption",
    "edge_encryption",
    // The four privatization tables, FORCEd by their own migrations (080, 082,
    // 083) rather than by 079. See the "079 IS NOT THE ONLY SOURCE" section
    // above.
    "privatization_plans",
    "privatization_plan_items",
    "privatization_audit",
    "instance_admins",
];

/// The role the application is expected to connect as from plan §9.2 step 11d.
///
/// This string is the ARMING MARKER for every posture refusal in
/// [`rls_verdict`]. See its documentation for why.
#[cfg(feature = "db")]
pub const EXPECTED_APP_ROLE: &str = "epigraph_app";

/// What a connection observed about the RLS posture of itself and the database.
///
/// Split from the verdict so the I/O and the decision can be tested separately —
/// the same reason `epigraph_db::MaintenancePrivilege` exists, and for the same
/// underlying constraint: **CI and every developer host connect as a superuser**,
/// for whom the interesting combinations never occur. Without the split, the
/// refusal branches here would be untestable prose.
#[cfg(feature = "db")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RlsPosture {
    /// `current_user` on this connection.
    pub current_user: String,
    /// Is `session_user` a superuser? Superusers hold implicit `BYPASSRLS`.
    pub is_superuser: bool,
    /// Does `session_user` carry the `BYPASSRLS` attribute explicitly? Half of
    /// the plan's first acceptance refusal, and it was probed NOWHERE on this
    /// tree before PR-17 — `rolbypassrls` appears in no file under
    /// `crates/epigraph-api`.
    pub has_bypassrls: bool,
    /// Can this connection take migration 074's `epigraph_seed` escape hatch?
    /// `D-PR16-seed-membership-refusal-downgraded` assigns arming this to PR-17
    /// and notes it is a SEVENTH refusal, not one of the six the plan lists.
    pub is_seed_member: bool,
    /// How many relations in `public` carry `relforcerowsecurity`, excluding
    /// `rls_canary` (which migration 078 FORCEs at creation and which 079's
    /// array deliberately omits).
    pub forced_count: i64,
    /// How many relations [`FORCE_PROTECTED_SET`] names and that exist.
    ///
    /// Deliberately not "migration 079's array": since PR-18a the constant is
    /// 079's 35 relations PLUS the four privatization tables, which 080–083
    /// FORCE at creation because 079 is applied and immutable. See
    /// [`FORCE_PROTECTED_SET`]'s own doc comment, ninety lines above.
    pub protected_count: i64,
    /// Does `public.rls_canary` exist? False below migration 078.
    pub canary_exists: bool,
    /// How many `rls_canary` rows THIS connection can see. Must be zero on an
    /// app connection: the table is `FORCE`d and its only policy is
    /// bypass-only, so a visible row means the policy is gone.
    pub canary_visible: i64,
}

/// The non-refusing outcomes of [`rls_verdict`].
#[cfg(feature = "db")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RlsVerdict {
    /// Connected as [`EXPECTED_APP_ROLE`] and every armed check passed.
    Armed,
    /// Not connected as [`EXPECTED_APP_ROLE`]. Carries the posture warning to
    /// emit. This is the state of every environment that exists today.
    NotYetTheAppRole(String),
}

/// The PR-17 boot rule, as a pure function.
///
/// # THE STAGING PROBLEM, AND WHY THE PLAN'S OWN TWO SENTENCES CANNOT BOTH HOLD
///
/// PR-17's *Acceptance* line says the process "refuses if
/// `pg_class.relforcerowsecurity` is false on any protected table". Plan §9.2
/// step **11d** says: point `DATABASE_URL` at `epigraph_app`, "confirm the six
/// boot assertions and the session-GUC probe, **then run**" the migrations.
///
/// At the moment the assertions are confirmed the migrations have not run, so
/// `relforcerowsecurity` is false everywhere, the flat assertion refuses, and
/// step 11d can never reach "then run". A flat FORCE assertion **bricks the
/// rollout it exists to protect**. It also bricks the window between 077
/// (ENABLE) and 079 (FORCE), and it bricks the documented `NO FORCE` kill
/// switch, which is step 11d's own stated rollback.
///
/// [`AppState::assert_tenancy_triggers_armed`] already solved this class of
/// problem in this file, and says why in the strongest available words: "a flat
/// assertion would refuse to boot — turning the control that prevents the
/// outage into the outage." This function stages the same way.
///
/// # THE MARKER IS `current_user`, NOT A MIGRATION NUMBER
///
/// Two candidate markers were considered and rejected.
///
/// * **FORCE itself** repeats the bug PR-15 fixed. A policy filters every role
///   except the table owner and `BYPASSRLS` holders; `FORCE` only
///   *additionally* subjects the owner. `epigraph-db/src/pool.rs`'s
///   `MaintenancePrivilege::rls_active` was widened to
///   `(relrowsecurity OR relforcerowsecurity)` for exactly that reason, and
///   anything keyed on FORCE alone is disarmed in the two states it exists
///   for — the 077→079 window and the post-`NO FORCE` rollback.
/// * **`rls_active`** (either flag, the maintenance-side signal) arms the
///   moment 077 lands, which is BEFORE the credential split. It would refuse to
///   boot on every developer host and in CI, both of which connect as the
///   superuser `epigraph`, and it would do so to prevent a failure that cannot
///   occur there — a superuser bypasses every policy.
///
/// The signal that actually distinguishes "this deployment has performed the
/// §9.2 step 11d credential split" from "this is a dev box" is **the connecting
/// role itself**. `epigraph_app` is `NOLOGIN` with no password until an
/// operator issues an out-of-band `ALTER ROLE`, so `current_user` cannot be
/// `epigraph_app` by accident. Keying on it gives exactly the property the
/// three states demand:
///
/// | State | Behaviour |
/// |---|---|
/// | pre-077, any role | inert (plus the partial-FORCE check, which is vacuous) |
/// | 077→079 window as `epigraph_app` | `forced_count` is 0, so the FORCE check is inert; the canary check is live and passes |
/// | post-079 as `epigraph_app` | fully armed |
/// | post-`NO FORCE` rollback as `epigraph_app` | `forced_count` is 0 again; boots, still filtered by 077's policies |
/// | rollback that also reverts `DATABASE_URL` | not the app role, so WARN; **boots** |
///
/// # THE SOLE CALLER IS `bin/server.rs`, AND THE STAGING DESIGN RELIES ON IT
///
/// MEASURED: `assert_rls_posture` is called from exactly one place,
/// `crates/epigraph-api/src/bin/server.rs`'s boot sequence, alongside
/// `assert_tenancy_triggers_armed` and `warn_on_privileged_connection`.
/// `epigraph_api::build_app_for_tests` — which `epigraph-api/tests/common`'s
/// `spawn_app` uses, and through it roughly sixty integration binaries —
/// reaches none of them.
///
/// **THE RE-CHECK THIS PARAGRAPH ASKED FOR HAS BEEN RUN.** It used to say the
/// fixture "builds its pool with `PgPoolOptions::connect` and calls
/// `AppState::with_db` directly", and then instructed a future author to
/// re-check if a refactor ever made it run the boot sequence. Conversion shard
/// 4 made exactly that refactor: the fixture now builds through
/// `epigraph_db::ScopedPool::connect_with_options` and
/// [`AppState::with_scoped_pool`]. The CONCLUSION survives, for a different
/// reason than the one originally written — `with_scoped_pool` delegates to
/// [`AppState::with_db`] and runs no boot assertion, so the fixture still calls
/// none of `assert_rls_posture`, [`assert_tenancy_triggers_armed`] or
/// [`warn_on_privileged_connection`]. The staging argument holds; the mechanism
/// sentence it rested on does not, and is corrected here rather than left to
/// mislead the next reader who consults this doc to answer "does the test
/// fixture arm the RLS posture checks?".
///
/// That is why arming these refusals does not turn the test suite red, and it
/// is also why arming them is MORE dangerous rather than less: no gate in the
/// four-command CI sequence exercises this function's refusal branches. They are
/// covered instead by the pure unit tests over [`rls_verdict`] below, which is
/// the same split `epigraph_db::maintenance_verdict` uses and for the same
/// reason. If a future refactor makes `build_app_for_tests` actually invoke the
/// boot sequence, re-check the staging argument before assuming it still holds.
///
/// # THE ONE ACCEPTANCE ITEM THIS DELIBERATELY DOES NOT ARM
///
/// "Refuses if `current_user <> 'epigraph_app'`" is **kept as a WARN**, and
/// that is a considered deviation rather than an omission. Arming it makes the
/// marker its own trigger: every environment that has not yet done 11d — CI,
/// every developer host, and production today — would refuse to boot the moment
/// this code deploys, which is plan §9.2 step (i)'s failure mode exactly. Worse,
/// it would make §9.2's *documented* rollback ("`NO FORCE` + revert
/// `DATABASE_URL`", sub-minute, no data change) un-bootable, because reverting
/// the DSN is precisely what puts `current_user` back to the owner role. There
/// is no marker that separates "misconfigured" from "deliberately rolled back",
/// so the honest instrument is the one that is: the CANARY. A privileged
/// connection serving traffic is caught by `canary_visible` whenever the
/// deployment claims to be the app role, which is the harm the `current_user`
/// check was reaching for.
///
/// # THE PARTIAL-FORCE CHECK IS IDENTITY-INDEPENDENT
///
/// Zero FORCEd relations is a pre-079 or rolled-back database and is inert; all
/// of them is the armed state; **a strict subset has no legitimate cause** — it
/// is a half-applied 079 or a half-applied `079-undo.sql`, and it means some
/// protected tables are enforcing against their owner and others are not. That
/// refusal fires whatever role is connecting, because a half-applied flip is
/// wrong for all of them. `docs/runbooks/079-undo.sql` loops the same array as
/// `079_rls_force.sql` so the rollback cannot create this state.
///
/// # Errors
/// `DbError::InvalidData` when a refusal fires. Each message names the fix.
#[cfg(feature = "db")]
pub fn rls_verdict(p: &RlsPosture) -> Result<RlsVerdict, epigraph_db::DbError> {
    let refuse = |reason: String| epigraph_db::DbError::InvalidData { reason };

    // Identity-independent: a half-applied FORCE, in either direction.
    if p.forced_count > 0 && p.forced_count < p.protected_count {
        return Err(refuse(format!(
            "refusing to serve: FORCE ROW LEVEL SECURITY is applied to {} of the {} protected \
             tables. A strict subset has no legitimate cause — it is a half-applied migration \
             079 or a half-applied docs/runbooks/079-undo.sql, and it leaves some protected \
             tables enforcing against their owner while others are not. Finish the flip by \
             re-running epigraph-migrate, or complete the rollback with \
             docs/runbooks/079-undo.sql, then restart.",
            p.forced_count, p.protected_count
        )));
    }

    if p.current_user != EXPECTED_APP_ROLE {
        return Ok(RlsVerdict::NotYetTheAppRole(format!(
            "connecting as `{}`, not `{EXPECTED_APP_ROLE}`. The PR-17 posture refusals are \
             STAGED on the connecting role and are therefore inert here: a superuser bypasses \
             every policy, so nothing this process does is filtered. FORCE is applied to {} of \
             {} protected tables. Plan §9.2 week 11d is the credential split that arms them.",
            p.current_user, p.forced_count, p.protected_count
        )));
    }

    // ---- armed from here: this deployment has performed the 11d split ----

    if p.is_superuser {
        return Err(refuse(format!(
            "refusing to serve: connected as `{EXPECTED_APP_ROLE}` but `session_user` is a \
             SUPERUSER. A superuser holds implicit BYPASSRLS, so every policy migration 077 \
             installs is inert for this process and tenancy is enforced by nothing below the \
             repo layer. Fix with: ALTER ROLE {EXPECTED_APP_ROLE} NOSUPERUSER."
        )));
    }
    if p.has_bypassrls {
        return Err(refuse(format!(
            "refusing to serve: connected as `{EXPECTED_APP_ROLE}` but `session_user` carries \
             BYPASSRLS. Every row-level security policy is skipped for this process. Fix with: \
             ALTER ROLE {EXPECTED_APP_ROLE} NOBYPASSRLS."
        )));
    }
    if p.is_seed_member {
        return Err(refuse(format!(
            "refusing to serve: connected as `{EXPECTED_APP_ROLE}` but this connection is a \
             member of `epigraph_seed`, so migration 074's arm 4 STAMPS an undeclared write \
             ('public', <seed group>) instead of raising 23502. The escape hatch exists for \
             test fixtures, not for a serving process. Audit with: SELECT count(*) FROM claims \
             WHERE owner_group_id = '00000000-0000-0000-0000-00000000dead'. Fix with: REVOKE \
             epigraph_seed FROM {EXPECTED_APP_ROLE}."
        )));
    }
    if p.canary_exists && p.canary_visible > 0 {
        return Err(refuse(format!(
            "refusing to serve: the `rls_canary` row IS VISIBLE on this `{EXPECTED_APP_ROLE}` \
             connection. That table is FORCE'd with a bypass-only policy (migration 078), so a \
             visible row means the policy has been dropped or row security has been disabled — \
             row-level security is NOT protecting this database and every group-private row is \
             readable. Re-run epigraph-migrate and restart; if that does not clear it, revert \
             DATABASE_URL to the owner role while you investigate."
        )));
    }

    Ok(RlsVerdict::Armed)
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
///
/// # ⚠ This list is 070's, not "every stamping trigger"
///
/// Migration 089's `harvester_claim_provenance_fragment_inherit_tenancy` is
/// deliberately absent from THIS tier and from [`TENANCY_TRIGGERS_074`], and
/// that is not an omission: an entry in either one would refuse a database that
/// is legitimately behind. Here it would refuse every pre-089 database — the
/// plan §9.2 step (i) failure this whole staged split exists to prevent — and in
/// 074's tier it would refuse every database between 074 and 089. It lives in
/// [`TENANCY_TRIGGERS_089`] instead, gated on its own migration's marker.
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

/// The tenancy trigger **migration 089** adds, as `(relation, trigger)`.
///
/// Transcribed from `migrations/089_harvester_fragment_provenance_stamp.sql`:
/// the statement-level `AFTER INSERT` trigger that stamps a harvester fragment
/// from the claim its provenance link names.
///
/// Required by [`AppState::assert_tenancy_triggers_armed`] **only when 089's
/// own function `public.epigraph_inherit_fragment_tenancy_stmt` exists**, which
/// is [`MIGRATION_089_MARKER`].
///
/// # Why a third tier rather than an entry in one of the other two
///
/// Both existing tiers would refuse a database that is legitimately behind:
/// unconditionally, every pre-089 database (plan §9.2 step (i)); under 074's
/// marker, every database between 074 and 089. The staging is the control, so
/// each migration's triggers have to be gated on that migration's own marker.
///
/// # Why the FUNCTION is the marker and the trigger is not
///
/// A gate keyed on the trigger would be vacuous by construction: the state it
/// exists to catch is the trigger's absence, and the marker would vanish with
/// it. 089 installs a `CREATE OR REPLACE FUNCTION` as well as a
/// `CREATE TRIGGER`, and dropping the trigger leaves the function behind — so
/// "function present, trigger absent" is exactly the state that now refuses.
/// Dropping both (a database that never ran 089, or one deliberately reverted
/// by 089's own documented reversal) requires nothing and boots, which is what
/// keeps the staging property intact.
///
/// # What this closes
///
/// Before this tier, a *disabled* 089 trigger was refused — the `disabled` half
/// of the check is built from the `%\_inherit\_tenancy` LIKE-matched rows rather
/// than from `required` — while a *dropped* one was not. That asymmetry was
/// finding `F-089-G` in `docs/tenancy/progress.json`.
#[cfg(feature = "db")]
const TENANCY_TRIGGERS_089: &[(&str, &str)] = &[(
    "harvester_claim_provenance",
    "harvester_claim_provenance_fragment_inherit_tenancy",
)];

/// The marker that migration 089 has run: the function it installs alongside
/// its trigger. See [`TENANCY_TRIGGERS_089`] for why it is the function and not
/// the trigger.
#[cfg(feature = "db")]
const MIGRATION_089_MARKER: &str = "epigraph_inherit_fragment_tenancy_stmt";

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
    /// Returns one [`epigraph_db::MaintenanceSession`] owning the privileged
    /// connection and the bypass viewer together: the viewer comes out only as
    /// `&Viewer`, so a call site that drops the connection and goes on using the
    /// viewer is now a borrow error rather than a review item. That is the
    /// accidental half of `D-PR17-maintenance-lease-coupling-is-a-convention`;
    /// the deliberate half is not closed, because `Viewer` is `Clone` — see
    /// [`epigraph_db::MaintenanceSession`]. The mint is
    /// `ScopedPool::maintenance_session`, shared with the CLI and MCP wrappers.
    ///
    /// The remaining discipline is one the type cannot express: from PR-15 on
    /// the statements must also RUN on that connection. A caller that holds the
    /// session and then queries `db_pool` gets a bypass viewer on an
    /// unprivileged connection — an empty result and a 200.
    /// `routes/claims.rs::find_claims_needing_embeddings` is the one call site
    /// and it takes both halves from [`epigraph_db::MaintenanceSession::split`].
    /// That residual is `D-PR17-hybrid-shape-lint`, which is a lint's job rather
    /// than a lifetime's.
    ///
    /// # Errors
    /// `DbError::InvalidData` when this `AppState` was not built from a
    /// `ScopedPool` (see [`Self::scoped`]); `DbError::ConnectionFailed` on the
    /// acquire.
    #[cfg(feature = "db")]
    pub async fn maintenance_viewer(
        &self,
        reason: epigraph_db::visibility::SystemReason,
    ) -> Result<epigraph_db::MaintenanceSession<'_>, epigraph_db::DbError> {
        let scoped = self
            .scoped
            .as_ref()
            .ok_or_else(|| epigraph_db::DbError::InvalidData {
                reason: "AppState was not built from a ScopedPool, so no maintenance \
                         lease can be minted; use AppState::with_scoped_pool"
                    .to_string(),
            })?;
        scoped.maintenance_session(reason).await
    }

    /// A connection stamped with `viewer`'s tenancy context, in whichever form
    /// the deployment's [`epigraph_db::SessionGucMode`] requires.
    ///
    /// The read-side twin of [`Self::maintenance_viewer`], and the entry point
    /// the request path converts onto: a handler that has a `Viewer` (from
    /// `ViewerExtractor`) hands it here and gets back something it can `&mut *`
    /// into the repo layer, instead of reaching for the raw `db_pool`.
    ///
    /// # It REFUSES rather than falling back to `db_pool`, and that is the point
    ///
    /// [`Self::scoped`] is an `Option`, and of the thirteen `AppState`
    /// constructors exactly one — [`Self::with_scoped_pool`], which
    /// `bin/server.rs` calls — populates it. Every other constructor, including
    /// the ones the test suite builds state through, leaves it `None`.
    ///
    /// So a version of this that fell back to `self.db_pool` when `scoped` is
    /// `None` would pass every test in the workspace *and be inert in
    /// production*: the fallback would be the only branch fixtures ever take,
    /// the stamped branch the only one the server ever takes, and no test could
    /// tell a correctly plumbed request from an unstamped one. That is the same
    /// "the control exists only under test" defect the `ScopedPool` module doc
    /// exists to prevent, and under FORCE it degrades from inert to invisible:
    /// an unstamped connection makes the RLS policy and the in-query predicate
    /// disagree, and rows go missing from their own owners with a 200.
    ///
    /// Refusing instead means a process that did not build a `ScopedPool`
    /// cannot serve a scoped read at all — loudly, at the first request, rather
    /// than silently at step 11d.
    ///
    /// # Errors
    /// * `DbError::InvalidData` when this `AppState` was not built from a
    ///   `ScopedPool`, or when `viewer` is a bypass viewer — a bypass belongs on
    ///   [`Self::maintenance_viewer`], because on an application connection it
    ///   emits no predicate and is still filtered, so it reads zero rows.
    /// * `DbError::ConnectionFailed` / `DbError::QueryFailed` on the acquire or
    ///   the stamp.
    #[cfg(feature = "db")]
    pub async fn read_as(
        &self,
        viewer: &epigraph_db::visibility::Viewer,
    ) -> Result<epigraph_db::ScopedRead<'_>, epigraph_db::DbError> {
        let scoped = self
            .scoped
            .as_ref()
            .ok_or_else(|| epigraph_db::DbError::InvalidData {
                reason: "AppState was not built from a ScopedPool, so this read cannot be \
                         stamped with the viewer's tenancy context. Refusing rather than \
                         falling back to the raw pool: an unstamped connection makes the RLS \
                         policy and the in-query predicate disagree, which hides rows from \
                         their own owners without an error. Use AppState::with_scoped_pool."
                    .to_string(),
            })?;
        scoped.read_as(viewer).await
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
    ///   * [`TENANCY_TRIGGERS_089`] is required only once
    ///     [`MIGRATION_089_MARKER`] — 089's own function — is present. The
    ///     marker is deliberately NOT the trigger: a gate keyed on the thing it
    ///     checks for is vacuous.
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
            // EVERY tier's relations, including 089's. A relation missing from
            // this bind list falls to `table_absent` and WARNS instead of
            // refusing — so forgetting one here makes the tier that names it
            // fail open, which is the defect this whole function exists to
            // remove. (089's relation happens also to be in 070's list, so the
            // chain below is currently redundant for it. It is spelled anyway:
            // the next tier's relation will not be.)
            TENANCY_TRIGGERS_070
                .iter()
                .chain(TENANCY_TRIGGERS_074.iter())
                .chain(TENANCY_TRIGGERS_089.iter())
                .map(|(rel, _)| (*rel).to_string())
                .collect::<Vec<_>>(),
        )
        .fetch_all(&self.db_pool)
        .await?;
        let existing: std::collections::HashSet<&str> =
            existing_tables.iter().map(String::as_str).collect();

        // 089 ran iff its function is installed. Keyed on the FUNCTION rather
        // than on the trigger, because the state this tier exists to catch is
        // the trigger's absence and a marker that disappears with its subject
        // can never fire. `pg_proc`, not `_sqlx_migrations`: the catalog is what
        // the trigger actually lives in, and a hand-edited migrations table
        // would otherwise decide a safety check.
        let migration_089_applied: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_proc p \
                              JOIN pg_namespace n ON n.oid = p.pronamespace \
                             WHERE n.nspname = 'public' AND p.proname = $1)",
        )
        .bind(MIGRATION_089_MARKER)
        .fetch_one(&self.db_pool)
        .await?;

        // 074 ran iff `claims_block_widening` is installed. It is created in
        // section 4, ahead of section 5's `DROP DEFAULT`, so this marker cannot
        // be true on a database that still has the defaults to fall back on.
        let migration_074_applied = present.contains(&("claims", "claims_block_widening"));

        let mut required: Vec<(&str, &str)> = TENANCY_TRIGGERS_070.to_vec();
        if migration_074_applied {
            required.extend_from_slice(TENANCY_TRIGGERS_074);
        }
        if migration_089_applied {
            required.extend_from_slice(TENANCY_TRIGGERS_089);
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
            migration_089_applied,
            "tenancy triggers armed"
        );
        Ok(())
    }

    /// Ask the database the questions [`rls_verdict`] decides on.
    ///
    /// One round trip for the role/catalog facts and one for the canary, which
    /// has to be a separate statement because it may not exist yet and a
    /// missing relation is a parse-time error, not a row-level one.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the catalog cannot be read at all.
    #[cfg(feature = "db")]
    pub async fn probe_rls_posture(&self) -> Result<RlsPosture, epigraph_db::DbError> {
        let (current_user, is_superuser, has_bypassrls, is_seed_member, forced, protected): (
            String,
            bool,
            bool,
            bool,
            i64,
            i64,
        ) = sqlx::query_as(
            "SELECT current_user::text, \
                    COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = session_user), false), \
                    COALESCE((SELECT rolbypassrls FROM pg_roles WHERE rolname = session_user), \
                             false), \
                    EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_seed') \
                      AND pg_has_role(session_user, 'epigraph_seed', 'MEMBER'), \
                    (SELECT count(*) FROM pg_class c \
                       JOIN pg_namespace n ON n.oid = c.relnamespace \
                      WHERE n.nspname = 'public' AND c.relname = ANY($1) \
                        AND c.relkind IN ('r','p') AND c.relforcerowsecurity), \
                    (SELECT count(*) FROM pg_class c \
                       JOIN pg_namespace n ON n.oid = c.relnamespace \
                      WHERE n.nspname = 'public' AND c.relname = ANY($1) \
                        AND c.relkind IN ('r','p'))",
        )
        .bind(FORCE_PROTECTED_SET)
        .fetch_one(&self.db_pool)
        .await?;

        // Below 078 there is no canary. `to_regclass` returns NULL rather than
        // raising, so this is one statement either way.
        let canary_exists: bool =
            sqlx::query_scalar("SELECT to_regclass('public.rls_canary') IS NOT NULL")
                .fetch_one(&self.db_pool)
                .await?;
        let canary_visible: i64 = if canary_exists {
            sqlx::query_scalar("SELECT count(*) FROM public.rls_canary")
                .fetch_one(&self.db_pool)
                .await?
        } else {
            0
        };

        Ok(RlsPosture {
            current_user,
            is_superuser,
            has_bypassrls,
            is_seed_member,
            forced_count: forced,
            protected_count: protected,
            canary_exists,
            canary_visible,
        })
    }

    /// Probe, decide, and either log or refuse. The PR-17 boot assertion.
    ///
    /// See [`rls_verdict`] for the staging rule and for the one acceptance item
    /// this deliberately leaves as a warning.
    ///
    /// # A FAILURE TO *READ* THE POSTURE IS NOT A REFUSAL
    ///
    /// The caller wraps this in `.expect()`, so anything returned here is a boot
    /// panic. Staging the VERDICT (see [`rls_verdict`]) buys nothing if the
    /// PROBE is unconditionally fatal, and the probe has a reachable failure
    /// that has nothing to do with posture: its canary read needs the GRANT that
    /// migration 078 issues inside `IF EXISTS (SELECT 1 FROM pg_roles WHERE
    /// rolname = 'epigraph_app')`. Migration 060 only `NOTICE`s when it cannot
    /// `CREATE ROLE` — the managed-Postgres case — so on any cluster where the
    /// tenancy roles are provisioned out of band AFTER the migrations, that
    /// grant silently no-ops and the read raises `42501 permission denied for
    /// table rls_canary`. Propagating that would crash-loop a database whose RLS
    /// posture is perfectly fine, and would make the documented sub-minute
    /// rollback un-bootable for the same reason an unstaged verdict would.
    ///
    /// So the two outcomes are separated: a probe error WARNS and continues,
    /// matching [`Self::warn_on_privileged_connection`] next to it in the boot
    /// sequence; only an [`rls_verdict`] refusal is returned. "Cannot measure"
    /// and "measured, and it is wrong" are different claims, and the metrics
    /// side already models the distinction with its `-1` unmeasured value.
    ///
    /// # Errors
    /// Propagates [`rls_verdict`] refusals ONLY.
    #[cfg(feature = "db")]
    pub async fn assert_rls_posture(&self) -> Result<(), epigraph_db::DbError> {
        let posture = match self.probe_rls_posture().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not read the RLS posture; continuing without the assertion"
                );
                return Ok(());
            }
        };
        match rls_verdict(&posture)? {
            RlsVerdict::Armed => {
                tracing::info!(
                    current_user = %posture.current_user,
                    forced = posture.forced_count,
                    protected = posture.protected_count,
                    canary_exists = posture.canary_exists,
                    "RLS posture armed: connected as the application role, canary invisible"
                );
            }
            RlsVerdict::NotYetTheAppRole(warning) => {
                tracing::warn!(
                    current_user = %posture.current_user,
                    superuser = posture.is_superuser,
                    bypassrls = posture.has_bypassrls,
                    seed_member = posture.is_seed_member,
                    canary_visible = posture.canary_visible,
                    "{warning}"
                );
            }
        }
        Ok(())
    }

    /// The number of `rls_canary` rows visible on the API pool.
    ///
    /// Zero is healthy on an app connection; non-zero means row security is not
    /// protecting this database. Sampled on the 60-second gauge tick by
    /// [`crate::tenancy_gauge::TenancyGaugeSampler`], which is where the plan's
    /// "60-second canary health metric" lives. `None` below migration 078.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the read fails.
    #[cfg(feature = "db")]
    pub async fn rls_canary_visible(&self) -> Result<Option<i64>, epigraph_db::DbError> {
        let exists: bool =
            sqlx::query_scalar("SELECT to_regclass('public.rls_canary') IS NOT NULL")
                .fetch_one(&self.db_pool)
                .await?;
        if !exists {
            return Ok(None);
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM public.rls_canary")
            .fetch_one(&self.db_pool)
            .await?;
        Ok(Some(n))
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

/// PR-17: the staging rule for [`rls_verdict`], proved on the pure function.
///
/// These are unit tests and not `#[sqlx::test]`s on purpose. The refusal
/// branches are unreachable against a real connection in this repository — CI
/// and every developer host connect as the superuser `epigraph`, so
/// `current_user` is never `epigraph_app` and the armed half never executes.
/// Splitting the I/O from the decision is what makes it testable at all, which
/// is the same split (and the same justification) as
/// `epigraph_db::maintenance_verdict`.
///
/// **The three-state property is the point.** A FORCE assertion that is not
/// staged bricks plan §9.2 step 11d, the 077→079 window, and the documented
/// `NO FORCE` rollback. Each of those is a test below, so "inert where it must
/// be inert" is asserted rather than argued.
#[cfg(all(test, feature = "db"))]
mod rls_verdict_tests {
    use super::{rls_verdict, RlsPosture, RlsVerdict, EXPECTED_APP_ROLE, FORCE_PROTECTED_SET};

    /// One row of the identity-refusal table: `(label, mutation, expected
    /// phrase)`. Named because the tuple trips `clippy::type_complexity`.
    type PostureCase = (&'static str, fn(&mut RlsPosture), &'static str);

    /// A posture with nothing wrong with it, as the app role at rest.
    fn armed() -> RlsPosture {
        let n = i64::try_from(FORCE_PROTECTED_SET.len()).expect("small");
        RlsPosture {
            current_user: EXPECTED_APP_ROLE.to_string(),
            is_superuser: false,
            has_bypassrls: false,
            is_seed_member: false,
            forced_count: n,
            protected_count: n,
            canary_exists: true,
            canary_visible: 0,
        }
    }

    #[test]
    fn a_correctly_configured_app_connection_is_armed() {
        assert_eq!(rls_verdict(&armed()).unwrap(), RlsVerdict::Armed);
    }

    /// STATE 1 — plan §9.2 step 11d: `DATABASE_URL` already points at
    /// `epigraph_app`, the migrations have NOT run yet, and the runbook says
    /// "confirm the six boot assertions, **then run**" them.
    ///
    /// A flat `relforcerowsecurity` assertion refuses here, and step 11d can
    /// then never reach "then run" — the control that prevents the outage
    /// becomes the outage.
    #[test]
    fn step_11d_boots_before_the_migrations_have_run() {
        let mut p = armed();
        p.forced_count = 0;
        p.canary_exists = false;
        p.protected_count = 0;
        assert_eq!(rls_verdict(&p).unwrap(), RlsVerdict::Armed);
    }

    /// STATE 2 — the window between 077 (ENABLE) and 079 (FORCE). Policies are
    /// live and filtering every non-owner; FORCE is not applied yet.
    #[test]
    fn the_enable_to_force_window_boots() {
        let mut p = armed();
        p.forced_count = 0;
        assert_eq!(rls_verdict(&p).unwrap(), RlsVerdict::Armed);
    }

    /// STATE 3 — after `docs/runbooks/079-undo.sql`. This is step 11d's own
    /// documented rollback, and an assertion that refuses here makes the
    /// rollback un-bootable.
    #[test]
    fn the_no_force_kill_switch_leaves_the_process_bootable() {
        let mut p = armed();
        p.forced_count = 0;
        // The canary stays FORCEd — 078 creates it that way and 079-undo.sql
        // deliberately does not touch it — so it is still invisible.
        assert_eq!(rls_verdict(&p).unwrap(), RlsVerdict::Armed);
    }

    /// STATE 4 — the rollback that also reverts `DATABASE_URL` to the owner.
    /// Everything is inert, and it must WARN rather than refuse.
    #[test]
    fn reverting_the_dsn_to_the_owner_role_warns_and_boots() {
        let mut p = armed();
        p.current_user = "epigraph".to_string();
        p.is_superuser = true;
        p.has_bypassrls = true;
        p.is_seed_member = true;
        p.canary_visible = 1;
        let RlsVerdict::NotYetTheAppRole(w) = rls_verdict(&p).unwrap() else {
            panic!("a non-app role must never refuse: that is what makes the rollback bootable");
        };
        assert!(w.contains("epigraph"), "the warning names the role: {w}");
    }

    /// Every environment that exists today: CI and every developer host.
    /// Nothing here is a refusal, which is what lets this code deploy at all.
    #[test]
    fn a_superuser_dev_or_ci_connection_warns_and_boots() {
        let mut p = armed();
        p.current_user = "epigraph".to_string();
        p.is_superuser = true;
        p.has_bypassrls = true;
        assert!(matches!(
            rls_verdict(&p).unwrap(),
            RlsVerdict::NotYetTheAppRole(_)
        ));
    }

    /// A strict subset FORCEd is a half-applied 079 or a half-applied undo. It
    /// has no legitimate cause and it refuses whatever role is connecting,
    /// because the state is wrong for all of them.
    #[test]
    fn a_partially_forced_set_refuses_for_any_role() {
        for user in [EXPECTED_APP_ROLE, "epigraph", "epigraph_admin"] {
            let mut p = armed();
            p.current_user = user.to_string();
            p.forced_count = p.protected_count - 1;
            let err = rls_verdict(&p).expect_err("a partial flip must refuse");
            let msg = format!("{err}");
            assert!(
                msg.contains("079-undo") && msg.contains("subset"),
                "the refusal must name both directions of the fix: {msg}"
            );
        }
    }

    /// The canary is the instrument that replaces the `current_user` refusal.
    #[test]
    fn a_visible_canary_refuses_under_the_app_role() {
        let mut p = armed();
        p.canary_visible = 1;
        let err = rls_verdict(&p).expect_err("a visible canary must refuse");
        assert!(format!("{err}").contains("rls_canary"));
    }

    /// ...and it cannot fire before migration 078 exists to make it meaningful.
    #[test]
    fn the_canary_check_is_inert_before_migration_078() {
        let mut p = armed();
        p.canary_exists = false;
        p.canary_visible = 7; // nonsense, and unreadable: the table is absent
        assert_eq!(rls_verdict(&p).unwrap(), RlsVerdict::Armed);
    }

    /// The three identity refusals, including `rolbypassrls`, which was probed
    /// NOWHERE in `crates/epigraph-api` before PR-17 — half of the plan's first
    /// acceptance refusal had no measurement at all.
    #[test]
    fn a_privileged_app_role_refuses_on_each_attribute_independently() {
        // (label, mutation, a phrase the refusal must contain). Each attribute
        // is set on an OTHERWISE-CLEAN posture, so a single over-broad refusal
        // cannot satisfy all three.
        let cases: [PostureCase; 3] = [
            ("superuser", |p| p.is_superuser = true, "SUPERUSER"),
            ("bypassrls", |p| p.has_bypassrls = true, "BYPASSRLS"),
            (
                "epigraph_seed",
                |p| p.is_seed_member = true,
                "epigraph_seed",
            ),
        ];
        for (label, mutate, phrase) in cases {
            let mut p = armed();
            mutate(&mut p);
            let err = rls_verdict(&p)
                .err()
                .unwrap_or_else(|| panic!("{label} must refuse under the app role"));
            let msg = format!("{err}");
            assert!(
                msg.contains(phrase),
                "the {label} refusal must name what is wrong and how to fix it; got: {msg}"
            );
        }
    }

    /// ...and none of the three fires when the connection is not the app role,
    /// which is what keeps CI and every dev host bootable.
    #[test]
    fn the_identity_refusals_are_staged_on_the_connecting_role() {
        let mut p = armed();
        p.current_user = "epigraph".to_string();
        p.is_superuser = true;
        p.has_bypassrls = true;
        p.is_seed_member = true;
        assert!(
            matches!(rls_verdict(&p).unwrap(), RlsVerdict::NotYetTheAppRole(_)),
            "all three identity findings are true here and NONE may refuse: this is the \
             posture of every environment that has not done the §9.2 11d credential split"
        );
    }
}
