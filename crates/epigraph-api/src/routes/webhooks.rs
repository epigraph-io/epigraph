//! Webhook subscription management endpoints
//!
//! POST   /api/v1/webhooks     - Register a new webhook subscription (protected)
//! GET    /api/v1/webhooks     - List the CALLER'S webhook subscriptions (protected)
//! GET    /api/v1/webhooks/:id - Get one of the caller's subscriptions (protected)
//! DELETE /api/v1/webhooks/:id - Remove a webhook subscription (protected)
//!
//! Webhooks enable external systems to receive real-time notifications when
//! epistemic events occur (claims submitted, truth updated, etc.). Payload
//! integrity is ensured via HMAC-SHA256 signing with a per-subscription secret.
//!
//! # Tenancy (PR-10)
//!
//! Two separate properties, both of which were absent:
//!
//! 1. **Subscription visibility.** `list_webhooks` and `get_webhook` took no
//!    auth extractor at all and returned every subscription in the process —
//!    id, url, event-type filter, created_at — to any authenticated caller.
//!    Both now take
//!    [`RequirePrincipal`](crate::middleware::bearer::RequirePrincipal) and
//!    answer only for rows whose `agent_id` is the caller's. (Anonymity was
//!    never the vector: both routes have always sat on the `protected` chain
//!    behind `bearer_auth_middleware`. Cross-tenant disclosure to an
//!    authenticated stranger was.)
//!
//! 2. **Fan-out.** [`deliver_event`] filtered on `sub.active` and
//!    `sub.event_types` and nothing else, so a `ClaimSubmitted` for a
//!    group-private claim was POSTed, in full, to every subscriber in the
//!    instance. It now resolves each subscription's `agent_id` into an
//!    [`epigraph_db::Viewer`] and drops any event whose payload names a claim
//!    that viewer cannot read.
//!
//! ## Why the event payload, and not a group on the event
//!
//! The plan's *Files* line says `owner_group_id` is "added to
//! `EpiGraphEvent`". `EpiGraphEvent` is an **enum of 11 variants** (not the
//! ~20 the scope recon estimated, and not a struct), so that literally means
//! editing eleven variants and every construction site, where one missed
//! variant is a silent fail-open. Worse, it is not derivable: four variants
//! (`ReputationChanged`, `AgentCreated`, `AgentSuspended`,
//! `WorkflowCompleted`) carry no `claim_id`, so the field would be `None` for
//! them and `None` would have to mean something.
//!
//! PR-09 already shipped the mechanism that answers the same question without
//! a schema change: scan the serialised payload for uuid-shaped tokens
//! (`routes/events.rs::payload_uuids`) and ask
//! `ClaimRepository::hidden_claim_ids` which of them name claims that exist and
//! are invisible. Over-collecting is safe in that direction — a token naming no
//! `claims` row cannot suppress anything. PR-09's commit body makes the
//! argument in the other direction verbatim ("any key allowlist is a rule the
//! next emitter escapes"), and a per-variant `owner_group_id` is a key
//! allowlist with extra steps.
//!
//! `epigraph-events` is therefore untouched by this PR.
//!
//! ## What this filter does NOT decide — stated, not glossed
//!
//! The predicate implemented here is exactly "the payload names no claim this
//! subscriber cannot read". Two things follow that an earlier draft of this
//! doc asserted its way past, and both are recorded in
//! `docs/tenancy/progress.json` under `open_findings` with owner PRs rather
//! than fixed here:
//!
//! * **A uuid naming no `claims` row does not suppress.** That is
//!   `hidden_claim_ids`' documented contract ("an id that names no row at all
//!   is not returned"), and it is load-bearing in the permissive direction:
//!   `routes/batch.rs::batch_create_claims` inserts only into
//!   `AppState::claim_store` and publishes a `ClaimSubmitted` per claim, so
//!   those claim ids name no row and the event reaches every subscriber. The
//!   two available in-scope fixes are both wrong. Suppressing on
//!   named-but-absent would suppress nearly everything, because `payload_uuids`
//!   also collects agent, frame and workflow ids, none of which name a `claims`
//!   row. Narrowing the scan to the ids an event *declares* as claim ids is the
//!   key allowlist rejected three paragraphs up. So the fourth branch is named
//!   here and in [`agent_may_receive`] instead of being left out of a
//!   "fails closed" list it contradicts. It is not a PR-10 regression: before
//!   this PR every event went to every subscriber unconditionally.
//! * **"No claim uuid" is not the same as "no cross-tenant content."** Four
//!   variants (`ReputationChanged`, `AgentCreated`, `AgentSuspended`,
//!   `WorkflowCompleted`) carry no `claim_id`, so this filter has nothing to
//!   act on and they are delivered. For `AgentCreated` and `WorkflowCompleted`
//!   that is harmless — `AgentRole` and `WorkflowState` are unit-only enums.
//!   For `AgentSuspended` it is not: `SuspensionReason::{PolicyViolation,
//!   SecurityConcern, Administrative}` each carry a `details: String` of
//!   operator-authored free text, and `ReputationChanged` carries per-agent
//!   scores. Nothing in production publishes either — every construction site
//!   of both is inside `epigraph-events`' own tests and its `event_type()`
//!   round-trip fixture, measured by grep over `crates/` — so this is latent,
//!   not live, and inventing a delivery policy for a variant no code emits
//!   would be policy without a requirement. The obligation is filed; the
//!   claim "they carry no claim content to leak" is withdrawn, because the
//!   property the fan-out needs is *no cross-tenant content*, which is a
//!   strictly stronger one.

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
/// Requires `webhooks:write` scope. The caller must provide a valid URL,
/// event type filters, and a secret of at least 32 characters for
/// HMAC-SHA256 payload signing.
///
/// # Write path — disclosed deliberately
///
/// PR-10 makes this handler write to the database (`webhook_subscriptions`,
/// migration 085) where it previously only touched an in-memory map. It adds
/// **no** write-side tenancy predicate: no `writable_bind()`, no `WITH CHECK`,
/// no policy. PR-16 owns that mechanism and it does not exist yet. What this
/// handler does is authenticate, check scope, and record the principal — which
/// is authentication, not the PR-16 control.
///
/// The scope gate stays in the **extractor** (`RequireScopeWebhooksWrite`) and
/// must not move into the body: `FromRequestParts` runs before `Json`, so a
/// wrong-scope request is 403 rather than 422 (issue #128), and
/// `negative_tests.rs::register_webhook_wrong_scope_with_malformed_body_returns_403_not_422`
/// pins it against a deliberately dead pool that a body-side check would try to
/// use.
///
/// # Errors
///
/// - 400 Bad Request: Empty URL or secret shorter than 32 characters
/// - 401 Unauthorized: Missing or invalid Bearer token, or a token that names
///   no `agents.id`
/// - 403 Forbidden: Missing `webhooks:write` scope
/// - 500 Internal: the subscription could not be persisted (including a token
///   naming an agent that no longer exists — an FK violation)
/// - 201 Created: Webhook subscription registered successfully
pub async fn register_webhook(
    State(state): State<AppState>,
    scope: crate::middleware::bearer::RequireScopeWebhooksWrite,
    Json(registration): Json<WebhookRegistration>,
) -> Result<(StatusCode, Json<WebhookSubscription>), ApiError> {
    // Scope gate ran in the extractor; if we reach the body, the caller has
    // `webhooks:write`. See `RequireScopeWebhooksWrite` in `middleware::bearer`.
    let auth = &scope.0;

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

    // 3. Determine the owning principal.
    //
    // `auth.agent_id`, NOT the old `auth.owner_id.unwrap_or(auth.client_id)`.
    // That was an `oauth_clients.id`: adequate as an equality token for the
    // delete check and useless for anything else, because
    // `Viewer::resolve` takes an `agents.id`. Refusing here rather than
    // storing `None` is what lets `deliver_event` treat a principal-less
    // subscription as unreachable-and-therefore-a-bug instead of a case it has
    // to have a policy for.
    let Some(agent_id) = auth.agent_id else {
        return Err(ApiError::Unauthorized {
            reason: "token carries no agent_id; re-authenticate to obtain \
                     a token bound to a principal"
                .into(),
        });
    };

    // 4. Create the subscription
    let subscription = WebhookSubscription {
        id: Uuid::new_v4(),
        url: registration.url,
        event_types: registration.event_types,
        created_at: Utc::now(),
        active: true,
        secret: registration.secret,
        agent_id: Some(agent_id),
    };

    // 5. Persist FIRST, then cache. This is a choice between two torn states,
    //    not an elimination of them, and both are named here so the next
    //    reader does not have to rediscover the one that was left out:
    //
    //      * store-but-no-row (cache first): the caller gets a 201, deliveries
    //        work until the next restart, and then the subscription vanishes
    //        with no error anywhere. That is the failure migration 085 exists
    //        to end.
    //      * row-but-no-store (this order): the caller gets a 201 and receives
    //        nothing until the process restarts and hydration picks the row up.
    //
    //    The second is strictly recoverable and the first is not, so the write
    //    goes to the table first. Neither is atomic; making it so would mean a
    //    transaction spanning a `RwLock`, which is not a thing.
    #[cfg(feature = "db")]
    {
        let row = epigraph_db::WebhookSubscriptionRow {
            id: subscription.id,
            agent_id,
            url: subscription.url.clone(),
            event_types: subscription.event_types.clone(),
            secret: subscription.secret.clone(),
            active: subscription.active,
            created_at: subscription.created_at,
        };
        epigraph_db::WebhookSubscriptionRepository::insert(&state.db_pool, &row)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, agent_id = %agent_id, "webhook persistence failed");
                // The driver text stays in the log and out of the body. This is
                // a NEW 500 surface — `register_webhook` could not fail on I/O
                // before PR-10 — and `errors.rs`'s `IntoResponse` serialises
                // `message` verbatim, so `{e}` would hand an API client
                // constraint names, relation names and driver internals
                // (`violates foreign key constraint
                // "webhook_subscriptions_agent_id_fkey"`). The `tracing::error!`
                // one line up already carries everything an operator needs.
                ApiError::InternalError {
                    message: "Failed to persist webhook subscription".to_string(),
                }
            })?;
    }

    // 6. Store the subscription
    {
        let mut store = state.webhook_store.write().await;
        store.insert(subscription.id, subscription.clone());
    }

    Ok((StatusCode::CREATED, Json(subscription)))
}

/// List the caller's active webhook subscriptions
///
/// GET /api/v1/webhooks
///
/// **Changed in PR-10.** This used to take `State` alone and return every
/// active subscription in the process to any authenticated caller. That is a
/// cross-tenant disclosure of the instance's delivery topology — every
/// subscriber's endpoint URL and event-type filter. (`secret` and `agent_id`
/// are `#[serde(skip_serializing)]`, so neither ever left the process.)
///
/// It now requires a principal and returns only that principal's rows.
/// Operator tooling that enumerated all subscriptions through this endpoint
/// stops working, deliberately; there is no admin-wide variant, and adding one
/// is a new route, a new allowlist entry and a new scope, not a fall-through.
///
/// No scope gate is added. `webhooks:write` would make a read require a write
/// scope, and a `webhooks:read` scope would mean editing
/// `epigraph-core::canonical_scopes` and the role vocabulary — outside this
/// PR's ledgered scope. The ownership filter, not a scope, is the control.
///
/// # Errors
///
/// - 401 Unauthorized: no `AuthContext`, or a token that names no `agents.id`
pub async fn list_webhooks(
    State(state): State<AppState>,
    caller: crate::middleware::bearer::RequirePrincipal,
) -> Json<Vec<WebhookSubscription>> {
    let store = state.webhook_store.read().await;
    let subscriptions: Vec<WebhookSubscription> = store
        .values()
        .filter(|sub| sub.active)
        // `== Some(principal)` and not a match on `Some`/`None`: a subscription
        // with no principal matches nobody. Fail closed.
        .filter(|sub| sub.agent_id == Some(caller.principal))
        .cloned()
        .collect();
    Json(subscriptions)
}

/// Get one of the caller's webhook subscriptions by ID
///
/// GET /api/v1/webhooks/:id
///
/// **Changed in PR-10.** This used to take `State` + `Path` alone: a
/// straightforward IDOR — any authenticated caller could fetch any
/// subscription by uuid.
///
/// A subscription owned by someone else answers **403**, not 404. That is the
/// same answer `delete_webhook` gives for the same condition on the same
/// resource pair, and `delete_webhook_by_different_caller_returns_403` pins it;
/// two different answers to "you do not own this" on one route pair is a thing
/// the next reader has to reconstruct. The existence-disclosure this trades
/// away is bounded: the id is an unguessable v4 uuid and the caller is already
/// authenticated.
///
/// # Errors
///
/// - 401 Unauthorized: no `AuthContext`, or a token that names no `agents.id`
/// - 403 Forbidden: the subscription belongs to another principal
/// - 404 Not Found: No subscription with the given ID
pub async fn get_webhook(
    State(state): State<AppState>,
    caller: crate::middleware::bearer::RequirePrincipal,
    Path(id): Path<Uuid>,
) -> Result<Json<WebhookSubscription>, ApiError> {
    let store = state.webhook_store.read().await;
    let sub = store.get(&id).cloned().ok_or(ApiError::NotFound {
        entity: "Webhook".to_string(),
        id: id.to_string(),
    })?;
    if sub.agent_id != Some(caller.principal) {
        return Err(ApiError::Forbidden {
            reason: "webhook is owned by another principal".into(),
        });
    }
    Ok(Json(sub))
}

/// Remove a webhook subscription
///
/// DELETE /api/v1/webhooks/:id
///
/// Requires `webhooks:write` scope. The caller must own the webhook
/// or have `claims:admin` scope.
///
/// # PR-10: this handler used to perform no authorization at all
///
/// Both guards were an `if let Some(Extension(ref auth))` over `auth_ctx`
/// with **no `else`**. (Spelled without the `axum::` path segment on purpose:
/// `viewer_route_table_lint.rs::measure_fail_open_scope_sites` is a raw
/// `str::matches` over the file's bytes with no comment stripping, so quoting
/// the fixed idiom verbatim in this doc comment would re-register the site the
/// commit just removed.) With no `AuthContext` in extensions the scope check was
/// skipped, the ownership check was skipped, and `store.remove(&id)` ran
/// unconditionally and returned 204. The only thing standing between that and
/// an unauthenticated delete was `bearer_auth_middleware` 401ing first — an
/// authz control that depends on axum parameter order, which is the exact
/// indictment in `viewer_route_table_lint.rs`'s
/// `fail_open_scope_check_sites_do_not_increase`, and the same shape PR-09
/// removed from `request_viewer`. `docs/tenancy/progress.json`
/// (`decisions_taken.Q7_failopen_scope_site_ownership`) assigns these two sites
/// to PR-10.
///
/// The `("webhooks.rs", 2)` row is REMOVED from that lint's
/// `FAIL_OPEN_SCOPE_SITES` in the same commit — not lowered to 0.
/// `measure_fail_open_scope_sites` only inserts keys with a non-zero count
/// while `expected()` maps every tuple unconditionally, and the assertion
/// compares whole maps, so a zeroed row is a key the measurement cannot
/// produce.
///
/// Ownership is compared on `agent_id` (an `agents.id`) rather than the old
/// `owner_id.unwrap_or(client_id)` (an `oauth_clients.id`). Those coincided for
/// tokens minted by `test_bearer_token_with_scopes`, which uses one uuid for
/// all three fields — a coincidence, not an invariant.
///
/// # Errors
///
/// - 401 Unauthorized: Missing or invalid Bearer token, or a token naming no
///   `agents.id`
/// - 403 Forbidden: Missing scope or caller is not the webhook owner
/// - 404 Not Found: No subscription with the given ID
/// - 500 Internal: the row could not be removed from the table
pub async fn delete_webhook(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    // REFUSE when absent. The prescribed shape, from the lint's own message and
    // from `crud.rs::get_theme_embeddings`.
    let axum::Extension(auth) = auth_ctx.ok_or(ApiError::Unauthorized {
        reason: "authentication required".into(),
    })?;

    // Unconditional, not conditional on the context being present.
    crate::middleware::scopes::check_scopes(&auth, &["webhooks:write"])?;

    let is_admin = auth.has_scope("claims:admin");
    let Some(principal) = auth.agent_id else {
        // A token with `webhooks:write` and no principal cannot be shown to own
        // anything, and `claims:admin` is not a substitute for a principal on a
        // path that has to identify the deleter.
        return Err(ApiError::Unauthorized {
            reason: "token carries no agent_id; re-authenticate to obtain \
                     a token bound to a principal"
                .into(),
        });
    };

    // NO GUARD IS HELD ACROSS THE DATABASE AWAIT.
    //
    // The obvious spelling — take `write()`, look the row up, delete it, then
    // `remove()` — holds the store's write guard for the whole duration of the
    // DB round trip. tokio's `RwLock` is FAIR, so a pending writer blocks new
    // readers: while that guard is held, `deliver_event`'s per-event read lock,
    // `list_webhooks`, `get_webhook` and `register_webhook` all block. A wedged
    // Postgres would therefore stall the very fan-out this PR exists to make
    // correct, and on this host a wedged Postgres is not hypothetical. Clippy
    // does not catch it: `clippy::await_holding_lock` fires only on
    // `std::sync::MutexGuard`, never on a tokio guard.
    //
    // So: copy the one field the decision needs out under a READ guard, drop
    // the guard at the end of the block, decide, hit the database unlocked,
    // and take the write guard solely for the `remove`. `register_webhook`
    // above already persists before taking its lock; this is the same
    // discipline, and the observable 401/403/404 ordering is unchanged.
    let owner = {
        let store = state.webhook_store.read().await;
        store
            .get(&id)
            .ok_or_else(|| ApiError::NotFound {
                entity: "Webhook".to_string(),
                id: id.to_string(),
            })?
            .agent_id
    };

    // Ownership check: caller must be the owner OR have claims:admin.
    if !is_admin && owner != Some(principal) {
        return Err(ApiError::Forbidden {
            reason: "webhook is owned by another principal".into(),
        });
    }

    // Remove from the table before the cache, so a failed delete leaves the
    // subscription live in both rather than resurrecting it at the next boot.
    #[cfg(feature = "db")]
    {
        let deleted = if is_admin {
            epigraph_db::WebhookSubscriptionRepository::delete_as_admin(&state.db_pool, id).await
        } else {
            epigraph_db::WebhookSubscriptionRepository::delete_owned(&state.db_pool, id, principal)
                .await
        };
        let rows = deleted.map_err(|e| {
            tracing::error!(error = %e, webhook_id = %id, "webhook delete failed");
            ApiError::InternalError {
                message: "Failed to delete webhook subscription".to_string(),
            }
        })?;
        // `delete_owned`'s whole argument for putting ownership in the `WHERE`
        // clause is that a caller comparing two values can forget to. Dropping
        // its return value makes that guard unobservable. Zero rows is not an
        // error — the cache is authoritative for 404 and the row may legitimately
        // be gone (an `agents` cascade, or a delete served by another process) —
        // but it means the cache and the table disagreed, and that is worth a
        // line in the log rather than a silent 204.
        if rows == 0 {
            tracing::warn!(
                webhook_id = %id,
                principal = %principal,
                is_admin,
                "webhook delete removed no row: the in-process store held a \
                 subscription the table does not (cascade, or another process \
                 already deleted it); evicting the cache entry anyway"
            );
        }
    }

    state.webhook_store.write().await.remove(&id);
    Ok(StatusCode::NO_CONTENT)
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

/// The subscriptions an event's TYPE selects, before any tenancy decision.
///
/// Split out of [`deliver_event`] in PR-10 so the type-filter rule stays unit
/// testable without a database, and so the tenancy filter that follows it is a
/// visibly separate step rather than a fourth clause in a `.filter()` chain
/// that a future edit can quietly drop.
///
/// This function deliberately does NOT look at `agent_id`: "who may see this"
/// is [`retain_visible_subscriptions`]'s question, and answering half of it
/// here would leave two places to check.
pub fn subscriptions_matching(
    store: &std::collections::HashMap<Uuid, crate::state::WebhookSubscription>,
    event_type: &str,
) -> Vec<crate::state::WebhookSubscription> {
    store
        .values()
        .filter(|sub| sub.active)
        .filter(|sub| sub.event_types.is_empty() || sub.event_types.iter().any(|t| t == event_type))
        .cloned()
        .collect()
}

/// Drop every subscription whose owner cannot read a claim the payload names.
///
/// The webhook half of PR-09's event-visibility rule, applied per subscriber
/// instead of per request:
///
/// 1. `routes/events::payload_uuids` collects every uuid-shaped token in the
///    serialised payload. Blunt on purpose — over-collecting is the safe
///    direction, because `hidden_claim_ids` reports only ids that name a
///    `claims` row **and** are invisible, so an agent id or a workflow id in
///    the payload can never suppress anything.
/// 2. Each surviving subscription's `agent_id` is resolved to a real
///    [`epigraph_db::Viewer`] — the subscriber's own reading authority, from
///    their own group memberships. One resolve per distinct agent per event,
///    not per subscription.
/// 3. If any payload uuid names a claim that viewer cannot read, the
///    subscription does not receive the event.
///
/// # Cost
///
/// Two round trips per DISTINCT AGENT per event (`Viewer::resolve`, then one
/// batched `hidden_claim_ids` over every uuid in the payload), and zero when
/// the payload names no uuid at all. Not per subscription: `ids` is fixed
/// within a call, so the verdict is memoised on `agent_id`.
///
/// # Everything here fails closed
///
/// * `agent_id == None` → **dropped**. There is no principal, so there is no
///   authority, so there is no defensible delivery. Migration 085 makes the
///   column `NOT NULL`, so this is unreachable for a persisted row; it is
///   reachable for a row deserialised from somewhere else, and that is exactly
///   when a fall-through would hurt.
/// * `Viewer::resolve` errors → **dropped**, logged at error.
/// * `hidden_claim_ids` errors → **dropped**, logged at error.
///
/// # Two branches that do NOT fail closed, and are not oversights
///
/// The heading above is about the branches this function controls. Two
/// conditions resolve permissively and are named here so the list is honest:
///
/// * **A payload uuid that names no `claims` row.** `hidden_claim_ids` returns
///   only existing-but-invisible ids, by documented contract, so an unknown id
///   contributes nothing and the event is delivered. See this module's
///   "What this filter does NOT decide" for why both available fixes are
///   worse than the condition, and `open_findings` in
///   `docs/tenancy/progress.json` for the owner.
/// * **A principal that names no `agents` row.**
///   `Viewer::resolve` → `GroupMembershipRepository::list_live_for_agent`
///   returns an empty `Vec` for an agent that does not exist rather than an
///   error, so the subscription is demoted to a public-only viewer instead of
///   being dropped. `agent_id` is `NOT NULL REFERENCES agents(id) ON DELETE
///   CASCADE`, so the row is removed from the TABLE the moment its agent is —
///   but nothing evicts it from `AppState::webhook_store`, so a running
///   process keeps the subscription until it restarts. Both halves are filed;
///   neither is invented policy here.
///
/// A database outage therefore stops webhook delivery rather than flooding
/// every subscriber with every tenant's claims. That is the intended trade and
/// it is worth stating: the failure mode of this function is silence, and
/// silence is what a suppressed webhook already looks like. The `warn!` on
/// every suppression is the only thing that distinguishes them in a log.
///
/// # Why this is not `Viewer::system`
///
/// `no_bypass_in_handlers.rs` bans `Viewer::system(` and `MaintenanceLease`
/// anywhere under `epigraph-api/src/routes/`, and this file is under it. That
/// ban is right even though this is background code: the dispatcher's job is
/// precisely to decide what a *caller* may see, and a bypass viewer answers
/// "everything". `viewer_ratchet.rs` independently bounds `SystemReason::ALL`
/// at ≤10 and monotone-decreasing, so there is no `WebhookFanOut` reason to add
/// either. Both controls point the same way.
#[cfg(feature = "db")]
async fn retain_visible_subscriptions(
    pool: &sqlx::PgPool,
    payload: &serde_json::Value,
    subscriptions: Vec<crate::state::WebhookSubscription>,
) -> Vec<crate::state::WebhookSubscription> {
    // Principal-less subscriptions are dropped whether or not the payload names
    // a claim: an unattributable delivery endpoint is not a tenancy question
    // with a "no claims involved" exemption.
    let (attributed, orphaned): (Vec<_>, Vec<_>) = subscriptions
        .into_iter()
        .partition(|s| s.agent_id.is_some());
    for sub in &orphaned {
        tracing::warn!(
            target: "webhook.delivery.suppressed",
            subscription_id = %sub.id,
            reason = "no_agent_id",
            "webhook suppressed: subscription carries no principal, so no reading \
             authority can be resolved for it"
        );
    }

    let ids = crate::routes::events::payload_uuids(payload);
    if ids.is_empty() {
        // No uuid-shaped token anywhere in the document, so no claim can be
        // named by it and there is nothing for a viewer to decide. Same
        // early-out, for the same reason, as
        // `routes/events::retain_visible_events`.
        return attributed;
    }

    // The verdict is a pure function of (agent, ids), and `ids` is fixed for
    // this call — so it is computed ONCE PER DISTINCT AGENT, not once per
    // subscription. Without this an instance with N subscribers costs N
    // `Viewer::resolve` + N `hidden_claim_ids` round trips **per published
    // event**, on a live path (`bin/server.rs` wires the dispatcher at
    // startup). PR-09's `retain_visible_events` batches for the same reason.
    let mut verdicts: std::collections::HashMap<Uuid, bool> = std::collections::HashMap::new();
    let mut keep = Vec::with_capacity(attributed.len());

    for sub in attributed {
        let agent_id = sub.agent_id.expect("partitioned on is_some");

        // `Entry` rather than `contains_key` + `insert` (clippy::map_entry).
        // The `await`s sit inside the vacant arm, which is sound: nothing else
        // borrows `verdicts` across them.
        if let std::collections::hash_map::Entry::Vacant(slot) = verdicts.entry(agent_id) {
            slot.insert(agent_may_receive(pool, agent_id, &ids).await);
        }

        if verdicts.get(&agent_id).copied().unwrap_or(false) {
            keep.push(sub);
        } else {
            // Logged per subscription as well as per agent: the agent-level
            // log above says WHY, this one says WHICH endpoint went silent,
            // which is what an operator is actually looking for.
            tracing::warn!(
                target: "webhook.delivery.suppressed",
                subscription_id = %sub.id,
                agent_id = %agent_id,
                "webhook suppressed for this subscription"
            );
        }
    }

    keep
}

/// May `agent_id` be told about an event whose payload names `ids`?
///
/// `true` only when a `Viewer` resolves AND the visibility probe succeeds AND
/// it reports nothing hidden. Every branch this function *decides* returns
/// `false` on failure — see [`retain_visible_subscriptions`]'s doc for why each
/// one fails closed, and, in the same doc, for the two conditions that resolve
/// permissively before this function can see them (a uuid naming no `claims`
/// row, and a principal naming no `agents` row). Those are named there rather
/// than silently absent from a "fails closed" list.
///
/// Split out so the three failure branches are one function's worth of code
/// that a reviewer reads together, rather than three arms interleaved with the
/// per-subscription loop.
#[cfg(feature = "db")]
async fn agent_may_receive(pool: &sqlx::PgPool, agent_id: Uuid, ids: &[Uuid]) -> bool {
    let viewer = match epigraph_db::Viewer::resolve(pool, agent_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "webhook.delivery.suppressed",
                agent_id = %agent_id,
                error = %e,
                reason = "viewer_resolve_failed",
                "webhook suppressed: could not resolve the subscriber's reading authority"
            );
            return false;
        }
    };

    match epigraph_db::ClaimRepository::hidden_claim_ids(pool, &viewer, ids).await {
        Ok(hidden) if hidden.is_empty() => true,
        Ok(hidden) => {
            tracing::warn!(
                target: "webhook.delivery.suppressed",
                agent_id = %agent_id,
                hidden = hidden.len(),
                reason = "payload_names_invisible_claim",
                "webhook suppressed: event payload names a claim this subscriber cannot read"
            );
            false
        }
        Err(e) => {
            tracing::error!(
                target: "webhook.delivery.suppressed",
                agent_id = %agent_id,
                error = %e,
                reason = "visibility_probe_failed",
                "webhook suppressed: could not determine payload visibility"
            );
            false
        }
    }
}

/// Deliver a single event to every matching webhook subscription whose owner
/// may see it.
///
/// For each active subscription whose event-type filter matches the event AND
/// whose owning principal can read every claim the payload names, this
/// function:
/// 1. Serializes the event payload as JSON
/// 2. Signs the payload with the subscription's HMAC-SHA256 secret
/// 3. POSTs the payload to the subscription's URL
///
/// Delivery failures are logged but do not block the caller. Each
/// subscription is attempted independently.
///
/// The returned `Vec` contains one entry per **attempted** delivery. A
/// subscription suppressed on tenancy grounds produces no entry — it is not a
/// failed delivery, it is a delivery that was never owed. The suppression is
/// visible only in the `webhook.delivery.suppressed` tracing target.
///
/// # Arguments
/// * `client` - HTTP client for making requests
/// * `pool` - the pool the per-subscriber visibility probe runs on
/// * `webhook_store` - The shared webhook subscription store
/// * `event` - The event to deliver
/// * `config` - Delivery configuration (timeout, retries)
#[cfg(feature = "db")]
pub async fn deliver_event(
    client: &reqwest::Client,
    pool: &sqlx::PgPool,
    webhook_store: &crate::state::WebhookStore,
    event: &epigraph_events::EpiGraphEvent,
    config: &WebhookDeliveryConfig,
) -> Vec<WebhookDeliveryResult> {
    let event_type = event.event_type();

    // Read subscriptions snapshot
    let candidates = {
        let store = webhook_store.read().await;
        subscriptions_matching(&store, &event_type)
    };
    if candidates.is_empty() {
        return Vec::new();
    }

    let payload = serde_json::json!({
        "event_type": event_type,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": event,
    });

    let subscriptions = retain_visible_subscriptions(pool, &payload, candidates).await;

    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();

    let mut results = Vec::with_capacity(subscriptions.len());

    for sub in &subscriptions {
        let signature = sign_webhook_payload(&sub.secret, &payload_bytes);
        let result = deliver_to_subscription(client, sub, &payload_bytes, &signature, config).await;
        results.push(result);
    }

    results
}

/// The `not(feature = "db")` fan-out: **delivers nothing**.
///
/// There is no `epigraph_db` in this build, hence no `Viewer`, hence no way to
/// decide whether a subscriber may see a claim the payload names. The two
/// available answers are "deliver to everyone" and "deliver to no one"; PR-10
/// exists because the first one is a leak. `list_webhooks` still authenticates
/// and still filters on ownership in this build, because that needs no
/// database — only the fan-out is disabled.
///
/// This configuration is not built by any CI job or deployment (`epigraph-api`'s
/// default features are `["db"]`); it is kept compiling by
/// `cargo check -p epigraph-api --no-default-features`.
#[cfg(not(feature = "db"))]
pub async fn deliver_event(
    _client: &reqwest::Client,
    webhook_store: &crate::state::WebhookStore,
    event: &epigraph_events::EpiGraphEvent,
    _config: &WebhookDeliveryConfig,
) -> Vec<WebhookDeliveryResult> {
    let event_type = event.event_type();
    let candidates = {
        let store = webhook_store.read().await;
        subscriptions_matching(&store, &event_type)
    };
    if !candidates.is_empty() {
        tracing::warn!(
            target: "webhook.delivery.suppressed",
            suppressed = candidates.len(),
            reason = "no_db_feature",
            "webhook fan-out suppressed: this build has no epigraph-db, so no \
             subscriber's reading authority can be resolved"
        );
    }
    Vec::new()
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
/// The `vec![]` filter means "every event type". That stays: narrowing the
/// SUBSCRIPTION would be a filter on event types, and the property PR-10 needs
/// is a filter on tenancy, which is applied per-subscriber inside
/// [`deliver_event`]. A dispatcher that subscribed to a subset would silently
/// stop delivering event types nobody remembered to list.
///
/// # Arguments
/// * `event_bus` - The shared event bus to subscribe to
/// * `pool` - the pool [`deliver_event`]'s visibility probe runs on. Cloned
///   into a `'static` background closure and held for the process lifetime; a
///   `PgPool` is an `Arc` internally, so this is a handle, not a connection.
/// * `webhook_store` - The shared webhook subscription store
/// * `config` - Delivery configuration
///
/// # Returns
/// The subscription ID for the webhook dispatcher (can be used to unsubscribe)
#[cfg(feature = "db")]
pub fn start_webhook_dispatcher(
    event_bus: &crate::state::SharedEventBus,
    pool: sqlx::PgPool,
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
        let pool = pool.clone();
        let store = store.clone();
        let cfg = std::sync::Arc::clone(&cfg);

        tokio::spawn(async move {
            let results = deliver_event(&client, &pool, &store, &event, &cfg).await;
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

/// The `not(feature = "db")` dispatcher. See the `db` variant for the contract.
///
/// It still subscribes, so the wiring in `bin/server.rs` is identical in both
/// builds and the "webhook dispatcher started" log line does not lie about
/// whether anything is listening. What it delivers is nothing — see the
/// `not(feature = "db")` [`deliver_event`].
#[cfg(not(feature = "db"))]
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
            let _ = deliver_event(&client, &store, &event, &cfg).await;
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
            agent_id: None,
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
            agent_id: None,
        };

        let sub_filtered = WebhookSubscription {
            id: Uuid::new_v4(),
            url: "https://example.com/filtered".to_string(),
            event_types: vec!["ClaimSubmitted".to_string()],
            created_at: Utc::now(),
            active: true,
            secret: "x".repeat(32),
            agent_id: None,
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

    // ---- Event-type selection (PR-10) ----
    //
    // These four used to call `deliver_event` against a bare `WebhookStore`.
    // PR-10 gives `deliver_event` a `&PgPool` (it resolves a real Viewer per
    // subscriber), so a no-database unit test can no longer reach the *whole*
    // function without either a live DB or a fake authority — and a fake
    // authority in a unit test is how a fan-out filter gets asserted into
    // existence without existing.
    //
    // The type-filter rule they actually assert is now
    // `subscriptions_matching`, tested here directly and exactly. The delivery
    // ATTEMPT they asserted as a side effect, and the tenancy rule they never
    // asserted at all, moved to `tests/webhook_tenancy.rs`, which has a real
    // database and can therefore make both a hiding assertion and its positive
    // control.

    fn test_sub(active: bool, event_types: &[&str]) -> WebhookSubscription {
        WebhookSubscription {
            id: Uuid::new_v4(),
            url: "http://127.0.0.1:1/nonexistent".to_string(),
            event_types: event_types.iter().map(|s| (*s).to_string()).collect(),
            created_at: Utc::now(),
            active,
            secret: "x".repeat(32),
            agent_id: Some(Uuid::new_v4()),
        }
    }

    fn store_of(
        subs: Vec<WebhookSubscription>,
    ) -> std::collections::HashMap<Uuid, WebhookSubscription> {
        subs.into_iter().map(|s| (s.id, s)).collect()
    }

    #[test]
    fn subscriptions_matching_returns_nothing_for_an_empty_store() {
        let store = store_of(vec![]);
        assert!(subscriptions_matching(&store, "ClaimSubmitted").is_empty());
    }

    #[test]
    fn subscriptions_matching_filters_by_event_type() {
        let store = store_of(vec![test_sub(true, &["TruthUpdated"])]);
        assert!(
            subscriptions_matching(&store, "ClaimSubmitted").is_empty(),
            "ClaimSubmitted must not match a TruthUpdated filter"
        );
        assert_eq!(
            subscriptions_matching(&store, "TruthUpdated").len(),
            1,
            "…and the positive control: TruthUpdated must match it"
        );
    }

    #[test]
    fn subscriptions_matching_treats_an_empty_filter_as_all() {
        let sub = test_sub(true, &[]);
        let id = sub.id;
        let store = store_of(vec![sub]);
        for event_type in ["ClaimSubmitted", "TruthUpdated", "AgentSuspended"] {
            let hit = subscriptions_matching(&store, event_type);
            assert_eq!(hit.len(), 1, "empty filter should match {event_type}");
            assert_eq!(hit[0].id, id);
        }
    }

    #[test]
    fn subscriptions_matching_skips_inactive_subscriptions() {
        let store = store_of(vec![test_sub(false, &[])]);
        assert!(
            subscriptions_matching(&store, "ClaimSubmitted").is_empty(),
            "inactive subscriptions are not candidates"
        );
    }

    /// `deliver_event` short-circuits before it touches the pool when no
    /// subscription matches. Asserted against a pool that can never connect, so
    /// a regression that queries first shows up as a failure here rather than as
    /// a round trip per event in production.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn test_deliver_event_with_no_subscriptions_does_not_touch_the_pool() {
        let client = reqwest::Client::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/nobody")
            .expect("lazy pool construction must succeed");
        let store: crate::state::WebhookStore =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
        let event = epigraph_events::EpiGraphEvent::ClaimSubmitted {
            claim_id: epigraph_core::ClaimId::new(),
            agent_id: epigraph_core::AgentId::new(),
            initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
        };
        let config = WebhookDeliveryConfig::default();

        let results = deliver_event(&client, &pool, &store, &event, &config).await;
        assert!(
            results.is_empty(),
            "No subscriptions means no delivery results"
        );
    }

    // ---- Handler integration tests (need AppState without DB) ----

    // NOT COMPILED, NOT RUN: `epigraph-api`'s default features are `["db"]`
    // and the `not(feature = "db")` configuration has pre-existing compile
    // errors, so no CI job or local run builds this module. PR-03's
    // `OK -> UNAUTHORIZED` flips inside it are DOCUMENTATION of the intended
    // behaviour; `tests/public_router_allowlist.rs` is what asserts it, by
    // probing every route on the buildable variant's `protected` chain.
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
                require_packet_signatures: false,
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
                require_packet_signatures: false,
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
                require_packet_signatures: false,
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
                require_packet_signatures: false,
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
                require_packet_signatures: false,
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
            // Use the full router, which applies bearer_auth_middleware
            let state = AppState::new(ApiConfig {
                require_packet_signatures: true,
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
                require_packet_signatures: true,
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
                require_packet_signatures: true,
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
                require_packet_signatures: true,
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
                require_packet_signatures: false,
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
                require_packet_signatures: false,
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
