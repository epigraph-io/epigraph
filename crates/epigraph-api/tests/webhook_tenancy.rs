//! PR-10 acceptance: the webhook surface is tenancy-aware.
//!
//! The plan's acceptance line is *"a subscription owned by group A never
//! receives an event for a group-B claim; `list_webhooks` requires auth."*
//!
//! Both halves of that are satisfiable by code that does nothing useful. A
//! fan-out that delivers to **nobody** never delivers a group-B event to a
//! group-A subscriber, and `list_webhooks` returning 401 to everyone certainly
//! "requires auth". `visibility.rs`'s module doc names that failure directly —
//! an over-restricting viewer "is invisible to a test strategy written as
//! 'assert a stranger CANNOT read', so it would pass every adversarial test
//! while producing silent, permanent empty result sets" — and plan §8.4's
//! Class P assertions exist for it.
//!
//! So every hiding assertion here is paired with its positive control **in the
//! same fixture**: the same event, the same store, the same call, asserting
//! that the subscriber who SHOULD receive it does.
//!
//! # What each test reaches
//!
//! * The fan-out tests call `deliver_event` directly. They cannot go through
//!   `spawn_app`: `epigraph_api::build_app_for_tests` builds a router and never
//!   calls `start_webhook_dispatcher` (only `bin/server.rs` does), so an app
//!   spawned for tests has an event bus with no webhook subscriber attached.
//!   Extending `build_app_for_tests` to start a real dispatcher would put an
//!   HTTP-POSTing background task into every one of the ~40 integration-test
//!   binaries that call it. The dispatcher is three lines of `tokio::spawn`
//!   around `deliver_event`; `deliver_event` is where the rule lives.
//! * The route tests go through `spawn_app`, so they exercise the production
//!   middleware layering rather than hand-passing an `AuthContext`.
//! * `delete_webhook_refuses_when_no_auth_context_reaches_the_handler` mounts
//!   the handler on a bare router with **no** bearer middleware, because that
//!   is the only way to observe the property PR-10 fixed. Over HTTP the
//!   middleware 401s first, which is what made the handler's fall-through
//!   invisible for as long as it existed.
#![cfg(feature = "db")]

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::routes::webhooks::{deliver_event, WebhookDeliveryConfig};
use epigraph_api::state::{WebhookStore, WebhookSubscription};
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

const SECRET: &str = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"; // 32 chars

async fn test_pool() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool")
}

/// An unreachable delivery target with retries off.
///
/// The discriminator this file uses is the LENGTH of `deliver_event`'s result
/// vector, not the HTTP outcome: a suppressed subscription produces no entry at
/// all, while an attempted-and-refused one produces an entry with
/// `success = false`. That distinction is the whole point — "the POST failed"
/// and "the POST was never owed" are different facts, and a test that only
/// looked at delivery success could not tell them apart.
fn unreachable_sub(agent_id: Option<Uuid>) -> WebhookSubscription {
    WebhookSubscription {
        id: Uuid::new_v4(),
        url: "http://127.0.0.1:1/nonexistent".to_string(),
        event_types: vec![],
        created_at: chrono::Utc::now(),
        active: true,
        secret: SECRET.to_string(),
        agent_id,
    }
}

fn store_of(subs: &[WebhookSubscription]) -> WebhookStore {
    let map: HashMap<Uuid, WebhookSubscription> = subs.iter().cloned().map(|s| (s.id, s)).collect();
    Arc::new(tokio::sync::RwLock::new(map))
}

fn fast_config() -> WebhookDeliveryConfig {
    WebhookDeliveryConfig {
        timeout: std::time::Duration::from_millis(100),
        max_retries: 0,
    }
}

fn claim_submitted(claim_id: Uuid, agent_id: Uuid) -> epigraph_events::EpiGraphEvent {
    epigraph_events::EpiGraphEvent::ClaimSubmitted {
        claim_id: epigraph_core::ClaimId::from_uuid(claim_id),
        agent_id: epigraph_core::AgentId::from(agent_id),
        initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
    }
}

// ===========================================================================
// Fan-out — the acceptance criterion, with its control
// ===========================================================================

/// The plan's acceptance clause AND its Class P control, in one call.
///
/// One `ClaimSubmitted` for a **group-B-private** claim, two subscribers:
/// agent B (a member of group B) and agent A (a member of group A only).
/// B must receive it; A must not. Asserting only the second half would be
/// satisfied by a fan-out that delivers nothing at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_group_a_subscription_never_receives_a_group_b_claim_event() {
    let pool = test_pool().await;
    let (agent_a, _group_a) = fixture::seed_agent_with_group(&pool, "pr10-a").await;
    let (agent_b, group_b) = fixture::seed_agent_with_group(&pool, "pr10-b").await;

    let claim_b =
        fixture::seed_group_claim(&pool, agent_b, group_b, "pr10 group-B private claim").await;

    let sub_a = unreachable_sub(Some(agent_a));
    let sub_b = unreachable_sub(Some(agent_b));
    let store = store_of(&[sub_a.clone(), sub_b.clone()]);

    let results = deliver_event(
        &reqwest::Client::new(),
        &pool,
        &store,
        &claim_submitted(claim_b, agent_b),
        &fast_config(),
    )
    .await;

    let attempted: Vec<Uuid> = results.iter().map(|r| r.subscription_id).collect();

    assert!(
        !attempted.contains(&sub_a.id),
        "group-A subscriber received an event naming a group-B private claim: {attempted:?}"
    );
    // The control. If this ever fails the filter has become "deliver nothing",
    // which satisfies the plan's acceptance line and is useless.
    assert!(
        attempted.contains(&sub_b.id),
        "the OWNING group's subscriber must still receive its own event; \
         got {attempted:?}"
    );
}

/// A `visibility = 'public'` claim reaches every subscriber, including one in a
/// group that has nothing to do with it.
///
/// This is the other half of the over-restriction control: the filter must be
/// keyed on the claim's visibility, not on "the subscriber authored it".
#[tokio::test(flavor = "multi_thread")]
async fn a_public_claim_event_reaches_every_active_subscriber() {
    let pool = test_pool().await;
    let (agent_a, _group_a) = fixture::seed_agent_with_group(&pool, "pr10-pub-a").await;
    let (agent_b, _group_b) = fixture::seed_agent_with_group(&pool, "pr10-pub-b").await;

    let public_claim = fixture::seed_public_claim(&pool, agent_b, "pr10 public claim").await;

    let sub_a = unreachable_sub(Some(agent_a));
    let sub_b = unreachable_sub(Some(agent_b));
    let store = store_of(&[sub_a.clone(), sub_b.clone()]);

    let results = deliver_event(
        &reqwest::Client::new(),
        &pool,
        &store,
        &claim_submitted(public_claim, agent_b),
        &fast_config(),
    )
    .await;

    let attempted: Vec<Uuid> = results.iter().map(|r| r.subscription_id).collect();
    assert!(
        attempted.contains(&sub_a.id) && attempted.contains(&sub_b.id),
        "a public claim must reach both subscribers; got {attempted:?}"
    );
}

/// `AgentCreated` — a variant whose payload is a uuid and a unit-only enum —
/// is delivered.
///
/// SCOPE OF WHAT THIS PINS, stated narrowly on purpose. It is NOT "every
/// claim-less variant may be delivered". `AgentCreated`, `AgentSuspended`,
/// `ReputationChanged` and `WorkflowCompleted` carry no `claim_id` — four of
/// `EpiGraphEvent`'s eleven variants — so the plan's "add `owner_group_id` to
/// `EpiGraphEvent`" has nothing to derive for them, and if the resulting `None`
/// meant "deliver to everyone" PR-10 would ship the leak it exists to close.
/// Deriving visibility from the payload instead leaves the claim-visibility
/// probe with nothing to act on, and this test fixes the resulting behaviour
/// for the one variant where that is unambiguously harmless: `AgentRole` is a
/// unit-only enum, so the whole payload is an agent uuid.
///
/// The other three are NOT covered by this test and must not inherit its
/// permission. `AgentSuspended` carries
/// `SuspensionReason::{PolicyViolation, SecurityConcern, Administrative}`, each
/// with a `details: String` of operator free text, and `ReputationChanged`
/// carries per-agent scores; neither has any production publisher today
/// (measured by grep: every construction site is in `epigraph-events`' own
/// tests), and both are filed in `docs/tenancy/progress.json` under
/// `open_findings`. See `routes/webhooks.rs`'s "What this filter does NOT
/// decide".
///
/// Pinned so that a future "fail closed harder" edit that silences all
/// non-claim events is a deliberate decision rather than a side effect.
#[tokio::test(flavor = "multi_thread")]
async fn an_event_naming_no_claim_is_still_delivered() {
    let pool = test_pool().await;
    let (agent_a, _group_a) = fixture::seed_agent_with_group(&pool, "pr10-noclaim").await;

    let sub_a = unreachable_sub(Some(agent_a));
    let store = store_of(std::slice::from_ref(&sub_a));

    let event = epigraph_events::EpiGraphEvent::AgentCreated {
        agent_id: epigraph_core::AgentId::from(agent_a),
        role: epigraph_core::domain::AgentRole::Analyst,
    };

    let results = deliver_event(
        &reqwest::Client::new(),
        &pool,
        &store,
        &event,
        &fast_config(),
    )
    .await;

    assert_eq!(
        results.len(),
        1,
        "the claim-visibility probe has nothing to act on for a payload naming \
         no claim, so this variant is delivered; this is not a general licence \
         for every claim-less variant"
    );
    assert_eq!(results[0].subscription_id, sub_a.id);
}

/// A subscription with no principal is delivered to under NO circumstances —
/// not even for a public claim, and not even for an event naming no claim.
///
/// Migration 085 makes `agent_id` `NOT NULL`, so this row cannot come from the
/// table; it can come from a deserialised or hand-built one, and that is
/// precisely when "skip the check" would be wrong. The control is in the same
/// store: an attributed subscriber alongside it does receive both events.
#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_with_no_principal_is_never_delivered_to() {
    let pool = test_pool().await;
    let (agent_a, _group_a) = fixture::seed_agent_with_group(&pool, "pr10-orphan").await;
    let public_claim = fixture::seed_public_claim(&pool, agent_a, "pr10 orphan control").await;

    let orphan = unreachable_sub(None);
    let attributed = unreachable_sub(Some(agent_a));
    let store = store_of(&[orphan.clone(), attributed.clone()]);

    for event in [
        claim_submitted(public_claim, agent_a),
        epigraph_events::EpiGraphEvent::AgentCreated {
            agent_id: epigraph_core::AgentId::from(agent_a),
            role: epigraph_core::domain::AgentRole::Analyst,
        },
    ] {
        let results = deliver_event(
            &reqwest::Client::new(),
            &pool,
            &store,
            &event,
            &fast_config(),
        )
        .await;
        let attempted: Vec<Uuid> = results.iter().map(|r| r.subscription_id).collect();
        assert!(
            !attempted.contains(&orphan.id),
            "a principal-less subscription must never be delivered to; got {attempted:?}"
        );
        assert!(
            attempted.contains(&attributed.id),
            "control: the attributed subscription must still receive it; got {attempted:?}"
        );
    }
}

/// The event-type filter still works, and it composes with the tenancy filter
/// rather than replacing it.
#[tokio::test(flavor = "multi_thread")]
async fn the_event_type_filter_still_applies_under_the_tenancy_filter() {
    let pool = test_pool().await;
    let (agent_a, _group_a) = fixture::seed_agent_with_group(&pool, "pr10-types").await;
    let public_claim = fixture::seed_public_claim(&pool, agent_a, "pr10 type filter").await;

    let mut wants_truth_updated = unreachable_sub(Some(agent_a));
    wants_truth_updated.event_types = vec!["TruthUpdated".to_string()];
    let wants_everything = unreachable_sub(Some(agent_a));
    let store = store_of(&[wants_truth_updated.clone(), wants_everything.clone()]);

    let results = deliver_event(
        &reqwest::Client::new(),
        &pool,
        &store,
        &claim_submitted(public_claim, agent_a),
        &fast_config(),
    )
    .await;
    let attempted: Vec<Uuid> = results.iter().map(|r| r.subscription_id).collect();

    assert!(!attempted.contains(&wants_truth_updated.id));
    assert!(attempted.contains(&wants_everything.id));
}

// ===========================================================================
// Routes — `list_webhooks` / `get_webhook` gained auth and an owner filter
// ===========================================================================

async fn register(addr: std::net::SocketAddr, token: &str) -> Uuid {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/webhooks"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "url": "https://example.com/pr10",
            "event_types": [],
            "secret": SECRET,
        }))
        .send()
        .await
        .expect("register request");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("register body");
    assert_eq!(status, 201, "register failed: {status} — {body}");
    body["id"]
        .as_str()
        .expect("id in response")
        .parse()
        .expect("uuid")
}

/// The plan's second acceptance clause. Both read routes took no auth extractor
/// at all before PR-10.
#[tokio::test(flavor = "multi_thread")]
async fn the_webhook_read_routes_require_a_token() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    for path in [
        "/api/v1/webhooks",
        &format!("/api/v1/webhooks/{}", Uuid::new_v4()),
    ] {
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .expect("request");
        assert_eq!(resp.status(), 401, "GET {path} must require a token");
    }
}

/// `list_webhooks` used to return every subscription in the process to any
/// authenticated caller — url, event-type filter and created_at for every
/// tenant. It now returns the caller's own, and only those.
///
/// The positive control is in the same response pair: A sees exactly A's row.
#[tokio::test(flavor = "multi_thread")]
async fn list_webhooks_returns_only_the_callers_own_subscriptions() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = test_pool().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let agent_a = common::seed_system_agent(&pool).await;
    let agent_b = common::seed_system_agent(&pool).await;
    let token_a = common::mint_token_with_agent(&["webhooks:write"], agent_a);
    let token_b = common::mint_token_with_agent(&["webhooks:write"], agent_b);

    let id_a = register(addr, &token_a).await;
    let id_b = register(addr, &token_b).await;

    let listed_a: Vec<serde_json::Value> = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/webhooks"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("list body");

    let ids: Vec<String> = listed_a
        .iter()
        .map(|v| v["id"].as_str().unwrap_or_default().to_string())
        .collect();

    assert!(
        ids.contains(&id_a.to_string()),
        "control: A must see A's own subscription; got {ids:?}"
    );
    assert!(
        !ids.contains(&id_b.to_string()),
        "A must not see B's subscription; got {ids:?}"
    );
}

/// `get_webhook` was a straight IDOR: `State` + `Path(id)` and nothing else.
///
/// 403 rather than 404 for a subscription owned by someone else, matching
/// `delete_webhook`'s existing answer to the same condition.
#[tokio::test(flavor = "multi_thread")]
async fn get_webhook_refuses_another_principals_subscription() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = test_pool().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let agent_a = common::seed_system_agent(&pool).await;
    let agent_b = common::seed_system_agent(&pool).await;
    let token_a = common::mint_token_with_agent(&["webhooks:write"], agent_a);
    let token_b = common::mint_token_with_agent(&["webhooks:write"], agent_b);

    let id_a = register(addr, &token_a).await;

    let stranger = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/webhooks/{id_a}"))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("stranger get");
    assert_eq!(
        stranger.status(),
        403,
        "a stranger must not be able to fetch another principal's subscription"
    );

    // Control: the owner still can.
    let owner = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/webhooks/{id_a}"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("owner get");
    assert_eq!(
        owner.status(),
        200,
        "the owner must still be able to read it"
    );
}

/// A registration survives a restart of the process that made it.
///
/// The in-memory store is a cache; `webhook_subscriptions` (migration 085) is
/// the record. This is the property that makes the migration load-bearing
/// rather than decorative — the plan's stated justification ("there is nothing
/// to join") is stale, because `AuthContext.agent_id` has been non-null since
/// PR-02.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_is_persisted_and_a_delete_removes_the_row() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = test_pool().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let agent = common::seed_system_agent(&pool).await;
    let token = common::mint_token_with_agent(&["webhooks:write"], agent);
    let id = register(addr, &token).await;

    let persisted: Option<Uuid> =
        sqlx::query_scalar("SELECT agent_id FROM webhook_subscriptions WHERE id = $1")
            .bind(id)
            .fetch_optional(&pool)
            .await
            .expect("probe");
    assert_eq!(
        persisted,
        Some(agent),
        "the subscription must be on disk, keyed on the registering agents.id"
    );

    let del = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/webhooks/{id}"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), 204);

    let after: Option<Uuid> =
        sqlx::query_scalar("SELECT agent_id FROM webhook_subscriptions WHERE id = $1")
            .bind(id)
            .fetch_optional(&pool)
            .await
            .expect("probe after delete");
    assert_eq!(
        after, None,
        "a deleted subscription must not survive on disk"
    );
}

// ===========================================================================
// The fail-open site PR-10 was assigned
// ===========================================================================

/// `delete_webhook` must REFUSE when no `AuthContext` reaches it, not skip its
/// checks and delete anyway.
///
/// Before PR-10 both guards were `if let Some(axum::Extension(ref auth)) =
/// auth_ctx { .. }` with no `else`, and `store.remove(&id)` ran unconditionally
/// on the fall-through. `webhooks_auth_test.rs::delete_webhook_no_token_returns_401`
/// does not catch that: it proves `bearer_auth_middleware` rejects first, which
/// is a property of the ROUTER, not of the handler. This test mounts the
/// handler with no middleware at all — the configuration in which the
/// difference between "refuses" and "is protected by something upstream" is
/// observable.
///
/// The pool is deliberately un-connectable: reaching it at all would mean the
/// handler got past the authorization gate.
#[tokio::test(flavor = "multi_thread")]
async fn delete_webhook_refuses_when_no_auth_context_reaches_the_handler() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/nobody")
        .expect("lazy pool");
    let state =
        epigraph_api::state::AppState::with_db(pool, epigraph_api::state::ApiConfig::default());

    let victim = unreachable_sub(Some(Uuid::new_v4()));
    let victim_id = victim.id;
    state
        .webhook_store
        .write()
        .await
        .insert(victim_id, victim.clone());

    let app = axum::Router::new()
        .route(
            "/api/v1/webhooks/:id",
            axum::routing::delete(epigraph_api::routes::webhooks::delete_webhook),
        )
        .with_state(state.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/webhooks/{victim_id}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        401,
        "delete_webhook must refuse without an AuthContext, not fall through to \
         store.remove()"
    );
    assert!(
        state.webhook_store.read().await.contains_key(&victim_id),
        "the subscription must still be there — a 401 that already deleted the \
         row is the fall-through with a different status code"
    );
}
