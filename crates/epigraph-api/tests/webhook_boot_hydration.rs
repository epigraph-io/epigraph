//! `D-PR-bin-server-boot-hydration-test`: the boot hydration actually fills the
//! store, and fills it with a usable mapping.
//!
//! # What the obligation said, and what re-measuring it found
//!
//! The obligation's stated reason is *"`bin/server.rs` has no test harness in
//! this workspace"*. **That is false on this tree**:
//! `tests/boot_secret_gate_test.rs` drives the compiled binary through
//! `env!("CARGO_BIN_EXE_server")`. The GAP still reproduced — nothing executed
//! the hydration mapping — but the stated reason for it did not, so this file
//! does not work around a harness that exists. It takes the other route: the
//! mapping moved out of `main` into
//! `epigraph_api::state::hydrate_webhook_store`, which `main` now calls under
//! the `#[cfg(feature = "db")]` the block already carried. The subprocess route
//! was available and was not taken — booting a real server to observe a log
//! line asserts less about the mapping and costs a port, a readiness wait and a
//! JWT.
//!
//! # Why containment and not length
//!
//! `list_active` is a corpus-wide enumerator and this suite runs against a
//! shared database that other tests write to, so `store.len()` is not a fact
//! about this test. Every assertion here is about the two rows this test seeded:
//! the active one must arrive with its fields intact, and the inactive one must
//! not arrive at all. That pairing is the positive control and the filter test
//! in one fixture — a hydration that inserted nothing would satisfy "the
//! inactive row is absent" on its own.
//!
//! # The field that matters
//!
//! `agent_id`. `list_webhooks`, `get_webhook` and `deliver_event` all compare
//! `agent_id == Some(principal)`, so a subscription hydrated with `None` is
//! invisible to its owner and undeliverable while the row on disk looks
//! healthy. It is asserted explicitly rather than folded into a whole-struct
//! comparison, so a failure names the field.
//!
//! # The second test pins the contract the first one cannot see
//!
//! `boot_hydration_loads_active_subscriptions_with_their_principal` starts from
//! an empty store, so it passes identically whether the function clears the
//! store first or merges into it. Those are different contracts and only one of
//! them is implemented: `hydrate_webhook_store` inserts under the write guard
//! and never removes, so it fills a store rather than reconciling one against
//! the table. `hydration_merges_into_the_store_and_never_evicts` states that in
//! an assertion instead of leaving it to be inferred from the body, so an author
//! who turns it into a reconciling function has to change a named test in the
//! same commit rather than silently changing what every caller gets.
//!
//! # The third test: hydration is also where grandfathered rows are refused
//!
//! `hydration_refuses_and_deactivates_grandfathered_internal_targets` seeds
//! rows whose URLs `register_webhook` would now refuse. It asserts that they
//! are neither loaded nor left `active`. Its URLs are internal ON PURPOSE,
//! which is the opposite of `row_for`'s `.invalid` fixture. Every other test in
//! this file must keep using a URL the policy accepts. Otherwise hydration
//! would refuse and deactivate its "active" row, and the test would be
//! checking the policy instead of the mapping.
#![cfg(feature = "db")]

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::state::{hydrate_webhook_store, WebhookStore};
use epigraph_db::{WebhookSubscriptionRepository, WebhookSubscriptionRow};
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

fn empty_store() -> WebhookStore {
    Arc::new(tokio::sync::RwLock::new(HashMap::new()))
}

/// A row shaped like one `register_webhook` would have persisted.
///
/// The URL is a `https://` host that resolves to nothing. It is never fetched
/// here — this file exercises the hydration mapping, not delivery — but it is
/// deliberately not a loopback address, so nothing in this fixture depends on a
/// URL that `validate_webhook_url` would refuse at registration.
fn row_for(agent_id: Uuid, active: bool, tag: &str) -> WebhookSubscriptionRow {
    WebhookSubscriptionRow {
        id: Uuid::new_v4(),
        agent_id,
        url: format!("https://hydration-{tag}.invalid/sink"),
        event_types: vec!["claim.submitted".to_string()],
        secret: SECRET.to_string(),
        active,
        created_at: chrono::Utc::now(),
    }
}

/// The mechanism the durability half of migration 085 rests on.
///
/// Two rows for the same principal, one active and one not. After hydration the
/// active one is in the store with every field the delivery path reads, and the
/// inactive one is not.
#[tokio::test(flavor = "multi_thread")]
async fn boot_hydration_loads_active_subscriptions_with_their_principal() {
    let pool = test_pool().await;
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hydrate-a").await;

    let active = row_for(agent, true, "active");
    let inactive = row_for(agent, false, "inactive");
    WebhookSubscriptionRepository::insert(&pool, &active)
        .await
        .expect("seed active subscription");
    WebhookSubscriptionRepository::insert(&pool, &inactive)
        .await
        .expect("seed inactive subscription");

    let store = empty_store();
    hydrate_webhook_store(&pool, &store)
        .await
        .expect("hydration must succeed against a reachable database");

    let guard = store.read().await;

    // Positive control. Without this, "the inactive row is absent" is satisfied
    // by a hydration that inserts nothing at all.
    let loaded = guard
        .get(&active.id)
        .expect("boot hydration did not load an active subscription into the store");

    // The field every ownership and delivery comparison is keyed on.
    assert_eq!(
        loaded.agent_id,
        Some(agent),
        "hydrated subscription lost its principal: it is undeliverable and \
         invisible to its owner while the row on disk looks healthy"
    );
    assert_eq!(
        loaded.id, active.id,
        "hydrated subscription changed identity"
    );
    assert_eq!(
        loaded.url, active.url,
        "hydrated subscription changed its delivery target"
    );
    assert_eq!(
        loaded.event_types, active.event_types,
        "hydrated subscription changed its event-type filter"
    );
    assert_eq!(
        loaded.secret, active.secret,
        "hydrated subscription lost its signing secret: deliveries would be \
         signed with the wrong key"
    );
    assert!(loaded.active, "an active row hydrated as inactive");

    assert!(
        !guard.contains_key(&inactive.id),
        "boot hydration loaded an INACTIVE subscription; the store is the set \
         the fan-out delivers to"
    );
}

/// The cache entry a row's deactivation leaves behind.
fn cached(row: &WebhookSubscriptionRow) -> epigraph_api::state::WebhookSubscription {
    epigraph_api::state::WebhookSubscription {
        id: row.id,
        url: row.url.clone(),
        event_types: row.event_types.clone(),
        created_at: row.created_at,
        active: true,
        secret: row.secret.clone(),
        agent_id: Some(row.agent_id),
    }
}

/// Hydration fills a store; it does not reconcile one.
///
/// The store is pre-populated with an entry whose row is INACTIVE in the table,
/// which is the state a process reaches by hydrating and then having a
/// subscription deactivated underneath it. Hydrating again does not take that
/// entry back out — `hydrate_webhook_store` only ever inserts. That is the
/// implemented contract and it is asserted here rather than left to be read off
/// the loop, because the store is the set the fan-out delivers to and a caller
/// that expected the other contract would get no error, only a different
/// answer.
///
/// An ACTIVE row is seeded in the same fixture as the positive control: without
/// it, a `hydrate_webhook_store` that did nothing at all would satisfy the
/// survival assertion on its own.
#[tokio::test(flavor = "multi_thread")]
async fn hydration_merges_into_the_store_and_never_evicts() {
    let pool = test_pool().await;
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hydrate-merge").await;

    let deactivated = row_for(agent, false, "merge-deactivated");
    let live = row_for(agent, true, "merge-live");
    WebhookSubscriptionRepository::insert(&pool, &deactivated)
        .await
        .expect("seed the deactivated subscription");
    WebhookSubscriptionRepository::insert(&pool, &live)
        .await
        .expect("seed the live subscription");

    // The state a running process is in: the entry is cached, the row behind it
    // is no longer active.
    let store = empty_store();
    store
        .write()
        .await
        .insert(deactivated.id, cached(&deactivated));

    hydrate_webhook_store(&pool, &store)
        .await
        .expect("hydration must succeed against a reachable database");

    let guard = store.read().await;

    // Positive control, first: hydration did something on this call.
    assert!(
        guard.contains_key(&live.id),
        "hydration inserted nothing, so the survival assertion below would hold \
         for a function that does not work at all"
    );

    assert!(
        guard.contains_key(&deactivated.id),
        "hydrate_webhook_store removed a pre-existing store entry. It is \
         documented as a merge — it inserts and never removes — and a caller \
         relying on that would silently get a different set. If this is now a \
         reconciling function, that is a contract change and this assertion is \
         where it must be argued."
    );
}

/// A row with an internal URL on this state of `webhook_subscriptions`.
///
/// Seeded through the repo, NOT through `register_webhook`, which would now
/// refuse every one of these with 400. That is the point: these are the rows
/// written before the delivery-target policy existed ("grandfathered"), and
/// the repo insert is the only way left to produce one. Migration 085's CHECK
/// only requires a non-blank URL, so the table accepts them.
fn grandfathered_row(agent_id: Uuid, url: &str) -> WebhookSubscriptionRow {
    WebhookSubscriptionRow {
        id: Uuid::new_v4(),
        agent_id,
        url: url.to_string(),
        event_types: vec![],
        secret: SECRET.to_string(),
        active: true,
        created_at: chrono::Utc::now(),
    }
}

async fn is_active(pool: &sqlx::PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT active FROM webhook_subscriptions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("seeded row still exists: refusal deactivates, it never deletes")
}

/// Screen key `webhook-ssrf-egress-grandfathered`: boot hydration used to
/// re-arm every active row on every deploy, whatever its URL. So a subscription
/// registered before the policy existed kept its internal target forever,
/// while re-registering the same URL returned 400.
///
/// Now each row goes through `validate_webhook_url`. A refused row is kept
/// out of the store AND switched off in the table (kept, not deleted). An
/// acceptable row seeded beside them is the positive control: a hydration
/// that refused everything, or loaded nothing, fails here.
#[tokio::test(flavor = "multi_thread")]
async fn hydration_refuses_and_deactivates_grandfathered_internal_targets() {
    let pool = test_pool().await;
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hydrate-grandfathered").await;

    let refused: Vec<WebhookSubscriptionRow> = [
        "http://127.0.0.1/x",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5:8080/hook",
        "http://[::ffff:127.0.0.1]/hook",
        "http://localhost:9000/hook",
        "file:///etc/passwd",
    ]
    .iter()
    .map(|url| grandfathered_row(agent, url))
    .collect();
    let control = row_for(agent, true, "grandfathered-control");

    for row in refused.iter().chain(std::iter::once(&control)) {
        WebhookSubscriptionRepository::insert(&pool, row)
            .await
            .unwrap_or_else(|e| panic!("seed {}: {e}", row.url));
    }

    let store = empty_store();
    hydrate_webhook_store(&pool, &store)
        .await
        .expect("a refused row must not fail hydration");

    {
        let guard = store.read().await;
        assert!(
            guard.contains_key(&control.id),
            "positive control: an acceptable row must still be hydrated, or the \
             refusals below would hold for a hydration that loads nothing"
        );
        for row in &refused {
            assert!(
                !guard.contains_key(&row.id),
                "{} was re-armed by boot hydration: a grandfathered internal \
                 target is back in the fan-out's delivery set",
                row.url
            );
        }
    }

    for row in &refused {
        assert!(
            !is_active(&pool, row.id).await,
            "{} is still `active` in webhook_subscriptions: the next boot would \
             re-arm it (and log it) again",
            row.url
        );
    }
    assert!(
        is_active(&pool, control.id).await,
        "the acceptable row must not be deactivated"
    );

    // A second boot sees the refused rows as inactive and has nothing to redo.
    // It must not resurrect them.
    let second = empty_store();
    hydrate_webhook_store(&pool, &second)
        .await
        .expect("second hydration");
    let guard = second.read().await;
    for row in &refused {
        assert!(
            !guard.contains_key(&row.id),
            "{} was resurrected by a second boot",
            row.url
        );
    }
}
