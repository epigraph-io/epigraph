//! `D-PR-webhook-dispatcher-behavioural-test`: what the dispatcher DOES.
//!
//! The obligation records that `start_webhook_dispatcher` *"is type-checked in
//! both cfg arms and behaviour-checked in neither"*, and scopes the gap
//! precisely: `deliver_event` is already covered end-to-end by
//! `webhook_tenancy.rs`, so what nothing executed is **the subscribe-and-spawn
//! wiring** — an event published on the bus reaching `deliver_event` with the
//! right pool and the right store.
//!
//! Re-measured on `ce925885` and it reproduced: `start_webhook_dispatcher` HAD
//! exactly one caller, `bin/server.rs::main`, and no test caller at all before
//! this file existed. (Present tense would make the sentence assert this file's
//! own non-existence, which is why it is written in the past.)
//! `build_app_for_tests` builds a router and never starts a dispatcher, so
//! `spawn_app` cannot reach it. This file therefore calls it directly, over a
//! hand-built store, which is also the only way to point a subscription at a
//! reachable sink: `validate_webhook_url` refuses loopback targets at
//! REGISTRATION, so a wiremock receiver on 127.0.0.1 is unregisterable over
//! HTTP and a store built by hand is the supported route (the same one
//! `webhook_tenancy.rs::store_of` takes).
//!
//! # Why the assertion is a received request and not a result vector
//!
//! `webhook_tenancy.rs` discriminates on `deliver_event`'s returned
//! `Vec<WebhookDeliveryResult>`, which it can because it calls that function
//! directly. The dispatcher returns a `SubscriptionId` and drops its results
//! into a detached `tokio::spawn`, so there is no value to inspect — the only
//! observable effect is whether the POST arrived. That is also the effect the
//! obligation asks for: *"a delivery happens / does not happen"*, not a status
//! code and not that it links.
//!
//! # The wait is bounded and the assertion is outside it
//!
//! The dispatcher's bus callback is synchronous and spawns, so nothing in the
//! publish path can be awaited to completion. The poll loop below terminates in
//! a plain `assert_eq!`, never in a `.expect()` or in wiremock's drop-time
//! `verify()`: a test that fails inside a helper's panic reports a timeout
//! rather than a claim about behaviour.
//!
//! # Both directions, in one fixture
//!
//! One publish, two subscribers, two distinct sink paths. The group-B member
//! must receive the event for the group-B claim and the group-A member must
//! not. Asserting only the second half would be satisfied by a dispatcher that
//! was never wired to the bus at all — which is exactly the state this file
//! exists to detect.
//!
//! # What the coverage claim is, and what it is not
//!
//! Both tests publish a `ClaimSubmitted`. The fan-out's tenancy predicate is
//! defined over the claim ids it finds in the payload, so these tests certify
//! its behaviour for event variants that carry one — not for the fan-out in
//! general. The variants that carry none are a separate, already-filed and
//! already-dispositioned matter: `F-PR10-claimless-variants-carry-non-claim-content`
//! in `docs/tenancy/progress.json`, owned there. Nothing about it is restated
//! here. The test names describe what each test does; this paragraph is the
//! boundary of what they establish, so that the first behavioural coverage this
//! surface has ever had is not read as more than it is.
#![cfg(feature = "db")]

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::routes::webhooks::{start_webhook_dispatcher, WebhookDeliveryConfig};
use epigraph_api::state::{SharedEventBus, WebhookStore, WebhookSubscription};
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET: &str = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"; // 32 chars

const SINK_A: &str = "/sink-a";
const SINK_B: &str = "/sink-b";

async fn test_pool() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool")
}

fn sub_to(url: String, agent_id: Uuid) -> WebhookSubscription {
    WebhookSubscription {
        id: Uuid::new_v4(),
        url,
        event_types: vec![],
        created_at: chrono::Utc::now(),
        active: true,
        secret: SECRET.to_string(),
        agent_id: Some(agent_id),
    }
}

fn store_of(subs: &[WebhookSubscription]) -> WebhookStore {
    let map: HashMap<Uuid, WebhookSubscription> = subs.iter().cloned().map(|s| (s.id, s)).collect();
    Arc::new(tokio::sync::RwLock::new(map))
}

fn fast_config() -> WebhookDeliveryConfig {
    WebhookDeliveryConfig {
        timeout: std::time::Duration::from_millis(500),
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

/// How many POSTs the sink has seen on each of the two paths.
async fn hits(sink: &MockServer) -> (usize, usize) {
    let requests = sink
        .received_requests()
        .await
        .expect("wiremock records requests by default");
    let count = |p: &str| requests.iter().filter(|r| r.url.path() == p).count();
    (count(SINK_A), count(SINK_B))
}

/// Wait for the detached delivery, then let the rest of the fan-out settle.
///
/// Two phases on purpose. The first bounds how long a PASS may take. The second
/// is what makes the NEGATIVE half honest: the fan-out walks its retained
/// subscriptions in an unspecified order, so returning the instant the expected
/// delivery lands could report "the other one never arrived" before it had a
/// chance to. The settle period is unconditional.
async fn deliveries_after_settling(sink: &MockServer) -> (usize, usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if hits(sink).await.1 > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    hits(sink).await
}

/// The wiring, asserted by its only observable effect.
///
/// A `ClaimSubmitted` for a group-B-private claim is published on the bus the
/// dispatcher subscribed to. The group-B subscriber's sink must receive a POST;
/// the group-A subscriber's must not.
#[tokio::test(flavor = "multi_thread")]
async fn a_published_event_reaches_the_subscriber_who_may_read_its_claim_and_no_other() {
    let pool = test_pool().await;
    let (agent_a, _group_a) = fixture::seed_agent_with_group(&pool, "dispatch-a").await;
    let (agent_b, group_b) = fixture::seed_agent_with_group(&pool, "dispatch-b").await;
    let claim_b = fixture::seed_group_claim(
        &pool,
        agent_b,
        group_b,
        "dispatcher wiring: group-B private claim",
    )
    .await;

    let sink = MockServer::start().await;
    for p in [SINK_A, SINK_B] {
        Mock::given(method("POST"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200))
            .mount(&sink)
            .await;
    }

    let sub_a = sub_to(format!("{}{SINK_A}", sink.uri()), agent_a);
    let sub_b = sub_to(format!("{}{SINK_B}", sink.uri()), agent_b);
    let store = store_of(&[sub_a, sub_b]);

    let bus: SharedEventBus = Arc::new(epigraph_events::EventBus::new(64));

    // A NAMED binding, to record that the dispatcher subscription is meant to
    // stay live for the whole test. It is NOT an RAII guard and dropping it
    // would change nothing: `epigraph_events::SubscriptionId` is a `Copy`
    // newtype over a `Uuid` with no `Drop` impl, and the subscription lives in
    // the `EventBus` until someone passes that id to `EventBus::unsubscribe`.
    // `bin/server.rs::main` binds it the same way and for the same reason.
    let _dispatcher = start_webhook_dispatcher(&bus, pool.clone(), store.clone(), fast_config());

    bus.publish(claim_submitted(claim_b, agent_b))
        .await
        .expect("publish on the bus the dispatcher subscribed to");

    let (a_hits, b_hits) = deliveries_after_settling(&sink).await;

    // Positive control. If this fails, the dispatcher is not wired to the bus —
    // which no assertion about who did NOT receive the event can detect.
    assert_eq!(
        b_hits, 1,
        "the dispatcher did not deliver a published event to a subscriber \
         entitled to it: the subscribe-and-spawn wiring is not carrying events \
         from the bus to the fan-out"
    );
    assert_eq!(
        a_hits, 0,
        "a subscriber outside the claim's group received the delivery through \
         the dispatcher path"
    );
}

/// The per-subscription event-type filter survives the trip through the wiring.
///
/// Same principal, same claim, same publish, two subscriptions that differ only
/// in `event_types`. The one that lists every type receives the delivery; the
/// one that lists an unrelated type does not. The tenancy filter is held
/// constant here on purpose — the test above varies tenancy and holds the type
/// filter constant, so between them each discriminator is exercised alone.
#[tokio::test(flavor = "multi_thread")]
async fn the_event_type_filter_still_applies_through_the_dispatcher() {
    let pool = test_pool().await;
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "dispatch-filter").await;
    let claim = fixture::seed_public_claim(&pool, agent, "dispatcher wiring: public claim").await;

    let sink = MockServer::start().await;
    for p in [SINK_A, SINK_B] {
        Mock::given(method("POST"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200))
            .mount(&sink)
            .await;
    }

    let mut narrowed = sub_to(format!("{}{SINK_A}", sink.uri()), agent);
    narrowed.event_types = vec!["some.other.type".to_string()];
    let catch_all = sub_to(format!("{}{SINK_B}", sink.uri()), agent);
    let store = store_of(&[narrowed, catch_all]);

    let bus: SharedEventBus = Arc::new(epigraph_events::EventBus::new(64));
    let _dispatcher = start_webhook_dispatcher(&bus, pool.clone(), store.clone(), fast_config());

    bus.publish(claim_submitted(claim, agent))
        .await
        .expect("publish on the bus the dispatcher subscribed to");

    let (a_hits, b_hits) = deliveries_after_settling(&sink).await;

    assert_eq!(
        b_hits, 1,
        "a subscription with no event-type filter did not receive a published \
         event through the dispatcher"
    );
    assert_eq!(
        a_hits, 0,
        "the dispatcher delivered an event whose type the subscription does not \
         list"
    );
}
