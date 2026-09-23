//! The `not(feature = "db")` arm of the webhook dispatcher, asserted by what it
//! does rather than by the fact that it type-checks.
//!
//! # The contract
//!
//! Without `epigraph_db` there is no `Viewer`, so no subscriber's reading
//! authority can be resolved, and the no-db `deliver_event` delivers to NO ONE
//! (delivering to everyone is the PR-10 leak). The dispatcher still subscribes
//! and still spawns the fan-out. For each published event that some active
//! subscription matches, it emits one `webhook.delivery.suppressed` WARN with
//! `suppressed = <matching count>` and `reason = "no_db_feature"`, and it
//! sends nothing.
//!
//! # What each assertion rules out
//!
//! * **The suppression line fires, with `suppressed = 1`.** This is the
//!   positive control. A dispatcher that never subscribed, subscribed to the
//!   wrong event types, never spawned, or panicked in the task would all pass
//!   "the sink received nothing". Only the line proves the event travelled bus
//!   → subscriber → spawned task → `deliver_event` → candidate match.
//! * **Exactly one line, not two.** An event type that matches no subscription
//!   is published FIRST and must produce no line. The second store entry
//!   listens only for a type that is never published, so `suppressed = 2`
//!   would mean the per-subscription event-type filter stopped applying.
//! * **The sink receives nothing.** The dispatcher is handed a client that CAN
//!   reach the sink (a `.resolve()` override on an RFC 2606 name, the same
//!   technique `webhook_dispatcher_wiring.rs` uses for the `db` arm). The same
//!   client then POSTs to a control path, and that request must arrive.
//!   Without that control, "zero requests" would also hold for a fan-out that
//!   did try to deliver but could not connect.
//!
//! # Why the capture is a hand-written layer on a current-thread runtime
//!
//! The dispatcher hands delivery to `tokio::spawn`. `tracing_test`'s capture is
//! scoped to a span on the test's own thread, and a spawned task does not enter
//! that span, which is why the `db` arm's `webhook_suppression_log.rs` calls
//! `deliver_event` directly instead. Going through the dispatcher is the point
//! here, so this file installs its own layer with `set_default` (thread-local)
//! and runs on a `current_thread` runtime. Every spawned task is then polled on
//! the test's thread, inside that default. The flavor is load-bearing: on a
//! multi-thread runtime the task would run on a worker thread outside the
//! default, the line would never be captured, and the positive control would
//! fail for a reason unrelated to the dispatcher.
#![cfg(not(feature = "db"))]

use epigraph_api::routes::webhooks::{
    dispatcher_client_builder, start_webhook_dispatcher_with_client, WebhookDeliveryConfig,
};
use epigraph_api::state::{SharedEventBus, WebhookStore, WebhookSubscription};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET: &str = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"; // 32 chars

const SUPPRESSED_TARGET: &str = "webhook.delivery.suppressed";

/// RFC 2606 name: accepted by the literal SSRF guard on its face, pointed at
/// wiremock by the client's `.resolve()` override.
const SINK_HOST: &str = "nodb-dispatcher-sink.example";

const MATCHING_PATH: &str = "/matching";
const OTHER_PATH: &str = "/other";
const CONTROL_PATH: &str = "/reachability-control";

/// One captured `webhook.delivery.suppressed` event.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Suppressed {
    count: Option<u64>,
    reason: Option<String>,
}

#[derive(Default)]
struct SuppressedFields {
    count: Option<u64>,
    reason: Option<String>,
}

impl Visit for SuppressedFields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "suppressed" {
            self.count = Some(value);
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "suppressed" {
            self.count = u64::try_from(value).ok();
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "reason" {
            self.reason = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

/// Records every event on [`SUPPRESSED_TARGET`] and ignores the rest.
#[derive(Clone, Default)]
struct CaptureSuppressed(Arc<Mutex<Vec<Suppressed>>>);

impl CaptureSuppressed {
    fn lines(&self) -> Vec<Suppressed> {
        self.0.lock().expect("capture lock").clone()
    }
}

impl<S: tracing::Subscriber> Layer<S> for CaptureSuppressed {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != SUPPRESSED_TARGET {
            return;
        }
        let mut fields = SuppressedFields::default();
        event.record(&mut fields);
        self.0.lock().expect("capture lock").push(Suppressed {
            count: fields.count,
            reason: fields.reason,
        });
    }
}

fn sink_url(sink: &MockServer, path: &str) -> String {
    format!("http://{SINK_HOST}:{}{path}", sink.address().port())
}

/// The dispatcher's own client builder, with DNS for [`SINK_HOST`] pointed at
/// `sink`. Not `reqwest::Client::new()`: the point is to hand the dispatcher
/// the client shape it runs with in production, plus the one override.
fn client_resolving_to(sink: &MockServer, config: &WebhookDeliveryConfig) -> reqwest::Client {
    dispatcher_client_builder(config.timeout)
        .resolve(SINK_HOST, *sink.address())
        .build()
        .expect("dispatcher client must build")
}

fn sub_to(url: String, event_types: &[&str]) -> WebhookSubscription {
    WebhookSubscription {
        id: Uuid::new_v4(),
        url,
        event_types: event_types.iter().map(|t| (*t).to_string()).collect(),
        created_at: chrono::Utc::now(),
        active: true,
        secret: SECRET.to_string(),
        agent_id: Some(Uuid::new_v4()),
    }
}

fn store_of(subs: &[WebhookSubscription]) -> WebhookStore {
    let map: HashMap<Uuid, WebhookSubscription> = subs.iter().cloned().map(|s| (s.id, s)).collect();
    Arc::new(tokio::sync::RwLock::new(map))
}

fn claim_submitted() -> epigraph_events::EpiGraphEvent {
    epigraph_events::EpiGraphEvent::ClaimSubmitted {
        claim_id: epigraph_core::ClaimId::new(),
        agent_id: epigraph_core::AgentId::new(),
        initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
    }
}

fn reputation_changed() -> epigraph_events::EpiGraphEvent {
    epigraph_events::EpiGraphEvent::ReputationChanged {
        agent_id: epigraph_core::AgentId::new(),
        old_reputation: 0.5,
        new_reputation: 0.6,
    }
}

/// How many requests the sink has seen on `path`.
async fn hits(sink: &MockServer, path: &str) -> usize {
    sink.received_requests()
        .await
        .expect("wiremock records requests by default")
        .iter()
        .filter(|r| r.url.path() == path)
        .count()
}

#[tokio::test(flavor = "current_thread")]
async fn the_no_db_dispatcher_logs_the_suppression_and_delivers_nothing() {
    let capture = CaptureSuppressed::default();
    let _default =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));

    let sink = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&sink)
        .await;

    let matching = sub_to(sink_url(&sink, MATCHING_PATH), &["ClaimSubmitted"]);
    let other = sub_to(sink_url(&sink, OTHER_PATH), &["TruthUpdated"]);
    let store = store_of(&[matching, other]);

    let bus: SharedEventBus = Arc::new(epigraph_events::EventBus::new(64));
    let config = WebhookDeliveryConfig {
        timeout: std::time::Duration::from_millis(500),
        max_retries: 0,
    };
    let client = client_resolving_to(&sink, &config);
    // Named, not RAII: `SubscriptionId` is a `Copy` uuid newtype with no `Drop`.
    let _dispatcher = start_webhook_dispatcher_with_client(&bus, store, config, client.clone());

    // Published first, matches neither subscription: must produce no line.
    bus.publish(reputation_changed())
        .await
        .expect("publish on the bus the dispatcher subscribed to");
    // Matches exactly one subscription.
    bus.publish(claim_submitted())
        .await
        .expect("publish on the bus the dispatcher subscribed to");

    // Wait for the spawned fan-out. Sleeping yields this thread to the
    // runtime, which is what polls the spawned tasks.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while capture.lines().is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // Then let anything else settle, so the "exactly one" and "zero requests"
    // assertions below are not read before the other task had its turn.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let lines = capture.lines();
    assert!(
        !lines.is_empty(),
        "no `{SUPPRESSED_TARGET}` line within 10s of publishing a matching event: \
         the no-db dispatcher is not carrying events from the bus to `deliver_event`"
    );
    assert_eq!(
        lines,
        vec![Suppressed {
            count: Some(1),
            reason: Some("no_db_feature".to_string()),
        }],
        "expected exactly one suppression line, for the one matching subscription, \
         with the no-db reason"
    );

    // Reachability control: the client the dispatcher holds CAN deliver here.
    let control = client
        .post(sink_url(&sink, CONTROL_PATH))
        .body("control")
        .send()
        .await
        .expect("the injected client must reach the sink");
    assert!(control.status().is_success());
    assert_eq!(hits(&sink, CONTROL_PATH).await, 1);

    assert_eq!(
        hits(&sink, MATCHING_PATH).await,
        0,
        "the no-db build delivered a webhook; it has no Viewer to decide who may \
         read the payload, so it must deliver to no one"
    );
    assert_eq!(hits(&sink, OTHER_PATH).await, 0);
}
