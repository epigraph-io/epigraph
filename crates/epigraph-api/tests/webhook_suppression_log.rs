//! The second half of `D-PR-webhook-dispatcher-behavioural-test`: the
//! `webhook.delivery.suppressed` target actually fires.
//!
//! The obligation's `detail` names this separately from the wiring gap: *"Nor
//! does any test assert that the `webhook.delivery.suppressed` tracing target
//! actually fires — the suppression is only observable in a log, so the log
//! line is the sole operator-facing difference between a suppressed webhook and
//! a dead one."* `webhook_tenancy.rs` pins that the suppressed subscription
//! produces no delivery RESULT; nothing pinned that anything is said about it.
//! An endpoint that silently stops receiving events and an endpoint that is
//! being correctly withheld from them look identical from outside the process,
//! and this line is the only thing that tells an operator which one is
//! happening.
//!
//! # Why this is its own test binary
//!
//! `tracing_test::traced_test` installs a GLOBAL subscriber at `trace` for the
//! whole binary and accumulates every captured line in a process-wide buffer.
//! Kept in a binary with one short test so that buffer stays small, rather than
//! folded into `webhook_dispatcher_wiring.rs` where it would capture the trace
//! output of two database-backed delivery tests for the life of the run.
//!
//! # Why it calls `deliver_event` directly rather than going through the
//! dispatcher
//!
//! `traced_test`'s capture is scoped to a span entered on the test's own thread.
//! The dispatcher hands delivery to `tokio::spawn`, whose task is polled on a
//! worker thread that never entered that span, so a log emitted there would not
//! be captured and the assertion would fail for a reason that has nothing to do
//! with the emission. The wiring is asserted in
//! `webhook_dispatcher_wiring.rs`; what is asserted here is the emission, and
//! `deliver_event` is where it happens.
#![cfg(feature = "db")]

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::routes::webhooks::{deliver_event, WebhookDeliveryConfig};
use epigraph_api::state::{WebhookStore, WebhookSubscription};
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::sync::Arc;
use tracing_test::traced_test;
use uuid::Uuid;

const SECRET: &str = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"; // 32 chars

async fn test_pool() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect test pool")
}

/// Unreachable on purpose: this file asserts what is LOGGED, and a delivery
/// that is owed must not depend on a live HTTP sink to be counted.
fn unreachable_sub(agent_id: Uuid) -> WebhookSubscription {
    WebhookSubscription {
        id: Uuid::new_v4(),
        url: "http://127.0.0.1:1/nonexistent".to_string(),
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

/// The delivery egress guard for these tests: a stub resolver that answers
/// nothing. Every target here is the literal `127.0.0.1:1`, which the guard
/// refuses before resolving, so no DNS is involved and an attempted delivery
/// still yields a result entry — the discriminator these tests count.
fn no_dns_egress() -> epigraph_jobs::egress::EgressGuard {
    epigraph_jobs::egress::EgressGuard::with_resolver(std::sync::Arc::new(
        epigraph_jobs::egress::StubResolver::new(),
    ))
}

/// A suppressed subscriber is REPORTED, not merely dropped.
///
/// Current-thread runtime, deliberately: `traced_test` enters its span on the
/// calling thread, and `#[tokio::test]`'s default flavour guarantees every
/// `.await` in this body is polled there.
#[traced_test]
#[tokio::test]
async fn suppressing_a_subscriber_emits_the_suppression_target() {
    let pool = test_pool().await;
    let (agent_a, _group_a) = fixture::seed_agent_with_group(&pool, "suppress-a").await;
    let (agent_b, group_b) = fixture::seed_agent_with_group(&pool, "suppress-b").await;
    let claim_b =
        fixture::seed_group_claim(&pool, agent_b, group_b, "suppression log: group-B claim").await;

    let outside = unreachable_sub(agent_a);
    let inside = unreachable_sub(agent_b);
    let store = store_of(&[outside.clone(), inside.clone()]);

    let results = deliver_event(
        &no_dns_egress(),
        &pool,
        &store,
        &epigraph_events::EpiGraphEvent::ClaimSubmitted {
            claim_id: epigraph_core::ClaimId::from_uuid(claim_b),
            agent_id: epigraph_core::AgentId::from(agent_b),
            initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
        },
        &WebhookDeliveryConfig {
            timeout: std::time::Duration::from_millis(100),
            max_retries: 0,
        },
    )
    .await;

    // Positive direction first. If the fan-out suppressed EVERYONE the log
    // assertion below would still pass, and the property under test would be
    // "the process can log", not "suppression is reported".
    let attempted: Vec<Uuid> = results.iter().map(|r| r.subscription_id).collect();
    assert!(
        attempted.contains(&inside.id),
        "the entitled subscriber was not even attempted, so this fixture \
         suppressed everything and proves nothing about reporting: {attempted:?}"
    );
    assert!(
        !attempted.contains(&outside.id),
        "the unentitled subscriber was delivered to: {attempted:?}"
    );

    // The operator-facing half. The target, and the machine-readable reason
    // that distinguishes this suppression from the other seven.
    assert!(
        logs_contain("webhook.delivery.suppressed"),
        "a subscriber was suppressed and nothing was written to the \
         webhook.delivery.suppressed target: from outside the process this is \
         indistinguishable from a dead endpoint"
    );
    assert!(
        logs_contain("payload_names_invisible_claim"),
        "the suppression was logged without the reason that says WHY, so an \
         operator cannot tell a tenancy decision from a failed probe"
    );
}
