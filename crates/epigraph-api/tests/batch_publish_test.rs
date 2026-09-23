#![cfg(feature = "db")]

//! `POST /api/v1/claims/batch` imports claims and announces none of them.
//!
//! # Why the assertion is on the event bus and not on a status code
//!
//! The defect was not a status code. `batch_create_claims` inserted only into
//! `AppState::claim_store` — an in-memory map nothing drains into `claims` — and
//! then published one `ClaimSubmitted` per item, each naming a claim uuid minted
//! in `validate_batch_item` moments earlier. The webhook fan-out decides
//! visibility by asking which of a payload's uuids name claims that exist and are
//! invisible; an id naming no row contributes nothing, so those payloads were
//! POSTed to every active external subscription with no tenancy decision made.
//! What has to be asserted is therefore the EFFECT — nothing entered the bus that
//! feeds the fan-out — with the import itself still working.
//!
//! # Why this drives the handler rather than the route
//!
//! `deliver_event`'s own test file explains the equivalent choice: the dispatcher
//! is only wired by `bin/server.rs`, so an app from `build_app_for_tests` has an
//! event bus with no webhook subscriber attached and the POST would be
//! unobservable. Holding the `AppState` directly is what makes
//! `event_bus.history_size()` readable, and it is the discriminator the (never
//! compiled) in-`src` module used for the same property. It also keeps this file
//! independent of `/api/v1/admin/stats`, whose scope gate changes in the same
//! batch — a test of one fix should not fail when the other is mutated.
//!
//! `the_event_bus_history_counts_what_is_published` is the control. Without it
//! "history_size is 0" would also be satisfied by a counter that never moves.

use axum::extract::State;
use axum::Json;

async fn state() -> epigraph_api::AppState {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect test pool");
    epigraph_api::AppState::with_db(pool, epigraph_api::ApiConfig::default())
}

fn two_valid_and_one_invalid() -> serde_json::Value {
    serde_json::json!({
        "claims": [
            { "content": "batch import A", "truth_value": 0.6 },
            { "content": "", "truth_value": 0.5 },
            { "content": "batch import B", "truth_value": 0.8 }
        ]
    })
}

/// The import succeeds and publishes nothing.
///
/// Both halves matter. The `created == 2` assertion is the over-suppression
/// control: a "fix" that made the handler reject everything would also publish
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_batch_import_creates_its_claims_and_publishes_no_event() {
    let state = state().await;
    assert_eq!(
        state.event_bus.history_size(),
        0,
        "fixture precondition: a fresh AppState has an empty bus"
    );

    let request: epigraph_api::routes::batch::BatchClaimRequest =
        serde_json::from_value(two_valid_and_one_invalid()).expect("request body parses");

    let response =
        epigraph_api::routes::batch::batch_create_claims(State(state.clone()), Json(request))
            .await
            .expect("a batch with one invalid item is a partial success, not an error");

    assert_eq!(response.0.created, 2, "the two valid items were imported");
    assert_eq!(response.0.failed, 1);
    assert_eq!(
        response
            .0
            .results
            .iter()
            .filter(|r| r.claim_id.is_some())
            .count(),
        2,
        "and the caller was told their ids"
    );

    assert_eq!(
        state.event_bus.history_size(),
        0,
        "a batch-imported claim has no `claims` row, so announcing it would send \
         an id the fan-out cannot make a tenancy decision about; nothing may \
         reach the bus that feeds it"
    );
}

/// THE CONTROL for the discriminator itself: the counter this file asserts on
/// does move when something is published, so `0` above is a fact about the
/// handler and not about a dead counter.
#[tokio::test(flavor = "multi_thread")]
async fn the_event_bus_history_counts_what_is_published() {
    let state = state().await;
    state
        .event_bus
        .publish(epigraph_events::EpiGraphEvent::ClaimSubmitted {
            claim_id: epigraph_core::ClaimId::from_uuid(uuid::Uuid::new_v4()),
            agent_id: epigraph_core::AgentId::new(),
            initial_truth: epigraph_core::TruthValue::new(0.5).unwrap(),
        })
        .await
        .expect("publish to an in-process bus");
    assert_eq!(state.event_bus.history_size(), 1);
}
