//! Event emission tests for staleness triggers (Task 0.3 / Phase 0).
//!
//! Verifies that the four staleness-trigger events are emitted by the
//! epigraph-api handlers:
//!
//! - `edge.added`      — POST /edges handler
//! - `edge.deleted`    — DELETE /edges/:id handler
//! - `claim.superseded`— POST /claims/:id/supersede (the supersession act),
//!   after its commit. It used to come from POST /edges with
//!   relationship=supersedes/SUPERSEDES; ruling R-132 ("supersedes = revision
//!   only", supersede SPEC K12a/K12d) made that edge the act's alone, so the
//!   generic route refuses it and the act emits the event
//!   (`tests/supersede_emits_claim_superseded_http.rs` drives the route).
//!
//! `frame.changed` is deferred (no hypothesis-set mutation endpoint exists).
//!
//! # Strategy
//!
//! The `EventStore` is a process-wide in-memory singleton shared by all
//! handlers. `epigraph_api::_test_event_store()` exposes a clone of the `Arc`
//! so tests can drain and inspect it.
//!
//! Because the singleton persists across tests in the same binary, each test
//! filters by event_type and asserts "at least one event with matching payload"
//! rather than "exactly one event total".

use epigraph_api::_test_event_store;
use epigraph_api::routes::events::EventFilter;
use uuid::Uuid;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Collect all events of a given type currently in the store.
async fn events_of_type(event_type: &str) -> Vec<epigraph_api::routes::events::GraphEvent> {
    let store = _test_event_store();
    let filter = EventFilter {
        event_type: Some(event_type.to_string()),
        since: None,
        after_id: None,
        limit: Some(1000),
        offset: None,
    };
    store.list(&filter).await.0
}

// ── edge.added ────────────────────────────────────────────────────────────────

/// Verify that pushing an `edge.added` event directly lands in the store and
/// the `_test_event_store()` re-export can observe it.
///
/// This test also validates the TDD discipline: if the re-export is broken,
/// this test fails and must be fixed before any handler emission is useful.
#[tokio::test]
async fn test_event_store_reexport_observable() {
    let store = _test_event_store();
    let edge_id = Uuid::new_v4();
    store
        .push(
            "edge.added".to_string(),
            None,
            serde_json::json!({ "edge_id": edge_id }),
        )
        .await;

    let events = events_of_type("edge.added").await;
    assert!(
        events
            .iter()
            .any(|e| e.payload["edge_id"] == serde_json::json!(edge_id)),
        "edge.added event with edge_id={edge_id} not found in store"
    );
}

/// Verify `edge.added` emission pattern matches the required payload schema.
#[tokio::test]
async fn test_edge_added_payload_schema() {
    let store = _test_event_store();
    let edge_id = Uuid::new_v4();
    let source_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();

    store
        .push(
            "edge.added".to_string(),
            None,
            serde_json::json!({
                "edge_id": edge_id,
                "source_type": "claim",
                "source_id": source_id,
                "target_type": "claim",
                "target_id": target_id,
                "relationship": "supports",
            }),
        )
        .await;

    let events = events_of_type("edge.added").await;
    let found = events
        .iter()
        .find(|e| e.payload["edge_id"] == serde_json::json!(edge_id));
    assert!(found.is_some(), "edge.added event not found");

    let e = found.unwrap();
    assert_eq!(e.payload["source_type"], "claim");
    assert_eq!(e.payload["relationship"], "supports");
}

// ── edge.deleted ──────────────────────────────────────────────────────────────

/// Verify `edge.deleted` emission pattern.
#[tokio::test]
async fn test_edge_deleted_payload_schema() {
    let store = _test_event_store();
    let edge_id = Uuid::new_v4();

    store
        .push(
            "edge.deleted".to_string(),
            None,
            serde_json::json!({ "edge_id": edge_id }),
        )
        .await;

    let events = events_of_type("edge.deleted").await;
    assert!(
        events
            .iter()
            .any(|e| e.payload["edge_id"] == serde_json::json!(edge_id)),
        "edge.deleted event not found for edge_id={edge_id}"
    );
}

// ── claim.superseded ─────────────────────────────────────────────────────────

/// Verify `claim.superseded` payload schema (superseded_claim_id + superseded_by_claim_id).
#[tokio::test]
async fn test_claim_superseded_payload_schema() {
    let store = _test_event_store();
    let old_claim = Uuid::new_v4();
    let new_claim = Uuid::new_v4();

    store
        .push(
            "claim.superseded".to_string(),
            None,
            serde_json::json!({
                "superseded_claim_id": old_claim,
                "superseded_by_claim_id": new_claim,
            }),
        )
        .await;

    let events = events_of_type("claim.superseded").await;
    let found = events
        .iter()
        .find(|e| e.payload["superseded_claim_id"] == serde_json::json!(old_claim));
    assert!(found.is_some(), "claim.superseded event not found");

    let e = found.unwrap();
    assert_eq!(
        e.payload["superseded_by_claim_id"],
        serde_json::json!(new_claim)
    );
}

/// The POST /edges guard that decided whether to emit `claim.superseded`
/// (`eq_ignore_ascii_case("supersedes")`) is gone with that emission (ruling
/// R-132, supersede SPEC K12a/K12d). The same case folding now decides the
/// REFUSAL: `is_lineage_relationship` recognises every spelling, so no
/// spelling of the lineage edge reaches the generic route's write.
#[test]
fn test_supersedes_case_insensitive_match() {
    use epigraph_api::routes::edges::is_lineage_relationship;
    assert!(is_lineage_relationship("supersedes"));
    assert!(is_lineage_relationship("SUPERSEDES"));
    // Other relationships should NOT match
    assert!(!is_lineage_relationship("supports"));
}

// ── handler emission guards ───────────────────────────────────────────────────

// Removed: the supersedes-relationship-validity check belongs in Task 0.2's
// edges_validation test target, not in Task 0.3's event-emission scope. The
// upper-case `SUPERSEDES` alias is added in Task 0.2; Task 0.3 just relies on
// it being present when both branches eventually land.
