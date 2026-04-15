//! Event Bus Integration Tests
//!
//! These tests verify the correct behavior of the `EpiGraph` event bus system.
//! The event bus provides pub/sub messaging for decoupled communication
//! between system components.
//!
//! # Test Categories
//!
//! 1. **Event Creation Tests**: Verify `EpiGraphEvent` variants can be created correctly
//! 2. **Event Type Tests**: Verify event type string representations
//! 3. **Pub/Sub Tests**: Verify publish/subscribe mechanics
//! 4. **Subscription Management**: Verify subscribe/unsubscribe operations
//! 5. **History Tests**: Verify event history management and replay
//! 6. **Concurrency Tests**: Verify thread safety
//! 7. **Serialization Tests**: Verify JSON serialization/deserialization
//!
//! # TDD Approach
//!
//! These tests are written FIRST (red phase). Implementations should be added
//! to make these tests pass (green phase), then refactored (refactor phase).

use chrono::{Duration, Utc};
use epigraph_core::domain::{AgentRole, SuspensionReason};
use epigraph_core::{AgentId, ClaimId, TruthValue};
use epigraph_events::events::{ChallengeId, WorkflowId};
use epigraph_events::{
    EpiGraphEvent, EventBus, EventError, SubscriptionId, TimestampedEvent, VerificationStatus,
    WorkflowState,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test `ClaimSubmitted` event
fn create_claim_submitted_event() -> EpiGraphEvent {
    EpiGraphEvent::ClaimSubmitted {
        claim_id: ClaimId::new(),
        agent_id: AgentId::new(),
        initial_truth: TruthValue::new(0.5).unwrap(),
    }
}

/// Create a test `TruthUpdated` event
fn create_truth_updated_event() -> EpiGraphEvent {
    EpiGraphEvent::TruthUpdated {
        claim_id: ClaimId::new(),
        old_truth: TruthValue::new(0.5).unwrap(),
        new_truth: TruthValue::new(0.8).unwrap(),
        source_claim_id: ClaimId::new(),
    }
}

/// Create a test `ClaimVerified` event
fn create_claim_verified_event() -> EpiGraphEvent {
    EpiGraphEvent::ClaimVerified {
        claim_id: ClaimId::new(),
        verification_status: VerificationStatus::VerifiedTrue,
    }
}

/// Create a test `ReputationChanged` event
fn create_reputation_changed_event() -> EpiGraphEvent {
    EpiGraphEvent::ReputationChanged {
        agent_id: AgentId::new(),
        old_reputation: 0.5,
        new_reputation: 0.7,
    }
}

/// Create a test `ClaimChallenged` event
fn create_claim_challenged_event() -> EpiGraphEvent {
    EpiGraphEvent::ClaimChallenged {
        claim_id: ClaimId::new(),
        challenger_id: AgentId::new(),
        challenge_id: ChallengeId::new(),
    }
}

/// Create a test `WorkflowCompleted` event
fn create_workflow_completed_event() -> EpiGraphEvent {
    EpiGraphEvent::WorkflowCompleted {
        workflow_id: WorkflowId::new(),
        final_state: WorkflowState::Completed,
    }
}

/// Create a test `AgentCreated` event
fn create_agent_created_event() -> EpiGraphEvent {
    EpiGraphEvent::AgentCreated {
        agent_id: AgentId::new(),
        role: AgentRole::Harvester,
    }
}

/// Create a test `AgentSuspended` event
fn create_agent_suspended_event() -> EpiGraphEvent {
    EpiGraphEvent::AgentSuspended {
        agent_id: AgentId::new(),
        reason: SuspensionReason::PolicyViolation {
            details: "Test violation".to_string(),
        },
        suspended_by: AgentId::new(),
    }
}

// ============================================================================
// Test 1: Event Creation - ClaimSubmitted
// ============================================================================

#[test]
fn test_event_creation_claim_submitted() {
    // Test that ClaimSubmitted events can be created with all required fields
    let claim_id = ClaimId::new();
    let agent_id = AgentId::new();
    let initial_truth = TruthValue::new(0.75).unwrap();

    let event = EpiGraphEvent::ClaimSubmitted {
        claim_id,
        agent_id,
        initial_truth,
    };

    // Verify the event contains the expected data
    match event {
        EpiGraphEvent::ClaimSubmitted {
            claim_id: cid,
            agent_id: aid,
            initial_truth: truth,
        } => {
            assert_eq!(cid, claim_id, "Claim ID should match");
            assert_eq!(aid, agent_id, "Agent ID should match");
            assert_eq!(truth.value(), 0.75, "Initial truth should match");
        }
        _ => panic!("Expected ClaimSubmitted event"),
    }
}

// ============================================================================
// Test 2: Event Creation - TruthUpdated
// ============================================================================

#[test]
fn test_event_creation_truth_updated() {
    // Test that TruthUpdated events correctly capture truth value changes
    let claim_id = ClaimId::new();
    let old_truth = TruthValue::new(0.5).unwrap();
    let new_truth = TruthValue::new(0.85).unwrap();
    let source_claim_id = ClaimId::new();

    let event = EpiGraphEvent::TruthUpdated {
        claim_id,
        old_truth,
        new_truth,
        source_claim_id,
    };

    match event {
        EpiGraphEvent::TruthUpdated {
            claim_id: cid,
            old_truth: old,
            new_truth: new,
            source_claim_id: source,
        } => {
            assert_eq!(cid, claim_id, "Claim ID should match");
            assert_eq!(old.value(), 0.5, "Old truth should match");
            assert_eq!(new.value(), 0.85, "New truth should match");
            assert_eq!(source, source_claim_id, "Source claim ID should match");
        }
        _ => panic!("Expected TruthUpdated event"),
    }
}

// ============================================================================
// Test 3: Event Creation - ClaimVerified
// ============================================================================

#[test]
fn test_event_creation_claim_verified() {
    // Test that ClaimVerified events capture verification status changes
    let claim_id = ClaimId::new();

    // Test all verification statuses
    let statuses = [
        VerificationStatus::Pending,
        VerificationStatus::VerifiedTrue,
        VerificationStatus::VerifiedFalse,
        VerificationStatus::Uncertain,
        VerificationStatus::Disputed,
    ];

    for status in statuses {
        let event = EpiGraphEvent::ClaimVerified {
            claim_id,
            verification_status: status,
        };

        match event {
            EpiGraphEvent::ClaimVerified {
                claim_id: cid,
                verification_status: vs,
            } => {
                assert_eq!(cid, claim_id, "Claim ID should match");
                assert_eq!(vs, status, "Verification status should match");
            }
            _ => panic!("Expected ClaimVerified event"),
        }
    }
}

// ============================================================================
// Test 4: Event Creation - ReputationChanged
// ============================================================================

#[test]
fn test_event_creation_reputation_changed() {
    // Test that ReputationChanged events correctly capture reputation changes
    let agent_id = AgentId::new();
    let old_reputation = 0.6;
    let new_reputation = 0.45;

    let event = EpiGraphEvent::ReputationChanged {
        agent_id,
        old_reputation,
        new_reputation,
    };

    match event {
        EpiGraphEvent::ReputationChanged {
            agent_id: aid,
            old_reputation: old,
            new_reputation: new,
        } => {
            assert_eq!(aid, agent_id, "Agent ID should match");
            assert!(
                (old - 0.6).abs() < f64::EPSILON,
                "Old reputation should match"
            );
            assert!(
                (new - 0.45).abs() < f64::EPSILON,
                "New reputation should match"
            );
        }
        _ => panic!("Expected ReputationChanged event"),
    }
}

// ============================================================================
// Test 5: Event Type String Representation
// ============================================================================

#[test]
fn test_event_type_string_representation() {
    // Test that event_type() returns correct string representation for each variant
    let events = [
        (create_claim_submitted_event(), "ClaimSubmitted"),
        (create_truth_updated_event(), "TruthUpdated"),
        (create_claim_verified_event(), "ClaimVerified"),
        (create_reputation_changed_event(), "ReputationChanged"),
        (create_claim_challenged_event(), "ClaimChallenged"),
        (create_workflow_completed_event(), "WorkflowCompleted"),
        (create_agent_created_event(), "AgentCreated"),
        (create_agent_suspended_event(), "AgentSuspended"),
    ];

    for (event, expected_type) in events {
        let actual_type = event.event_type();
        assert_eq!(
            actual_type,
            expected_type,
            "Event type for {:?} should be '{}'",
            std::mem::discriminant(&event),
            expected_type
        );
    }
}

// ============================================================================
// Test 6: Event Bus Publish Notifies Subscribers
// ============================================================================

#[tokio::test]
async fn test_event_bus_publish_notifies_subscribers() {
    // Test that publishing an event notifies all subscribers
    let bus = EventBus::new(100);
    let received_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&received_count);

    // Subscribe to all events
    let _sub_id = bus.subscribe(vec![], move |_event| {
        count_clone.fetch_add(1, Ordering::SeqCst);
    });

    // Publish an event
    let event = create_claim_submitted_event();
    bus.publish(event).await.expect("Publish should succeed");

    // Allow time for async notification
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert_eq!(
        received_count.load(Ordering::SeqCst),
        1,
        "Subscriber should receive exactly one event"
    );
}

// ============================================================================
// Test 7: Event Bus Multiple Subscribers
// ============================================================================

#[tokio::test]
async fn test_event_bus_multiple_subscribers() {
    // Test that multiple subscribers all receive published events
    let bus = EventBus::new(100);
    let received_count = Arc::new(AtomicUsize::new(0));

    // Create 5 subscribers
    for _ in 0..5 {
        let count_clone = Arc::clone(&received_count);
        let _sub_id = bus.subscribe(vec![], move |_event| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        });
    }

    assert_eq!(bus.subscriber_count(), 5, "Should have 5 subscribers");

    // Publish an event
    let event = create_claim_submitted_event();
    bus.publish(event).await.expect("Publish should succeed");

    // Allow time for async notifications
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert_eq!(
        received_count.load(Ordering::SeqCst),
        5,
        "All 5 subscribers should receive the event"
    );
}

// ============================================================================
// Test 8: Event Bus Subscribe by Event Type
// ============================================================================

#[tokio::test]
async fn test_event_bus_subscribe_by_event_type() {
    // Test that subscribers only receive events they're interested in
    let bus = EventBus::new(100);

    let claim_count = Arc::new(AtomicUsize::new(0));
    let truth_count = Arc::new(AtomicUsize::new(0));
    let all_count = Arc::new(AtomicUsize::new(0));

    // Subscriber for ClaimSubmitted only
    let claim_clone = Arc::clone(&claim_count);
    bus.subscribe(vec!["ClaimSubmitted".to_string()], move |_| {
        claim_clone.fetch_add(1, Ordering::SeqCst);
    });

    // Subscriber for TruthUpdated only
    let truth_clone = Arc::clone(&truth_count);
    bus.subscribe(vec!["TruthUpdated".to_string()], move |_| {
        truth_clone.fetch_add(1, Ordering::SeqCst);
    });

    // Subscriber for all events
    let all_clone = Arc::clone(&all_count);
    bus.subscribe(vec![], move |_| {
        all_clone.fetch_add(1, Ordering::SeqCst);
    });

    // Publish different event types
    bus.publish(create_claim_submitted_event())
        .await
        .expect("Publish should succeed");
    bus.publish(create_truth_updated_event())
        .await
        .expect("Publish should succeed");
    bus.publish(create_claim_verified_event())
        .await
        .expect("Publish should succeed");

    // Allow time for async notifications
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert_eq!(
        claim_count.load(Ordering::SeqCst),
        1,
        "ClaimSubmitted subscriber should receive 1 event"
    );
    assert_eq!(
        truth_count.load(Ordering::SeqCst),
        1,
        "TruthUpdated subscriber should receive 1 event"
    );
    assert_eq!(
        all_count.load(Ordering::SeqCst),
        3,
        "All-events subscriber should receive 3 events"
    );
}

// ============================================================================
// Test 9: Event Bus Unsubscribe
// ============================================================================

#[tokio::test]
async fn test_event_bus_unsubscribe() {
    // Test that unsubscribed handlers no longer receive events
    let bus = EventBus::new(100);
    let received_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&received_count);

    // Subscribe
    let sub_id = bus.subscribe(vec![], move |_event| {
        count_clone.fetch_add(1, Ordering::SeqCst);
    });

    assert_eq!(bus.subscriber_count(), 1, "Should have 1 subscriber");

    // Publish first event
    bus.publish(create_claim_submitted_event())
        .await
        .expect("Publish should succeed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(
        received_count.load(Ordering::SeqCst),
        1,
        "Should have received 1 event before unsubscribe"
    );

    // Unsubscribe
    bus.unsubscribe(sub_id).expect("Unsubscribe should succeed");
    assert_eq!(bus.subscriber_count(), 0, "Should have 0 subscribers");

    // Publish second event
    bus.publish(create_claim_submitted_event())
        .await
        .expect("Publish should succeed");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(
        received_count.load(Ordering::SeqCst),
        1,
        "Should still have only 1 event (unsubscribed handler not called)"
    );
}

// ============================================================================
// Test 10: Event Bus Event Type Filtering
// ============================================================================

#[tokio::test]
async fn test_event_bus_event_type_filtering() {
    // Test that event type filtering works correctly with multiple types
    let bus = EventBus::new(100);
    let received_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&received_count);

    // Subscribe to multiple specific event types
    bus.subscribe(
        vec![
            "ClaimSubmitted".to_string(),
            "ClaimVerified".to_string(),
            "ReputationChanged".to_string(),
        ],
        move |_| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        },
    );

    // Publish 6 events, 3 matching the filter
    bus.publish(create_claim_submitted_event()).await.unwrap(); // Match
    bus.publish(create_truth_updated_event()).await.unwrap(); // No match
    bus.publish(create_claim_verified_event()).await.unwrap(); // Match
    bus.publish(create_workflow_completed_event())
        .await
        .unwrap(); // No match
    bus.publish(create_reputation_changed_event())
        .await
        .unwrap(); // Match
    bus.publish(create_agent_created_event()).await.unwrap(); // No match

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    assert_eq!(
        received_count.load(Ordering::SeqCst),
        3,
        "Should receive only the 3 matching events"
    );
}

// ============================================================================
// Test 11: Event Bus Maintains History
// ============================================================================

#[tokio::test]
async fn test_event_bus_maintains_history() {
    // Test that published events are stored in history
    let bus = EventBus::new(100);

    assert_eq!(bus.history_size(), 0, "History should start empty");

    // Publish several events
    for _ in 0..5 {
        bus.publish(create_claim_submitted_event())
            .await
            .expect("Publish should succeed");
    }

    assert_eq!(bus.history_size(), 5, "History should contain 5 events");

    // Verify history contents
    let history = bus.get_history().expect("Should get history");
    assert_eq!(history.len(), 5, "History vec should have 5 events");

    // All should be ClaimSubmitted events
    for timestamped in &history {
        assert!(
            matches!(timestamped.event, EpiGraphEvent::ClaimSubmitted { .. }),
            "All events should be ClaimSubmitted"
        );
    }
}

// ============================================================================
// Test 12: Event Bus History Max Size Bounded
// ============================================================================

#[tokio::test]
async fn test_event_bus_history_max_size_bounded() {
    // Test that history doesn't exceed the configured maximum
    let max_size = 10;
    let bus = EventBus::new(max_size);

    // Publish more events than the max size
    for _ in 0..25 {
        bus.publish(create_claim_submitted_event())
            .await
            .expect("Publish should succeed");
    }

    assert!(
        bus.history_size() <= max_size,
        "History size {} should not exceed max {}",
        bus.history_size(),
        max_size
    );
    assert_eq!(
        bus.max_history(),
        max_size,
        "Max history should match config"
    );
}

// ============================================================================
// Test 13: Event Bus Replay Events From Timestamp
// ============================================================================

#[tokio::test]
async fn test_event_bus_replay_events_from_timestamp() {
    // Test that replay only includes events after the specified timestamp
    let bus = EventBus::new(100);

    // Publish some events
    bus.publish(create_claim_submitted_event()).await.unwrap();
    bus.publish(create_claim_submitted_event()).await.unwrap();

    // Record timestamp
    let midpoint = Utc::now();

    // Small delay to ensure timestamp separation
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Publish more events
    bus.publish(create_truth_updated_event()).await.unwrap();
    bus.publish(create_truth_updated_event()).await.unwrap();
    bus.publish(create_truth_updated_event()).await.unwrap();

    // Replay only events after midpoint
    let replay_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&replay_count);

    let replayed = bus
        .replay(midpoint, move |_| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("Replay should succeed");

    assert_eq!(
        replayed, 3,
        "Replay should return count of 3 events after midpoint"
    );
    assert_eq!(
        replay_count.load(Ordering::SeqCst),
        3,
        "Handler should be called 3 times"
    );
}

// ============================================================================
// Test 14: Event Bus Replay Calls Handler For Each Event
// ============================================================================

#[tokio::test]
async fn test_event_bus_replay_calls_handler_for_each() {
    // Test that replay handler is called for each matching event in order
    let bus = EventBus::new(100);

    // Publish events of different types
    bus.publish(create_claim_submitted_event()).await.unwrap();
    bus.publish(create_truth_updated_event()).await.unwrap();
    bus.publish(create_claim_verified_event()).await.unwrap();

    let events_received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let events_clone = Arc::clone(&events_received);

    // Replay from the beginning
    let from = Utc::now() - Duration::hours(1);
    let replayed = bus
        .replay(from, move |event| {
            let event_type = event.event_type();
            events_clone.lock().unwrap().push(event_type);
        })
        .expect("Replay should succeed");

    assert_eq!(replayed, 3, "Should replay all 3 events");

    let received = events_received.lock().unwrap();
    assert_eq!(received.len(), 3, "Handler should be called 3 times");
    assert_eq!(
        received[0], "ClaimSubmitted",
        "First event should be ClaimSubmitted"
    );
    assert_eq!(
        received[1], "TruthUpdated",
        "Second event should be TruthUpdated"
    );
    assert_eq!(
        received[2], "ClaimVerified",
        "Third event should be ClaimVerified"
    );
}

// ============================================================================
// Test 15: Concurrent Publish Thread Safe
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_publish_thread_safe() {
    // Test that concurrent publishes don't corrupt state
    let bus = Arc::new(EventBus::new(1000));

    let mut handles = vec![];

    // Spawn 10 concurrent tasks, each publishing 100 events
    for _ in 0..10 {
        let bus_clone = Arc::clone(&bus);
        let handle = tokio::spawn(async move {
            for _ in 0..100 {
                bus_clone
                    .publish(create_claim_submitted_event())
                    .await
                    .expect("Publish should succeed");
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.expect("Task should complete without panic");
    }

    // Verify state is consistent
    assert!(
        bus.history_size() <= 1000,
        "History should be bounded to max size"
    );

    // All events should be valid
    let history = bus.get_history().expect("Should get history");
    for timestamped in &history {
        assert!(
            matches!(timestamped.event, EpiGraphEvent::ClaimSubmitted { .. }),
            "All events should be valid ClaimSubmitted"
        );
    }
}

// ============================================================================
// Test 16: Subscriber Receives Events In Order
// ============================================================================

#[tokio::test]
async fn test_subscriber_receives_events_in_order() {
    // Test that a subscriber receives events in the order they were published
    let bus = EventBus::new(100);
    let received_order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let order_clone = Arc::clone(&received_order);

    bus.subscribe(vec![], move |event| {
        let event_type = event.event_type();
        order_clone.lock().unwrap().push(event_type);
    });

    // Publish events in a specific order
    bus.publish(create_claim_submitted_event()).await.unwrap();
    bus.publish(create_truth_updated_event()).await.unwrap();
    bus.publish(create_claim_verified_event()).await.unwrap();
    bus.publish(create_reputation_changed_event())
        .await
        .unwrap();
    bus.publish(create_workflow_completed_event())
        .await
        .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let order = received_order.lock().unwrap();
    assert_eq!(order.len(), 5, "Should receive all 5 events");

    let expected = [
        "ClaimSubmitted",
        "TruthUpdated",
        "ClaimVerified",
        "ReputationChanged",
        "WorkflowCompleted",
    ];
    for (i, (actual, expected)) in order.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            actual, *expected,
            "Event {i} should be {expected} but was {actual}"
        );
    }
}

// ============================================================================
// Test 17: Timestamped Event Includes UTC Time
// ============================================================================

#[test]
fn test_timestamped_event_includes_utc_time() {
    // Test that TimestampedEvent correctly captures UTC timestamp
    let before = Utc::now();
    let event = create_claim_submitted_event();
    let timestamped = TimestampedEvent::new(event);
    let after = Utc::now();

    assert!(
        timestamped.timestamp >= before,
        "Timestamp should be at or after test start"
    );
    assert!(
        timestamped.timestamp <= after,
        "Timestamp should be at or before test end"
    );

    // Verify the event is preserved
    assert!(
        matches!(timestamped.event, EpiGraphEvent::ClaimSubmitted { .. }),
        "Event should be ClaimSubmitted"
    );
}

// ============================================================================
// Test 18: Event Serialization JSON
// ============================================================================

#[test]
fn test_event_serialization_json() {
    // Test that all event types can be serialized to JSON
    let events = [
        create_claim_submitted_event(),
        create_truth_updated_event(),
        create_claim_verified_event(),
        create_reputation_changed_event(),
        create_claim_challenged_event(),
        create_workflow_completed_event(),
        create_agent_created_event(),
        create_agent_suspended_event(),
    ];

    for event in events {
        let json = serde_json::to_string(&event);
        assert!(
            json.is_ok(),
            "Event {:?} should serialize to JSON: {:?}",
            std::mem::discriminant(&event),
            json.err()
        );

        let json_str = json.unwrap();
        assert!(!json_str.is_empty(), "JSON should not be empty");

        // Verify it's valid JSON by parsing it back
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
        assert!(parsed.is_ok(), "Serialized JSON should be valid");
    }
}

// ============================================================================
// Test 19: Event Deserialization JSON
// ============================================================================

#[test]
fn test_event_deserialization_json() {
    // Test that all event types can be deserialized from JSON
    let events = [
        create_claim_submitted_event(),
        create_truth_updated_event(),
        create_claim_verified_event(),
        create_reputation_changed_event(),
        create_claim_challenged_event(),
        create_workflow_completed_event(),
        create_agent_created_event(),
        create_agent_suspended_event(),
    ];

    for original_event in events {
        // Serialize
        let json = serde_json::to_string(&original_event).expect("Serialization should succeed");

        // Deserialize
        let deserialized: Result<EpiGraphEvent, _> = serde_json::from_str(&json);
        assert!(
            deserialized.is_ok(),
            "Deserialization should succeed: {:?}",
            deserialized.err()
        );

        let restored = deserialized.unwrap();

        // Verify the event type matches
        assert_eq!(
            std::mem::discriminant(&original_event),
            std::mem::discriminant(&restored),
            "Event type should match after round-trip"
        );
    }
}

// ============================================================================
// Test 20: Subscription ID Unique
// ============================================================================

#[test]
fn test_subscription_id_unique() {
    // Test that each subscription gets a unique ID
    let bus = EventBus::new(100);
    let mut subscription_ids = HashSet::new();

    // Create many subscriptions
    for _ in 0..1000 {
        let sub_id = bus.subscribe(vec![], |_| {});
        let is_new = subscription_ids.insert(sub_id);
        assert!(is_new, "Subscription ID should be unique");
    }

    assert_eq!(subscription_ids.len(), 1000, "Should have 1000 unique IDs");
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

#[test]
fn test_subscription_id_display() {
    // Test that SubscriptionId has a useful Display implementation
    let sub_id = SubscriptionId::new();
    let display = format!("{sub_id}");
    assert!(
        display.starts_with("subscription:"),
        "Display should have 'subscription:' prefix"
    );
}

#[tokio::test]
async fn test_unsubscribe_nonexistent_fails() {
    // Test that unsubscribing a nonexistent subscription fails gracefully
    let bus = EventBus::new(100);
    let fake_id = SubscriptionId::new();

    let result = bus.unsubscribe(fake_id);
    assert!(
        matches!(result, Err(EventError::SubscriptionNotFound { .. })),
        "Should return SubscriptionNotFound error"
    );
}

#[tokio::test]
async fn test_event_bus_empty_history_replay() {
    // Test replay with empty history
    let bus = EventBus::new(100);
    let replay_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&replay_count);

    let from = Utc::now() - Duration::hours(1);
    let replayed = bus
        .replay(from, move |_| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("Replay should succeed even with empty history");

    assert_eq!(replayed, 0, "Should replay 0 events from empty history");
    assert_eq!(
        replay_count.load(Ordering::SeqCst),
        0,
        "Handler should not be called"
    );
}

#[tokio::test]
async fn test_event_bus_clear_history() {
    // Test that history can be cleared
    let bus = EventBus::new(100);

    // Add some events
    for _ in 0..5 {
        bus.publish(create_claim_submitted_event()).await.unwrap();
    }

    assert_eq!(bus.history_size(), 5, "Should have 5 events in history");

    // Clear history
    bus.clear_history().expect("Clear should succeed");

    assert_eq!(bus.history_size(), 0, "History should be empty after clear");
}

#[test]
fn test_timestamped_event_with_specific_timestamp() {
    // Test creating TimestampedEvent with a specific timestamp
    let event = create_claim_submitted_event();
    let specific_time = Utc::now() - Duration::days(7);
    let timestamped = TimestampedEvent::with_timestamp(event, specific_time);

    assert_eq!(
        timestamped.timestamp, specific_time,
        "Should use the specified timestamp"
    );
}

#[test]
fn test_verification_status_equality() {
    // Test VerificationStatus enum equality
    assert_eq!(VerificationStatus::Pending, VerificationStatus::Pending);
    assert_ne!(
        VerificationStatus::Pending,
        VerificationStatus::VerifiedTrue
    );
    assert_ne!(
        VerificationStatus::VerifiedTrue,
        VerificationStatus::VerifiedFalse
    );
}

#[test]
fn test_workflow_state_equality() {
    // Test WorkflowState enum equality
    assert_eq!(WorkflowState::Completed, WorkflowState::Completed);
    assert_ne!(WorkflowState::Completed, WorkflowState::Failed);
    assert_ne!(WorkflowState::Running, WorkflowState::Cancelled);
}

#[test]
fn test_agent_role_equality() {
    // Test AgentRole enum equality
    assert_eq!(AgentRole::Harvester, AgentRole::Harvester);
    assert_ne!(AgentRole::Harvester, AgentRole::Validator);
    assert_ne!(AgentRole::Admin, AgentRole::Custom);
}

#[test]
fn test_suspension_reason_equality() {
    // Test SuspensionReason enum equality
    let reason1 = SuspensionReason::RateLimitExceeded;
    let reason2 = SuspensionReason::RateLimitExceeded;
    let reason3 = SuspensionReason::Inactivity { days: 30 };

    assert_eq!(reason1, reason2);
    assert_ne!(reason1, reason3);
}

#[test]
fn test_challenge_id_unique() {
    // Test that ChallengeId generates unique values
    let id1 = ChallengeId::new();
    let id2 = ChallengeId::new();
    assert_ne!(id1, id2, "Challenge IDs should be unique");
}

#[test]
fn test_workflow_id_unique() {
    // Test that WorkflowId generates unique values
    let id1 = WorkflowId::new();
    let id2 = WorkflowId::new();
    assert_ne!(id1, id2, "Workflow IDs should be unique");
}

// ============================================================================
// Test 21: Event Creation - ClaimChallenged
// ============================================================================

#[test]
fn test_event_creation_claim_challenged() {
    // Test that ClaimChallenged events correctly capture challenge data
    let claim_id = ClaimId::new();
    let challenger_id = AgentId::new();
    let challenge_id = ChallengeId::new();

    let event = EpiGraphEvent::ClaimChallenged {
        claim_id,
        challenger_id,
        challenge_id,
    };

    match event {
        EpiGraphEvent::ClaimChallenged {
            claim_id: cid,
            challenger_id: chid,
            challenge_id: chgid,
        } => {
            assert_eq!(cid, claim_id, "Claim ID should match");
            assert_eq!(chid, challenger_id, "Challenger ID should match");
            assert_eq!(chgid, challenge_id, "Challenge ID should match");
        }
        _ => panic!("Expected ClaimChallenged event"),
    }
}

// ============================================================================
// Test 22: Event Creation - WorkflowCompleted
// ============================================================================

#[test]
fn test_event_creation_workflow_completed() {
    // Test that WorkflowCompleted events correctly capture all workflow states
    let workflow_id = WorkflowId::new();

    // Test all workflow states
    let states = [
        WorkflowState::Created,
        WorkflowState::Running,
        WorkflowState::Completed,
        WorkflowState::Failed,
        WorkflowState::Cancelled,
        WorkflowState::TimedOut,
    ];

    for state in states {
        let event = EpiGraphEvent::WorkflowCompleted {
            workflow_id,
            final_state: state,
        };

        match event {
            EpiGraphEvent::WorkflowCompleted {
                workflow_id: wid,
                final_state: fs,
            } => {
                assert_eq!(wid, workflow_id, "Workflow ID should match");
                assert_eq!(fs, state, "Final state should match");
            }
            _ => panic!("Expected WorkflowCompleted event"),
        }
    }
}

// ============================================================================
// Test 23: Event Creation - AgentCreated
// ============================================================================

#[test]
fn test_event_creation_agent_created() {
    // Test that AgentCreated events correctly capture all agent roles
    let agent_id = AgentId::new();

    // Test all agent roles
    let roles = [
        AgentRole::Harvester,
        AgentRole::Validator,
        AgentRole::Orchestrator,
        AgentRole::Analyst,
        AgentRole::Admin,
        AgentRole::Custom,
    ];

    for role in roles {
        let event = EpiGraphEvent::AgentCreated { agent_id, role };

        match event {
            EpiGraphEvent::AgentCreated {
                agent_id: aid,
                role: r,
            } => {
                assert_eq!(aid, agent_id, "Agent ID should match");
                assert_eq!(r, role, "Role should match");
            }
            _ => panic!("Expected AgentCreated event"),
        }
    }
}

// ============================================================================
// Test 24: Event Creation - AgentSuspended (All SuspensionReason variants)
// ============================================================================

#[test]
fn test_event_creation_agent_suspended_all_reasons() {
    // Test that AgentSuspended events correctly capture all suspension reasons
    let agent_id = AgentId::new();
    let suspended_by = AgentId::new();

    // Test all SuspensionReason variants
    let reasons = [
        SuspensionReason::PolicyViolation {
            details: "Violated content policy".to_string(),
        },
        SuspensionReason::RateLimitExceeded,
        SuspensionReason::SecurityConcern {
            details: "Suspicious access pattern detected".to_string(),
        },
        SuspensionReason::Administrative {
            details: "Account under review".to_string(),
        },
        SuspensionReason::Inactivity { days: 90 },
    ];

    for reason in reasons {
        let event = EpiGraphEvent::AgentSuspended {
            agent_id,
            reason: reason.clone(),
            suspended_by,
        };

        match event {
            EpiGraphEvent::AgentSuspended {
                agent_id: aid,
                reason: r,
                suspended_by: sb,
            } => {
                assert_eq!(aid, agent_id, "Agent ID should match");
                assert_eq!(r, reason, "Reason should match");
                assert_eq!(sb, suspended_by, "Suspended by should match");
            }
            _ => panic!("Expected AgentSuspended event"),
        }
    }
}

#[test]
fn test_event_creation_agent_suspended_policy_violation() {
    // Test PolicyViolation reason preserves details
    let agent_id = AgentId::new();
    let suspended_by = AgentId::new();
    let details = "Submitted false claims repeatedly".to_string();

    let event = EpiGraphEvent::AgentSuspended {
        agent_id,
        reason: SuspensionReason::PolicyViolation {
            details: details.clone(),
        },
        suspended_by,
    };

    match event {
        EpiGraphEvent::AgentSuspended { reason, .. } => match reason {
            SuspensionReason::PolicyViolation { details: d } => {
                assert_eq!(d, details, "Policy violation details should be preserved");
            }
            _ => panic!("Expected PolicyViolation reason"),
        },
        _ => panic!("Expected AgentSuspended event"),
    }
}

#[test]
fn test_event_creation_agent_suspended_security_concern() {
    // Test SecurityConcern reason preserves details
    let agent_id = AgentId::new();
    let suspended_by = AgentId::new();
    let details = "Multiple failed authentication attempts".to_string();

    let event = EpiGraphEvent::AgentSuspended {
        agent_id,
        reason: SuspensionReason::SecurityConcern {
            details: details.clone(),
        },
        suspended_by,
    };

    match event {
        EpiGraphEvent::AgentSuspended { reason, .. } => match reason {
            SuspensionReason::SecurityConcern { details: d } => {
                assert_eq!(d, details, "Security concern details should be preserved");
            }
            _ => panic!("Expected SecurityConcern reason"),
        },
        _ => panic!("Expected AgentSuspended event"),
    }
}

#[test]
fn test_event_creation_agent_suspended_administrative() {
    // Test Administrative reason preserves details
    let agent_id = AgentId::new();
    let suspended_by = AgentId::new();
    let details = "Manual suspension by admin".to_string();

    let event = EpiGraphEvent::AgentSuspended {
        agent_id,
        reason: SuspensionReason::Administrative {
            details: details.clone(),
        },
        suspended_by,
    };

    match event {
        EpiGraphEvent::AgentSuspended { reason, .. } => match reason {
            SuspensionReason::Administrative { details: d } => {
                assert_eq!(d, details, "Administrative details should be preserved");
            }
            _ => panic!("Expected Administrative reason"),
        },
        _ => panic!("Expected AgentSuspended event"),
    }
}

#[test]
fn test_event_creation_agent_suspended_inactivity() {
    // Test Inactivity reason preserves days count
    let agent_id = AgentId::new();
    let suspended_by = AgentId::new();
    let days = 365;

    let event = EpiGraphEvent::AgentSuspended {
        agent_id,
        reason: SuspensionReason::Inactivity { days },
        suspended_by,
    };

    match event {
        EpiGraphEvent::AgentSuspended { reason, .. } => match reason {
            SuspensionReason::Inactivity { days: d } => {
                assert_eq!(d, days, "Inactivity days should be preserved");
            }
            _ => panic!("Expected Inactivity reason"),
        },
        _ => panic!("Expected AgentSuspended event"),
    }
}

#[test]
fn test_event_creation_agent_suspended_rate_limit() {
    // Test RateLimitExceeded reason (no additional fields)
    let agent_id = AgentId::new();
    let suspended_by = AgentId::new();

    let event = EpiGraphEvent::AgentSuspended {
        agent_id,
        reason: SuspensionReason::RateLimitExceeded,
        suspended_by,
    };

    match event {
        EpiGraphEvent::AgentSuspended { reason, .. } => {
            assert_eq!(
                reason,
                SuspensionReason::RateLimitExceeded,
                "Should be RateLimitExceeded"
            );
        }
        _ => panic!("Expected AgentSuspended event"),
    }
}

// ============================================================================
// Test 25: History FIFO Order Verification
// ============================================================================

#[tokio::test]
async fn test_event_bus_history_fifo_order() {
    // Test that history maintains FIFO order (oldest events evicted first)
    let max_size = 5;
    let bus = EventBus::new(max_size);

    // Publish 10 events with distinguishable data
    // We'll use different truth values to identify them
    let mut claim_ids = Vec::new();
    for i in 0..10 {
        let claim_id = ClaimId::new();
        claim_ids.push(claim_id);

        let event = EpiGraphEvent::ClaimSubmitted {
            claim_id,
            agent_id: AgentId::new(),
            initial_truth: TruthValue::new(f64::from(i) / 10.0).unwrap(),
        };
        bus.publish(event).await.unwrap();

        // Small delay to ensure timestamp ordering
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
    }

    // Get history - should only contain the last 5 events
    let history = bus.get_history().expect("Should get history");
    assert_eq!(
        history.len(),
        max_size,
        "History should contain exactly max_size events"
    );

    // Verify the history contains the LAST 5 events (FIFO eviction of oldest)
    // Events 5, 6, 7, 8, 9 should remain (indices in claim_ids)
    for (i, timestamped) in history.iter().enumerate() {
        match &timestamped.event {
            EpiGraphEvent::ClaimSubmitted { claim_id, .. } => {
                let expected_claim_id = claim_ids[5 + i];
                assert_eq!(
                    *claim_id,
                    expected_claim_id,
                    "Event at index {} should be event {} (FIFO order)",
                    i,
                    5 + i
                );
            }
            _ => panic!("Expected ClaimSubmitted event"),
        }
    }

    // Verify timestamps are in ascending order
    for i in 1..history.len() {
        assert!(
            history[i].timestamp >= history[i - 1].timestamp,
            "History should be in chronological order (event {} timestamp should be >= event {})",
            i,
            i - 1
        );
    }
}

#[tokio::test]
async fn test_event_bus_history_order_with_mixed_events() {
    // Test that history maintains FIFO order with mixed event types
    let max_size = 4;
    let bus = EventBus::new(max_size);

    // Publish 8 events of different types
    bus.publish(create_claim_submitted_event()).await.unwrap(); // 0 - evicted
    bus.publish(create_truth_updated_event()).await.unwrap(); // 1 - evicted
    bus.publish(create_claim_verified_event()).await.unwrap(); // 2 - evicted
    bus.publish(create_reputation_changed_event())
        .await
        .unwrap(); // 3 - evicted
    bus.publish(create_claim_challenged_event()).await.unwrap(); // 4 - kept
    bus.publish(create_workflow_completed_event())
        .await
        .unwrap(); // 5 - kept
    bus.publish(create_agent_created_event()).await.unwrap(); // 6 - kept
    bus.publish(create_agent_suspended_event()).await.unwrap(); // 7 - kept

    let history = bus.get_history().expect("Should get history");
    assert_eq!(history.len(), max_size, "History should be bounded");

    // Verify the remaining events are in correct FIFO order
    let expected_types = [
        "ClaimChallenged",
        "WorkflowCompleted",
        "AgentCreated",
        "AgentSuspended",
    ];

    for (i, (timestamped, expected_type)) in history.iter().zip(expected_types.iter()).enumerate() {
        let actual_type = timestamped.event.event_type();
        assert_eq!(
            actual_type.as_str(),
            *expected_type,
            "Event at index {i} should be {expected_type} but was {actual_type}"
        );
    }
}

// ============================================================================
// Test 26: Replay Edge Cases - Future Timestamp
// ============================================================================

#[tokio::test]
async fn test_event_bus_replay_future_timestamp() {
    // Test replay with a timestamp in the future returns no events
    let bus = EventBus::new(100);

    // Publish some events
    for _ in 0..5 {
        bus.publish(create_claim_submitted_event()).await.unwrap();
    }

    assert_eq!(bus.history_size(), 5, "Should have 5 events in history");

    // Replay from a future timestamp
    let future = Utc::now() + Duration::hours(1);
    let replay_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&replay_count);

    let replayed = bus
        .replay(future, move |_| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("Replay should succeed");

    assert_eq!(
        replayed, 0,
        "Replay from future timestamp should return 0 events"
    );
    assert_eq!(
        replay_count.load(Ordering::SeqCst),
        0,
        "Handler should not be called for future timestamp"
    );
}

#[tokio::test]
async fn test_event_bus_replay_far_future_timestamp() {
    // Test replay with a timestamp far in the future
    let bus = EventBus::new(100);

    for _ in 0..3 {
        bus.publish(create_claim_submitted_event()).await.unwrap();
    }

    // Replay from a timestamp years in the future
    let far_future = Utc::now() + Duration::days(365 * 10);
    let replayed = bus
        .replay(far_future, |_| {})
        .expect("Replay should succeed");

    assert_eq!(
        replayed, 0,
        "Should replay 0 events from far future timestamp"
    );
}

// ============================================================================
// Test 27: Replay Edge Cases - Exact Timestamp Boundaries
// ============================================================================

#[tokio::test]
async fn test_event_bus_replay_exact_timestamp_boundary() {
    // Test replay with timestamp exactly matching an event's timestamp
    let bus = EventBus::new(100);

    // Publish first event and capture its timestamp
    bus.publish(create_claim_submitted_event()).await.unwrap();

    // Get the timestamp of the first event
    let history = bus.get_history().expect("Should get history");
    let first_event_timestamp = history[0].timestamp;

    // Small delay to ensure next event has different timestamp
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Publish more events
    bus.publish(create_truth_updated_event()).await.unwrap();
    bus.publish(create_claim_verified_event()).await.unwrap();

    // Replay using the exact timestamp of the first event
    // Events AT the timestamp should NOT be included (strictly after)
    let replay_count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&replay_count);

    let replayed = bus
        .replay(first_event_timestamp, move |_| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("Replay should succeed");

    // Should include events AFTER the first event's timestamp (2 events)
    assert_eq!(
        replayed, 2,
        "Replay from exact timestamp should return events strictly after that time"
    );
    assert_eq!(
        replay_count.load(Ordering::SeqCst),
        2,
        "Handler should be called for events after the boundary"
    );
}

#[tokio::test]
async fn test_event_bus_replay_boundary_includes_same_millisecond() {
    // Test behavior when multiple events have same timestamp (edge case)
    let bus = EventBus::new(100);

    // Publish several events as fast as possible (may have same timestamp)
    for _ in 0..5 {
        bus.publish(create_claim_submitted_event()).await.unwrap();
    }

    // Get history and find oldest timestamp
    let history = bus.get_history().expect("Should get history");
    let oldest_timestamp = history.iter().map(|e| e.timestamp).min().unwrap();

    // Replay from 1 nanosecond before the oldest event
    let just_before = oldest_timestamp - Duration::nanoseconds(1);
    let replayed = bus
        .replay(just_before, |_| {})
        .expect("Replay should succeed");

    // Should include all events
    assert_eq!(
        replayed,
        history.len(),
        "Replay from just before oldest should include all events"
    );
}

#[tokio::test]
async fn test_event_bus_replay_at_most_recent_timestamp() {
    // Test replay at the timestamp of the most recent event
    let bus = EventBus::new(100);

    bus.publish(create_claim_submitted_event()).await.unwrap();
    bus.publish(create_truth_updated_event()).await.unwrap();
    bus.publish(create_claim_verified_event()).await.unwrap();

    // Get the timestamp of the most recent event
    let history = bus.get_history().expect("Should get history");
    let most_recent_timestamp = history.last().unwrap().timestamp;

    let replayed = bus
        .replay(most_recent_timestamp, |_| {})
        .expect("Replay should succeed");

    // Should return 0 since we want events AFTER the most recent
    assert_eq!(
        replayed, 0,
        "Replay from most recent timestamp should return 0 events"
    );
}

// ============================================================================
// Test 28: Concurrent Subscribe/Unsubscribe Race Conditions
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_subscribe_unsubscribe_race() {
    // Test that concurrent subscribe/unsubscribe operations don't corrupt state
    let bus = Arc::new(EventBus::new(1000));
    let mut handles = vec![];

    // Track subscription IDs created by each task
    let subscription_ids = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Spawn 10 tasks that each subscribe and unsubscribe rapidly
    for task_id in 0..10 {
        let bus_clone = Arc::clone(&bus);
        let ids_clone = Arc::clone(&subscription_ids);

        let handle = tokio::spawn(async move {
            let mut local_ids = Vec::new();

            // Each task subscribes 50 times, then unsubscribes all
            for i in 0..50 {
                let filter = if i % 2 == 0 {
                    vec!["ClaimSubmitted".to_string()]
                } else {
                    vec![]
                };

                let sub_id = bus_clone.subscribe(filter, move |_| {});
                local_ids.push(sub_id);
            }

            // Small yield to increase race condition chance
            tokio::task::yield_now().await;

            // Unsubscribe all
            for sub_id in &local_ids {
                // Ignore errors - another task may have caused issues
                let _ = bus_clone.unsubscribe(*sub_id);
            }

            // Store IDs for verification
            ids_clone.lock().unwrap().extend(local_ids);
            task_id // Return task ID to verify all completed
        });
        handles.push(handle);
    }

    // Wait for all tasks and verify they completed
    let mut completed_tasks = Vec::new();
    for handle in handles {
        let task_id = handle.await.expect("Task should complete without panic");
        completed_tasks.push(task_id);
    }

    assert_eq!(
        completed_tasks.len(),
        10,
        "All 10 tasks should complete successfully"
    );

    // Verify all subscription IDs were unique
    let all_ids = subscription_ids.lock().unwrap();
    let unique_ids: HashSet<_> = all_ids.iter().collect();
    assert_eq!(
        unique_ids.len(),
        all_ids.len(),
        "All subscription IDs should be unique even under concurrency"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_subscribe_publish_race() {
    // Test that subscribing while publishing doesn't cause issues
    let bus = Arc::new(EventBus::new(1000));
    let received_events = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    // Spawn publishers
    for _ in 0..5 {
        let bus_clone = Arc::clone(&bus);
        let handle = tokio::spawn(async move {
            for _ in 0..100 {
                bus_clone
                    .publish(create_claim_submitted_event())
                    .await
                    .expect("Publish should succeed");
                tokio::task::yield_now().await;
            }
        });
        handles.push(handle);
    }

    // Spawn subscribers that subscribe, receive some events, then unsubscribe
    for _ in 0..5 {
        let bus_clone = Arc::clone(&bus);
        let received_clone = Arc::clone(&received_events);

        let handle = tokio::spawn(async move {
            for _ in 0..20 {
                let received = Arc::clone(&received_clone);
                let sub_id = bus_clone.subscribe(vec![], move |_| {
                    received.fetch_add(1, Ordering::SeqCst);
                });

                // Let some events flow
                tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

                // Unsubscribe - ignore error if already unsubscribed
                let _ = bus_clone.unsubscribe(sub_id);
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.expect("Task should complete without panic");
    }

    // Verify the bus is in consistent state
    assert!(
        bus.history_size() <= 1000,
        "History should still be bounded"
    );

    // Some events should have been received (exact count varies due to timing)
    let total_received = received_events.load(Ordering::SeqCst);
    assert!(
        total_received > 0,
        "At least some events should have been received: got {total_received}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_unsubscribe_during_publish() {
    // Test that unsubscribing during event delivery doesn't panic
    let bus = Arc::new(EventBus::new(100));

    // Create subscriptions that will be unsubscribed during event delivery
    let subscription_ids = Arc::new(std::sync::Mutex::new(Vec::new()));

    for _ in 0..10 {
        let bus_clone = Arc::clone(&bus);
        let ids_clone = Arc::clone(&subscription_ids);

        let sub_id = bus.subscribe(vec![], move |_event| {
            // Try to unsubscribe from within the handler (this tests re-entrancy)
            // This might fail which is expected behavior
            let ids = ids_clone.lock().unwrap();
            for id in ids.iter() {
                let _ = bus_clone.unsubscribe(*id);
            }
        });

        subscription_ids.lock().unwrap().push(sub_id);
    }

    // Publish events - should not panic even with handlers trying to unsubscribe
    for _ in 0..50 {
        let result = bus.publish(create_claim_submitted_event()).await;
        // Publication should succeed (handlers may fail but that's ok)
        assert!(
            result.is_ok(),
            "Publish should succeed even during concurrent unsubscribe"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_high_concurrency_subscribe_unsubscribe() {
    // Stress test with high concurrency
    let bus = Arc::new(EventBus::new(10000));
    let mut handles = vec![];

    // Spawn many concurrent subscribers
    for _ in 0..50 {
        let bus_clone = Arc::clone(&bus);
        let handle = tokio::spawn(async move {
            let mut ids = Vec::new();

            // Rapid subscribe
            for _ in 0..100 {
                let sub_id = bus_clone.subscribe(vec![], |_| {});
                ids.push(sub_id);
            }

            // Yield to allow interleaving
            tokio::task::yield_now().await;

            // Rapid unsubscribe
            for sub_id in ids {
                let _ = bus_clone.unsubscribe(sub_id);
            }
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        handle
            .await
            .expect("Should not panic under high concurrency");
    }

    // Final state should be consistent (0 or very few subscribers)
    // Some may remain due to timing, but it should be reasonable
    assert!(
        bus.subscriber_count() < 100,
        "Most subscriptions should be cleaned up, got {}",
        bus.subscriber_count()
    );
}

// ============================================================================
// Property-Based Tests
// ============================================================================

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// All truth values in events should be bounded [0, 1]
        #[test]
        fn prop_truth_values_bounded(
            initial in 0.0f64..1.0,
            old in 0.0f64..1.0,
            new in 0.0f64..1.0,
        ) {
            let event1 = EpiGraphEvent::ClaimSubmitted {
                claim_id: ClaimId::new(),
                agent_id: AgentId::new(),
                initial_truth: TruthValue::new(initial).unwrap(),
            };

            let event2 = EpiGraphEvent::TruthUpdated {
                claim_id: ClaimId::new(),
                old_truth: TruthValue::new(old).unwrap(),
                new_truth: TruthValue::new(new).unwrap(),
                source_claim_id: ClaimId::new(),
            };

            // Both should serialize successfully
            let json1 = serde_json::to_string(&event1);
            let json2 = serde_json::to_string(&event2);

            prop_assert!(json1.is_ok());
            prop_assert!(json2.is_ok());
        }

        /// Reputation changes should preserve values
        #[test]
        fn prop_reputation_preserved(
            old_rep in 0.0f64..1.0,
            new_rep in 0.0f64..1.0,
        ) {
            let event = EpiGraphEvent::ReputationChanged {
                agent_id: AgentId::new(),
                old_reputation: old_rep,
                new_reputation: new_rep,
            };

            let json = serde_json::to_string(&event).unwrap();
            let restored: EpiGraphEvent = serde_json::from_str(&json).unwrap();

            match restored {
                EpiGraphEvent::ReputationChanged {
                    old_reputation,
                    new_reputation,
                    ..
                } => {
                    prop_assert!((old_reputation - old_rep).abs() < 1e-10);
                    prop_assert!((new_reputation - new_rep).abs() < 1e-10);
                }
                _ => prop_assert!(false, "Should be ReputationChanged"),
            }
        }

        /// Event bus history size should never exceed max
        #[test]
        fn prop_history_bounded(
            max_size in 1usize..100,
            num_events in 0usize..500,
        ) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let bus = EventBus::new(max_size);

            runtime.block_on(async {
                for _ in 0..num_events {
                    bus.publish(create_claim_submitted_event()).await.unwrap();
                }
            });

            prop_assert!(bus.history_size() <= max_size);
        }
    }
}
