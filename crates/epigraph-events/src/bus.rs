//! Event bus implementation for pub/sub messaging
//!
//! The `EventBus` provides:
//! - Publishing events to all interested subscribers
//! - Subscribing to specific event types
//! - Event history with bounded size
//! - Replay of historical events

use crate::errors::EventError;
use crate::events::{EpiGraphEvent, TimestampedEvent};
use crate::subscriber::{EventHandler, Subscriber, SubscriptionId};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

/// Event bus for pub/sub messaging in `EpiGraph`
///
/// The event bus allows components to publish events and subscribe to
/// events they're interested in. It maintains a bounded history of
/// events for replay purposes.
///
/// # Thread Safety
///
/// The `EventBus` is thread-safe and can be shared across threads using `Arc`.
pub struct EventBus {
    /// Subscribers indexed by their subscription ID
    subscribers: RwLock<HashMap<SubscriptionId, Subscriber>>,
    /// Event history for replay (bounded circular buffer)
    history: RwLock<VecDeque<TimestampedEvent>>,
    /// Maximum number of events to keep in history
    max_history: usize,
}

impl EventBus {
    /// Create a new event bus with the specified history size
    ///
    /// # Arguments
    /// * `max_history` - Maximum number of events to keep in history
    #[must_use]
    pub fn new(max_history: usize) -> Self {
        Self {
            subscribers: RwLock::new(HashMap::new()),
            history: RwLock::new(VecDeque::with_capacity(max_history)),
            max_history,
        }
    }

    /// Publish an event to all interested subscribers
    ///
    /// The event is added to history and all subscribers interested in
    /// this event type are notified.
    ///
    /// # Errors
    /// Returns an error if the internal lock cannot be acquired
    #[allow(clippy::unused_async)]
    pub async fn publish(&self, event: EpiGraphEvent) -> Result<(), EventError> {
        let event_type = event.event_type();
        let timestamped = TimestampedEvent::new(event.clone());

        // Add to history
        {
            let mut history = self.history.write().map_err(|e| EventError::LockError {
                reason: format!("Failed to acquire history write lock: {e}"),
            })?;

            // Enforce max history size (FIFO eviction)
            while history.len() >= self.max_history {
                history.pop_front();
            }

            history.push_back(timestamped);
        }

        // Notify subscribers - collect handlers first to avoid holding lock during notification
        let handlers: Vec<EventHandler> = {
            let subscribers = self.subscribers.read().map_err(|e| EventError::LockError {
                reason: format!("Failed to acquire subscribers read lock: {e}"),
            })?;

            subscribers
                .values()
                .filter(|sub| sub.is_interested_in(&event_type))
                .filter_map(|sub| sub.handler.clone())
                .collect()
        };

        // Call handlers outside the lock
        for handler in handlers {
            handler(event.clone());
        }

        Ok(())
    }

    /// Subscribe to events with a handler function
    ///
    /// # Arguments
    /// * `event_types` - Event types to subscribe to (empty = all events)
    /// * `handler` - Function to call when matching events occur
    ///
    /// # Returns
    /// A unique subscription ID that can be used to unsubscribe
    pub fn subscribe<F>(&self, event_types: Vec<String>, handler: F) -> SubscriptionId
    where
        F: Fn(EpiGraphEvent) + Send + Sync + 'static,
    {
        let subscriber = Subscriber::with_handler(event_types, handler);
        let sub_id = subscriber.id;

        // Add subscriber to the map
        if let Ok(mut subscribers) = self.subscribers.write() {
            subscribers.insert(sub_id, subscriber);
        }

        sub_id
    }

    /// Unsubscribe from events
    ///
    /// # Arguments
    /// * `subscription_id` - The subscription ID returned from `subscribe`
    ///
    /// # Errors
    /// Returns an error if the subscription is not found
    pub fn unsubscribe(&self, subscription_id: SubscriptionId) -> Result<(), EventError> {
        let mut subscribers = self
            .subscribers
            .write()
            .map_err(|e| EventError::LockError {
                reason: format!("Failed to acquire subscribers write lock: {e}"),
            })?;

        if subscribers.remove(&subscription_id).is_some() {
            Ok(())
        } else {
            Err(EventError::SubscriptionNotFound {
                subscription_id: subscription_id.as_uuid(),
            })
        }
    }

    /// Get the current number of subscribers
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Get the current history size
    #[must_use]
    pub fn history_size(&self) -> usize {
        self.history.read().map(|h| h.len()).unwrap_or(0)
    }

    /// Get the maximum history size
    #[must_use]
    pub const fn max_history(&self) -> usize {
        self.max_history
    }

    /// Replay events from history starting from a timestamp
    ///
    /// # Arguments
    /// * `from` - Replay events that occurred strictly after this timestamp
    /// * `handler` - Function to call for each replayed event
    ///
    /// # Returns
    /// The number of events replayed
    ///
    /// # Errors
    /// Returns an error if the internal lock cannot be acquired
    #[allow(clippy::significant_drop_tightening)]
    pub fn replay<F>(&self, from: DateTime<Utc>, handler: F) -> Result<usize, EventError>
    where
        F: Fn(EpiGraphEvent),
    {
        let history = self.history.read().map_err(|e| EventError::LockError {
            reason: format!("Failed to acquire history read lock: {e}"),
        })?;

        let mut count = 0;
        for timestamped in history.iter() {
            // Replay events strictly after the given timestamp
            if timestamped.timestamp > from {
                handler(timestamped.event.clone());
                count += 1;
            }
        }

        Ok(count)
    }

    /// Get a copy of the event history
    ///
    /// # Errors
    /// Returns an error if the internal lock cannot be acquired
    pub fn get_history(&self) -> Result<Vec<TimestampedEvent>, EventError> {
        let history = self.history.read().map_err(|e| EventError::LockError {
            reason: format!("Failed to acquire history read lock: {e}"),
        })?;

        Ok(history.iter().cloned().collect())
    }

    /// Clear all event history
    ///
    /// # Errors
    /// Returns an error if the internal lock cannot be acquired
    #[allow(clippy::significant_drop_tightening)]
    pub fn clear_history(&self) -> Result<(), EventError> {
        let mut history = self.history.write().map_err(|e| EventError::LockError {
            reason: format!("Failed to acquire history write lock: {e}"),
        })?;

        history.clear();
        Ok(())
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1000) // Default history size of 1000 events
    }
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("max_history", &self.max_history)
            .field(
                "subscriber_count",
                &self.subscribers.read().map(|s| s.len()).unwrap_or(0),
            )
            .field(
                "history_size",
                &self.history.read().map(|h| h.len()).unwrap_or(0),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EpiGraphEvent;
    use chrono::Duration;
    use epigraph_core::domain::AgentRole;
    use epigraph_core::{AgentId, ClaimId, TruthValue};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Helper: create a minimal `ClaimSubmitted` event for testing
    fn make_claim_submitted() -> EpiGraphEvent {
        EpiGraphEvent::ClaimSubmitted {
            claim_id: ClaimId::new(),
            agent_id: AgentId::new(),
            initial_truth: TruthValue::new(0.5).unwrap(),
        }
    }

    /// Helper: create a `TruthUpdated` event
    fn make_truth_updated() -> EpiGraphEvent {
        EpiGraphEvent::TruthUpdated {
            claim_id: ClaimId::new(),
            old_truth: TruthValue::new(0.3).unwrap(),
            new_truth: TruthValue::new(0.7).unwrap(),
            source_claim_id: ClaimId::new(),
        }
    }

    /// Helper: create an `AgentCreated` event
    fn make_agent_created() -> EpiGraphEvent {
        EpiGraphEvent::AgentCreated {
            agent_id: AgentId::new(),
            role: AgentRole::Validator,
        }
    }

    // ========================================================================
    // Basic Functionality
    // ========================================================================

    #[tokio::test]
    async fn test_publish_event_succeeds() {
        // Publishing an event to a bus with no subscribers should succeed
        // without errors -- the event is still stored in history.
        let bus = EventBus::new(100);
        let result = bus.publish(make_claim_submitted()).await;
        assert!(result.is_ok(), "Publish should succeed with no subscribers");
        assert_eq!(bus.history_size(), 1, "Event should be recorded in history");
    }

    #[tokio::test]
    async fn test_subscribe_and_receive() {
        // A subscriber should receive the event it is subscribed to.
        let bus = EventBus::new(100);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        bus.subscribe(vec!["ClaimSubmitted".to_string()], move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        bus.publish(make_claim_submitted())
            .await
            .expect("Publish should succeed");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Subscriber handler should be invoked exactly once"
        );
    }

    #[tokio::test]
    async fn test_subscribe_filter_by_type() {
        // A subscriber for "TruthUpdated" should NOT receive a "ClaimSubmitted" event.
        let bus = EventBus::new(100);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        bus.subscribe(vec!["TruthUpdated".to_string()], move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        // Publish a ClaimSubmitted event (not TruthUpdated)
        bus.publish(make_claim_submitted())
            .await
            .expect("Publish should succeed");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "Subscriber should NOT receive non-matching event type"
        );
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        // All subscribers interested in the same event type should receive it.
        let bus = EventBus::new(100);
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..5 {
            let c = Arc::clone(&counter);
            bus.subscribe(vec!["ClaimSubmitted".to_string()], move |_| {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }

        bus.publish(make_claim_submitted()).await.unwrap();

        assert_eq!(
            counter.load(Ordering::SeqCst),
            5,
            "All 5 subscribers should receive the event"
        );
    }

    #[tokio::test]
    async fn test_unsubscribe() {
        // After unsubscribing, the handler must not be invoked on subsequent publishes.
        let bus = EventBus::new(100);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let sub_id = bus.subscribe(vec![], move |_| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        // First publish -- should be received
        bus.publish(make_claim_submitted()).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Unsubscribe
        bus.unsubscribe(sub_id).expect("Unsubscribe should succeed");

        // Second publish -- should NOT be received
        bus.publish(make_claim_submitted()).await.unwrap();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Handler must not be called after unsubscribe"
        );
    }

    // ========================================================================
    // Event History
    // ========================================================================

    #[tokio::test]
    async fn test_event_history_stored() {
        // Published events should appear in history.
        let bus = EventBus::new(100);

        bus.publish(make_claim_submitted()).await.unwrap();
        bus.publish(make_truth_updated()).await.unwrap();
        bus.publish(make_agent_created()).await.unwrap();

        let history = bus.get_history().expect("Should retrieve history");
        assert_eq!(history.len(), 3, "History should contain all 3 events");
    }

    #[tokio::test]
    async fn test_event_history_order() {
        // Events should be stored in chronological order (oldest first).
        let bus = EventBus::new(100);

        bus.publish(make_claim_submitted()).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        bus.publish(make_truth_updated()).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        bus.publish(make_agent_created()).await.unwrap();

        let history = bus.get_history().unwrap();
        for i in 1..history.len() {
            assert!(
                history[i].timestamp >= history[i - 1].timestamp,
                "History event {} should have timestamp >= event {}",
                i,
                i - 1,
            );
        }

        // Verify correct event type ordering
        assert_eq!(history[0].event.event_type(), "ClaimSubmitted");
        assert_eq!(history[1].event.event_type(), "TruthUpdated");
        assert_eq!(history[2].event.event_type(), "AgentCreated");
    }

    #[tokio::test]
    async fn test_clear_history() {
        let bus = EventBus::new(100);

        for _ in 0..5 {
            bus.publish(make_claim_submitted()).await.unwrap();
        }
        assert_eq!(bus.history_size(), 5);

        bus.clear_history().expect("Clear should succeed");
        assert_eq!(bus.history_size(), 0, "History should be empty after clear");

        let history = bus.get_history().unwrap();
        assert!(history.is_empty(), "get_history should return empty vec");
    }

    #[tokio::test]
    async fn test_replay_events() {
        // Replay should invoke the handler for each event after the given timestamp.
        let bus = EventBus::new(100);

        // Publish 2 events before the checkpoint
        bus.publish(make_claim_submitted()).await.unwrap();
        bus.publish(make_claim_submitted()).await.unwrap();

        let checkpoint = Utc::now();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Publish 3 events after the checkpoint
        bus.publish(make_truth_updated()).await.unwrap();
        bus.publish(make_truth_updated()).await.unwrap();
        bus.publish(make_truth_updated()).await.unwrap();

        let replay_counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&replay_counter);

        let replayed = bus
            .replay(checkpoint, move |_event| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("Replay should succeed");

        assert_eq!(replayed, 3, "Replay should report 3 events");
        assert_eq!(
            replay_counter.load(Ordering::SeqCst),
            3,
            "Handler should be called 3 times"
        );
    }

    // ========================================================================
    // Error Handling
    // ========================================================================

    #[tokio::test]
    async fn test_publish_to_empty_bus() {
        // Publishing to a bus with zero subscribers should succeed without panic.
        let bus = EventBus::new(50);
        assert_eq!(bus.subscriber_count(), 0);

        let result = bus.publish(make_claim_submitted()).await;
        assert!(
            result.is_ok(),
            "Publishing to empty bus should succeed gracefully"
        );
        assert_eq!(
            bus.history_size(),
            1,
            "Event should still be stored in history"
        );
    }

    #[tokio::test]
    async fn test_unsubscribe_unknown_id_returns_error() {
        let bus = EventBus::new(100);
        let fake_id = SubscriptionId::new();
        let result = bus.unsubscribe(fake_id);
        assert!(
            result.is_err(),
            "Unsubscribing unknown ID should return error"
        );
        match result.unwrap_err() {
            EventError::SubscriptionNotFound { subscription_id } => {
                assert_eq!(subscription_id, fake_id.as_uuid());
            }
            other => panic!("Expected SubscriptionNotFound, got: {other:?}"),
        }
    }

    // ========================================================================
    // Thread Safety
    // ========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_publish() {
        // Multiple threads publishing simultaneously should not corrupt state.
        let bus = Arc::new(EventBus::new(500));
        let mut handles = vec![];

        for _ in 0..10 {
            let bus_clone = Arc::clone(&bus);
            handles.push(tokio::spawn(async move {
                for _ in 0..50 {
                    bus_clone
                        .publish(make_claim_submitted())
                        .await
                        .expect("Concurrent publish should succeed");
                }
            }));
        }

        for handle in handles {
            handle.await.expect("Task should not panic");
        }

        // 10 tasks * 50 events = 500, history max is 500
        assert!(
            bus.history_size() <= 500,
            "History should respect max bound"
        );
        // All history entries should be valid
        let history = bus.get_history().unwrap();
        for ts_event in &history {
            assert!(
                matches!(ts_event.event, EpiGraphEvent::ClaimSubmitted { .. }),
                "All stored events should be valid ClaimSubmitted"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_subscribe_and_publish() {
        // Subscribing and publishing from different threads should not deadlock or panic.
        let bus = Arc::new(EventBus::new(1000));
        let received = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        // Spawn publishers
        for _ in 0..4 {
            let bus_clone = Arc::clone(&bus);
            handles.push(tokio::spawn(async move {
                for _ in 0..50 {
                    bus_clone.publish(make_claim_submitted()).await.unwrap();
                    tokio::task::yield_now().await;
                }
            }));
        }

        // Spawn subscribe/unsubscribe tasks
        for _ in 0..4 {
            let bus_clone = Arc::clone(&bus);
            let recv_clone = Arc::clone(&received);
            handles.push(tokio::spawn(async move {
                for _ in 0..10 {
                    let r = Arc::clone(&recv_clone);
                    let sub_id = bus_clone.subscribe(vec![], move |_| {
                        r.fetch_add(1, Ordering::SeqCst);
                    });
                    tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
                    let _ = bus_clone.unsubscribe(sub_id);
                }
            }));
        }

        for handle in handles {
            handle.await.expect("No task should panic");
        }

        // Bus should be in a consistent state
        assert!(bus.history_size() <= 1000, "History should remain bounded");
    }

    // ========================================================================
    // Default / Debug
    // ========================================================================

    #[test]
    fn test_event_bus_default() {
        let bus = EventBus::default();
        assert_eq!(
            bus.max_history(),
            1000,
            "Default max_history should be 1000"
        );
        assert_eq!(bus.subscriber_count(), 0);
        assert_eq!(bus.history_size(), 0);
    }

    #[test]
    fn test_event_bus_debug() {
        let bus = EventBus::new(42);
        let debug = format!("{bus:?}");
        assert!(
            debug.contains("EventBus"),
            "Debug output should contain 'EventBus'"
        );
        assert!(
            debug.contains("42"),
            "Debug output should contain max_history value"
        );
    }

    // ========================================================================
    // History Eviction
    // ========================================================================

    #[tokio::test]
    async fn test_history_evicts_oldest_when_full() {
        // When max_history is exceeded, the oldest events should be evicted.
        let bus = EventBus::new(3);

        let id1 = ClaimId::new();
        let id2 = ClaimId::new();
        let id3 = ClaimId::new();
        let id4 = ClaimId::new();

        for cid in [id1, id2, id3, id4] {
            let event = EpiGraphEvent::ClaimSubmitted {
                claim_id: cid,
                agent_id: AgentId::new(),
                initial_truth: TruthValue::new(0.5).unwrap(),
            };
            bus.publish(event).await.unwrap();
        }

        assert_eq!(bus.history_size(), 3, "History should be capped at 3");

        let history = bus.get_history().unwrap();
        // The first event (id1) should have been evicted
        let stored_ids: Vec<ClaimId> = history
            .iter()
            .map(|ts| match &ts.event {
                EpiGraphEvent::ClaimSubmitted { claim_id, .. } => *claim_id,
                _ => panic!("Unexpected event type"),
            })
            .collect();

        assert_eq!(
            stored_ids,
            vec![id2, id3, id4],
            "Oldest event should be evicted"
        );
    }

    // ========================================================================
    // Subscribe with empty filter (wildcard)
    // ========================================================================

    #[tokio::test]
    async fn test_empty_filter_receives_all_event_types() {
        // A subscriber with an empty event_types vec should receive all events.
        let bus = EventBus::new(100);
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        bus.subscribe(vec![], move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        });

        bus.publish(make_claim_submitted()).await.unwrap();
        bus.publish(make_truth_updated()).await.unwrap();
        bus.publish(make_agent_created()).await.unwrap();

        assert_eq!(
            counter.load(Ordering::SeqCst),
            3,
            "Wildcard subscriber should receive all event types"
        );
    }

    // ========================================================================
    // Replay edge cases
    // ========================================================================

    #[tokio::test]
    async fn test_replay_empty_history() {
        let bus = EventBus::new(100);
        let from = Utc::now() - Duration::hours(1);
        let replayed = bus.replay(from, |_| {}).unwrap();
        assert_eq!(replayed, 0, "Replay on empty history should return 0");
    }

    #[tokio::test]
    async fn test_replay_future_timestamp_returns_nothing() {
        let bus = EventBus::new(100);
        bus.publish(make_claim_submitted()).await.unwrap();

        let future = Utc::now() + Duration::hours(1);
        let replayed = bus.replay(future, |_| {}).unwrap();
        assert_eq!(replayed, 0, "Replay from future timestamp should return 0");
    }
}
