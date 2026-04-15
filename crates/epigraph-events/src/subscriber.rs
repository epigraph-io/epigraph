//! Subscriber management for the event bus
//!
//! Subscribers register interest in specific event types and receive
//! notifications when matching events are published.

use crate::events::EpiGraphEvent;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Unique identifier for a subscription
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubscriptionId(Uuid);

impl SubscriptionId {
    /// Create a new random `SubscriptionId`
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for SubscriptionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "subscription:{}", self.0)
    }
}

/// Type alias for the event handler function
pub type EventHandler = Arc<dyn Fn(EpiGraphEvent) + Send + Sync + 'static>;

/// A subscriber to the event bus
///
/// Subscribers specify which event types they're interested in and provide
/// a handler function to process matching events.
pub struct Subscriber {
    /// Unique identifier for this subscription
    pub id: SubscriptionId,
    /// Event types this subscriber is interested in (empty = all events)
    pub event_types: Vec<String>,
    /// Channel sender for async notification
    pub sender: Option<mpsc::Sender<EpiGraphEvent>>,
    /// Synchronous handler function
    pub handler: Option<EventHandler>,
}

impl Subscriber {
    /// Create a new subscriber with a channel
    #[must_use]
    pub fn with_channel(event_types: Vec<String>, sender: mpsc::Sender<EpiGraphEvent>) -> Self {
        Self {
            id: SubscriptionId::new(),
            event_types,
            sender: Some(sender),
            handler: None,
        }
    }

    /// Create a new subscriber with a handler function
    #[must_use]
    pub fn with_handler<F>(event_types: Vec<String>, handler: F) -> Self
    where
        F: Fn(EpiGraphEvent) + Send + Sync + 'static,
    {
        Self {
            id: SubscriptionId::new(),
            event_types,
            sender: None,
            handler: Some(Arc::new(handler)),
        }
    }

    /// Check if this subscriber is interested in the given event type
    #[must_use]
    pub fn is_interested_in(&self, event_type: &str) -> bool {
        // Empty event_types means subscribe to all events
        if self.event_types.is_empty() {
            return true;
        }
        // Otherwise, check if the event type is in the list
        self.event_types.iter().any(|t| t == event_type)
    }

    /// Notify this subscriber of an event
    ///
    /// # Errors
    /// Returns an error if the notification channel is closed
    pub async fn notify(&self, event: EpiGraphEvent) -> Result<(), crate::EventError> {
        // Call the synchronous handler if present
        if let Some(handler) = &self.handler {
            handler(event.clone());
        }

        // Send to the async channel if present
        if let Some(sender) = &self.sender {
            // We ignore send errors since the receiver may have been dropped
            let _ = sender.send(event).await;
        }

        Ok(())
    }
}

impl fmt::Debug for Subscriber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscriber")
            .field("id", &self.id)
            .field("event_types", &self.event_types)
            .field("has_sender", &self.sender.is_some())
            .field("has_handler", &self.handler.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_core::{AgentId, ClaimId, TruthValue};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn make_test_event() -> EpiGraphEvent {
        EpiGraphEvent::ClaimSubmitted {
            claim_id: ClaimId::new(),
            agent_id: AgentId::new(),
            initial_truth: TruthValue::new(0.5).unwrap(),
        }
    }

    // ========================================================================
    // SubscriptionId
    // ========================================================================

    #[test]
    fn test_subscription_id_unique() {
        let a = SubscriptionId::new();
        let b = SubscriptionId::new();
        assert_ne!(a, b, "SubscriptionIds should be unique");
    }

    #[test]
    fn test_subscription_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let id = SubscriptionId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
    }

    #[test]
    fn test_subscription_id_display() {
        let id = SubscriptionId::new();
        let display = format!("{id}");
        assert!(
            display.starts_with("subscription:"),
            "Display should start with 'subscription:'"
        );
    }

    #[test]
    fn test_subscription_id_default() {
        let a = SubscriptionId::default();
        let b = SubscriptionId::default();
        assert_ne!(a, b, "Default SubscriptionIds should be unique");
    }

    #[test]
    fn test_subscription_id_hash_equality() {
        use std::collections::HashSet;

        let uuid = Uuid::new_v4();
        let a = SubscriptionId::from_uuid(uuid);
        let b = SubscriptionId::from_uuid(uuid);
        assert_eq!(a, b, "Same UUID should produce equal SubscriptionIds");

        // Verify they hash the same (usable in HashMap)
        let mut set = HashSet::new();
        set.insert(a);
        assert!(
            set.contains(&b),
            "Equal SubscriptionIds should hash equally"
        );
    }

    // ========================================================================
    // Subscriber interest filtering
    // ========================================================================

    #[test]
    fn test_subscriber_interested_in_matching_type() {
        let sub = Subscriber::with_handler(vec!["ClaimSubmitted".to_string()], |_| {});
        assert!(
            sub.is_interested_in("ClaimSubmitted"),
            "Should be interested in matching type"
        );
    }

    #[test]
    fn test_subscriber_not_interested_in_non_matching_type() {
        let sub = Subscriber::with_handler(vec!["ClaimSubmitted".to_string()], |_| {});
        assert!(
            !sub.is_interested_in("TruthUpdated"),
            "Should NOT be interested in non-matching type"
        );
    }

    #[test]
    fn test_subscriber_empty_filter_matches_all() {
        // Empty event_types means "subscribe to everything"
        let sub = Subscriber::with_handler(vec![], |_| {});
        assert!(sub.is_interested_in("ClaimSubmitted"));
        assert!(sub.is_interested_in("TruthUpdated"));
        assert!(sub.is_interested_in("AnythingElse"));
    }

    #[test]
    fn test_subscriber_multiple_types_filter() {
        let sub = Subscriber::with_handler(
            vec!["ClaimSubmitted".to_string(), "TruthUpdated".to_string()],
            |_| {},
        );
        assert!(sub.is_interested_in("ClaimSubmitted"));
        assert!(sub.is_interested_in("TruthUpdated"));
        assert!(!sub.is_interested_in("ReputationChanged"));
    }

    // ========================================================================
    // Subscriber with handler
    // ========================================================================

    #[test]
    fn test_subscriber_with_handler_has_handler() {
        let sub = Subscriber::with_handler(vec![], |_| {});
        assert!(sub.handler.is_some(), "with_handler should set handler");
        assert!(sub.sender.is_none(), "with_handler should NOT set sender");
    }

    #[test]
    fn test_subscriber_with_handler_invokes_handler() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let sub = Subscriber::with_handler(vec![], move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        });

        // Invoke handler directly
        if let Some(handler) = &sub.handler {
            handler(make_test_event());
        }

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Handler should be invoked"
        );
    }

    // ========================================================================
    // Subscriber with channel
    // ========================================================================

    #[test]
    fn test_subscriber_with_channel_has_sender() {
        let (tx, _rx) = mpsc::channel(10);
        let sub = Subscriber::with_channel(vec!["ClaimSubmitted".to_string()], tx);
        assert!(sub.sender.is_some(), "with_channel should set sender");
        assert!(sub.handler.is_none(), "with_channel should NOT set handler");
    }

    // ========================================================================
    // Subscriber notify
    // ========================================================================

    #[tokio::test]
    async fn test_subscriber_notify_calls_handler() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let sub = Subscriber::with_handler(vec![], move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        });

        sub.notify(make_test_event())
            .await
            .expect("Notify should succeed");

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_subscriber_notify_sends_to_channel() {
        let (tx, mut rx) = mpsc::channel(10);
        let sub = Subscriber::with_channel(vec![], tx);

        sub.notify(make_test_event())
            .await
            .expect("Notify should succeed");

        let received = rx.recv().await;
        assert!(received.is_some(), "Should receive event on channel");
        assert!(
            matches!(received.unwrap(), EpiGraphEvent::ClaimSubmitted { .. }),
            "Received event should be ClaimSubmitted"
        );
    }

    // ========================================================================
    // Debug implementation
    // ========================================================================

    #[test]
    fn test_subscriber_debug() {
        let sub = Subscriber::with_handler(vec!["ClaimSubmitted".to_string()], |_| {});
        let debug = format!("{sub:?}");
        assert!(
            debug.contains("Subscriber"),
            "Debug should contain 'Subscriber'"
        );
        assert!(
            debug.contains("ClaimSubmitted"),
            "Debug should contain event type"
        );
        assert!(
            debug.contains("has_handler: true"),
            "Debug should show has_handler"
        );
    }
}
