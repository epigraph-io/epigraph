//! Error types for the event bus system

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur in the event bus system
#[derive(Error, Debug)]
pub enum EventError {
    /// Subscription not found
    #[error("Subscription {subscription_id} not found")]
    SubscriptionNotFound { subscription_id: Uuid },

    /// Event type not recognized
    #[error("Unknown event type: {event_type}")]
    UnknownEventType { event_type: String },

    /// History replay failed
    #[error("Failed to replay events: {reason}")]
    ReplayFailed { reason: String },

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Lock acquisition failed (for concurrent access)
    #[error("Failed to acquire lock: {reason}")]
    LockError { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_not_found_display() {
        let uuid = Uuid::new_v4();
        let err = EventError::SubscriptionNotFound {
            subscription_id: uuid,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains(&uuid.to_string()),
            "Error message should contain the subscription UUID"
        );
        assert!(
            msg.contains("not found"),
            "Error message should indicate 'not found'"
        );
    }

    #[test]
    fn test_unknown_event_type_display() {
        let err = EventError::UnknownEventType {
            event_type: "BogusEvent".to_string(),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("BogusEvent"),
            "Error message should contain the unknown event type"
        );
    }

    #[test]
    fn test_replay_failed_display() {
        let err = EventError::ReplayFailed {
            reason: "history corrupted".to_string(),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("history corrupted"),
            "Error message should contain the reason"
        );
    }

    #[test]
    fn test_lock_error_display() {
        let err = EventError::LockError {
            reason: "poisoned".to_string(),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("poisoned"),
            "Error message should contain the lock error reason"
        );
    }

    #[test]
    fn test_serialization_error_from_serde() {
        // Trigger a real serde_json error and convert it
        let bad_json = "not valid json {{{";
        let serde_err = serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();
        let event_err: EventError = serde_err.into();

        assert!(
            matches!(event_err, EventError::SerializationError(_)),
            "serde_json::Error should convert to SerializationError"
        );

        let msg = format!("{event_err}");
        assert!(
            msg.contains("Serialization error"),
            "Display should indicate serialization error"
        );
    }

    #[test]
    fn test_event_error_is_debug() {
        // Verify all variants implement Debug (compile-time + runtime check)
        let err = EventError::LockError {
            reason: "test".to_string(),
        };
        let debug = format!("{err:?}");
        assert!(
            debug.contains("LockError"),
            "Debug should contain variant name"
        );
    }
}
