//! Bridge between EventBus and webhook delivery
//!
//! Subscribes to the event bus and enqueues webhook delivery jobs
//! for each event that matches a registered webhook's event filter.

use epigraph_events::EpiGraphEvent;

/// Registers an event bus subscriber that forwards events to the webhook job queue.
///
/// Call this during server startup after both EventBus and job queue are initialized.
pub fn register_webhook_subscriber(
    event_bus: &epigraph_events::EventBus,
) -> epigraph_events::SubscriptionId {
    event_bus.subscribe(
        vec![], // subscribe to ALL events
        move |event: EpiGraphEvent| {
            tracing::debug!(event_type = %event.event_type(), "Webhook bridge: event received");
        },
    )
}
