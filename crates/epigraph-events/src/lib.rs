//! `EpiGraph` Event Bus: Pub/Sub Messaging for the Agentic Framework
//!
//! This crate provides an event-driven architecture for `EpiGraph`, enabling:
//! - Decoupled communication between system components
//! - Event history for replay and audit
//! - Subscription management with filtering by event type
//!
//! # Core Types
//!
//! - [`EpiGraphEvent`]: Enum of all system events
//! - [`EventBus`]: Pub/sub message broker with history
//! - [`Subscriber`]: Event handler with filtering
//! - [`SubscriptionId`]: Unique subscription identifier
//!
//! # Example
//!
//! ```ignore
//! use epigraph_events::{EventBus, EpiGraphEvent};
//!
//! let bus = EventBus::new(1000);
//! let sub_id = bus.subscribe(vec!["ClaimSubmitted"], |event| {
//!     println!("Got event: {:?}", event);
//! });
//!
//! bus.publish(EpiGraphEvent::ClaimSubmitted { ... }).await;
//! ```

pub mod bus;
pub mod errors;
pub mod events;
pub mod subscriber;

// Re-export primary types at crate root
pub use bus::EventBus;
pub use epigraph_core::domain::{AgentRole, SuspensionReason, WorkflowState};
pub use errors::EventError;
pub use events::{EpiGraphEvent, TimestampedEvent, VerificationStatus};
pub use subscriber::{Subscriber, SubscriptionId};
