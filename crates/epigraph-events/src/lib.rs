//! `EpiGraph` Event Bus: Pub/Sub Messaging for the Agentic Framework
//!
//! This crate provides an event-driven architecture for `EpiGraph`, enabling:
//! - Decoupled communication between system components
//! - Event history for replay and audit
//! - Subscription management with filtering by event type
//!
//! # Scope in the running system
//!
//! The bus is in-process and in-memory. Only `epigraph-api` depends on this
//! crate: its webhook dispatcher is the one wired subscriber, and three of
//! its handlers are the only publishers (`ClaimSubmitted` from the packet
//! submit and supersede routes, `ClaimChallenged` from the challenge route).
//! The MCP server, the CLI and every other API route publish nothing here,
//! history is lost on restart, and nothing replays it. The durable event log
//! is a different thing, the `events` table (`epigraph_db::EventRepository`).
//! `docs/deploy.md` ("What webhooks see", backlog 5902eed5) has the list.
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
