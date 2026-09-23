//! **DEAD CODE. This is not the webhook fan-out path, and it never was.**
//!
//! # What its doc comment used to claim
//!
//! > Subscribes to the event bus and enqueues webhook delivery jobs for each
//! > event that matches a registered webhook's event filter.
//!
//! None of that is true. [`register_webhook_subscriber`]'s entire body is a
//! `tracing::debug!`. It reads no webhook store, matches no event filter,
//! enqueues no job, and delivers nothing. It also has **no caller anywhere in
//! `crates/`** — only the `pub mod webhook_bridge;` declaration in `lib.rs`.
//!
//! Corrected rather than left standing (PR-10). A doc comment that describes
//! behaviour its function does not have is itself the defect — and this one is
//! actively dangerous on this particular surface: a reader auditing "is the
//! webhook fan-out tenancy-filtered?" who found a *second* webhook-named
//! all-events subscriber claiming to do the filtering could reasonably conclude
//! the filtering lived here.
//!
//! # Where the real fan-out is
//!
//! `crates/epigraph-api/src/routes/webhooks.rs` —
//! `start_webhook_dispatcher` (wired in `bin/server.rs`) → `deliver_event` →
//! `retain_visible_subscriptions`. That is the path PR-10 made tenancy-aware.
//!
//! # Why it is not deleted here
//!
//! Deleting it is right and is not PR-10's decision to make in passing: it is a
//! `pub` item in a `pub mod`, so removal is an API change to a library crate,
//! and PR-10's scope is the webhook tenancy filter. It is inert — no caller, no
//! side effect beyond a debug log — so leaving it correctly described costs
//! nothing, while removing it silently in a security PR hides a deletion inside
//! a diff nobody is reading for deletions.

use epigraph_events::EpiGraphEvent;

/// Registers an event-bus subscriber that **logs** each event at debug level.
///
/// Despite the name, this performs no webhook delivery, consults no
/// subscription store, and applies no tenancy filter — see the module doc. It
/// has no caller. Do not wire it up expecting fan-out behaviour; wire
/// `routes::webhooks::start_webhook_dispatcher` instead, which is what
/// `bin/server.rs` does.
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
