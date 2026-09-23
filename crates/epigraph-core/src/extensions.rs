//! Extension point traits for downstream and domain-specific capabilities.
//!
//! These traits are defined in [`epigraph_interfaces`] and re-exported here for
//! convenience. Prefer importing directly from `epigraph-interfaces` in new code.
//!
//! # PR-11
//!
//! Two of the original four extension points are gone. `EncryptionProvider` and
//! `OrchestrationBackend` were declared, defaulted into `AppState` and never
//! consulted anywhere in the workspace, so their legacy aliases
//! (`NoOpEncryption`, `NoOpOrchestration`) went with them.
//!
//! [`PolicyGate`]'s kernel default is now [`DenyAllPolicyGate`], not an
//! allow-all. `epigraph_interfaces::policy::AllowAllPolicyGate` is deliberately
//! **not** re-exported here: it exists only under
//! `#[cfg(any(test, feature = "insecure-allow-all"))]`, and a re-export would
//! give a downstream crate a second path to a name whose whole purpose is to be
//! hard to reach.

pub use epigraph_interfaces::{
    Action, Decision, DenyAllPolicyGate, InterfaceError, PolicyError, PolicyGate, Principal,
    ResourceKind, ResourceRef,
};
