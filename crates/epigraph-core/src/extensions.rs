//! Extension point traits for enterprise and domain-specific capabilities.
//!
//! These traits are defined in [`epigraph_interfaces`] and re-exported here for
//! convenience. Prefer importing directly from `epigraph-interfaces` in new code.
//!
//! # Migration note
//!
//! The legacy no-op types (`NoOpEncryption`, `NoOpOrchestration`) are type aliases
//! pointing to the canonical names in `epigraph-interfaces`. Use the canonical names
//! (`NoOpEncryptionProvider`, `NoOpOrchestrationBackend`) in new code.

pub use epigraph_interfaces::{
    Action, EncryptionError, EncryptionProvider, InterfaceError, NoOpEncryptionProvider,
    NoOpOrchestrationBackend, NoOpPolicyGate, OrchestrationBackend, OrchestrationError,
    PolicyError, PolicyGate, TaskStatus,
};

/// Legacy alias — prefer [`NoOpEncryptionProvider`].
pub type NoOpEncryption = NoOpEncryptionProvider;

/// Legacy alias — prefer [`NoOpOrchestrationBackend`].
pub type NoOpOrchestration = NoOpOrchestrationBackend;
