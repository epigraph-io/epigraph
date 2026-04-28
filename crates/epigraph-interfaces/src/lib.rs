//! Extension point traits for the `EpiGraph` kernel.
//!
//! This crate defines the three interface boundaries that separate the open
//! kernel from enterprise features:
//!
//! | Trait | Kernel default | Enterprise implementation |
//! |---|---|---|
//! | [`EncryptionProvider`] | [`NoOpEncryptionProvider`] — pass-through | AES-256-GCM group-keyed subgraphs |
//! | [`PolicyGate`] | [`NoOpPolicyGate`] — allow all | RBAC/ABAC enforcement |
//! | [`OrchestrationBackend`] | [`NoOpOrchestrationBackend`] — silent drop | Durable task queue |
//!
//! The kernel holds each as `Arc<dyn Trait>` in `AppState`, initialised to
//! the no-op at startup. Enterprise deployments replace them at startup with
//! their own implementations before calling `create_router`.
//!
//! # Design principles
//!
//! - **Open by default.** The no-op implementations are correct and complete
//!   for single-tenant, unencrypted, open-kernel deployments.
//! - **No enterprise code in the kernel.** The trait definitions live here;
//!   the AES-GCM, RBAC, and queue implementations live in `epigraph-enterprise`.
//! - **`is_active()` skip flag.** Each no-op returns `false` so callers can
//!   skip expensive metadata writes that would be meaningless without a real
//!   backend.

pub mod auth;
pub mod encryption;
pub mod orchestration;
pub mod policy;

pub use auth::{AuthError, AuthProvider, ClientType, ProviderIdentity};
pub use encryption::{EncryptionError, EncryptionProvider, NoOpEncryptionProvider};
pub use orchestration::{
    NoOpOrchestrationBackend, OrchestrationBackend, OrchestrationError, TaskStatus,
};
pub use policy::{Action, NoOpPolicyGate, PolicyError, PolicyGate};

/// A generic, opaque backend error for wrapping provider-specific failures.
///
/// Used as the `#[from]` source in each module's error enum so that
/// enterprise implementations can wrap arbitrary internal errors.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InterfaceError(pub String);

impl InterfaceError {
    /// Wrap any display-able error as an [`InterfaceError`].
    pub fn new(msg: impl std::fmt::Display) -> Self {
        Self(msg.to_string())
    }
}
