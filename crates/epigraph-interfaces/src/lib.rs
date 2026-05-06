//! Extension point traits for the `EpiGraph` kernel.
//!
//! This crate defines the four interface boundaries that separate the open
//! kernel from enterprise / private features:
//!
//! | Trait | Kernel default | Enterprise / private implementation |
//! |---|---|---|
//! | [`EncryptionProvider`] | [`NoOpEncryptionProvider`] — pass-through | AES-256-GCM group-keyed subgraphs |
//! | [`PolicyGate`] | [`NoOpPolicyGate`] — allow all | RBAC/ABAC enforcement |
//! | [`OrchestrationBackend`] | [`NoOpOrchestrationBackend`] — silent drop | Durable task queue |
//! | [`LlmProvider`] | [`NoOpLlmProvider`] — error on use | Anthropic API, Claude CLI subprocess, OpenAI, vLLM, … |
//!
//! The kernel holds each as `Arc<dyn Trait>`, initialised to the no-op at
//! startup. Enterprise / private deployments replace them at startup with
//! their own implementations.
//!
//! For [`LlmProvider`] specifically, multiple concrete impls can be
//! registered simultaneously via [`register_llm_provider`]; the kernel-side
//! [`default_llm_provider`] helper walks the registry and returns the first
//! provider whose `is_active()` is `true`. This lets a single binary support
//! both an Anthropic-API fallback (for builds without a Claude CLI binary
//! installed) and a private subprocess provider (registered ahead of the
//! built-ins so it wins).
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

pub mod encryption;
pub mod llm;
pub mod orchestration;
pub mod policy;

pub use encryption::{EncryptionError, EncryptionProvider, NoOpEncryptionProvider};
pub use llm::{
    default_llm_provider, llm_provider_by_name, register_llm_provider, registered_llm_providers,
    LlmError, LlmProvider, NoOpLlmProvider,
};
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
