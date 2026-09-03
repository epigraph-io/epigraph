//! Extension point traits for the `EpiGraph` kernel.
//!
//! This crate defines the interface boundaries that separate the open kernel
//! from private / downstream implementations:
//!
//! | Trait | Kernel default | Replacement |
//! |---|---|---|
//! | [`PolicyGate`] | [`DenyAllPolicyGate`] — **deny all** | `epigraph_authz::GroupPolicyGate` (installed by every `AppState` constructor) |
//! | [`LlmProvider`] | [`NoOpLlmProvider`] — error on use | Anthropic API, `OpenAI`, vLLM, private extensions, … |
//!
//! The kernel holds each as `Arc<dyn Trait>`. For [`LlmProvider`], multiple
//! concrete impls can be registered simultaneously via
//! [`register_llm_provider`]; the kernel-side [`default_llm_provider`] helper
//! walks the registry and returns the first provider whose `is_active()` is
//! `true`. Newer registrations outrank built-ins, so a private extension always
//! wins auto-detect when present.
//!
//! # Design principles
//!
//! - **Fail closed on the write side.** [`PolicyGate`]'s kernel default denies.
//!   The allow-all gate is `policy::AllowAllPolicyGate` and is compiled only
//!   under `#[cfg(any(test, feature = "insecure-allow-all"))]`.
//! - **Open by default on everything else.** The `LlmProvider` no-op is correct
//!   and complete for a deployment with no model configured.
//! - **No downstream code in the kernel.** The trait definitions live here.
//!
//! # PR-11 removed two of the original four
//!
//! `EncryptionProvider` and `OrchestrationBackend` are gone, with their no-ops
//! and their `AppState` fields. Both were declared, defaulted, stored and never
//! consulted: a workspace grep for `.encryption_provider` / `.orchestration_backend`
//! outside `epigraph-api/src/state.rs` returned nothing. They were the two
//! remaining halves of the enterprise seam whose other parts (`routes/mpc.rs`,
//! the `enterprise` cargo feature, `repos/embedding_share.rs`,
//! `repos/re_encryption_key.rs`, `epigraph-crypto/src/proxy_re.rs`) PR-01
//! already deleted. A dead trait in a struct field is indistinguishable, in a
//! grep or a threat model, from a live control.

pub mod llm;
pub mod policy;

pub use llm::{
    default_llm_provider, llm_provider_by_name, register_llm_provider, registered_llm_providers,
    LlmError, LlmProvider, NoOpLlmProvider,
};
pub use policy::{
    Action, Decision, DenyAllPolicyGate, PolicyError, PolicyGate, Principal, ResourceKind,
    ResourceRef,
};

/// A generic, opaque backend error for wrapping provider-specific failures.
///
/// Used as the `#[from]` source in each module's error enum so that downstream
/// implementations can wrap arbitrary internal errors.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InterfaceError(pub String);

impl InterfaceError {
    /// Wrap any display-able error as an [`InterfaceError`].
    pub fn new(msg: impl std::fmt::Display) -> Self {
        Self(msg.to_string())
    }
}
