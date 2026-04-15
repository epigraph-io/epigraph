//! `PolicyGate` — pluggable access control for the `EpiGraph` kernel.
//!
//! The kernel ships with [`NoOpPolicyGate`], which allows every action. The
//! enterprise layer supplies an RBAC/ABAC implementation that enforces role
//! assignments, attribute conditions, and group membership rules.
//!
//! # Extension point contract
//!
//! - [`PolicyGate::check`] must be called before any write that modifies
//!   claims, edges, or evidence on behalf of an agent.
//! - A `false` return means the action is **denied**; the caller should
//!   return HTTP 403.
//! - The no-op always returns `Ok(true)` — the kernel is single-tenant and
//!   trusts OAuth-authenticated agents unconditionally.
//! - Enterprise implementations may be stateful (cache role lookups) or
//!   stateless (evaluate attribute rules inline). The trait is async to
//!   support both.
//!
//! # Note on naming
//!
//! This gate is distinct from `epigraph-policy`, which manages *epistemic*
//! claim challenges (dispute resolution). `PolicyGate` governs *access
//! control* — who may do what.

use async_trait::async_trait;
use uuid::Uuid;

use crate::InterfaceError;

/// Errors returned by [`PolicyGate`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The agent's role or attributes could not be resolved.
    #[error("policy evaluation failed for agent {agent_id}: {reason}")]
    EvaluationFailed { agent_id: Uuid, reason: String },
    /// Any other provider-specific error.
    #[error("policy gate error: {0}")]
    Provider(#[from] InterfaceError),
}

/// An access-control action the caller wants to perform.
///
/// Passed to [`PolicyGate::check`]. Enterprise implementations can match on
/// this to implement fine-grained rules without a string-parsing step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create a new entity (claim, evidence, edge, …).
    Create,
    /// Read / query an entity.
    Read,
    /// Update an existing entity.
    Update,
    /// Delete an entity.
    Delete,
    /// Arbitrary named action for enterprise extensibility.
    Custom(String),
}

/// Pluggable access control gate.
///
/// The kernel holds an `Arc<dyn PolicyGate>` in [`AppState`]. At startup the
/// kernel installs [`NoOpPolicyGate`]; the enterprise layer replaces it with
/// an RBAC/ABAC implementation.
///
/// [`AppState`]: epigraph_api::state::AppState
#[async_trait]
pub trait PolicyGate: Send + Sync + 'static {
    /// Check whether `agent_id` may perform `action` on `resource_id`.
    ///
    /// - Returns `Ok(true)` → allow.
    /// - Returns `Ok(false)` → deny (caller should respond HTTP 403).
    /// - Returns `Err(_)` → policy evaluation failed (caller should respond
    ///   HTTP 500 or 403 depending on fail-open/fail-closed preference).
    async fn check(
        &self,
        agent_id: Uuid,
        action: &Action,
        resource_id: Uuid,
    ) -> Result<bool, PolicyError>;

    /// Return `true` if this gate enforces real policies.
    ///
    /// The kernel uses this to skip policy-logging overhead when the no-op
    /// gate is active.
    fn is_active(&self) -> bool;
}

/// Kernel-default allow-all policy gate.
///
/// Every action is permitted. `is_active()` returns `false`.
#[derive(Debug, Default, Clone)]
pub struct NoOpPolicyGate;

impl NoOpPolicyGate {
    /// Create a new allow-all policy gate.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PolicyGate for NoOpPolicyGate {
    async fn check(
        &self,
        _agent_id: Uuid,
        _action: &Action,
        _resource_id: Uuid,
    ) -> Result<bool, PolicyError> {
        Ok(true)
    }

    fn is_active(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_always_allows() {
        let gate = NoOpPolicyGate::new();
        let agent = Uuid::new_v4();
        let resource = Uuid::new_v4();
        for action in [
            Action::Create,
            Action::Read,
            Action::Update,
            Action::Delete,
            Action::Custom("publish".into()),
        ] {
            assert!(gate.check(agent, &action, resource).await.unwrap());
        }
    }

    #[test]
    fn noop_is_not_active() {
        assert!(!NoOpPolicyGate::new().is_active());
    }
}
