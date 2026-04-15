//! Extension point traits for enterprise and domain-specific capabilities.
//!
//! The open kernel defines these traits with no-op defaults. Enterprise crates
//! (epigraph-privacy, epigraph-policy, epigraph-orchestrator) implement them
//! with real logic. Consumers wire in the implementation via [`AppState`].
//!
//! # Design
//!
//! No-op defaults mean the kernel is fully functional for single-tenant,
//! unencrypted deployments without any enterprise crates installed.
//! Enterprise capabilities are opted into, not required.

use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

// ── EncryptionProvider ────────────────────────────────────────────────────────

/// Extension point for encrypted subgraph storage.
///
/// The no-op default (`NoOpEncryption`) passes data through unencrypted —
/// suitable for trusted/single-tenant deployments.
///
/// Enterprise: implement with AES-256-GCM via `epigraph-privacy`.
#[async_trait]
pub trait EncryptionProvider: Send + Sync {
    /// Encrypt `plaintext` for `group_id`. No-op: returns plaintext.
    async fn encrypt(&self, plaintext: &[u8], _group_id: Uuid) -> anyhow::Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    /// Decrypt `ciphertext` for `group_id`. No-op: returns ciphertext.
    async fn decrypt(&self, ciphertext: &[u8], _group_id: Uuid) -> anyhow::Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }

    /// Returns true only when real encryption is active.
    fn is_enabled(&self) -> bool {
        false
    }
}

/// No-op `EncryptionProvider` — data passes through unencrypted.
pub struct NoOpEncryption;

#[async_trait]
impl EncryptionProvider for NoOpEncryption {}

// ── PolicyGate ───────────────────────────────────────────────────────────────

/// Extension point for policy-based access control.
///
/// The no-op default (`NoOpPolicyGate`) allows all read and write operations —
/// suitable for single-tenant or trusted internal deployments.
///
/// Enterprise: implement with RBAC/ABAC via `epigraph-policy`.
#[async_trait]
pub trait PolicyGate: Send + Sync {
    /// Returns `Ok(true)` if `agent_id` may read `resource_id`.
    async fn check_read(&self, _agent_id: Uuid, _resource_id: Uuid) -> anyhow::Result<bool> {
        Ok(true)
    }

    /// Returns `Ok(true)` if `agent_id` may write to `resource_id`.
    async fn check_write(&self, _agent_id: Uuid, _resource_id: Uuid) -> anyhow::Result<bool> {
        Ok(true)
    }
}

/// No-op `PolicyGate` — all operations are permitted.
pub struct NoOpPolicyGate;

#[async_trait]
impl PolicyGate for NoOpPolicyGate {}

// ── OrchestrationBackend ──────────────────────────────────────────────────────

/// Extension point for task scheduling and lifecycle management.
///
/// The no-op default (`NoOpOrchestration`) returns an error on schedule attempts —
/// orchestration is not silently skipped; callers receive an explicit signal.
///
/// Enterprise: implement with `epigraph-orchestrator`.
#[async_trait]
pub trait OrchestrationBackend: Send + Sync {
    /// Schedule a task of `task_type` with `payload`.
    ///
    /// # Errors
    /// No-op implementation always returns `Err` — orchestration requires
    /// `epigraph-enterprise`.
    async fn schedule_task(&self, _task_type: &str, _payload: Value) -> anyhow::Result<Uuid> {
        Err(anyhow::anyhow!(
            "Orchestration is not available in the open kernel. \
             Install epigraph-enterprise and wire OrchestrationBackend to enable it."
        ))
    }

    /// Returns the status string of `task_id`, or `"not_available"`.
    async fn task_status(&self, _task_id: Uuid) -> anyhow::Result<String> {
        Ok("not_available".to_string())
    }
}

/// No-op `OrchestrationBackend` — scheduling always returns `Err`.
pub struct NoOpOrchestration;

#[async_trait]
impl OrchestrationBackend for NoOpOrchestration {}
