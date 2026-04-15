//! Type-safe identifiers for domain entities
//!
//! These newtype wrappers prevent accidental confusion between different entity types
//! (e.g., using a `ClaimId` where an `AgentId` is expected).

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Unique identifier for an Agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(Uuid);

impl AgentId {
    /// Create a new random `AgentId`
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create an `AgentId` from an existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "agent:{}", self.0)
    }
}

impl From<Uuid> for AgentId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<AgentId> for Uuid {
    fn from(id: AgentId) -> Self {
        id.0
    }
}

/// Unique identifier for a Claim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimId(Uuid);

impl ClaimId {
    /// Create a new random `ClaimId`
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a `ClaimId` from an existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for ClaimId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ClaimId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "claim:{}", self.0)
    }
}

impl From<Uuid> for ClaimId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<ClaimId> for Uuid {
    fn from(id: ClaimId) -> Self {
        id.0
    }
}

/// Unique identifier for Evidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceId(Uuid);

impl EvidenceId {
    /// Create a new random `EvidenceId`
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create an `EvidenceId` from an existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for EvidenceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EvidenceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "evidence:{}", self.0)
    }
}

impl From<Uuid> for EvidenceId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<EvidenceId> for Uuid {
    fn from(id: EvidenceId) -> Self {
        id.0
    }
}

/// Unique identifier for a `ReasoningTrace`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TraceId(Uuid);

impl TraceId {
    /// Create a new random `TraceId`
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a `TraceId` from an existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "trace:{}", self.0)
    }
}

impl From<Uuid> for TraceId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<TraceId> for Uuid {
    fn from(id: TraceId) -> Self {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_ids_are_distinct_types() {
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let evidence_id = EvidenceId::new();
        let trace_id = TraceId::new();

        // These would fail to compile if types were not distinct:
        // let _: AgentId = claim_id; // ERROR
        // let _: ClaimId = evidence_id; // ERROR

        // But we can compare their underlying UUIDs
        assert_ne!(agent_id.as_uuid(), claim_id.as_uuid());
        assert_ne!(claim_id.as_uuid(), evidence_id.as_uuid());
        assert_ne!(evidence_id.as_uuid(), trace_id.as_uuid());
    }

    #[test]
    fn ids_serialize_as_uuid_strings() {
        let agent_id = AgentId::from_uuid(Uuid::nil());
        let json = serde_json::to_string(&agent_id).unwrap();
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000000\"");
    }

    #[test]
    fn ids_display_with_prefix() {
        let agent_id = AgentId::from_uuid(Uuid::nil());
        let claim_id = ClaimId::from_uuid(Uuid::nil());
        let evidence_id = EvidenceId::from_uuid(Uuid::nil());
        let trace_id = TraceId::from_uuid(Uuid::nil());

        assert!(agent_id.to_string().starts_with("agent:"));
        assert!(claim_id.to_string().starts_with("claim:"));
        assert!(evidence_id.to_string().starts_with("evidence:"));
        assert!(trace_id.to_string().starts_with("trace:"));
    }
}
