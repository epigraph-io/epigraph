//! Agent domain model
//!
//! An Agent represents an entity that can make claims and provide evidence.
//! Agents are identified by their Ed25519 public key.
//!
//! # Key Principle: Reputation is Calculated, Never Stored
//!
//! Agent reputation is NEVER stored as a field on the Agent struct.
//! This prevents reputation gaming and ensures "Appeal to Authority" cannot bias truth values.
//! Reputation is always computed dynamically from historical claim accuracy.

use super::ids::AgentId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

/// An agent that can make claims and provide evidence
///
/// # Design Notes
///
/// - `public_key`: Ed25519 public key (32 bytes) used for signature verification
/// - `display_name`: Optional human-readable name (not used for identity)
/// - Reputation is NEVER stored here - it must be calculated from claim history
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    /// Unique identifier for this agent
    pub id: AgentId,

    /// Ed25519 public key (32 bytes) for signature verification
    /// This is the agent's true identity
    #[serde_as(as = "Bytes")]
    pub public_key: [u8; 32],

    /// Optional human-readable name (for UI display only, not authentication)
    pub display_name: Option<String>,

    /// When this agent was first registered
    pub created_at: DateTime<Utc>,

    /// LPG labels for PROV-O typing (e.g., "person", "organization", "software_agent", "instrument")
    pub labels: Vec<String>,

    /// ORCID identifier for person-type agents (format: 0000-0000-0000-000X)
    pub orcid: Option<String>,

    /// ROR identifier for organization-type agents (9-char compact format)
    pub ror_id: Option<String>,
}

impl Agent {
    /// Create a new agent with a public key
    ///
    /// # Arguments
    /// * `public_key` - The Ed25519 public key for this agent
    /// * `display_name` - Optional human-readable name
    #[must_use]
    pub fn new(public_key: [u8; 32], display_name: Option<String>) -> Self {
        Self {
            id: AgentId::new(),
            public_key,
            display_name,
            created_at: Utc::now(),
            labels: Vec::new(),
            orcid: None,
            ror_id: None,
        }
    }

    /// Create an agent with a specific ID (for database deserialization)
    #[must_use]
    pub fn with_id(
        id: AgentId,
        public_key: [u8; 32],
        display_name: Option<String>,
        created_at: DateTime<Utc>,
        labels: Vec<String>,
        orcid: Option<String>,
        ror_id: Option<String>,
    ) -> Self {
        Self {
            id,
            public_key,
            display_name,
            created_at,
            labels,
            orcid,
            ror_id,
        }
    }

    /// Get a display name, falling back to a truncated public key hex if not set
    #[must_use]
    pub fn display_name_or_default(&self) -> String {
        self.display_name.clone().unwrap_or_else(|| {
            // Show first 8 hex chars of public key
            let hex = hex::encode(&self.public_key[..4]);
            format!("agent:{hex}")
        })
    }
}

impl std::hash::Hash for Agent {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// Only compare by ID for equality (structural equivalence)
impl PartialEq for Agent {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Agent {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_agent_with_public_key() {
        let public_key = [42u8; 32];
        let agent = Agent::new(public_key, Some("Test Agent".to_string()));

        assert_eq!(agent.public_key, public_key);
        assert_eq!(agent.display_name, Some("Test Agent".to_string()));
        assert!(agent.created_at <= Utc::now());
    }

    #[test]
    fn agent_without_name_uses_default() {
        let public_key = [1u8; 32];
        let agent = Agent::new(public_key, None);

        let display = agent.display_name_or_default();
        assert!(display.starts_with("agent:"));
    }

    #[test]
    fn agents_with_same_id_are_equal() {
        let id = AgentId::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let now = Utc::now();

        let agent1 = Agent::with_id(id, key1, None, now, vec![], None, None);
        let agent2 = Agent::with_id(id, key2, None, now, vec![], None, None);

        assert_eq!(agent1, agent2); // Equal because same ID
    }

    #[test]
    fn agent_serializes_to_json() {
        let public_key = [42u8; 32];
        let agent = Agent::new(public_key, Some("Test".to_string()));

        let json = serde_json::to_string(&agent).unwrap();
        let deserialized: Agent = serde_json::from_str(&json).unwrap();

        assert_eq!(agent.public_key, deserialized.public_key);
        assert_eq!(agent.display_name, deserialized.display_name);
    }

    #[test]
    fn agent_has_labels_field() {
        let agent = Agent::new([0u8; 32], None);
        assert!(agent.labels.is_empty());
    }

    #[test]
    fn agent_has_orcid_field() {
        let agent = Agent::new([0u8; 32], None);
        assert!(agent.orcid.is_none());
    }

    #[test]
    fn agent_has_ror_id_field() {
        let agent = Agent::new([0u8; 32], None);
        assert!(agent.ror_id.is_none());
    }

    #[test]
    fn agent_with_id_accepts_labels() {
        let id = AgentId::new();
        let now = Utc::now();
        let labels = vec!["person".to_string()];
        let agent = Agent::with_id(
            id,
            [1u8; 32],
            Some("Dr. Smith".to_string()),
            now,
            labels.clone(),
            Some("0000-0001-2345-6789".to_string()),
            None,
        );
        assert_eq!(agent.labels, labels);
        assert_eq!(agent.orcid, Some("0000-0001-2345-6789".to_string()));
        assert!(agent.ror_id.is_none());
    }
}
