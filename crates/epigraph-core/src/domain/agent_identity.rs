//! Agent Identity & Authorization System
//!
//! This module provides types for managing agent identity, roles, capabilities,
//! and lifecycle states in the agentic framework.
//!
//! # Core Types
//!
//! - [`AgentRole`]: Defines the role an agent plays in the system
//! - [`AgentCapabilities`]: Fine-grained capability flags for authorization
//! - [`AgentState`]: Lifecycle state with valid state transitions
//! - [`AgentWithIdentity`]: Full agent with identity, role, capabilities, and state
//! - [`AgentMetadata`]: Additional metadata and custom attributes
//! - [`AgentLineage`]: Parent-child relationships between agents

use super::ids::AgentId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use std::collections::HashMap;
use thiserror::Error;

// ============================================================================
// AgentRole
// ============================================================================

/// Role that defines an agent's primary function in the system
///
/// Each role has default capabilities that can be customized per-agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentRole {
    /// Extracts claims from documents and external sources
    Harvester,
    /// Reviews and validates claims submitted by other agents
    Validator,
    /// Coordinates multi-agent workflows and spawns sub-agents
    Orchestrator,
    /// Queries and analyzes the knowledge graph (read-heavy)
    Analyst,
    /// Full system access with all capabilities
    Admin,
    /// Custom role with no default capabilities (must be explicitly granted)
    Custom,
}

impl AgentRole {
    /// Get the default capabilities for this role
    #[must_use]
    pub const fn default_capabilities(&self) -> AgentCapabilities {
        match self {
            Self::Harvester => AgentCapabilities {
                can_submit_claims: true,
                can_provide_evidence: true,
                can_challenge_claims: false,
                can_invoke_tools: true,
                can_spawn_agents: false,
                can_modify_policies: false,
                privileged_access: false,
            },
            Self::Validator => AgentCapabilities {
                can_submit_claims: false,
                can_provide_evidence: true,
                can_challenge_claims: true,
                can_invoke_tools: false,
                can_spawn_agents: false,
                can_modify_policies: false,
                privileged_access: false,
            },
            Self::Orchestrator => AgentCapabilities {
                can_submit_claims: true,
                can_provide_evidence: true,
                can_challenge_claims: true,
                can_invoke_tools: true,
                can_spawn_agents: true,
                can_modify_policies: false,
                privileged_access: true,
            },
            Self::Analyst => AgentCapabilities {
                can_submit_claims: false,
                can_provide_evidence: false,
                can_challenge_claims: false,
                can_invoke_tools: true,
                can_spawn_agents: false,
                can_modify_policies: false,
                privileged_access: false,
            },
            Self::Admin => AgentCapabilities::all(),
            Self::Custom => AgentCapabilities::none(),
        }
    }
}

// ============================================================================
// AgentCapabilities
// ============================================================================

/// Fine-grained capability flags for agent authorization
///
/// Capabilities can be combined using `union` (OR) or `intersect` (AND) operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Intentional: capability flags are naturally boolean
pub struct AgentCapabilities {
    /// Can submit new claims to the knowledge graph
    pub can_submit_claims: bool,
    /// Can provide evidence for existing claims
    pub can_provide_evidence: bool,
    /// Can challenge or dispute existing claims
    pub can_challenge_claims: bool,
    /// Can invoke external tools and integrations
    pub can_invoke_tools: bool,
    /// Can spawn child agents
    pub can_spawn_agents: bool,
    /// Can modify system policies and configurations
    pub can_modify_policies: bool,
    /// Has elevated access to system internals
    pub privileged_access: bool,
}

impl AgentCapabilities {
    /// Create capabilities with all flags set to true
    #[must_use]
    pub const fn all() -> Self {
        Self {
            can_submit_claims: true,
            can_provide_evidence: true,
            can_challenge_claims: true,
            can_invoke_tools: true,
            can_spawn_agents: true,
            can_modify_policies: true,
            privileged_access: true,
        }
    }

    /// Create capabilities with all flags set to false
    #[must_use]
    pub const fn none() -> Self {
        Self {
            can_submit_claims: false,
            can_provide_evidence: false,
            can_challenge_claims: false,
            can_invoke_tools: false,
            can_spawn_agents: false,
            can_modify_policies: false,
            privileged_access: false,
        }
    }

    /// Combine capabilities using OR (union)
    ///
    /// Returns capabilities that either self or other has.
    #[must_use]
    pub const fn union(&self, other: &Self) -> Self {
        Self {
            can_submit_claims: self.can_submit_claims || other.can_submit_claims,
            can_provide_evidence: self.can_provide_evidence || other.can_provide_evidence,
            can_challenge_claims: self.can_challenge_claims || other.can_challenge_claims,
            can_invoke_tools: self.can_invoke_tools || other.can_invoke_tools,
            can_spawn_agents: self.can_spawn_agents || other.can_spawn_agents,
            can_modify_policies: self.can_modify_policies || other.can_modify_policies,
            privileged_access: self.privileged_access || other.privileged_access,
        }
    }

    /// Combine capabilities using AND (intersection)
    ///
    /// Returns only capabilities that both self and other have.
    #[must_use]
    pub const fn intersect(&self, other: &Self) -> Self {
        Self {
            can_submit_claims: self.can_submit_claims && other.can_submit_claims,
            can_provide_evidence: self.can_provide_evidence && other.can_provide_evidence,
            can_challenge_claims: self.can_challenge_claims && other.can_challenge_claims,
            can_invoke_tools: self.can_invoke_tools && other.can_invoke_tools,
            can_spawn_agents: self.can_spawn_agents && other.can_spawn_agents,
            can_modify_policies: self.can_modify_policies && other.can_modify_policies,
            privileged_access: self.privileged_access && other.privileged_access,
        }
    }

    /// Check if a specific capability is enabled by name
    #[must_use]
    pub fn has_capability(&self, name: &str) -> bool {
        match name {
            "can_submit_claims" => self.can_submit_claims,
            "can_provide_evidence" => self.can_provide_evidence,
            "can_challenge_claims" => self.can_challenge_claims,
            "can_invoke_tools" => self.can_invoke_tools,
            "can_spawn_agents" => self.can_spawn_agents,
            "can_modify_policies" => self.can_modify_policies,
            "privileged_access" => self.privileged_access,
            _ => false,
        }
    }

    /// Set a capability by name
    fn set_capability(&mut self, name: &str, value: bool) {
        match name {
            "can_submit_claims" => self.can_submit_claims = value,
            "can_provide_evidence" => self.can_provide_evidence = value,
            "can_challenge_claims" => self.can_challenge_claims = value,
            "can_invoke_tools" => self.can_invoke_tools = value,
            "can_spawn_agents" => self.can_spawn_agents = value,
            "can_modify_policies" => self.can_modify_policies = value,
            "privileged_access" => self.privileged_access = value,
            _ => {} // Unknown capability - no-op
        }
    }
}

impl Default for AgentCapabilities {
    fn default() -> Self {
        Self::none()
    }
}

// ============================================================================
// SuspensionReason & RevocationReason
// ============================================================================

/// Reason for agent suspension (temporary disable)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspensionReason {
    /// Agent violated a system policy
    PolicyViolation { details: String },
    /// Agent exceeded allowed request rate
    RateLimitExceeded,
    /// Security concern raised about the agent
    SecurityConcern { details: String },
    /// Administrative action by an operator
    Administrative { details: String },
    /// Agent has been inactive for too long
    Inactivity { days: u32 },
}

/// Reason for agent revocation (permanent disable)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Agent's cryptographic keys were compromised
    KeyCompromise,
    /// Security incident involving this agent
    SecurityBreach { incident_id: String },
    /// Account closure by owner or admin
    AccountClosure,
}

// ============================================================================
// AgentState
// ============================================================================

/// Lifecycle state of an agent with valid state transitions
///
/// # State Machine
///
/// ```text
/// Pending -> Active -> Suspended -> Active (reactivation)
///                  \-> Revoked (terminal, except Archive)
///                  \-> Archived (terminal)
/// Pending -> Suspended -> Active or Revoked
/// Suspended -> Revoked
/// Revoked -> (no transitions except idempotent)
/// Archived -> (no transitions)
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "status")]
pub enum AgentState {
    /// Agent is registered but not yet activated
    #[default]
    Pending,
    /// Agent is active and can perform operations
    Active,
    /// Agent is temporarily suspended
    Suspended { reason: SuspensionReason },
    /// Agent is permanently revoked
    Revoked { reason: RevocationReason },
    /// Agent is archived (terminal state)
    Archived,
}

impl AgentState {
    /// Check if a transition to the target state is valid
    #[must_use]
    pub fn can_transition_to(&self, target: &Self) -> bool {
        // Idempotent transitions are always allowed
        if self.is_same_variant(target) {
            return true;
        }

        match self {
            Self::Pending => matches!(target, Self::Active | Self::Suspended { .. }),
            Self::Active => matches!(
                target,
                Self::Suspended { .. } | Self::Revoked { .. } | Self::Archived
            ),
            Self::Suspended { .. } => {
                matches!(target, Self::Active | Self::Revoked { .. } | Self::Archived)
            }
            // Terminal states: no transitions allowed
            Self::Revoked { .. } | Self::Archived => false,
        }
    }

    /// Check if two states are the same variant (ignoring payload)
    fn is_same_variant(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

// ============================================================================
// AgentStateTransitionError
// ============================================================================

/// Error when an invalid state transition is attempted
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AgentStateTransitionError {
    /// Attempted an invalid state transition
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidTransition { from: AgentState, to: AgentState },
}

// ============================================================================
// AgentMetadata
// ============================================================================

/// Additional metadata for an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    /// Optional description of the agent's purpose
    pub description: Option<String>,
    /// Parent agent ID (for spawned agents)
    pub parent_agent_id: Option<AgentId>,
    /// Maximum concurrent operations this agent can perform
    pub concurrency_limit: u32,
    /// Rate limit in requests per minute
    pub rate_limit_rpm: u32,
    /// Custom attributes as JSON values
    pub attributes: HashMap<String, serde_json::Value>,
}

impl AgentMetadata {
    /// Set a custom attribute
    pub fn set_attribute(&mut self, key: &str, value: serde_json::Value) {
        self.attributes.insert(key.to_string(), value);
    }

    /// Get a custom attribute
    #[must_use]
    pub fn get_attribute(&self, key: &str) -> Option<&serde_json::Value> {
        self.attributes.get(key)
    }
}

impl Default for AgentMetadata {
    fn default() -> Self {
        Self {
            description: None,
            parent_agent_id: None,
            concurrency_limit: 10,
            rate_limit_rpm: 60,
            attributes: HashMap::new(),
        }
    }
}

// ============================================================================
// WorkflowState
// ============================================================================

/// Lifecycle states for a workflow
///
/// Used by both the orchestrator and event bus to track workflow progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkflowState {
    /// Workflow created but not started
    Created,
    /// Workflow is actively executing tasks
    Running,
    /// All tasks completed successfully
    Completed,
    /// One or more tasks failed
    Failed,
    /// Workflow was cancelled by an agent or admin
    Cancelled,
    /// Workflow exceeded its timeout
    TimedOut,
}

// ============================================================================
// AgentWithIdentity
// ============================================================================

/// Full agent with identity, role, capabilities, and lifecycle state
///
/// This is the primary type for managing agents in the agentic framework.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWithIdentity {
    /// Unique identifier for this agent
    id: AgentId,

    /// Ed25519 public key (32 bytes) for signature verification
    #[serde_as(as = "Bytes")]
    public_key: [u8; 32],

    /// Optional human-readable name
    display_name: Option<String>,

    /// Agent's assigned role
    role: AgentRole,

    /// Current capabilities (may differ from role defaults)
    capabilities: AgentCapabilities,

    /// Current lifecycle state
    state: AgentState,

    /// Additional metadata
    metadata: AgentMetadata,

    /// When this agent was created
    created_at: DateTime<Utc>,

    /// When this agent was last updated
    updated_at: DateTime<Utc>,
}

impl AgentWithIdentity {
    /// Create a new agent with the given public key, name, and role
    #[must_use]
    pub fn new(public_key: [u8; 32], display_name: Option<String>, role: AgentRole) -> Self {
        let now = Utc::now();
        Self {
            id: AgentId::new(),
            public_key,
            display_name,
            role,
            capabilities: role.default_capabilities(),
            state: AgentState::Pending,
            metadata: AgentMetadata::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new agent with a parent (for spawned sub-agents)
    #[must_use]
    pub fn with_parent(
        public_key: [u8; 32],
        display_name: Option<String>,
        role: AgentRole,
        parent_id: AgentId,
    ) -> Self {
        let mut agent = Self::new(public_key, display_name, role);
        agent.metadata.parent_agent_id = Some(parent_id);
        agent
    }

    /// Get the agent's unique ID
    #[must_use]
    pub const fn id(&self) -> AgentId {
        self.id
    }

    /// Get the agent's public key
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Get the agent's display name
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Get the agent's role
    #[must_use]
    pub const fn role(&self) -> AgentRole {
        self.role
    }

    /// Get the agent's current capabilities
    #[must_use]
    pub const fn capabilities(&self) -> &AgentCapabilities {
        &self.capabilities
    }

    /// Get the agent's current state
    #[must_use]
    pub fn state(&self) -> AgentState {
        self.state.clone()
    }

    /// Get the agent's metadata
    #[must_use]
    pub const fn metadata(&self) -> &AgentMetadata {
        &self.metadata
    }

    /// Attempt to transition to a new state
    ///
    /// # Errors
    ///
    /// Returns `AgentStateTransitionError::InvalidTransition` if the transition is not allowed.
    pub fn transition_to(&mut self, target: AgentState) -> Result<(), AgentStateTransitionError> {
        if self.state.can_transition_to(&target) {
            self.state = target;
            self.updated_at = Utc::now();
            Ok(())
        } else {
            Err(AgentStateTransitionError::InvalidTransition {
                from: self.state.clone(),
                to: target,
            })
        }
    }

    /// Grant a capability by name
    ///
    /// Unknown capability names are silently ignored.
    pub fn grant_capability(&mut self, name: &str) {
        self.capabilities.set_capability(name, true);
        self.updated_at = Utc::now();
    }

    /// Revoke a capability by name
    ///
    /// Unknown capability names are silently ignored.
    pub fn revoke_capability(&mut self, name: &str) {
        self.capabilities.set_capability(name, false);
        self.updated_at = Utc::now();
    }

    /// Set the state directly (for testing purposes only)
    ///
    /// # Warning
    ///
    /// This bypasses the state machine validation and should ONLY be used in tests.
    /// In production code, always use `transition_to` to ensure valid state transitions.
    #[doc(hidden)]
    pub fn set_state_for_testing(&mut self, state: AgentState) {
        self.state = state;
    }
}

// ============================================================================
// AgentLineage
// ============================================================================

/// Tracks parent-child relationships between agents
///
/// This enables hierarchical agent management and capability inheritance.
#[derive(Debug, Clone)]
pub struct AgentLineage {
    /// The root agent ID
    root_id: AgentId,
    /// Map of parent -> children relationships
    children_map: HashMap<AgentId, Vec<AgentId>>,
    /// Map of child -> parent relationships
    parent_map: HashMap<AgentId, AgentId>,
}

impl AgentLineage {
    /// Build a lineage tree from a parent and its direct children
    #[must_use]
    pub fn build(parent: &AgentWithIdentity, children: &[AgentWithIdentity]) -> Self {
        let mut children_map = HashMap::new();
        let mut parent_map = HashMap::new();

        let child_ids: Vec<AgentId> = children.iter().map(AgentWithIdentity::id).collect();
        children_map.insert(parent.id(), child_ids);

        for child in children {
            parent_map.insert(child.id(), parent.id());
        }

        Self {
            root_id: parent.id(),
            children_map,
            parent_map,
        }
    }

    /// Build a lineage tree from a collection of agents
    #[must_use]
    pub fn from_agents(agents: &[AgentWithIdentity]) -> Self {
        let mut children_map: HashMap<AgentId, Vec<AgentId>> = HashMap::new();
        let mut parent_map = HashMap::new();
        let mut root_id = None;

        // Build parent-child relationships
        for agent in agents {
            if let Some(parent_id) = agent.metadata().parent_agent_id {
                children_map.entry(parent_id).or_default().push(agent.id());
                parent_map.insert(agent.id(), parent_id);
            } else {
                // Agent without parent is a potential root
                root_id = Some(agent.id());
            }
        }

        Self {
            root_id: root_id.unwrap_or_else(|| {
                // If no clear root, use the first agent
                agents
                    .first()
                    .map_or_else(AgentId::new, AgentWithIdentity::id)
            }),
            children_map,
            parent_map,
        }
    }

    /// Get the root agent ID
    #[must_use]
    pub const fn root_agent_id(&self) -> AgentId {
        self.root_id
    }

    /// Get the direct children of an agent
    #[must_use]
    pub fn children(&self, agent_id: AgentId) -> Vec<AgentId> {
        self.children_map
            .get(&agent_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get the parent of an agent
    #[must_use]
    pub fn parent(&self, agent_id: AgentId) -> Option<AgentId> {
        self.parent_map.get(&agent_id).copied()
    }

    /// Check if one agent is an ancestor of another
    #[must_use]
    pub fn is_ancestor(&self, potential_ancestor: AgentId, agent_id: AgentId) -> bool {
        let ancestors = self.ancestors(agent_id);
        ancestors.contains(&potential_ancestor)
    }

    /// Get all ancestors of an agent (parent, grandparent, etc.)
    #[must_use]
    pub fn ancestors(&self, agent_id: AgentId) -> Vec<AgentId> {
        let mut result = Vec::new();
        let mut current = agent_id;

        while let Some(parent_id) = self.parent_map.get(&current) {
            result.push(*parent_id);
            current = *parent_id;
        }

        result
    }
}
