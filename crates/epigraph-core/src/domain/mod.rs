//! Domain models for `EpiGraph`'s epistemic knowledge graph
//!
//! This module provides high-level domain types that build on the Label Property Graph
//! primitives. These types represent the core entities in `EpiGraph`:
//!
//! - [`Agent`]: An entity that can make claims and provide evidence
//! - [`Claim`]: An epistemic assertion with a truth value
//! - [`Evidence`]: Supporting material for claims
//! - [`ReasoningTrace`]: The logical derivation path of a claim
//!
//! # Agentic Framework Types
//!
//! - [`AgentRole`]: Defines the role an agent plays (Harvester, Validator, etc.)
//! - [`AgentCapabilities`]: Fine-grained capability flags for authorization
//! - [`AgentState`]: Lifecycle state with valid transitions
//! - [`AgentWithIdentity`]: Full agent with identity, role, capabilities, and state
//! - [`AgentMetadata`]: Additional metadata and custom attributes
//! - [`AgentLineage`]: Parent-child relationships between agents
//!
//! # Design Philosophy
//!
//! Unlike the `IMPLEMENTATION_PLAN.md` which suggested storing properties directly,
//! this implementation follows the established LPG pattern:
//! - Domain types are strongly typed Rust structs
//! - They can be converted to/from Node representations
//! - Properties are stored in `PropertyMap` for graph storage
//! - Type-safe IDs prevent accidental confusion

pub mod activity;
pub mod agent;
pub mod agent_identity;
pub mod claim;
pub mod evidence;
pub mod ids;
pub mod learning_event;
pub mod reasoning_trace;
pub mod semantic_link;

// Re-export primary types
pub use activity::{Activity, ActivityType};
pub use agent::Agent;
pub use claim::Claim;
pub use evidence::{Evidence, EvidenceType};
pub use ids::{AgentId, ClaimId, EvidenceId, TraceId};
pub use learning_event::LearningEvent;
pub use reasoning_trace::{Methodology, ReasoningTrace, TraceInput};
pub use semantic_link::{LinkStrength, SemanticLink, SemanticLinkId, SemanticLinkType};

// Re-export agentic framework types
pub use agent_identity::{
    AgentCapabilities, AgentLineage, AgentMetadata, AgentRole, AgentState,
    AgentStateTransitionError, AgentWithIdentity, RevocationReason, SuspensionReason,
    WorkflowState,
};
