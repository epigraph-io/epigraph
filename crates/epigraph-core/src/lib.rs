//! `EpiGraph` Core: Label Property Graph Primitives
//!
//! This crate provides the foundational types for `EpiGraph`'s epistemic knowledge graph,
//! built on a Label Property Graph (LPG) model that enables dynamic ontology evolution.
//!
//! # Design Philosophy
//!
//! Unlike traditional fixed-schema approaches, the LPG model stores:
//! - Node types as **labels** (data, not schema)
//! - Edge types as **relationship names** (data, not ENUMs)
//! - Properties as **typed key-value maps** on both nodes and edges
//!
//! This enables the ontology to evolve with the data without DDL migrations.
//!
//! # Core Types
//!
//! ## Graph Primitives
//! - [`NodeId`] / [`EdgeId`]: Type-safe identifiers
//! - [`Label`]: Validated ontology term for node classification
//! - [`PropertyValue`] / [`PropertyMap`]: Typed property storage
//! - [`Node`]: Graph vertex with labels and properties
//! - [`Edge`]: Directed relationship with type and properties
//!
//! ## Domain Models
//! - [`domain::Agent`]: Entity that makes claims
//! - [`domain::Claim`]: Epistemic assertion with truth value
//! - [`domain::Evidence`]: Supporting material for claims
//! - [`domain::ReasoningTrace`]: Logical derivation path

pub mod challenge;
pub mod domain;
pub mod edge;
pub mod errors;
pub mod extensions;
pub mod graph;
pub mod ids;
pub mod labels;
pub mod node;
pub mod properties;
pub mod prov;
pub mod traits;
pub mod truth;

// Re-export primary types at crate root
pub use edge::Edge;
pub use errors::CoreError;
pub use ids::{EdgeId, NodeId};
pub use labels::Label;
pub use node::Node;
pub use properties::{PropertyMap, PropertyValue};
pub use prov::ProvAgentType;
pub use traits::{ContentAddressable, Signable, Verifiable};
pub use truth::TruthValue;

pub use challenge::{
    auto_create_challenge, Challenge, ChallengeError, ChallengeId, ChallengeResolution,
    ChallengeService, ChallengeState, ChallengeType,
};
pub use extensions::{
    Action, EncryptionError, EncryptionProvider, InterfaceError, NoOpEncryption,
    NoOpEncryptionProvider, NoOpOrchestration, NoOpOrchestrationBackend, NoOpPolicyGate,
    OrchestrationBackend, OrchestrationError, PolicyError, PolicyGate, TaskStatus,
};

// Re-export domain types for convenience
pub use domain::{
    Activity, ActivityType, Agent, AgentId, Claim, ClaimId, Evidence, EvidenceId, EvidenceType,
    LearningEvent, LinkStrength, Methodology, ReasoningTrace, SemanticLink, SemanticLinkId,
    SemanticLinkType, TraceId, TraceInput, WorkflowState,
};
