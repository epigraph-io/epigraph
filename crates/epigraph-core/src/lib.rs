//! `EpiGraph` Core: the kernel's shared domain vocabulary
//!
//! The types every other crate agrees on: typed ids, the domain structs a
//! write path builds before it reaches the database, the tenancy declaration
//! every tier-A write carries, and the names edges are stored under. Storage
//! lives in `epigraph-db` (claims, evidence, agents and edges are rows, not
//! in-memory graph objects); this crate has no database dependency, so the
//! API's `--no-default-features` build can still name every type here.
//!
//! # Ids
//!
//! [`domain::ids`] wraps each entity's UUID in its own newtype ([`AgentId`],
//! [`ClaimId`], [`EvidenceId`], [`TraceId`]), so a claim id cannot be passed
//! where an agent id is expected.
//!
//! # Domain structs
//!
//! [`domain`] holds the entities: [`Agent`], [`Claim`] (with its
//! [`TruthValue`], see [`truth`]), [`Evidence`], [`ReasoningTrace`],
//! [`SemanticLink`], [`Activity`] and [`LearningEvent`]. Around them:
//!
//! - [`labels`] holds [`Label`], the validated term stored in a row's
//!   `labels`.
//! - [`prov`] holds [`ProvAgentType`], the W3C PROV-O agent type read off
//!   labels.
//! - [`traits`] holds [`Signable`], [`Verifiable`] and [`ContentAddressable`],
//!   the hooks between domain types and `epigraph-crypto`.
//! - [`challenge`] holds [`Challenge`] and [`ChallengeService`], disputes
//!   against an existing claim.
//! - [`atomicity`] holds the heuristic deciding whether a claim is already one
//!   atomic proposition.
//! - [`projection`] holds the deterministic 2-D projection served in place of
//!   raw embeddings.
//! - [`errors`] holds [`CoreError`].
//!
//! # Tenancy
//!
//! In [`tenancy`], [`TenancyDecl`] is what a write path says about who owns the
//! row it creates and at what [`Visibility`]; [`tenancy::consolidate_tenancy`]
//! derives the tenancy of a row merged from several claims, refusing a merge
//! across groups.
//!
//! [`canonical_scopes`] holds the scope sets of the service roles, and
//! [`extensions`] re-exports the [`PolicyGate`] extension point (deny-all by
//! default).
//!
//! # Relationship vocabulary
//!
//! [`edge::relationships`] names the relationships edges are stored under,
//! and decides which spelling a writer stores and which spellings a reader
//! matches. Downstream crates import it by that path.

pub mod atomicity;
pub mod canonical_scopes;
pub mod challenge;
pub mod domain;
pub mod edge;
pub mod errors;
pub mod extensions;
pub mod labels;
pub mod projection;
pub mod prov;
pub mod tenancy;
pub mod traits;
pub mod truth;

// Re-export primary types at crate root
pub use errors::CoreError;
pub use labels::Label;
pub use prov::ProvAgentType;
pub use tenancy::{
    consolidate_owner, consolidate_tenancy, ConsolidateTenancyError, SourceTenancy, TenancyDecl,
    Visibility, VisibilityChoice, WORLD_GROUP,
};
pub use traits::{ContentAddressable, Signable, Verifiable};
pub use truth::TruthValue;

pub use challenge::{
    auto_create_challenge, Challenge, ChallengeError, ChallengeId, ChallengeResolution,
    ChallengeService, ChallengeState, ChallengeType,
};
pub use extensions::{
    Action, Decision, DenyAllPolicyGate, InterfaceError, PolicyError, PolicyGate, Principal,
    ResourceKind, ResourceRef,
};

// Re-export domain types for convenience
pub use domain::{
    Activity, ActivityType, Agent, AgentId, Claim, ClaimId, DatasetAttestation,
    DatasetEvidenceError, DatasetManifestInput, Evidence, EvidenceId, EvidenceType, LearningEvent,
    LinkStrength, Methodology, ReasoningTrace, SemanticLink, SemanticLinkId, SemanticLinkType,
    TraceId, TraceInput, WorkflowState, MANIFEST_HASH_ALGORITHMS, STORED_EVIDENCE_TYPES,
};
