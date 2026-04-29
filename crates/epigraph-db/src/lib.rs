//! `epigraph-db`: Database access layer for EpiGraph
//!
//! This crate provides PostgreSQL repository implementations for all EpiGraph domain entities.
//!
//! # Architecture
//!
//! - **Pool Management**: Connection pooling with `sqlx::PgPool`
//! - **Repository Pattern**: Each domain entity has a dedicated repository
//! - **Type Safety**: Compile-time SQL verification with `sqlx::query!` macro
//! - **Error Handling**: Comprehensive error types with context
//!
//! # Usage
//!
//! ```rust,no_run
//! use epigraph_db::{create_pool, AgentRepository};
//! use epigraph_core::Agent;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create connection pool
//!     let pool = create_pool("postgres://user:pass@localhost/epigraph").await?;
//!
//!     // Create an agent
//!     let agent = Agent::new([0u8; 32], Some("Alice".to_string()));
//!     let created = AgentRepository::create(&pool, &agent).await?;
//!
//!     // Retrieve the agent
//!     let retrieved = AgentRepository::get_by_id(&pool, created.id).await?;
//!     assert!(retrieved.is_some());
//!
//!     Ok(())
//! }
//! ```
//!
//! # Repository Modules
//!
//! - [`AgentRepository`]: Agents who make claims
//! - [`ClaimRepository`]: Epistemic assertions with truth values
//! - [`EvidenceRepository`]: Supporting evidence for claims
//! - [`ReasoningTraceRepository`]: Logical derivation paths
//! - [`EdgeRepository`]: LPG-style flexible relationships
//! - [`LineageRepository`]: Recursive CTE-based claim provenance queries
//!
//! # Database Schema
//!
//! The schema follows a hybrid approach:
//! - **Core tables**: agents, claims, evidence, reasoning_traces (fixed schema)
//! - **LPG extensions**: labels, properties (JSONB), edges table (flexible schema)
//! - **DAG support**: trace_parents junction table for reasoning chains
//!
//! All migrations are in `/migrations/` and should be run with `sqlx migrate run`.

pub mod errors;
pub mod pool;
pub mod repos;

// Re-export primary types
pub use errors::DbError;
pub use pool::{create_pool, create_pool_from_options, create_pool_with_options};
pub use repos::{
    ActivityRepository, AgentKeyRepository, AgentKeyRow, AgentRepository, AnalysisRecord,
    AnalysisRepository, BehavioralExecutionRepository, BehavioralExecutionRow, ChallengeRepository,
    ChallengeRow, ClaimEncryptionRepository, ClaimEncryptionRow, ClaimNeighborBetpRow,
    ClaimRepository, ClaimSummary, ClaimThemeRepository, ClaimThemeRow, ClaimVersionRepository,
    ClaimVersionRow, CommunityRepository, ContextRepository, CounterfactualRepository,
    CounterfactualRow, DivergenceRepository, EdgeEncryptionRepository, EdgeEncryptionRow,
    EdgeRepository, EmbeddingShareRepository, EmbeddingShareRow, EntityRepository, EntityRow,
    EpistemicEdgePairRow, EventRepository, EventRow, EvidenceEncryptionRepository,
    EvidenceEncryptionRow, EvidenceRepository, EvidenceSearchResult, ExperimentRepository,
    ExperimentResultRepository, ExperimentResultRow, ExperimentRow, FactorRepository,
    FrameRepository, GapAnalysisResult, GapChallengeRow, GapRecord, GapRepository,
    GroupKeyEpochRepository, GroupMembershipRepository, GroupRepository, GroupRow, KeyEpochRow,
    LearningEventRepository, LearningEventRow, LineageRepository, MassFunctionRepository,
    MembershipRow, MentionRow, MethodCapability, MethodEvidenceStrength, MethodFailureModes,
    MethodForCapability, MethodRecord, MethodRepository, MethodSearchResult, MethodSourcePaper,
    MethodUsageExample, OAuthClientRepository, OAuthClientRow, OwnershipRepository,
    PaperRepository, PaperRow, PatternTemplateRepository, PatternTemplateRow,
    PerspectiveRepository, ProvenanceLogRow, ProvenanceRepository, ReEncryptionKeyRepository,
    ReEncryptionKeyRow, ReasoningTraceRepository, RefreshTokenRepository, RefreshTokenRow,
    ScopedBeliefRepository, SecurityEventRepository, SecurityEventRow, SheafRepository,
    TaskRepository, TaskRow, TripleRepository, TripleRow, WorkflowExecutionRepository,
    WorkflowExecutionRow, WorkflowListRow, WorkflowRecallResult, WorkflowRepository,
};

// Re-export sqlx types that users will need
pub use sqlx::PgPool;

// Re-export row types for users of repositories
pub use repos::activity::ActivityRow;
pub use repos::community::{CommunityMemberRow, CommunityRow};
pub use repos::context::ContextRow;
pub use repos::divergence::DivergenceRow;
pub use repos::edge::{AttributedClaimRow, EdgeRow};
pub use repos::factor::{BpMessageRow, FactorRow};
pub use repos::frame::{ClaimFrameRow, FrameRow};
pub use repos::mass_function::MassFunctionRow;
pub use repos::ownership::OwnershipRow;
pub use repos::perspective::PerspectiveRow;
pub use repos::scoped_belief::ScopedBeliefRow;

// Re-export Political network monitoring types
pub use repos::political::{
    AgentClaimProfileRow, CoalitionRow, EvidenceTypeCount, PoliticalRepository,
    PropagandaTechniqueRow, PropagationStepRow, TimelineClaimRow,
};

// Re-export Lineage types for users of LineageRepository
pub use repos::lineage::{
    LcaResult, LineageClaim, LineageEvidence, LineageNode, LineageResult, LineageTrace,
};
