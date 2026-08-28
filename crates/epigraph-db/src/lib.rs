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

pub mod access_control;
pub mod anchor;
pub mod errors;
pub mod pool;
pub mod repos;

// Re-export primary types
pub use access_control::{
    batch_check_content_access, check_content_access, ContentAccess, COARSE_EDGE_TYPES,
};
pub use anchor::{
    anchor_manifest_best_effort, AnchorService, AnchorServiceError, AnchorVerdict,
    AnchorVerification, MockAnchorBackend,
};
pub use errors::DbError;
pub use pool::{create_pool, create_pool_from_options, create_pool_with_options};
pub use repos::manifest::{ClaimLeafInput, EdgeLeafInput};
pub use repos::{
    ActivityRepository, AgentKeyRepository, AgentKeyRow, AgentRepository, AnalysisRecord,
    AnalysisRepository, AnchorRepository, AnchorRow, BehavioralExecutionRepository,
    BehavioralExecutionRow, BlobRepository, ChallengeRepository, ChallengeRow, ClaimBeliefColumns,
    ClaimDispute, ClaimEmbeddingHit, ClaimEncryptionRepository, ClaimEncryptionRow, ClaimNeighbor,
    ClaimNeighborBetpRow, ClaimRepository, ClaimSummary, ClaimThemeRepository, ClaimThemeRow,
    ClaimVersionRepository, ClaimVersionRow, CommunityRepository, ConsolidateMode,
    ConsolidateResult, ContextRepository, CounterfactualRepository, CounterfactualRow, DedupRepair,
    DivergenceRepository, EdgeEncryptionRepository, EdgeEncryptionRow, EdgeRepository,
    EmbeddingShareRepository, EmbeddingShareRow, EntityRepository, EntityRow, EntityTypeEntry,
    EntityTypeRepository, EpistemicEdgePairRow, EventRepository, EventRow,
    EvidenceEncryptionRepository, EvidenceEncryptionRow, EvidenceRepository, EvidenceSearchResult,
    EvolveStepResult, ExperimentRepository, ExperimentResultRepository, ExperimentResultRow,
    ExperimentRow, FactorRepository, FrameRepository, GapAnalysisResult, GapChallengeRow,
    GapRecord, GapRepository, GraphExpansionHit, GroupKeyEpochRepository,
    GroupMembershipRepository, GroupRepository, GroupRow, HierarchicalWorkflowRow, HybridHit,
    IndexCounts, KeyEpochRow, LearningEventRepository, LearningEventRow, LineageHead,
    LineageRepository, ManifestEntryRow, ManifestRepository, ManifestRow, MassFunctionRepository,
    MatchCandidateRepo, MatchCandidateRow, MembershipRow, MentionRow, MethodCapability,
    MethodEvidenceStrength, MethodFailureModes, MethodForCapability, MethodRecord,
    MethodRepository, MethodSearchResult, MethodSourcePaper, MethodUsageExample,
    MockChainRepository, MockChainRow, NearestClaimHit, NewAnchor, NewManifest, NewManifestEntry,
    NewObligation, NewRecallEvent, OAuthClientRepository, OAuthClientRow, ObligationRepository,
    ObligationRow, OwnershipRepository, PaperRepository, PaperRow, PatchClaimDiff, PatchClaimInput,
    PatternTemplateRepository, PatternTemplateRow, PerspectiveRepository, ProvenanceChain,
    ProvenanceChainRepository, ProvenanceEdge, ProvenanceLogRow, ProvenanceNode,
    ProvenanceRepository, ReEncryptionKeyRepository, ReEncryptionKeyRow, ReasoningTraceRepository,
    RecallEventRepository, RecallEventRow, RefreshTokenRepository, RefreshTokenRow, ResolvedStep,
    ScopedBeliefRepository, SecurityEventRepository, SecurityEventRow, SheafRepository,
    SourceArtifactRepository, StoredBlob, SweepCandidate, TaskRepository, TaskRow,
    TripleRepository, TripleRow, WorkflowExecutionRepository, WorkflowExecutionRow,
    WorkflowGoalEmbeddingHit, WorkflowListRow, WorkflowRecallResult, WorkflowRepository,
    EXPANSION_RELATIONSHIPS, HAS_ESSENCE_RELATIONSHIP, MANIFEST_ALGO, PRUNABLE_EVENT_TYPES,
    ROOT_TYPE_MANIFEST,
};

// Re-export sqlx types that users will need
pub use sqlx::PgPool;

// Re-export row types for users of repositories
pub use repos::activity::ActivityRow;
pub use repos::community::{CommunityMemberRow, CommunityRow};
pub use repos::context::ContextRow;
pub use repos::divergence::DivergenceRow;
pub use repos::edge::{
    is_essence_digest_hex, AttributedClaimRow, EdgeRow, EPISTEMIC_RELATIONSHIPS, ESSENCE_DIGEST_KEY,
};
pub use repos::factor::{BpMessageRow, FactorRow};
pub use repos::frame::{ClaimFrameRow, FrameRow};
pub use repos::mass_function::MassFunctionRow;
pub use repos::obligation::ANCHOR_KIND_CLAIM;
pub use repos::ownership::OwnershipRow;
pub use repos::paper::{AssertedClaimBinding, DecomposedAtomRow};
pub use repos::perspective::PerspectiveRow;
pub use repos::scoped_belief::ScopedBeliefRow;
pub use repos::source_artifact::EssenceRendition;

// Re-export Political network monitoring types
pub use repos::political::{
    AgentClaimProfileRow, CoalitionRow, EvidenceTypeCount, PoliticalRepository,
    PropagandaTechniqueRow, PropagationStepRow, TimelineClaimRow,
};

// Re-export Lineage types for users of LineageRepository
pub use repos::lineage::{
    LcaResult, LineageClaim, LineageEvidence, LineageNode, LineageResult, LineageTrace,
};
