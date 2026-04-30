//! Repository layer for database operations
//!
//! This module provides repository implementations for each domain entity,
//! following the repository pattern to abstract database access.

pub mod activity;
pub mod agent;
pub mod agent_key;
pub mod analysis;
pub mod behavioral_execution;
pub mod challenge;
pub mod claim;
pub mod claim_encryption;
pub mod claim_theme;
pub mod claim_version;
pub mod community;
pub mod context;
pub mod counterfactual;
pub mod divergence;
pub mod edge;
pub mod edge_encryption;
pub mod embedding_share;
pub mod entity;
pub mod event;
pub mod evidence;
pub mod evidence_encryption;
pub mod experiment;
pub mod factor;
pub mod frame;
pub mod gap;
pub mod group;
pub mod group_key_epoch;
pub mod group_membership;
pub mod learning_event;
pub mod lineage;
pub mod mass_function;
pub mod method;
pub mod oauth_client;
pub mod ownership;
pub mod paper;
pub mod pattern_template;
pub mod perspective;
pub mod political;
pub mod provenance;
pub mod re_encryption_key;
pub mod refresh_token;
pub mod scoped_belief;
pub mod security_event;
pub mod semantic_link;
pub mod sheaf;
pub mod span;
pub mod task;
pub mod trace;
pub mod triple;
pub mod workflow;
pub mod workflow_execution;

// Re-export all repositories for convenience
pub use activity::ActivityRepository;
pub use agent::{AgentCapabilitiesRow, AgentIdentityRow, AgentRepository, CapabilityFilter};
pub use agent_key::{AgentKeyRepository, AgentKeyRow};
pub use analysis::{AnalysisRecord, AnalysisRepository, ClaimSummary};
pub use challenge::{ChallengeRepository, ChallengeRow, GapChallengeRow};
pub use claim::{ClaimPairDistance, ClaimRepository};
pub use claim_theme::{
    BoundaryClaimRow, ClaimThemeRepository, ClaimThemeRow, DistantClaimsRow, RecomputedThemeRow,
    SplitCandidateRow,
};
pub use claim_version::{ClaimVersionRepository, ClaimVersionRow};
pub use community::CommunityRepository;
pub use context::ContextRepository;
pub use counterfactual::{CounterfactualRepository, CounterfactualRow};
pub use divergence::DivergenceRepository;
pub use edge::EdgeRepository;
pub use entity::{EntityRepository, EntityRow};
pub use event::{EventRepository, EventRow};
pub use evidence::{EvidenceRepository, EvidenceSearchResult};
pub use experiment::{
    ExperimentRepository, ExperimentResultRepository, ExperimentResultRow, ExperimentRow,
};
pub use factor::FactorRepository;
pub use frame::FrameRepository;
pub use gap::{GapAnalysisResult, GapRecord, GapRepository};
pub use learning_event::{LearningEventRepository, LearningEventRow};
pub use lineage::LineageRepository;
pub use mass_function::MassFunctionRepository;
pub use method::{
    MethodCapability, MethodEvidenceStrength, MethodFailureModes, MethodForCapability,
    MethodRecord, MethodRepository, MethodSearchResult, MethodSourcePaper, MethodUsageExample,
};
pub use ownership::OwnershipRepository;
pub use paper::{PaperRepository, PaperRow};
pub use perspective::PerspectiveRepository;
pub use political::{
    AgentClaimProfileRow, CoalitionRow, EvidenceTypeCount, PoliticalRepository,
    PropagandaTechniqueRow, PropagationStepRow, TimelineClaimRow,
};
pub use scoped_belief::ScopedBeliefRepository;
pub use semantic_link::SemanticLinkRepository;
pub use sheaf::{ClaimNeighborBetpRow, EpistemicEdgePairRow, SheafRepository};
pub use trace::ReasoningTraceRepository;
pub use triple::{MentionRow, TripleRepository, TripleRow};
pub use workflow::{
    HierarchicalWorkflowRow, WorkflowListRow, WorkflowRecallResult, WorkflowRepository,
};

// Privacy / encryption repositories
pub use behavioral_execution::{BehavioralExecutionRepository, BehavioralExecutionRow};
pub use claim_encryption::{ClaimEncryptionRepository, ClaimEncryptionRow};
pub use edge_encryption::{EdgeEncryptionRepository, EdgeEncryptionRow};
pub use embedding_share::{EmbeddingShareRepository, EmbeddingShareRow};
pub use evidence_encryption::{EvidenceEncryptionRepository, EvidenceEncryptionRow};
pub use group::{GroupRepository, GroupRow};
pub use group_key_epoch::{GroupKeyEpochRepository, KeyEpochRow};
pub use group_membership::{GroupMembershipRepository, MembershipRow};
pub use oauth_client::{OAuthClientRepository, OAuthClientRow};
pub use pattern_template::{PatternTemplateRepository, PatternTemplateRow};
pub use provenance::{ProvenanceLogRow, ProvenanceRepository, AUTO_POLICY_AUTHORIZER_ID};
pub use re_encryption_key::{ReEncryptionKeyRepository, ReEncryptionKeyRow};
pub use refresh_token::{RefreshTokenRepository, RefreshTokenRow};
pub use security_event::{SecurityEventFilter, SecurityEventRepository, SecurityEventRow};
pub use span::{SpanRepository, SpanRow};
pub use task::{TaskRepository, TaskRow};
pub use workflow_execution::{WorkflowExecutionRepository, WorkflowExecutionRow};
