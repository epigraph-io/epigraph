//! Repository layer for database operations
//!
//! This module provides repository implementations for each domain entity,
//! following the repository pattern to abstract database access.

pub mod activity;
pub mod admin_act;
pub mod admin_act_ceremony;
pub mod admin_cascade;
pub mod admin_scope_enforcement;
pub mod agent;
pub mod agent_identity;
pub mod agent_key;
pub mod agent_lookup;
pub mod alternative_set;
pub mod analysis;
pub mod atlas_layout;
pub mod atom_axiom;
pub mod authored_by;
pub mod authorization_code;
pub mod authorize_session;
pub mod behavioral_execution;
pub mod bug_report;
pub mod challenge;
pub mod claim;
pub mod claim_context;
pub mod claim_encryption;
pub mod claim_ingest;
pub mod claim_role;
pub mod claim_theme;
pub mod claim_version;
pub mod claim_visibility;
pub mod cluster_run;
pub mod community;
pub mod compound_valuation;
pub mod conflict_density;
pub mod context;
pub mod corpus_stats;
pub mod counterfactual;
pub mod countersign;
pub mod decomposition_priority;
pub mod derivation_scope;
pub mod divergence;
pub mod edge;
pub mod edge_encryption;
pub mod edge_signature;
pub mod ego;
pub mod elevated_access;
pub mod elevation_ceremony;
pub mod entity;
pub mod entity_type;
pub mod event;
pub mod evidence;
pub mod evidence_encryption;
pub mod experiment;
pub mod factor;
pub mod foreign_attach;
pub mod frame;
pub mod gap;
pub mod graph_view;
pub mod group;
pub mod group_key_epoch;
pub mod group_membership;
pub mod ingest_written;
pub mod instance_admin;
pub mod learning_event;
pub mod lineage;
pub mod maintenance_lock;
pub mod mass_function;
pub mod match_candidate;
pub mod method;
pub mod oauth_client;
pub mod paper;
pub mod passkey;
pub mod passkey_ceremony;
pub mod pattern_template;
pub mod perspective;
pub mod political;
pub mod privatization;
pub mod provenance;
pub mod provenance_chain;
pub mod recall_event;
pub mod refresh_token;
pub mod revoked_access_token;
pub mod role_assignment;
pub mod scoped_belief;
pub mod security_event;
pub mod semantic_link;
pub mod sheaf;
pub mod sources;
pub mod span;
pub mod structural;
pub mod system_agent;
pub mod task;
pub mod trace;
pub mod triple;
pub mod webhook;
pub mod workflow;
pub mod workflow_execution;

// Re-export all repositories for convenience
pub use activity::ActivityRepository;
pub use admin_act::{AdminActRepository, AdminActRow};
pub use admin_act_ceremony::{ActConfirmation, AdminActCeremony, CeremonyAct, ProposedAct};
pub use admin_scope_enforcement::{
    AdminScopeArmingCache, AdminScopeChange, AdminScopeEnforcement, AdminScopeState,
    AdminScopeSwitch,
};
pub use agent::{
    AgentCapabilitiesRow, AgentIdentityRow, AgentPublicProfile, AgentRepository, AuthorOperator,
    CapabilityFilter, OperatorLink, OperatorLinkOutcome, RetiredLinkOutcome, RoleAgentRunGate,
    SpeaksFor,
};
pub use agent::{DelegationLive, RunTokens, RUN_TOKENS_ENV};
pub use agent::{CLIENT_ALLOWLIST_BINDING, HUMAN_OPERATOR_BINDING, LIVE_LINK_BINDING};
pub use agent_identity::{
    AgentIdentityRepository, IdentityRegistered, IdentityRegistration, PromptBlob, PromptBlobRead,
    PromptFile, PromptHistoryEntry, PromptHistoryIndexEntry, PromptSnapshot, PromptSnapshotIndex,
};
pub use agent_key::{AgentKeyRepository, AgentKeyRow, AttestedKeyRow};
pub use agent_lookup::{
    AgentCard, AgentKind, AgentLookupRepository, AgentNameMatch, AgentRef, AgentSearchHit,
    AuthorNode, CardCounts, CardRole, FindAgentQuery, FindAgentResult, MatchTier,
};
pub use alternative_set::{AlternativePairRow, AlternativeSetRepository};
pub use analysis::{AnalysisRecord, AnalysisRepository, ClaimSummary};
pub use atlas_layout::{
    AtlasLayoutRepository, DetailPart, LayoutBuild, LayoutLinkCursor, LayoutLinkOut, LayoutLinkRow,
    LayoutOverview, LayoutRegionOut, LayoutRunRow, LayoutThemeOut, LinkPage, LinkPairCursor,
    LinkPairRow, LinkSide, LinkSideKind, PlacementLayoutRow, PublicLayoutInputs,
    PublicThemeCentroid, PublicThemeLinkCount, RegionDetail, ThemePageCursor, ThemePlacement,
    UnplacedCursor, UnplacedPage, VisibleRegionRow, VisibleThemeRow, ATLAS_DEFAULT_RELATIONSHIPS,
    ATLAS_LAYOUT_ALGO, ATLAS_LAYOUT_EXTENT, ATLAS_PAGE_MAX, ATLAS_STRUCTURE_RELATIONSHIPS,
};
pub use authored_by::{
    AgentAuthorship, AuthorRef, AuthoredBy, AuthoredByRepository, Corroboration, Filer, Ingester,
    LiteratureAuthorship, PaperAuthor, PaperAuthorship, PaperIngest, PaperRef, PromptSnapshotAt,
    PromptSnapshotAudience, PROMPT_SNAPSHOT_AUDIENCE,
};
pub use challenge::{ChallengeRepository, ChallengeRow, GapChallengeRow};
pub use claim::{
    carries_dedup_identity_key, reserved_edge_property_refusal, AdminClaimAction, AdminClaimWrite,
    AdminToken, BeliefBoundedClaimHit, BeliefSort, ClaimBeliefColumns, ClaimDispute,
    ClaimEmbeddingHit, ClaimListFilter, ClaimNeighbor, ClaimPairDistance, ClaimRepository,
    ClaimSortField, ClaimSortOrder, ConsolidateEdgeMigration, ConsolidateMode, ConsolidateResult,
    DedupRepair, DedupReversal, DedupRevert, DuplicateProvenance, EdgeTenancy, EmbeddingSeedScope,
    EvolveStepResult, FlatRanking, FrameClaimBeliefHit, GraphExpansionHit, GroundedNeighbor,
    HybridHit, LabelFamilyRow, LabelQuery, LevelAndSourceType, LineageHead, MarkedDuplicateRow,
    MarkedDuplicates, MovedBba, NearestClaimHit, PatchClaimDiff, PatchClaimInput, SortDirection,
    SupersedeActor, SupersedeEdgeMigration, SupersedeTool, SweepCandidate, UnmarkedDuplicate,
    CONSOLIDATE_MAX_SOURCES, CONSOLIDATE_MIN_SOURCES, DEDUP_IDENTITY_KEY_RESERVED,
    DUPLICATE_IDENTITY_PROPERTY, DUPLICATE_IDENTITY_RELATIONSHIP, EXPANSION_RELATIONSHIPS,
    RESERVED_EDGE_PROPERTIES, SUPERSEDE_ACT_KEY_RESERVED, SUPERSEDE_ACT_PROPERTY,
    SUPERSEDE_ACT_TOOLS,
};
pub use claim_context::{
    ClaimContextRepository, ContextClaimRow, ContextEdgeRow, ContextEdgeTally, ContextPage,
    ContextPaperRow, CONTEXT_EPISTEMIC_RELATIONSHIPS,
};
pub use claim_ingest::{
    credited_agent_end, ingest_only_edge_refusal, is_agent_attribution,
    staged_provenance_refusal_sql, ClaimIngestRecord, ClaimIngestRepository, ClaimIngests,
    CreditedEnd, AGENT_ATTRIBUTION_REFUSAL, AGENT_SOURCE_AUTHORSHIP, AGENT_TARGET_AUTHORSHIP,
    CREATED_CLAIM_PROPERTY, INGESTED_BY_PROPERTY, INGEST_ONLY_REFUSAL, INGEST_RECORD_KEYS_RESERVED,
    INGEST_RECORD_RELATIONSHIP, OPERATED_BY_REFUSAL, OPERATED_BY_RELATIONSHIP,
};
pub use claim_ingest::{INGEST_AUTHORS_PROPERTY, MAX_RECORDED_AUTHORS};
pub use claim_theme::{
    centroid_columns_for_dim, BoundaryClaimRow, ClaimThemeRepository, ClaimThemeRow,
    DistantClaimsRow, NeighbourhoodThemeCoverage, RecomputedThemeRow, SplitCandidateRow,
    ThemeMemberRow, ThemeOverviewCursor, ThemeOverviewPage, ThemeOverviewRow, ThemeSummaryRow,
    THEME_OVERVIEW_PAGE_MAX,
};
pub use claim_version::{ClaimVersionRepository, ClaimVersionRow};
pub use claim_visibility::{
    ChoiceResolution, DefaultGroupSetting, ResolvedWriteDecl, TeamWriteGrant, VisibilityActOutcome,
    WriteTenancyReport,
};
pub use cluster_run::{ClaimPlacement, ClusterRunRepository, ClusterRunRow};
pub use community::{CommunityRepository, MembershipOutcome};
pub use conflict_density::{ConflictDensityRepository, FrameConflictDensity};
pub use context::ContextRepository;
pub use corpus_stats::{CorpusCounts, CorpusStatsRepository};
pub use counterfactual::{CounterfactualRepository, CounterfactualRow};
pub use countersign::{CountersignDecision, CountersignRepository, CountersignedRow};
pub use divergence::DivergenceRepository;
pub use edge::EdgeRepository;
pub use ego::{EgoEdgeRow, EgoEdges, EgoEntity, EgoRepository};
pub use elevated_access::ElevatedAccess;
pub use elevation_ceremony::{
    AssertedCredential, CeremonyTicket, Confirmation, ElevationCeremony, EndReason, LiveElevation,
    Redemption, TicketMode, TicketPasskey,
};
pub use entity::{EntityRepository, EntityRow};
pub use entity_type::{EntityTypeEntry, EntityTypeRepository, TenancyPrecondition};
pub use event::{EventCursor, EventRepository, EventRow};
pub use evidence::{
    DerivationEvidence, EvidenceAtTimeRow, EvidenceDetailRow, EvidenceEdgeRow, EvidenceListFilter,
    EvidenceListRow, EvidenceRepository, EvidenceSearchResult,
};
pub use experiment::{
    ExperimentRepository, ExperimentResultRepository, ExperimentResultRow, ExperimentRow,
};
pub use factor::FactorRepository;
pub use frame::FrameRepository;
pub use gap::{GapAnalysisResult, GapRecord, GapRepository};
pub use graph_view::{
    AtomicNodeRow, CompoundGroupRow, CompoundNeighborRow, CompoundNodeRow, GqlColumn, GqlCondition,
    GqlDirection, GqlNodeTable, GqlOp, GqlValue, GqlWalk, GraphNodeRow, GraphViewRepository,
    SubgraphClaimRow, SubgraphEdgeRow, SubgraphEvidenceRow, SubgraphTraceRow,
};
pub use ingest_written::{
    create_ingest_written_edge_if_absent_conn, ingest_written_by_sql, ingest_written_edge_sql,
    same_ingest_sql, without_ingest_marker, INGEST_WRITTEN_BY_FIELD, INGEST_WRITTEN_KEY_RESERVED,
    INGEST_WRITTEN_PROPERTY, INGEST_WRITTEN_SETTING, INGEST_WRITTEN_SHAPES,
};
pub use learning_event::{LearningEventRepository, LearningEventRow};
pub use lineage::LineageRepository;
pub use mass_function::MassFunctionRepository;
pub use match_candidate::{
    DecideOutcome, MatchCandidateRepo, MatchCandidateRow, RetiredEdge, RetirementOutcome,
};
pub use method::{
    MethodCapability, MethodEvidenceStrength, MethodFailureModes, MethodForCapability,
    MethodRecord, MethodRepository, MethodSearchResult, MethodSourcePaper, MethodUsageExample,
};
pub use paper::{
    AssertedClaimRow, IngestAssertedClaimRow, PaperAuthorEdge, PaperAuthorListing,
    PaperIngestPrincipal, PaperRepository, PaperRow, AUTHORED_EXPLICIT_KEY,
    AUTHORED_INGESTED_BY_KEY, AUTHORED_NAME_KEY, AUTHORED_PENDING_KEY, AUTHORED_REPLACES_KEY,
    AUTHORED_REPLACES_KEY_RESERVED,
};
pub use perspective::PerspectiveRepository;
pub use political::{
    AgentClaimProfileRow, CoalitionRow, EvidenceTypeCount, PoliticalRepository,
    PropagandaTechniqueRow, PropagationStepRow, TimelineClaimRow,
};
pub use provenance_chain::{
    ProvenanceChain, ProvenanceChainRepository, ProvenanceEdge, ProvenanceNode, MAX_CHAIN_NODES,
    PROVENANCE_INCOMING, PROVENANCE_OUTGOING,
};
pub use recall_event::{
    NewRecallEvent, RecallEventRepository, RecallEventRow, DEFAULT_RETENTION_DAYS,
    PRUNABLE_EVENT_TYPES,
};
pub use scoped_belief::ScopedBeliefRepository;
pub use semantic_link::SemanticLinkRepository;
pub use sheaf::{ClaimNeighborBetpRow, EpistemicEdgePairRow, SheafRepository};
pub use sources::{
    SourceAuthor, SourceCursor, SourceDetail, SourceEntry, SourceKind, SourceOverviewRepository,
    SourcePage, SOURCES_PAGE_DEFAULT, SOURCES_PAGE_MAX, SOURCE_AUTHORS_MAX,
};
pub use structural::{BeliefIntervalRow, StructuralRepository};
pub use trace::{ReasoningTraceRepository, TraceProvenanceStep};
pub use triple::{IndexCounts, MentionRow, TripleRepository, TripleRow};
pub use webhook::{WebhookSubscriptionRepository, WebhookSubscriptionRow};
pub use workflow::{
    ExecutedClaim, FrozenPlanEdgeRow, FrozenPlanRead, FrozenPlanRow, HierarchicalWorkflowRow,
    ResolvedStep, ScoredHierarchicalWorkflowRow, WorkflowGoalEmbeddingHit, WorkflowListRow,
    WorkflowRecallResult, WorkflowRepository,
};

// Privacy / encryption repositories
pub use behavioral_execution::{BehavioralExecutionRepository, BehavioralExecutionRow};
pub use claim_encryption::{ClaimEncryptionRepository, ClaimEncryptionRow};
pub use edge_encryption::{EdgeEncryptionRepository, EdgeEncryptionRow};
pub use edge_signature::{
    edge_attestation_canonical_json, edge_attestation_digest, EdgeAttestation, EdgeSignOutcome,
    EdgeSignatureCheck, EdgeSignatureRepository, EdgeSigningCoverage, EdgeSigningKey,
};
pub use evidence_encryption::{EvidenceEncryptionRepository, EvidenceEncryptionRow};
pub use group::{GroupRepository, GroupRow};
pub use group_key_epoch::{GroupKeyEpochRepository, KeyEpochRow, RotateOutcome};
pub use group_membership::{GroupMembershipRepository, MembershipRow, RevokeOutcome};
pub use instance_admin::{InstanceAdminRepository, InstanceAdminRow};
pub use oauth_client::{OAuthClientRepository, OAuthClientRow};
pub use passkey::{CompromisedRevoke, PasskeyEnrollmentRow, PasskeyRepository, PasskeyRow};
pub use passkey_ceremony::{
    CeremonyEnrollment, EnrollmentAnchor, PasskeyCeremony, VerifiedPasskey,
};
pub use pattern_template::{PatternTemplateRepository, PatternTemplateRow};
pub use provenance::{ProvenanceLogRow, ProvenanceRepository, AUTO_POLICY_AUTHORIZER_ID};
pub use refresh_token::{
    RefreshCheck, RefreshRevokeReason, RefreshRotateOutcome, RefreshTokenRepository,
    RefreshTokenRow,
};
pub use revoked_access_token::RevokedAccessTokenRepository;
pub use role_assignment::{RoleAssignmentRepository, RoleAssignmentRow};
pub use security_event::{SecurityEventFilter, SecurityEventRepository, SecurityEventRow};
pub use span::{SpanRepository, SpanRow};
pub use system_agent::{SystemAgentLookup, SystemAgentRepository, SystemAgentRole};
pub use task::{TaskRepository, TaskRow};
pub use workflow_execution::{WorkflowExecutionRepository, WorkflowExecutionRow};

/// Compare what a write could SEE with what it CHANGED, and refuse loudly when
/// row security left a row it had to change as it was.
///
/// Migrations 115 and 117 made DELETE (every tier-A table) and UPDATE (`edges`
/// and the four registries) owner-scoped with RESTRICTIVE USING clauses. A
/// USING clause that refuses a row does not raise: the statement matches zero
/// rows and reports success. A caller that must change the rows it names runs
/// one statement shaped
///
/// ```sql
/// WITH seen AS (SELECT 1 FROM t WHERE <pred>),
///      done AS (DELETE FROM t WHERE <pred> RETURNING 1)
/// SELECT (SELECT count(*) FROM seen), (SELECT count(*) FROM done)
/// ```
///
/// (`seen` reads under the statement's snapshot, before the write) and hands
/// the pair here. Returns the number changed.
pub(crate) fn require_all_changed(
    entity: &str,
    id: uuid::Uuid,
    action: &str,
    (seen, done): (i64, i64),
) -> Result<u64, crate::errors::DbError> {
    if done < seen {
        return Err(crate::errors::DbError::WriteRefused {
            entity: entity.to_string(),
            id,
            action: action.to_string(),
        });
    }
    Ok(u64::try_from(done).unwrap_or(0))
}
