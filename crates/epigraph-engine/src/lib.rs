//! Epistemic Engine for `EpiGraph`
//!
//! This crate implements the core epistemic algorithms:
//! - **Evidence Weighting**: Calculate how much a piece of evidence supports a claim
//! - **Bayesian Truth Update**: Update claim truth values based on new evidence
//! - **DAG Validation**: Ensure the reasoning graph has no cycles
//! - **Reputation Calculation**: Compute agent reputation from track record
//!
//! # Core Principle
//!
//! Truth values are **derived from evidence**, not from agent reputation.
//! A high-reputation agent making an unsupported claim gets low truth value.
//! This prevents the "Appeal to Authority" fallacy.

pub mod agent_assessment;
pub mod bayesian;
pub mod bba;
pub mod belief_gate;
pub mod belief_query;
pub mod bp;
pub mod calibration;
pub mod cdst_bp;
pub mod cdst_sheaf;
pub mod classifier;
pub mod confidence;
pub mod cospan;
pub mod counterfactual;
pub mod dag;
pub mod diverse_select;
pub mod domain_decay;
pub mod embedder;
pub mod epistemic_interval;
pub mod error_mass;
pub mod errors;
pub mod evidence;
pub mod interval_bp;
pub mod lifecycle;
pub mod promotion;
pub mod propagation;
pub mod reasoning;
pub mod recall;
pub mod reconciliation;
pub mod reputation;
pub mod retention;
pub mod service;
pub mod sheaf;
pub mod silence_alarm;
pub mod theme_cluster;
pub mod uncertainty;
pub mod unified_bp;
pub mod voi;

#[allow(deprecated)]
pub use bayesian::BayesianUpdater;
pub use belief_query::{get_belief, BeliefInterval, BeliefQueryError};
pub use bp::{run_bp, BpConfig, BpResult, FactorPotential};
pub use cdst_sheaf::{
    classify_obstruction, compute_cdst_cohomology, compute_cdst_edge_inconsistency,
    compute_cdst_expected, compute_cdst_section, CdstSheafCohomology, CdstSheafObstruction,
    CdstSheafSection, FrameEvidenceProposal, ObstructionKind,
};
pub use cospan::{
    compose_cdst_cospans, compose_cospans, BoundaryDetail, CdstCompositionResult,
    CdstDecoratedCospan, CompositionResult, DecoratedCospan,
};
pub use dag::DagValidator;
pub use epistemic_interval::{
    restrict_epistemic_frame_evidence, restrict_epistemic_negative, restrict_epistemic_positive,
    EpistemicInterval,
};
pub use error_mass::{
    build_error_mass, ErrorBudget, ErrorMassResult, EvidenceDirection, ScopeLimitation,
};
pub use errors::EngineError;
pub use evidence::{EvidenceType, EvidenceWeightConfig, EvidenceWeighter};
pub use interval_bp::{
    compute_interval_factor_message, run_interval_bp, IntervalBpConfig, IntervalBpResult,
};
pub use promotion::{evaluate_promotion, PromotionFailure, PromotionInput, PromotionResult};
pub use propagation::{
    ClaimDependency, ConcurrentOrchestrator, DatabasePropagator, PropagationAuditRecord,
    PropagationConfig, PropagationOrchestrator, PropagationResult,
};
pub use reasoning::{
    Contradiction, IndirectChallenge, ReasoningClaim, ReasoningEdge, ReasoningEngine,
    ReasoningResult, ReasoningStats, SupportCluster, TransitiveSupport,
};
pub use recall::{recall, RecallError, RecallResult};
pub use reconciliation::{
    cluster_obstructions, extract_cospan, reconcile, ClusterSummary, ReconciliationConfig,
    ReconciliationResult,
};
pub use reputation::ReputationCalculator;
pub use service::{
    ClaimProcessingResult, EpistemicService, EpistemicServiceBuilder, EpistemicServiceConfig,
    ReputationResult, ValidationResult,
};
pub use sheaf::{
    compute_cohomology, compute_edge_inconsistency, compute_expected_betp, compute_section,
    restriction_kind, RestrictionKind, SheafCohomology, SheafObstruction, SheafSection,
};
pub use voi::{compute_voi, Neighbor, VoiResult};
