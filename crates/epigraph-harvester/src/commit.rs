//! Database commit layer for verified harvester extractions
//!
//! This module provides the `CommitHandler` which persists `VerifiedGraph` results
//! from the harvester intelligence worker to the database.
//!
//! # Responsibilities
//!
//! - Convert proto claims to domain `Claim` entities
//! - Create `Evidence` records from fragment citations
//! - Create `ReasoningTrace` records for each claim
//! - Sign all entities with the harvester agent key
//! - Persist atomically (all-or-nothing transaction)
//!
//! # Security Model
//!
//! All persisted entities are signed by the harvester agent to ensure:
//! - Provenance: Claims can be traced back to the harvester
//! - Integrity: Claims cannot be tampered with after extraction
//! - Accountability: The harvester agent is responsible for extractions

use crate::convert::{proto_claim_to_domain, PartialClaim};
use crate::errors::HarvesterError;
use crate::proto::{ExtractionStatus, VerifiedGraph};
use async_trait::async_trait;
use epigraph_core::{
    AgentId, Claim, ClaimId, ContentAddressable, Evidence, EvidenceId, EvidenceType,
    ReasoningTrace, Signable, TraceId, TraceInput, TruthValue,
};
use epigraph_crypto::{AgentSigner, ContentHasher};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

/// Result of committing a verified graph to the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResult {
    /// IDs of created claims
    pub claim_ids: Vec<ClaimId>,

    /// IDs of created evidence records
    pub evidence_ids: Vec<EvidenceId>,

    /// IDs of created reasoning traces
    pub trace_ids: Vec<TraceId>,

    /// Fragment ID that was processed
    pub fragment_id: String,

    /// Overall confidence of the extraction
    pub confidence: f64,
}

impl CommitResult {
    /// Create a new empty commit result for a fragment
    #[must_use]
    pub fn new(fragment_id: String, confidence: f64) -> Self {
        Self {
            claim_ids: Vec::new(),
            evidence_ids: Vec::new(),
            trace_ids: Vec::new(),
            fragment_id,
            confidence,
        }
    }

    /// Check if any entities were committed
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claim_ids.is_empty() && self.evidence_ids.is_empty() && self.trace_ids.is_empty()
    }

    /// Total number of entities committed
    #[must_use]
    pub fn entity_count(&self) -> usize {
        self.claim_ids.len() + self.evidence_ids.len() + self.trace_ids.len()
    }
}

/// Trait for claim repository operations
///
/// This abstraction allows testing with mock repositories.
#[async_trait]
pub trait ClaimStore: Send + Sync {
    /// Create a claim in the database
    async fn create(&self, claim: &Claim) -> Result<Claim, HarvesterError>;
}

/// Trait for evidence repository operations
#[async_trait]
pub trait EvidenceStore: Send + Sync {
    /// Create evidence in the database
    async fn create(&self, evidence: &Evidence) -> Result<Evidence, HarvesterError>;
}

/// Trait for reasoning trace repository operations
#[async_trait]
pub trait TraceStore: Send + Sync {
    /// Create a reasoning trace in the database
    async fn create(
        &self,
        trace: &ReasoningTrace,
        claim_id: ClaimId,
    ) -> Result<ReasoningTrace, HarvesterError>;
}

/// Trait for transaction management
#[async_trait]
pub trait TransactionManager: Send + Sync {
    /// Begin a transaction
    async fn begin(&self) -> Result<(), HarvesterError>;

    /// Commit the current transaction
    async fn commit(&self) -> Result<(), HarvesterError>;

    /// Rollback the current transaction
    async fn rollback(&self) -> Result<(), HarvesterError>;
}

/// Handler for committing verified graphs to the database
///
/// The `CommitHandler` is responsible for:
/// 1. Converting proto types to domain entities
/// 2. Signing all entities with the harvester agent key
/// 3. Persisting atomically within a transaction
///
/// # Example
///
/// ```rust,ignore
/// let handler = CommitHandler::new(
///     harvester_agent_id,
///     signer,
///     claim_store,
///     evidence_store,
///     trace_store,
///     tx_manager,
/// );
///
/// let result = handler.commit_verified_graph(graph, agent_id).await?;
/// println!("Committed {} claims", result.claim_ids.len());
/// ```
pub struct CommitHandler<C, E, T, TX>
where
    C: ClaimStore,
    E: EvidenceStore,
    T: TraceStore,
    TX: TransactionManager,
{
    /// The harvester agent's ID (used for signing)
    harvester_agent_id: AgentId,

    /// The signer for the harvester agent
    signer: Arc<AgentSigner>,

    /// Claim repository
    claim_store: Arc<C>,

    /// Evidence repository
    evidence_store: Arc<E>,

    /// Trace repository
    trace_store: Arc<T>,

    /// Transaction manager
    tx_manager: Arc<TX>,
}

impl<C, E, T, TX> CommitHandler<C, E, T, TX>
where
    C: ClaimStore,
    E: EvidenceStore,
    T: TraceStore,
    TX: TransactionManager,
{
    /// Create a new commit handler
    #[must_use]
    pub fn new(
        harvester_agent_id: AgentId,
        signer: Arc<AgentSigner>,
        claim_store: Arc<C>,
        evidence_store: Arc<E>,
        trace_store: Arc<T>,
        tx_manager: Arc<TX>,
    ) -> Self {
        Self {
            harvester_agent_id,
            signer,
            claim_store,
            evidence_store,
            trace_store,
            tx_manager,
        }
    }

    /// Commit a verified graph to the database atomically
    ///
    /// This method:
    /// 1. Validates the graph status (must be SUCCESS or PARTIAL_SUCCESS)
    /// 2. Converts proto claims to domain claims
    /// 3. Creates evidence from citations
    /// 4. Creates reasoning traces
    /// 5. Signs and persists all entities
    ///
    /// # Arguments
    /// * `graph` - The verified graph from the harvester
    /// * `source_agent_id` - The agent who submitted the original document
    ///
    /// # Errors
    /// Returns error if:
    /// - Graph status is FAILED or NO_CONTENT
    /// - Database operations fail
    /// - Transaction cannot be completed
    ///
    /// On error, the transaction is rolled back and no entities are persisted.
    #[instrument(skip(self, graph), fields(fragment_id = %graph.fragment_id))]
    pub async fn commit_verified_graph(
        &self,
        graph: VerifiedGraph,
        source_agent_id: AgentId,
    ) -> Result<CommitResult, HarvesterError> {
        // Validate graph status
        let status = ExtractionStatus::try_from(graph.status).unwrap_or(ExtractionStatus::Failed);

        match status {
            ExtractionStatus::Failed => {
                return Err(HarvesterError::ExtractionFailed {
                    fragment_id: graph.fragment_id.clone(),
                    reason: graph.error_message.clone(),
                });
            }
            ExtractionStatus::NoContent => {
                debug!("No content to commit for fragment {}", graph.fragment_id);
                return Ok(CommitResult::new(
                    graph.fragment_id,
                    f64::from(graph.overall_confidence),
                ));
            }
            ExtractionStatus::TransientError => {
                return Err(HarvesterError::ExtractionFailed {
                    fragment_id: graph.fragment_id.clone(),
                    reason: "Transient error - retry recommended".to_string(),
                });
            }
            _ => {
                // SUCCESS, LOW_CONFIDENCE, PARTIAL_SUCCESS are all valid
            }
        }

        // Begin transaction
        self.tx_manager.begin().await?;

        let result = self.commit_internal(&graph, source_agent_id).await;

        match result {
            Ok(commit_result) => {
                self.tx_manager.commit().await?;
                info!(
                    "Committed {} claims, {} evidence, {} traces for fragment {}",
                    commit_result.claim_ids.len(),
                    commit_result.evidence_ids.len(),
                    commit_result.trace_ids.len(),
                    commit_result.fragment_id
                );
                Ok(commit_result)
            }
            Err(e) => {
                warn!("Commit failed, rolling back: {}", e);
                // Attempt rollback, but don't mask the original error
                let _ = self.tx_manager.rollback().await;
                Err(e)
            }
        }
    }

    /// Internal commit logic (runs within a transaction)
    async fn commit_internal(
        &self,
        graph: &VerifiedGraph,
        source_agent_id: AgentId,
    ) -> Result<CommitResult, HarvesterError> {
        let mut result = CommitResult::new(
            graph.fragment_id.clone(),
            f64::from(graph.overall_confidence),
        );

        // Convert and persist each claim
        for proto_claim in &graph.claims {
            // Convert proto claim to partial claim
            let partial = proto_claim_to_domain(proto_claim)?;

            // Create and persist claim, evidence, and trace
            let (claim_id, evidence_id, trace_id) = self
                .create_claim_with_evidence_and_trace(&partial, source_agent_id, &graph.fragment_id)
                .await?;

            result.claim_ids.push(claim_id);
            if let Some(eid) = evidence_id {
                result.evidence_ids.push(eid);
            }
            result.trace_ids.push(trace_id);
        }

        Ok(result)
    }

    /// Create a claim along with its evidence and reasoning trace
    ///
    /// This creates:
    /// 1. Evidence from the first citation (if any)
    /// 2. A reasoning trace linking evidence to claim
    /// 3. The claim with trace_id already set (so signature is valid)
    ///
    /// Note: We create trace first (with a temporary claim ID), then create
    /// the claim with the trace_id already set, so the signature covers
    /// the complete claim state.
    async fn create_claim_with_evidence_and_trace(
        &self,
        partial: &PartialClaim,
        source_agent_id: AgentId,
        fragment_id: &str,
    ) -> Result<(ClaimId, Option<EvidenceId>, TraceId), HarvesterError> {
        // Calculate initial truth value based on confidence and methodology
        let initial_truth = self.calculate_initial_truth(partial);

        // We need to create the claim ID first so we can reference it
        let claim_id = ClaimId::new();

        // Create evidence from the first citation (if any)
        let evidence_id = if let Some(citation) = partial.citations.first() {
            let evidence = self.create_evidence_from_citation(citation, claim_id, fragment_id)?;
            let created_evidence = self.evidence_store.create(&evidence).await?;
            Some(created_evidence.id)
        } else {
            None
        };

        // Create reasoning trace
        let trace = self.create_reasoning_trace(partial, evidence_id, source_agent_id)?;
        let created_trace = self.trace_store.create(&trace, claim_id).await?;
        let trace_id = created_trace.id;

        // Now create the claim with trace_id already set (so signature is valid)
        let mut claim = Claim::new_with_trace(
            partial.content.clone(),
            self.harvester_agent_id,
            self.signer.public_key(),
            trace_id,
            initial_truth,
        );

        // Override the generated ID with our pre-created one
        // Note: We need to use with_id to set the ID, but we want to keep other fields
        claim = Claim::with_id(
            claim_id,
            claim.content,
            claim.agent_id,
            claim.public_key,
            claim.content_hash,
            claim.trace_id,
            claim.signature,
            claim.truth_value,
            claim.created_at,
            claim.updated_at,
        );

        // Compute content hash and sign
        claim
            .update_hash()
            .map_err(|e| HarvesterError::InvalidResponse {
                reason: format!("Failed to hash claim: {}", e),
            })?;
        claim
            .sign(&self.signer)
            .map_err(|e| HarvesterError::InvalidResponse {
                reason: format!("Failed to sign claim: {}", e),
            })?;

        // Persist claim (now with trace_id and valid signature)
        self.claim_store.create(&claim).await?;

        Ok((claim_id, evidence_id, trace_id))
    }

    /// Calculate initial truth value for a claim
    ///
    /// CRITICAL: This follows EpiGraph's anti-authority principle.
    /// Truth is calculated from evidence quality, NOT from agent reputation.
    fn calculate_initial_truth(&self, partial: &PartialClaim) -> TruthValue {
        // Base truth from extraction confidence
        let mut truth = partial.confidence;

        // Apply methodology weight modifier
        let weight = partial.methodology.weight_modifier();
        truth *= weight;

        // Penalize low-confidence flagged claims
        if partial.low_confidence_flag {
            truth *= 0.7;
        }

        // Clamp to valid range [0.01, 0.99] to prevent certainty lock-in
        truth = truth.clamp(0.01, 0.99);

        TruthValue::new(truth).unwrap_or_else(|_| TruthValue::uncertain())
    }

    /// Create evidence from a citation
    fn create_evidence_from_citation(
        &self,
        citation: &crate::convert::Citation,
        claim_id: ClaimId,
        fragment_id: &str,
    ) -> Result<Evidence, HarvesterError> {
        // Hash the citation content
        let content_bytes = citation.quote.as_bytes();
        let content_hash_vec = ContentHasher::hash(content_bytes);
        let mut content_hash = [0u8; 32];
        content_hash.copy_from_slice(&content_hash_vec);

        // Create evidence with Document type
        let evidence_type = EvidenceType::Document {
            source_url: Some(format!("fragment://{}", fragment_id)),
            mime_type: "text/plain".to_string(),
            checksum: None,
        };

        let mut evidence = Evidence::new(
            self.harvester_agent_id,
            self.signer.public_key(),
            content_hash,
            evidence_type,
            Some(citation.quote.clone()),
            claim_id,
        );

        // Sign the evidence
        evidence
            .sign(&self.signer)
            .map_err(|e| HarvesterError::InvalidResponse {
                reason: format!("Failed to sign evidence: {}", e),
            })?;

        Ok(evidence)
    }

    /// Create a reasoning trace for a claim
    fn create_reasoning_trace(
        &self,
        partial: &PartialClaim,
        evidence_id: Option<EvidenceId>,
        _source_agent_id: AgentId,
    ) -> Result<ReasoningTrace, HarvesterError> {
        // Build trace inputs
        let inputs = if let Some(eid) = evidence_id {
            vec![TraceInput::Evidence { id: eid }]
        } else {
            vec![]
        };

        // Build explanation from reasoning trace and agent name
        let explanation = if let Some(ref trace) = partial.reasoning_trace {
            if let Some(ref agent_name) = partial.agent_name {
                format!("{} (attributed to {})", trace, agent_name)
            } else {
                trace.clone()
            }
        } else {
            "Extracted from source document".to_string()
        };

        let mut trace = ReasoningTrace::new(
            self.harvester_agent_id,
            self.signer.public_key(),
            partial.methodology,
            inputs,
            partial.confidence,
            explanation,
        );

        // Compute hash and sign
        trace
            .update_hash()
            .map_err(|e| HarvesterError::InvalidResponse {
                reason: format!("Failed to hash trace: {}", e),
            })?;
        trace
            .sign(&self.signer)
            .map_err(|e| HarvesterError::InvalidResponse {
                reason: format!("Failed to sign trace: {}", e),
            })?;

        Ok(trace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        Citation as ProtoCitation, ClaimType, ExtractedClaim, Methodology as ProtoMethodology,
    };
    use epigraph_core::Verifiable;
    use std::sync::Mutex;

    // ==================== Mock Implementations ====================

    /// Mock claim store for testing
    struct MockClaimStore {
        created_claims: Mutex<Vec<Claim>>,
        should_fail: Mutex<bool>,
    }

    impl MockClaimStore {
        fn new() -> Self {
            Self {
                created_claims: Mutex::new(Vec::new()),
                should_fail: Mutex::new(false),
            }
        }

        fn set_should_fail(&self, fail: bool) {
            *self.should_fail.lock().unwrap() = fail;
        }
    }

    #[async_trait]
    impl ClaimStore for MockClaimStore {
        async fn create(&self, claim: &Claim) -> Result<Claim, HarvesterError> {
            if *self.should_fail.lock().unwrap() {
                return Err(HarvesterError::ExtractionFailed {
                    fragment_id: "test".to_string(),
                    reason: "Mock failure".to_string(),
                });
            }
            let mut claims = self.created_claims.lock().unwrap();
            claims.push(claim.clone());
            Ok(claim.clone())
        }
    }

    /// Mock evidence store for testing
    struct MockEvidenceStore {
        created_evidence: Mutex<Vec<Evidence>>,
    }

    impl MockEvidenceStore {
        fn new() -> Self {
            Self {
                created_evidence: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl EvidenceStore for MockEvidenceStore {
        async fn create(&self, evidence: &Evidence) -> Result<Evidence, HarvesterError> {
            let mut list = self.created_evidence.lock().unwrap();
            list.push(evidence.clone());
            Ok(evidence.clone())
        }
    }

    /// Mock trace store for testing
    struct MockTraceStore {
        created_traces: Mutex<Vec<(ReasoningTrace, ClaimId)>>,
    }

    impl MockTraceStore {
        fn new() -> Self {
            Self {
                created_traces: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl TraceStore for MockTraceStore {
        async fn create(
            &self,
            trace: &ReasoningTrace,
            claim_id: ClaimId,
        ) -> Result<ReasoningTrace, HarvesterError> {
            let mut list = self.created_traces.lock().unwrap();
            list.push((trace.clone(), claim_id));
            Ok(trace.clone())
        }
    }

    /// Mock transaction manager for testing
    struct MockTxManager {
        began: Mutex<bool>,
        committed: Mutex<bool>,
        rolled_back: Mutex<bool>,
    }

    impl MockTxManager {
        fn new() -> Self {
            Self {
                began: Mutex::new(false),
                committed: Mutex::new(false),
                rolled_back: Mutex::new(false),
            }
        }

        fn was_committed(&self) -> bool {
            *self.committed.lock().unwrap()
        }

        fn was_rolled_back(&self) -> bool {
            *self.rolled_back.lock().unwrap()
        }
    }

    #[async_trait]
    impl TransactionManager for MockTxManager {
        async fn begin(&self) -> Result<(), HarvesterError> {
            *self.began.lock().unwrap() = true;
            Ok(())
        }

        async fn commit(&self) -> Result<(), HarvesterError> {
            *self.committed.lock().unwrap() = true;
            Ok(())
        }

        async fn rollback(&self) -> Result<(), HarvesterError> {
            *self.rolled_back.lock().unwrap() = true;
            Ok(())
        }
    }

    // ==================== Test Helpers ====================

    fn create_test_handler() -> (
        CommitHandler<MockClaimStore, MockEvidenceStore, MockTraceStore, MockTxManager>,
        Arc<MockClaimStore>,
        Arc<MockEvidenceStore>,
        Arc<MockTraceStore>,
        Arc<MockTxManager>,
    ) {
        let signer = Arc::new(AgentSigner::generate());
        let agent_id = AgentId::new();
        let claim_store = Arc::new(MockClaimStore::new());
        let evidence_store = Arc::new(MockEvidenceStore::new());
        let trace_store = Arc::new(MockTraceStore::new());
        let tx_manager = Arc::new(MockTxManager::new());

        let handler = CommitHandler::new(
            agent_id,
            signer,
            Arc::clone(&claim_store),
            Arc::clone(&evidence_store),
            Arc::clone(&trace_store),
            Arc::clone(&tx_manager),
        );

        (
            handler,
            claim_store,
            evidence_store,
            trace_store,
            tx_manager,
        )
    }

    fn create_test_graph(claims: Vec<ExtractedClaim>) -> VerifiedGraph {
        VerifiedGraph {
            fragment_id: "test-fragment-123".to_string(),
            status: ExtractionStatus::Success as i32,
            claims,
            concepts: vec![],
            relations: vec![],
            audit_trail: None,
            overall_confidence: 0.85,
            error_message: String::new(),
        }
    }

    fn create_test_claim(id: &str, statement: &str) -> ExtractedClaim {
        ExtractedClaim {
            id: id.to_string(),
            statement: statement.to_string(),
            agent_name: "Test Author".to_string(),
            reasoning_trace: "Based on experimental evidence".to_string(),
            methodology: ProtoMethodology::Extraction as i32,
            citations: vec![ProtoCitation {
                quote: "This is the cited text".to_string(),
                char_start: 0,
                char_end: 25,
            }],
            claim_type: ClaimType::Factual as i32,
            confidence: 0.8,
            low_confidence_flag: false,
        }
    }

    // ==================== Tests ====================

    #[tokio::test]
    async fn test_successful_commit() {
        let (handler, claim_store, evidence_store, trace_store, tx_manager) = create_test_handler();

        let graph = create_test_graph(vec![
            create_test_claim("claim-1", "The Earth is round"),
            create_test_claim("claim-2", "Water is H2O"),
        ]);

        let source_agent = AgentId::new();
        let result = handler.commit_verified_graph(graph, source_agent).await;

        assert!(result.is_ok(), "Commit should succeed");

        let commit_result = result.unwrap();
        assert_eq!(commit_result.claim_ids.len(), 2, "Should have 2 claims");
        assert_eq!(
            commit_result.evidence_ids.len(),
            2,
            "Should have 2 evidence records"
        );
        assert_eq!(commit_result.trace_ids.len(), 2, "Should have 2 traces");
        assert_eq!(commit_result.fragment_id, "test-fragment-123");

        // Verify transaction was committed
        assert!(
            tx_manager.was_committed(),
            "Transaction should be committed"
        );
        assert!(
            !tx_manager.was_rolled_back(),
            "Transaction should not be rolled back"
        );

        // Verify claims were stored
        let claims = claim_store.created_claims.lock().unwrap();
        assert_eq!(claims.len(), 2);
        assert!(claims[0].is_signed(), "Claims should be signed");

        // Verify evidence was stored
        let evidence = evidence_store.created_evidence.lock().unwrap();
        assert_eq!(evidence.len(), 2);
        assert!(evidence[0].is_signed(), "Evidence should be signed");

        // Verify traces were stored
        let traces = trace_store.created_traces.lock().unwrap();
        assert_eq!(traces.len(), 2);
    }

    #[tokio::test]
    async fn test_rollback_on_failure() {
        let (handler, claim_store, _evidence_store, _trace_store, tx_manager) =
            create_test_handler();

        // Configure mock to fail
        claim_store.set_should_fail(true);

        let graph = create_test_graph(vec![create_test_claim("claim-1", "Test claim")]);
        let source_agent = AgentId::new();

        let result = handler.commit_verified_graph(graph, source_agent).await;

        assert!(result.is_err(), "Commit should fail");

        // Verify transaction was rolled back
        assert!(
            tx_manager.was_rolled_back(),
            "Transaction should be rolled back"
        );
        assert!(
            !tx_manager.was_committed(),
            "Transaction should not be committed"
        );
    }

    #[tokio::test]
    async fn test_failed_graph_status_rejected() {
        let (handler, _claim_store, _evidence_store, _trace_store, _tx_manager) =
            create_test_handler();

        let mut graph = create_test_graph(vec![create_test_claim("claim-1", "Test")]);
        graph.status = ExtractionStatus::Failed as i32;
        graph.error_message = "LLM extraction failed".to_string();

        let result = handler.commit_verified_graph(graph, AgentId::new()).await;

        assert!(result.is_err());
        if let Err(HarvesterError::ExtractionFailed { reason, .. }) = result {
            assert!(reason.contains("LLM extraction failed"));
        } else {
            panic!("Expected ExtractionFailed error");
        }
    }

    #[tokio::test]
    async fn test_no_content_returns_empty_result() {
        let (handler, _claim_store, _evidence_store, _trace_store, _tx_manager) =
            create_test_handler();

        let mut graph = create_test_graph(vec![]);
        graph.status = ExtractionStatus::NoContent as i32;

        let result = handler.commit_verified_graph(graph, AgentId::new()).await;

        assert!(result.is_ok());
        let commit_result = result.unwrap();
        assert!(commit_result.is_empty(), "Should have no entities");
    }

    #[tokio::test]
    async fn test_low_confidence_flag_reduces_truth() {
        let (handler, claim_store, _evidence_store, _trace_store, _tx_manager) =
            create_test_handler();

        // Create a low-confidence claim
        let mut low_conf_claim = create_test_claim("low-conf", "Uncertain claim");
        low_conf_claim.low_confidence_flag = true;
        low_conf_claim.confidence = 0.9; // High extraction confidence

        let graph = create_test_graph(vec![low_conf_claim]);

        let result = handler.commit_verified_graph(graph, AgentId::new()).await;
        assert!(result.is_ok());

        let claims = claim_store.created_claims.lock().unwrap();
        assert_eq!(claims.len(), 1);

        // Truth should be reduced due to low_confidence_flag
        // Base: 0.9 * 0.75 (Extraction weight) * 0.7 (low conf penalty) = 0.4725
        let truth = claims[0].truth_value.value();
        assert!(
            truth < 0.6,
            "Low confidence flag should reduce truth. Got: {}",
            truth
        );
    }

    #[tokio::test]
    async fn test_claim_without_citation_has_no_evidence() {
        let (handler, _claim_store, evidence_store, _trace_store, _tx_manager) =
            create_test_handler();

        let mut claim = create_test_claim("no-citation", "Claim without citation");
        claim.citations = vec![]; // No citations

        let graph = create_test_graph(vec![claim]);

        let result = handler.commit_verified_graph(graph, AgentId::new()).await;
        assert!(result.is_ok());

        let commit_result = result.unwrap();
        assert_eq!(commit_result.claim_ids.len(), 1);
        assert!(
            commit_result.evidence_ids.is_empty(),
            "Should have no evidence without citations"
        );

        // Verify no evidence was stored
        let evidence = evidence_store.created_evidence.lock().unwrap();
        assert!(evidence.is_empty());
    }

    #[tokio::test]
    async fn test_partial_success_is_accepted() {
        let (handler, claim_store, _evidence_store, _trace_store, tx_manager) =
            create_test_handler();

        let mut graph = create_test_graph(vec![create_test_claim("claim-1", "Partial claim")]);
        graph.status = ExtractionStatus::PartialSuccess as i32;

        let result = handler.commit_verified_graph(graph, AgentId::new()).await;

        assert!(result.is_ok(), "Partial success should be accepted");
        assert!(tx_manager.was_committed());

        let claims = claim_store.created_claims.lock().unwrap();
        assert_eq!(claims.len(), 1);
    }

    #[tokio::test]
    async fn test_commit_result_entity_count() {
        let result = CommitResult {
            claim_ids: vec![ClaimId::new(), ClaimId::new()],
            evidence_ids: vec![EvidenceId::new()],
            trace_ids: vec![TraceId::new(), TraceId::new()],
            fragment_id: "test".to_string(),
            confidence: 0.9,
        };

        assert_eq!(result.entity_count(), 5);
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn test_claims_are_signed_with_harvester_key() {
        let (handler, claim_store, _evidence_store, _trace_store, _tx_manager) =
            create_test_handler();

        let graph = create_test_graph(vec![create_test_claim("claim-1", "Signed claim")]);

        let result = handler.commit_verified_graph(graph, AgentId::new()).await;
        assert!(result.is_ok());

        let claims = claim_store.created_claims.lock().unwrap();
        assert_eq!(claims.len(), 1);

        let claim = &claims[0];
        assert!(claim.is_signed(), "Claim must be signed");
        assert!(claim.signature.is_some(), "Signature must be present");

        // Verify the signature is valid
        let is_valid = claim.verify().expect("Verification should succeed");
        assert!(is_valid, "Signature should be valid");
    }

    #[tokio::test]
    async fn test_traces_are_linked_to_claims() {
        let (handler, claim_store, _evidence_store, trace_store, _tx_manager) =
            create_test_handler();

        let graph = create_test_graph(vec![create_test_claim("claim-1", "Claim with trace")]);

        let result = handler.commit_verified_graph(graph, AgentId::new()).await;
        assert!(result.is_ok());

        let commit_result = result.unwrap();
        let claim_id = commit_result.claim_ids[0];
        let trace_id = commit_result.trace_ids[0];

        // Check that claim has trace_id set
        let claims = claim_store.created_claims.lock().unwrap();
        let claim = claims.iter().find(|c| c.id == claim_id).unwrap();
        assert_eq!(
            claim.trace_id,
            Some(trace_id),
            "Claim should reference its trace"
        );
        assert!(
            claim.has_reasoning_trace(),
            "Claim must have reasoning trace"
        );

        // Check that trace was stored with claim_id
        let traces = trace_store.created_traces.lock().unwrap();
        let (trace, stored_claim_id) = traces.iter().find(|(t, _)| t.id == trace_id).unwrap();
        assert_eq!(
            *stored_claim_id, claim_id,
            "Trace should reference its claim"
        );
        assert!(trace.is_signed(), "Trace must be signed");
    }
}
