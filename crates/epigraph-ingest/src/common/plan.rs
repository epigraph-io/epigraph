//! Shared plan types for hierarchical artifact ingest. Used by both
//! `document::` (papers) and `workflow::` (workflows).

use std::collections::HashMap;
use uuid::Uuid;

/// Resolved axis placement for one planned claim (issue #222): the frame to
/// wire its BBA on, and which hypothesis index within that frame it asserts.
///
/// Produced from an `AxisDeclaration` after validation, so `hypothesis_index`
/// is guaranteed to be in range for `hypotheses` and `hypotheses.len() >= 2`.
/// `None` on a `PlannedClaim` means the default binary `{TRUE, FALSE}` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAxis {
    pub frame: String,
    pub hypotheses: Vec<String>,
    pub hypothesis_index: usize,
}

/// A planned claim to be persisted.
#[derive(Debug, Clone)]
pub struct PlannedClaim {
    pub id: Uuid,
    pub content: String,
    pub level: u8, // 0=thesis, 1=section/phase, 2=paragraph/step, 3=atom/operation
    pub properties: serde_json::Value,
    /// BLAKE3. The value a writer must store in `claims.content_hash` — NOT
    /// necessarily `blake3(content)`. For document-scoped (compound) claims
    /// the builder sets this to
    /// [`crate::common::ids::compound_content_hash`], which folds in the
    /// artifact seed; for atoms it is the plain content hash. Writers must
    /// bind this value rather than re-deriving from `content`.
    pub content_hash: [u8; 32],
    pub confidence: f64,
    pub methodology: Option<String>,
    pub evidence_type: Option<String>,
    /// Declared labeled axis this claim sits on, or `None` for `binary_truth`.
    pub axis: Option<PlannedAxis>,
    pub supporting_text: Option<String>,
    pub enrichment: serde_json::Value,
}

impl PlannedClaim {
    /// True iff `id` was minted with
    /// [`COMPOUND_NAMESPACE`](crate::common::ids::COMPOUND_NAMESPACE) — i.e.
    /// this is a structural node (thesis / section-phase / paragraph-step)
    /// whose identity is scoped to its host artifact.
    ///
    /// This is the single predicate a write path may use to choose between
    /// preserving the planner's id (`true`) and letting content-hash
    /// convergence pick the row (`false`). Levels 0–2 are minted by
    /// [`compound_claim_id`](crate::common::ids::compound_claim_id) and level 3
    /// by [`atom_id`](crate::common::ids::atom_id) in BOTH builders
    /// (`document::builder`, `workflow::builder`); the drift guard
    /// `planned_id_namespace_matches_declared_scope` in `lib.rs` re-derives
    /// every id in a built plan and fails if that ever stops holding.
    #[must_use]
    pub const fn id_is_document_scoped(&self) -> bool {
        self.level < 3
    }
}

/// A planned edge to be persisted.
#[derive(Debug, Clone)]
pub struct PlannedEdge {
    pub source_id: Uuid,
    pub source_type: String,
    pub target_id: Uuid,
    pub target_type: String,
    pub relationship: String,
    pub properties: serde_json::Value,
}

/// Complete plan of operations for ingesting a hierarchical artifact (paper
/// or workflow). The walker that produced this plan is the same in both cases;
/// only the source-node type, namespace seed, and label/relationship strings
/// differ between artifact kinds.
#[derive(Debug)]
pub struct IngestPlan {
    pub claims: Vec<PlannedClaim>,
    pub edges: Vec<PlannedEdge>,
    pub path_index: HashMap<String, Uuid>,
}
