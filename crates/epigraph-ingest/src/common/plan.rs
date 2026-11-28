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
    /// artifact seed; for atoms it is the plain content hash, except in a
    /// non-public document ingest, where it is
    /// [`crate::common::ids::scoped_atom_content_hash`]. Writers must bind
    /// this value rather than re-deriving from `content`.
    pub content_hash: [u8; 32],
    pub confidence: f64,
    pub methodology: Option<String>,
    pub evidence_type: Option<String>,
    /// Declared labeled axis this claim sits on, or `None` for `binary_truth`.
    pub axis: Option<PlannedAxis>,
    pub supporting_text: Option<String>,
    /// Where this claim's supporting passage sits in the source, e.g.
    /// `sections[0].paragraphs[2] ("Intro"), bytes 120..340`. The evidence
    /// writer stores this locator plus a BLAKE3 hash of the passage instead of
    /// the passage itself unless the source's licence permits retention
    /// (backlog 8709d128). A document locator ends in exactly one of two ways
    /// (backlog c083c1c9): a byte span into `source_text` whose bytes ARE the
    /// hashed passage (the extractor's span when its source bytes are the
    /// passage, else the passage found verbatim in `source_text`), so a
    /// reader who holds the source can re-derive the quote and check the
    /// hash; or
    /// [`NOT_SOURCE_VERIFIABLE`](crate::document::builder::NOT_SOURCE_VERIFIABLE)
    /// when there is no `source_text` (Tier 2) or the passage does not occur
    /// in it, where the hash pins only what the extractor emitted. `None` for
    /// plans with no source document (workflows).
    pub supporting_locator: Option<String>,
    pub enrichment: serde_json::Value,
    /// The owning group folded into this claim's id and stored hash, or `None`
    /// for a global (public-ingest or workflow) id. See
    /// [`crate::common::ids`], "Scope-derived ids". A scoped claim's
    /// `properties` also carry
    /// [`ID_SCOPE_KEY`](crate::common::ids::ID_SCOPE_KEY) so a reader of the
    /// persisted row knows it.
    pub id_scope: Option<Uuid>,
}

impl PlannedClaim {
    /// True iff `id` is NOT the global content address
    /// `uuid_v5(ATOM_NAMESPACE, blake3(content))`: a structural node (thesis /
    /// section-phase / paragraph-step) minted with
    /// [`COMPOUND_NAMESPACE`](crate::common::ids::COMPOUND_NAMESPACE) and
    /// scoped to its host artifact, or an atom of a non-public ingest whose id
    /// folds in its owning group
    /// ([`scoped_atom_id`](crate::common::ids::scoped_atom_id), `id_scope`
    /// set).
    ///
    /// This is the single predicate a write path may use to choose between
    /// preserving the planner's id (`true`) and letting content-hash
    /// convergence pick the row (`false`). A scoped atom MUST take the id
    /// path: content-hash convergence looks the text up in every scope, which
    /// is exactly what a non-public ingest may not do. Levels 0–2 are minted by
    /// [`compound_claim_id`](crate::common::ids::compound_claim_id) and level 3
    /// by [`scoped_atom_id`](crate::common::ids::scoped_atom_id) (with no
    /// scope, [`atom_id`](crate::common::ids::atom_id)) in BOTH builders
    /// (`document::builder`, `workflow::builder`); the drift guard
    /// `planned_id_namespace_matches_declared_scope` in `lib.rs` re-derives
    /// every id in a built plan, public and scoped, and fails if that ever
    /// stops holding.
    #[must_use]
    pub const fn id_is_document_scoped(&self) -> bool {
        self.level < 3 || self.id_scope.is_some()
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
