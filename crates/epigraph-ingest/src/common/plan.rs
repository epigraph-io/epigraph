//! Shared plan types for hierarchical artifact ingest. Used by both
//! `document::` (papers) and `workflow::` (workflows).

use std::collections::HashMap;
use uuid::Uuid;

/// A planned claim to be persisted.
#[derive(Debug, Clone)]
pub struct PlannedClaim {
    pub id: Uuid,
    pub content: String,
    pub level: u8, // 0=thesis, 1=section/phase, 2=paragraph/step, 3=atom/operation
    pub properties: serde_json::Value,
    pub content_hash: [u8; 32], // BLAKE3
    pub confidence: f64,
    pub methodology: Option<String>,
    pub evidence_type: Option<String>,
    pub supporting_text: Option<String>,
    pub enrichment: serde_json::Value,
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
