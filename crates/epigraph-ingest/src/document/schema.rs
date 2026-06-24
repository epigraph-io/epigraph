//! Schema types for document (paper) extraction.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};

/// A byte-offset span into `DocumentExtraction.source_text` (D9). Optional on
/// each node; when present, the writer re-verifies the node text against it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

/// Top-level extraction result from a document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DocumentExtraction {
    pub source: DocumentSource,
    #[serde(default)]
    pub thesis: Option<String>,
    #[serde(default)]
    pub thesis_derivation: ThesisDerivation,
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub relationships: Vec<ClaimRelationship>,
    /// Original source bytes the spans index into (D9). Present ⇒ the writer
    /// re-runs the verbatim guard. Tier 2 (HTML/CNXML) omits it.
    #[serde(default)]
    pub source_text: Option<String>,
}

/// Metadata about the source document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DocumentSource {
    pub title: String,
    #[serde(default)]
    pub doi: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub source_type: SourceType,
    #[serde(default)]
    pub authors: Vec<AuthorEntry>,
    #[serde(default)]
    pub journal: Option<String>,
    #[serde(default)]
    pub year: Option<u32>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// The type of source document.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub enum SourceType {
    #[default]
    Paper,
    Textbook,
    InternalDocument,
    Report,
    Transcript,
    Legal,
    Tabular,
}

/// A section within the document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Section {
    pub title: String,
    #[serde(default)]
    pub heading_span: Option<ByteSpan>,
    #[serde(default)]
    pub paragraphs: Vec<Paragraph>,
}

/// A paragraph containing atomic claims.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Paragraph {
    /// Verbatim source text (Tier 1) or faithful full extraction (Tier 2).
    pub text: String,
    #[serde(default)]
    pub span: Option<ByteSpan>,
    #[serde(default)]
    pub atoms: Vec<String>,
    #[serde(default)]
    pub generality: Vec<i32>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default)]
    pub methodology: Option<String>,
    /// Evidence type for this paragraph and its atoms. The extractor picks ONE
    /// canonical value from [`crate::common::evidence_type::EVIDENCE_TYPES`]
    /// (regulatory, empirical, statistical, logical, testimonial,
    /// circumstantial, conversational). Normalised at plan-build time; any
    /// unrecognised value is dropped to `None`.
    #[serde(default)]
    pub evidence_type: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub instruments_used: Vec<String>,
    #[serde(default)]
    pub reagents_involved: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<String>,
}

#[must_use]
pub fn default_confidence() -> f64 {
    0.8
}
