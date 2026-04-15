use serde::{Deserialize, Serialize};

/// Top-level extraction result from a document.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Metadata about the source document.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
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

/// Whether the thesis was derived top-down or bottom-up.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThesisDerivation {
    #[default]
    TopDown,
    BottomUp,
}

/// An author with affiliations and roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorEntry {
    pub name: String,
    #[serde(default)]
    pub affiliations: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

/// A section within the document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub paragraphs: Vec<Paragraph>,
}

/// A paragraph containing atomic claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paragraph {
    pub compound: String,
    #[serde(default)]
    pub supporting_text: String,
    #[serde(default)]
    pub atoms: Vec<String>,
    #[serde(default)]
    pub generality: Vec<i32>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default)]
    pub methodology: Option<String>,
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

fn default_confidence() -> f64 {
    0.8
}

/// A relationship between two claims identified by path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRelationship {
    pub source_path: String,
    pub target_path: String,
    pub relationship: String,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub strength: Option<f64>,
}
