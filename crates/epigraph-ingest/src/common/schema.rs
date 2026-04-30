//! Schema types shared across `document::` and `workflow::` artifact kinds.

use serde::{Deserialize, Serialize};

/// An author with affiliations and roles. Workflows can be authored by humans,
/// LLMs, or external systems — same shape as document authors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorEntry {
    pub name: String,
    #[serde(default)]
    pub affiliations: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

/// A relationship between two claims identified by path. Workflow steps can
/// support / contradict / refute each other across phases just like document
/// atoms can across paragraphs.
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

/// Whether the thesis was derived top-down or bottom-up.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThesisDerivation {
    #[default]
    TopDown,
    BottomUp,
}
