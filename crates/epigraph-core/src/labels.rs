//! Labels for classifying nodes in the property graph
//!
//! Labels enable dynamic ontology - node types are stored as data, not schema.

use crate::errors::CoreError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A validated label for classifying nodes
///
/// Labels follow a restricted format to ensure consistency:
/// - Alphanumeric characters and underscores only
/// - Must start with a letter
/// - Case-sensitive (convention: `PascalCase` for types, `snake_case` for domains)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Label(String);

impl Label {
    /// Create a new label with validation
    ///
    /// # Errors
    /// Returns `CoreError::InvalidLabel` if the label doesn't match the required format.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        Self::validate(&value)?;
        Ok(Self(value))
    }

    /// Create a label without validation (for trusted internal use)
    ///
    /// # Panics
    /// This function does not panic, but passing an invalid label format
    /// may cause unexpected behavior in serialization or validation contexts.
    ///
    /// # Correctness
    /// Caller must ensure the value is a valid label format (alphanumeric + underscore,
    /// starting with a letter). This is intended for well-known constants only.
    #[must_use]
    pub const fn new_unchecked(value: String) -> Self {
        Self(value)
    }

    /// Get the label value as a string slice
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(value: &str) -> Result<(), CoreError> {
        if value.is_empty() {
            return Err(CoreError::InvalidLabel {
                value: value.to_string(),
                reason: "label cannot be empty".to_string(),
            });
        }

        // Safe: we verified value is non-empty above
        let first_char = value.chars().next().expect("already checked non-empty");
        if !first_char.is_ascii_alphabetic() {
            return Err(CoreError::InvalidLabel {
                value: value.to_string(),
                reason: "label must start with a letter".to_string(),
            });
        }

        if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(CoreError::InvalidLabel {
                value: value.to_string(),
                reason: "label must contain only alphanumeric characters and underscores"
                    .to_string(),
            });
        }

        Ok(())
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for Label {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Label> for String {
    fn from(label: Label) -> Self {
        label.0
    }
}

/// Well-known labels for `EpiGraph` domain types
///
/// These are lazily initialized on first access to avoid
/// repeated allocations.
pub mod well_known {
    use super::Label;
    use std::sync::OnceLock;

    /// Claim node - an assertion with a truth value
    pub fn claim() -> &'static Label {
        static CLAIM: OnceLock<Label> = OnceLock::new();
        CLAIM.get_or_init(|| Label::new_unchecked("Claim".to_string()))
    }

    /// Evidence node - supporting material for claims
    pub fn evidence() -> &'static Label {
        static EVIDENCE: OnceLock<Label> = OnceLock::new();
        EVIDENCE.get_or_init(|| Label::new_unchecked("Evidence".to_string()))
    }

    /// Agent node - entity that creates claims/evidence
    pub fn agent() -> &'static Label {
        static AGENT: OnceLock<Label> = OnceLock::new();
        AGENT.get_or_init(|| Label::new_unchecked("Agent".to_string()))
    }

    /// `ReasoningTrace` node - the logical path to a claim
    pub fn reasoning_trace() -> &'static Label {
        static REASONING_TRACE: OnceLock<Label> = OnceLock::new();
        REASONING_TRACE.get_or_init(|| Label::new_unchecked("ReasoningTrace".to_string()))
    }

    /// Concept node - a defined term or entity
    pub fn concept() -> &'static Label {
        static CONCEPT: OnceLock<Label> = OnceLock::new();
        CONCEPT.get_or_init(|| Label::new_unchecked("Concept".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_labels() {
        assert!(Label::new("Claim").is_ok());
        assert!(Label::new("reasoning_trace").is_ok());
        assert!(Label::new("Agent123").is_ok());
    }

    #[test]
    fn invalid_labels() {
        assert!(Label::new("").is_err());
        assert!(Label::new("123start").is_err());
        assert!(Label::new("has-dash").is_err());
        assert!(Label::new("has space").is_err());
    }

    #[test]
    fn label_serializes_as_string() {
        let label = Label::new("Claim").unwrap();
        let json = serde_json::to_string(&label).unwrap();
        assert_eq!(json, "\"Claim\"");
    }
}
