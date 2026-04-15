//! PROV-O agent typing and serialization
//!
//! Maps EpiGraph LPG labels to W3C PROV-O types:
//! - person → prov:Person
//! - organization → prov:Organization
//! - software_agent → prov:SoftwareAgent
//! - instrument → prov:SoftwareAgent (with role qualifier)

use serde::{Deserialize, Serialize};

/// PROV-O agent type derived from LPG labels.
///
/// Priority order: person > organization > instrument > software_agent.
/// This priority is enforced by `from_labels()` iteration order, not by
/// label ordering in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvAgentType {
    Person,
    Organization,
    SoftwareAgent,
    Instrument,
}

impl ProvAgentType {
    /// Derive the PROV-O agent type from a set of LPG labels.
    ///
    /// Scans labels in priority order: person > organization > instrument > software_agent.
    /// Priority is enforced by checking in fixed order, not by label array position.
    /// Falls back to `SoftwareAgent` if no recognized label is found.
    pub fn from_labels(labels: &[String]) -> Self {
        let strs: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();
        if strs.contains(&"person") {
            return Self::Person;
        }
        if strs.contains(&"organization") {
            return Self::Organization;
        }
        if strs.contains(&"instrument") {
            return Self::Instrument;
        }
        if strs.contains(&"software_agent") {
            return Self::SoftwareAgent;
        }
        Self::SoftwareAgent
    }

    /// Return the W3C PROV-O type URI for this agent type.
    pub fn prov_type(&self) -> &'static str {
        match self {
            Self::Person => "prov:Person",
            Self::Organization => "prov:Organization",
            Self::SoftwareAgent | Self::Instrument => "prov:SoftwareAgent",
        }
    }

    /// Return the canonical label string for this agent type.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Organization => "organization",
            Self::SoftwareAgent => "software_agent",
            Self::Instrument => "instrument",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn person_label_yields_person_type() {
        let labels = vec!["person".to_string()];
        assert_eq!(ProvAgentType::from_labels(&labels), ProvAgentType::Person);
    }

    #[test]
    fn organization_label_yields_organization_type() {
        let labels = vec!["organization".to_string()];
        assert_eq!(
            ProvAgentType::from_labels(&labels),
            ProvAgentType::Organization
        );
    }

    #[test]
    fn instrument_label_yields_instrument_type() {
        let labels = vec!["instrument".to_string()];
        assert_eq!(
            ProvAgentType::from_labels(&labels),
            ProvAgentType::Instrument
        );
    }

    #[test]
    fn software_agent_label_yields_software_agent_type() {
        let labels = vec!["software_agent".to_string()];
        assert_eq!(
            ProvAgentType::from_labels(&labels),
            ProvAgentType::SoftwareAgent
        );
    }

    #[test]
    fn empty_labels_default_to_software_agent() {
        assert_eq!(
            ProvAgentType::from_labels(&[]),
            ProvAgentType::SoftwareAgent
        );
    }

    #[test]
    fn person_has_priority_over_software_agent() {
        let labels = vec!["software_agent".to_string(), "person".to_string()];
        assert_eq!(ProvAgentType::from_labels(&labels), ProvAgentType::Person);
    }

    #[test]
    fn organization_has_priority_over_instrument() {
        let labels = vec!["instrument".to_string(), "organization".to_string()];
        assert_eq!(
            ProvAgentType::from_labels(&labels),
            ProvAgentType::Organization
        );
    }

    #[test]
    fn unknown_labels_ignored() {
        let labels = vec!["robot".to_string(), "alien".to_string()];
        assert_eq!(
            ProvAgentType::from_labels(&labels),
            ProvAgentType::SoftwareAgent
        );
    }

    #[test]
    fn prov_type_mappings() {
        assert_eq!(ProvAgentType::Person.prov_type(), "prov:Person");
        assert_eq!(ProvAgentType::Organization.prov_type(), "prov:Organization");
        assert_eq!(
            ProvAgentType::SoftwareAgent.prov_type(),
            "prov:SoftwareAgent"
        );
        assert_eq!(ProvAgentType::Instrument.prov_type(), "prov:SoftwareAgent");
    }

    #[test]
    fn label_roundtrip() {
        for ty in [
            ProvAgentType::Person,
            ProvAgentType::Organization,
            ProvAgentType::SoftwareAgent,
            ProvAgentType::Instrument,
        ] {
            let labels = vec![ty.label().to_string()];
            assert_eq!(ProvAgentType::from_labels(&labels), ty);
        }
    }

    #[test]
    fn serde_roundtrip() {
        let ty = ProvAgentType::Person;
        let json = serde_json::to_string(&ty).unwrap();
        assert_eq!(json, "\"person\"");
        let deserialized: ProvAgentType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ty);
    }
}
