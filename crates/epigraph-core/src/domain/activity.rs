//! Activity domain model (PROV-O alignment)
//!
//! An Activity represents a bounded process that generated or used entities:
//! - **Extraction**: AI agent extracting claims/evidence from a paper
//! - **Ingestion**: CLI tool loading data into the knowledge graph
//! - **Reasoning**: Truth propagation or evaluation run

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Activity type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityType {
    /// AI extraction from a source document
    Extraction,
    /// Data ingestion into the knowledge graph
    Ingestion,
    /// Truth propagation or reasoning evaluation
    Reasoning,
    /// Experimental work described in a paper
    Experiment,
}

impl ActivityType {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Extraction => "extraction",
            Self::Ingestion => "ingestion",
            Self::Reasoning => "reasoning",
            Self::Experiment => "experiment",
        }
    }
}

impl std::fmt::Display for ActivityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A bounded process that generated or used entities (PROV-O prov:Activity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activity {
    pub id: Uuid,
    pub activity_type: ActivityType,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub agent_id: Option<Uuid>,
    pub description: Option<String>,
    pub properties: serde_json::Value,
    pub created_at: DateTime<Utc>,
}
