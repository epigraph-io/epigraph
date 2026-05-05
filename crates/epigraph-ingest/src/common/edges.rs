//! Edge helpers shared by the document and workflow walkers.
//!
//! These were previously duplicated verbatim in `document/builder.rs` and
//! `workflow/builder.rs`. Centralizing them here keeps the two walkers in
//! lockstep and gives the executor crate a single import surface.

use uuid::Uuid;

use crate::common::plan::PlannedEdge;
use crate::common::schema::ThesisDerivation;

/// String representation of a `ThesisDerivation` enum, used as an edge property.
#[must_use]
pub const fn thesis_derivation_str(td: &ThesisDerivation) -> &'static str {
    match td {
        ThesisDerivation::TopDown => "TopDown",
        ThesisDerivation::BottomUp => "BottomUp",
    }
}

/// Build a `decomposes_to` edge between two claim nodes. Used for parent →
/// child relationships in the hierarchy (thesis → section, section →
/// paragraph, paragraph → atom; or workflow root → phase, phase → step,
/// step → operation).
#[must_use]
pub fn decomposes_edge(source_id: Uuid, target_id: Uuid) -> PlannedEdge {
    PlannedEdge {
        source_id,
        source_type: "claim".to_string(),
        target_id,
        target_type: "claim".to_string(),
        relationship: "decomposes_to".to_string(),
        properties: serde_json::json!({}),
    }
}
