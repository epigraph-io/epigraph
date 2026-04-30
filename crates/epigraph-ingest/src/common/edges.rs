//! Edge constructors shared across hierarchy walkers.
//!
//! Walkers in `document::builder` and `workflow::builder` emit identical
//! `decomposes_to` edges between adjacent levels of the claim hierarchy.
//! This module hosts that constructor so all walkers depend on `common::`
//! rather than duplicating the same five-line struct literal.

use uuid::Uuid;

use crate::common::plan::PlannedEdge;

/// `claim --decomposes_to--> claim` edge linking a parent claim to a child
/// in the hierarchy (thesis→section/phase, section/phase→paragraph/step,
/// paragraph/step→atom). Properties are intentionally empty — walkers that
/// want to attach extra metadata should mutate the returned edge.
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
