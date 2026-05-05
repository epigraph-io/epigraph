//! Shared infrastructure for hierarchical artifact ingest. The hierarchy
//! walker, ID derivation namespaces, and plan types live here. Document-
//! and workflow-specific schemas wrap them in `document::` and `workflow::`.

pub mod edges;
pub mod ids;
pub mod paths;
pub mod plan;
pub mod schema;
pub mod walker;
