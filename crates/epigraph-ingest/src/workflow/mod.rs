//! Workflow-specific extraction and ingest. Mirrors `document::` for hierarchical
//! workflows; uses the same `common::` infrastructure (Walker, IngestPlan,
//! ID derivation, ATOM_NAMESPACE for cross-source convergence).

pub mod builder;
pub mod schema;

pub use builder::build_ingest_plan;
pub use schema::*;
