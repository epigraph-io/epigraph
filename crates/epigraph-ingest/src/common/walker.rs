//! Parameterized hierarchy walker. Document and workflow ingestion both
//! implement `Walker` to produce an `IngestPlan` from their respective
//! extraction shapes.
//!
//! The walker contract is intentionally minimal: kind-specific schemas walk
//! their own data, but use shared `common::ids` helpers and emit
//! `common::plan::IngestPlan`. There is no single generic walk function —
//! each kind's `build_ingest_plan` reads naturally with its own field names.
//! This trait exists to define the *interface* both kinds expose.

use crate::common::plan::IngestPlan;

/// Implemented by `document::DocumentExtraction` and `workflow::WorkflowExtraction`.
/// Building a plan is the only operation that varies by kind.
pub trait Walker {
    /// Walk the artifact's hierarchy and produce a complete ingest plan.
    fn build_ingest_plan(&self) -> IngestPlan;
}
