//! Back-compat shim. Document builder lives in `document::builder` now; workflow
//! builder lives in `workflow::builder`. Re-exports here keep existing
//! `epigraph_ingest::build_ingest_plan` callers compiling.

pub use crate::common::plan::{IngestPlan, PlannedClaim, PlannedEdge};
pub use crate::document::builder::{build_ingest_plan, normalize_claim_path};
