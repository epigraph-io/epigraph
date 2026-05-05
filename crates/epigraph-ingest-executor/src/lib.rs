//! Persistence-layer executor for hierarchical workflow ingest plans.
//!
//! This crate consolidates the workflow-ingest execution logic that was
//! previously duplicated between `epigraph-mcp::tools::workflow_ingest` and
//! `epigraph-api::routes::workflows`. Both call sites now reduce to a thin
//! wrapper that builds an [`epigraph_ingest::workflow::IngestPlan`] and calls
//! [`execute_workflow_ingest_plan`].

pub mod error;
pub mod system_agent;
pub mod workflow;

pub use error::IngestExecutorError;
pub use system_agent::get_or_create_system_agent;
pub use workflow::{execute_workflow_ingest_plan, WorkflowIngestExecutionResult};
