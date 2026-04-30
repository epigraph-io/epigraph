//! Plan-application layer for hierarchical artifact ingest.
//!
//! Bridges leaf-ish `epigraph-ingest` (plan-building, no DB) with the
//! `epigraph-db` repos (plan-applying), so the MCP tool surface and the
//! HTTP API surface call the same code path instead of maintaining two
//! parallel ~200-line implementations.
//!
//! Today this hosts the workflow ingest flow only. Document ingest already
//! lives in `epigraph-mcp::tools::ingestion::do_ingest_document` and is not
//! HTTP-exposed; if/when it is, it should move here too.

pub mod error;
pub mod workflow;

pub use error::IngestError;
pub use workflow::{ingest_workflow, IngestWorkflowResponse};
