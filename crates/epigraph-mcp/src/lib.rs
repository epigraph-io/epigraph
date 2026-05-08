#![allow(clippy::doc_markdown)]

pub mod claim_helper;
pub mod embed;
pub mod errors;
pub mod migrate_flat;
pub mod server;
pub mod tools;
pub mod types;

pub use server::EpiGraphMcpFull;

/// Return all registered MCP tools as a JSON value.
///
/// Calls the static tool router (no database access) so callers don't need a
/// live server instance. Used by the REST discovery endpoint in epigraph-api.
#[must_use]
pub fn list_tools() -> serde_json::Value {
    EpiGraphMcpFull::all_tools_json()
}
