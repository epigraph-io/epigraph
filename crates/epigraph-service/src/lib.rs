//! The transport-neutral service layer of EpiGraph.
//!
//! # Why this crate exists (backlog 93e01896, 6ffcb138)
//!
//! The three front ends, the HTTP API (`epigraph-api`), the MCP server
//! (`epigraph-mcp`) and the operator CLI (`epigraph-cli`), were not peers over
//! a shared layer: shared operations lived inside the MCP crate and the other
//! two imported them from it (`epigraph-api`'s `db` feature pulls in
//! `epigraph-mcp`, its `genai` feature pulls in `epigraph-cli`, and
//! `epigraph-cli` depends on `epigraph-mcp`). The layering rule adopted for
//! that finding is:
//!
//! * an operation more than one front end needs lives HERE, in terms of
//!   kernel types (`epigraph-core`, `epigraph-db`, `epigraph-crypto`,
//!   `epigraph-embeddings`, `epigraph-engine`, ...);
//! * the front ends depend on this crate and, eventually, not on each other;
//! * this crate never depends on a front end.
//!
//! The move is a wave of small steps (93e01896's work items), each moving one
//! module here and re-exporting it from where it was, so no caller changes in
//! the same step. `crates/epigraph-api/tests/crate_layering_ratchet.rs` holds
//! the front-end edges and the per-file `epigraph_mcp::` / `epigraph_cli::`
//! reference counts at their current values; each step lowers them, and the
//! last one takes them to zero.
//!
//! # What is here so far
//!
//! * [`errors`]: [`ServiceError`](errors::ServiceError), the error a service
//!   operation returns, and [`HttpClass`](errors::HttpClass), the HTTP status
//!   class a front end answers it with. Each front end converts it into its
//!   own error type (the MCP server's JSON-RPC error, the API's `ApiError`).

pub mod errors;

pub use errors::{HttpClass, ServiceError};
