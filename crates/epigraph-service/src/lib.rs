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
//! the front-end edges and each file's references to another front end's
//! crate at their current values (this crate's at zero); each step lowers them, and the
//! last one takes them to zero.
//!
//! # What is here so far
//!
//! * [`errors`]: [`ServiceError`](errors::ServiceError), the error a service
//!   operation returns, and [`HttpClass`](errors::HttpClass), the HTTP status
//!   class a front end answers it with. Each front end converts it into its
//!   own error type (the MCP server's JSON-RPC error, the API's `ApiError`).
//! * [`ctx`]: [`Ctx`](ctx::Ctx), the context a shared operation runs in (the
//!   pools, the signer, the process's own agent), with the tenancy entry
//!   points: the stamped read, the author-stamped write transaction, the write
//!   identity resolver and the write-time visibility resolution.
//! * [`write_identity`]: [`WriteIdentity`](write_identity::WriteIdentity), the
//!   agent a write authors and stamps as, constructible only by `Ctx`.
//! * [`background`]: the detached tasks a `Ctx` tracks.

pub mod background;
pub mod ctx;
pub mod errors;
pub mod write_identity;

pub use ctx::{Ctx, ServiceHost};
pub use errors::{HttpClass, ServiceError};
