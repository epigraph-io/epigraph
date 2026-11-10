//! The rmcp transport behind `epigraph-mcp-full`'s stdio mode, built in one
//! place.
//!
//! `main.rs` serves stdio through [`stdio_server_transport`], and
//! `tests/mcp_stdio_transport.rs` builds its server end through the same
//! function, so the line-length decision below is what both of them run.
//!
//! # The line-length cap
//!
//! rmcp 3.x frames stdio JSON-RPC with
//! [`AsyncRwTransport`](rmcp::transport::async_rw::AsyncRwTransport), which
//! caps one incoming line (one JSON-RPC message) at
//! `rmcp::transport::async_rw::DEFAULT_MAX_LINE_LENGTH` (16 MiB). A longer line
//! is logged and DROPPED: no JSON-RPC error goes back, so the client waits on
//! that request id until its own timeout. rmcp 2.2 had no cap and answered
//! such a request. Local MCP clients (Claude Code, epiclaw's agents) reach
//! tools like `ingest_document_inline` over stdio, where a large document is a
//! legitimate request, and a silent drop is the worst way for it to fail.
//!
//! So this transport sets [`STDIO_MAX_LINE_LENGTH`] = `usize::MAX`, which
//! rmcp documents as restoring the previous unbounded behaviour. rmcp's cap
//! guards against a peer that never sends a newline and grows the read buffer
//! without bound. On stdio that peer is the parent process that spawned this
//! server and owns both of its pipes; it can already stop or starve the
//! process, so the cap buys no isolation from it.
//!
//! The HTTP listener keeps rmcp's request-body cap, which answers an over-cap
//! request with an explicit 413 rather than dropping it.

use rmcp::transport::async_rw::AsyncRwTransport;
use rmcp::RoleServer;
use tokio::io::{AsyncRead, AsyncWrite};

/// The largest single stdio JSON-RPC line this server reads: unbounded, as on
/// rmcp 2.2. See the module docs for why.
pub const STDIO_MAX_LINE_LENGTH: usize = usize::MAX;

/// The server-side stdio transport over `read` / `write` (in production,
/// the halves of `rmcp::transport::stdio()`), with [`STDIO_MAX_LINE_LENGTH`].
#[must_use]
pub fn stdio_server_transport<R, W>(read: R, write: W) -> AsyncRwTransport<RoleServer, R, W>
where
    R: Send + AsyncRead + Unpin,
    W: Send + AsyncWrite + Unpin + 'static,
{
    AsyncRwTransport::new_server(read, write).with_max_line_length(STDIO_MAX_LINE_LENGTH)
}
