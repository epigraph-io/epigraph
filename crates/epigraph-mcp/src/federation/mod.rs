//! MCP federation gateway.
//!
//! The gateway mounts zero or more downstream "extension" MCP servers
//! (e.g. episcience) and exposes their tools alongside the kernel's own,
//! behind the single EpiGraph MCP endpoint. Callers see one flat tool list;
//! the gateway routes each federated `tools/call` to the owning extension.
//!
//! ## Modules
//!
//! - [`config`] — parse `EPIGRAPH_MCP_EXTENSIONS` into [`config::ExtensionConfig`]s.
//!   (Stage 1; no networking.)
//!
//! Stage 2 (networking) adds:
//! - `client` — thin wrapper over rmcp `serve_client` + streamable-HTTP client
//!   transport, with a persistent discovery session (service token) and an
//!   ephemeral per-call invocation session (caller token).
//! - `registry` — [`config::ExtensionConfig`] → mounted extensions with cached
//!   tool lists, a `tool_name -> extension` routing map, collision detection,
//!   health, and a reconnect timer.
//!
//! ## Transport (v1)
//!
//! Loopback TCP only: rmcp's reqwest streamable-HTTP client cannot dial Unix
//! sockets. Extensions serve on `127.0.0.1:PORT` (never Caddy-exposed). UDS via
//! a custom hyper connector is a documented fast-follow.

pub mod config;

// Stage 2 (networking) — filled in the next stage:
// pub mod client;
// pub mod registry;
