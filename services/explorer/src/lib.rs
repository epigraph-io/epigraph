//! EpiGraph Explorer: a server-rendered reader for the EpiGraph knowledge
//! graph, and the BFF its client-side JS talks to.
//!
//! The contract is `docs/superpowers/plans/2026-09-15-epigraph-explorer-impl-plan.md`.
//! Everything lives in the library so integration tests can build the same
//! router the binary serves.

pub mod app;
pub mod assets;
pub mod auth;
pub mod config;
pub mod error;
pub mod links;
pub mod security;
pub mod state;
pub mod ttl;
pub mod upstream;
pub mod view;

pub use app::build_app;
pub use config::Config;
pub use error::AppError;
pub use state::AppState;
