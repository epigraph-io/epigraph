//! EpiGraph Explorer: a server-rendered reader for the EpiGraph knowledge
//! graph, and the BFF its client-side JS talks to.
//!
//! The contract is `docs/superpowers/plans/2026-09-15-epigraph-explorer-impl-plan.md`.

pub mod config;
pub mod ttl;

pub use config::Config;
