//! Route integration tests for epigraph-api
//!
//! These tests validate the HTTP API endpoints for epistemic integrity.
//!
//! Note: `edges_validation.rs` lives in this directory but is registered as a
//! standalone `[[test]]` binary in Cargo.toml, not as a submodule here.

pub mod semantic_search_tests;
pub mod submit_packet_tests;
