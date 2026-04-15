//! Integration tests for epigraph-api
//!
//! This module contains integration tests that verify the API layer
//! correctly integrates with the database layer and middleware.

pub mod db_integration_tests;
pub mod lineage_integration_tests;
pub mod middleware_integration_tests;
pub mod rag_persistence_tests;
pub mod semantic_search_integration_tests;
pub mod submit_persistence_tests;
