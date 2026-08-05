//! Library API for the bridge-validation reranker.
//!
//! Two entry points:
//! - [`rerank_global_join`] — original behavior: scan all pairs above similarity threshold.
//! - [`rerank_candidates_table`] — new (issue #53): score pairs from a caller-supplied temp
//!   table of `(source_id, target_id)` rows, bypassing the O(N²) global join.
//!
//! See docs/superpowers/specs/2026-05-05-cross-component-bridge-sweep-design.md §2.2.

pub mod candidates;
pub mod core;
pub mod errors;
mod prompt;

pub use core::{
    rerank_candidates_table, rerank_global_join, PerPairVerdict, RerankConfig, RerankSummary,
};
pub use errors::RerankError;
