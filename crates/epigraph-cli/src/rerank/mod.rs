//! Library API for the bridge-validation reranker.
//!
//! Entry points:
//! - [`rerank_global_join`] — original behavior: scan all pairs above similarity threshold.
//! - [`rerank_candidates_table`] — new (issue #53): score pairs from a caller-supplied
//!   table of `(source_id, target_id)` rows, bypassing the O(N²) global join.
//! - [`find_candidates_from_table`] + [`rerank_candidates`] — the same, split so a TEMP
//!   scratch table is read in the session that created it.
//!
//! See docs/superpowers/specs/2026-05-05-cross-component-bridge-sweep-design.md §2.2.

pub mod candidates;
pub mod core;
pub mod errors;
mod prompt;

pub use candidates::DiscardReason;
pub use core::{
    find_candidates_from_table, rerank_candidates, rerank_candidates_table, rerank_global_join,
    PerPairDiscard, PerPairVerdict, RerankConfig, RerankSummary,
};
pub use errors::RerankError;
