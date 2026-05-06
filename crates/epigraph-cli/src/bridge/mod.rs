//! Cross-component bridge sweep: detect disconnected components in the claim
//! graph, generate cross-component candidate pairs, run the LLM reranker,
//! emit spine-destination report.
//!
//! See docs/superpowers/specs/2026-05-05-cross-component-bridge-sweep-design.md.

pub mod candidates;
pub mod components;
pub mod spine;
