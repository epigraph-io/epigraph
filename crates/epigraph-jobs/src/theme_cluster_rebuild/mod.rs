//! Scheduled theme rebuild job.
//!
//! Sibling to `cluster_graph` — runs nightly, rebuilds `claim_themes`
//! from scratch via `epigraph_engine::theme_kmeans::run_theme_kmeans`
//! when the corpus has changed since the last run.

pub mod handler;
pub mod namer;

pub use handler::ThemeClusterRebuildHandler;
