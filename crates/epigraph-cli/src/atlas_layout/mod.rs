//! The Atlas theme-layout build (migration 197), run by the operator binary
//! `atlas_layout` on the maintenance connection.
//!
//! [`math`] is the pure arithmetic (Ward clustering of public theme centroids,
//! the region count chosen by silhouette, nested 2-D placement); `build` turns
//! one snapshot of public inputs into a run ready to write. Both are
//! deterministic: two builds over one snapshot give identical positions.

pub mod math;

#[cfg(feature = "db")]
pub mod build;
