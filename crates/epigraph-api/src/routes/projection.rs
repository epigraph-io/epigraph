//! Deterministic 2-D PCA projection of high-dimensional embeddings.
//!
//! # Why this exists
//!
//! `GET /api/v1/themes/:id/embeddings` used to return the complete raw
//! 1536-dimensional `claims.embedding` for up to 5000 claims at `claims:read`.
//! Embeddings are approximately invertible to the content they encode, so that
//! endpoint was a bulk content-exfiltration primitive wearing a clustering
//! endpoint's clothes — plan §4.9 row 4 rates it a blocker in all three columns
//! and assigns the fix to PR-07.
//!
//! The endpoint's one real consumer is
//! `scripts/maintain_themes.py::split_oversized_theme`, which runs
//! `MiniBatchKMeans` over the returned vectors purely to decide *which claim
//! goes in which half* of an oversized theme. A 2-D PCA projection preserves the
//! dominant separating structure that k-means is looking for while disclosing
//! two floats per claim instead of 1536. The sub-theme centroids the script used
//! to compute client-side are now computed server-side from the claim ids (see
//! `crud::create_theme_with_centroid`), so no caller needs raw vectors at all.
//!
//! # Where the body lives
//!
//! The projection moved, unchanged, to [`epigraph_core::projection`] so the
//! operator CLI `atlas_layout` can use the same deterministic PCA. This module
//! re-exports it so `crud.rs` and every other caller keep their path. Its
//! determinism notes and tests moved with it.

pub use epigraph_core::projection::project_to_2d;
