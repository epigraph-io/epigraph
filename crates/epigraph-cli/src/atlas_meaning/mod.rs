//! The Atlas "by meaning" hierarchy (Atlas W4, backlog f9fc052c): under each
//! theme of one map, its claims grouped by embedding similarity, recursively,
//! until every leaf fits the 100-node cap (claims + agents + evidence, a
//! shared agent or evidence row counted once). Run by the operator binary
//! `atlas_meaning`.
//!
//! Three steps, W1's shape (design 2026-11-12 §2: the heavy maths may leave
//! the box on ids, embeddings and structure only):
//!
//! 1. **export** (box, [`build::export_map`]): per theme, the current embedded
//!    members the map draws, their embeddings, and each member's agents and
//!    evidence after W3's per-claim cap, renumbered per theme as integers
//!    ([`files`]);
//! 2. **compute** (anywhere, `scripts/atlas_meaning_core.py compute`): the
//!    recursive UMAP + k-means split, to a result file of group ids, parents,
//!    depths, leaf members and child ids;
//! 3. **apply** (box, [`build::apply_result`]): in one snapshot, every theme's
//!    leaves must be exactly its members now and every id the minted one
//!    ([`tree::check_tree`]); W3's `assemble_leaf` re-counts each leaf and
//!    one over the cap is split on the box ([`tree::resolve_tree`]); the level
//!    documents ([`docs`]) go into one run of migration 210.
//!
//! **Ids** are deterministic ([`tree::root_id`], [`tree::group_id`]): a group
//! with an unchanged member set keeps its id across runs, and a rerun over
//! unchanged input reproduces every id. No matching against an earlier run.
//!
//! **Membership** (claim to leaf, for the nightly's incremental assignment) is
//! read back from the stored leaf documents
//! (`AtlasMeaningRepository::leaf_membership`); no table of its own.

pub mod build;
pub mod docs;
pub mod files;
pub mod tree;
