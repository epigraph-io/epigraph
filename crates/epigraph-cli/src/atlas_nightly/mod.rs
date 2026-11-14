//! The incremental nightly Atlas refresh (Atlas W9, backlog 1da9ed16): one
//! scheduled job that keeps every map's nested levels current, replacing the
//! paused theme-maintenance task (the theme-v2 runbook's "rewire the
//! nightly" step).
//!
//! Each night ([`build::run_night`]):
//!
//! 1. assigns unthemed embedded claims to their nearest theme (the existing
//!    `ClaimThemeRepository::assign_unthemed_batch`) and REPORTS the themes
//!    over W1's member cap (the theme split stays W1's operator-run,
//!    off-box tool; no UMAP runs on the box);
//! 2. per map with a finished run, in one REPEATABLE READ snapshot: rebuilds
//!    the previous run's trees ([`previous`]), updates them incrementally
//!    ([`incremental`]: new claims by nearest centroid and by linked
//!    neighbours, W5b mirrors, a leaf over the node cap or the contract's
//!    1,024 edges split by W3's on-box fallback), checks them with W4's
//!    and W5's checks, builds REAL leaves ([`leaves`]: W3 nodes, W7
//!    weights), then, outside the snapshot, lays
//!    out the changed levels (W6, warm-started) and names the changed groups
//!    (W8, under a call budget, with no transaction open);
//! 3. writes ONE new run per map holding both hierarchies, with the
//!    snapshot's epochs, unless every level is unchanged and the epochs too;
//!    then prunes the map's old runs.
//!
//! A theme whose update fails is carried from the previous run (both
//! hierarchies, only if every node and edge of every carried leaf is still
//! in that leaf assembled from what the map may draw now: a subset check, so
//! an operator build's skeleton leaves carry too) or dropped, and reported;
//! it never fails the night.

// W3's leaf assembly splits on the contract's edge limit without depending
// on the contract crate; keep the two numbers one.
const _: () = assert!(
    epigraph_db::repos::atlas_leaf::ATLAS_LEAF_EDGE_CAP == epigraph_atlas_contract::MAX_LEAF_EDGES
);

pub mod build;
pub mod incremental;
pub mod leaves;
pub mod previous;
