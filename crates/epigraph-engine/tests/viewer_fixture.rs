//! Re-export of the ONE canonical viewer fixture.
//!
//! The fixture itself lives at `crates/epigraph-db/tests/viewer_fixture.rs`.
//! This file used to be a hand-maintained copy of it; PR-28 added the same 69
//! lines to two of those copies by hand, and nothing detected that the copies
//! had drifted apart in the first place. The helpers encode schema knowledge
//! that a migration can invalidate — `seed_reasoning_trace` must both insert
//! into `reasoning_traces` AND update the claim's `trace_id`, and the seeders
//! omit tenancy columns on the strength of migration 070's inheritance arm — so
//! a drifted copy means one crate's tests keep passing against a shape the
//! database no longer has.
//!
//! Kept as a shim rather than rewriting every `mod viewer_fixture;` to a
//! `#[path]` of the canonical file: there are ~145 such declarations across the
//! workspace, and none of them has to know where the fixture lives.
//!
//! `epigraph-db/tests/viewer_fixture_single_source.rs` fails if a second full
//! copy reappears.

#[path = "../../epigraph-db/tests/viewer_fixture.rs"]
mod canonical;

// A test binary may declare `mod viewer_fixture;` and use only some of the
// helpers, or none — the canonical file already carries `#![allow(dead_code)]`
// for exactly that reason, and the glob re-export needs the same latitude.
#[allow(unused_imports)]
pub use canonical::*;
