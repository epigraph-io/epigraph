//! LLM names for the Atlas's nested groups (Atlas W8, backlog a71816e1):
//! every group and leaf at every level, in both hierarchies, and each map's
//! theme roots (the per-map theme names), generated only from text every
//! viewer of that map can read.
//!
//! * [`name::plan_samples`] picks each group's sample candidates from the
//!   level documents (claim ids only);
//! * [`build::read_member_texts`] reads their text through the MAP-scoped
//!   read (W3/W4's predicate), so a claim the map may not draw feeds no name;
//! * [`name::name_levels`] names the levels deepest first (an inner group
//!   from its children's names and a sample of its members), copies an
//!   earlier run's name when the key over the whole prompt input is unchanged
//!   (zero model calls), and fills every name the documents repeat;
//! * the model is a [`backend::NameBackend`]: on the box,
//!   [`backend::ClaudeCliBackend`] (`claude -p`, never an API key); in tests,
//!   [`backend::RecordingBackend`].
//!
//! The nightly (W9) calls the first three on the documents it assembled and
//! puts the returned [`name::NamingRecord`] under the run's `params.naming`
//! before `write_run`. The operator binary `atlas_naming` runs
//! [`build::name_map`], which names the latest finished run of a map and
//! stores it as a new run.

pub mod backend;
pub mod build;
pub mod name;
pub mod prompt;
