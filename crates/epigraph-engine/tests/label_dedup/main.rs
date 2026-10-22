//! Behaviour tests for `epigraph_engine::label_dedup`.
//!
//! Every fixture is neutral (synthetic entities, ids and labels). Each module
//! covers one stage of the engine; negative assertions carry a positive control
//! in the same test, so an engine that plans nothing cannot pass them.

mod fixtures;

mod carry;
mod classify;
mod closeout;
mod constrained;
mod hygiene;
mod ids;
mod lifecycle;
mod marks;
mod parse;
mod plan;
mod precedence;
mod probe;
mod profile;
mod properties;
mod revert;
mod signal;
mod snapshot;
mod writes;
