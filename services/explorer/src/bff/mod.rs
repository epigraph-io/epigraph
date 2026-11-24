//! `/bff/*` JSON for client-side JS. Errors render as JSON automatically
//! (see `error::render_errors`). Each module exposes `routes()`, already
//! merged by `app::build_app`.

pub mod atlas;
pub mod atlas_nested;
pub mod atlas_provenance;
pub mod atlas_sources;
pub mod atlas_timeline;
pub mod core;
pub mod graph;
