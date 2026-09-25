//! `/bff/*` JSON for client-side JS. Errors render as JSON automatically
//! (see `error::render_errors`). Each module exposes `routes()`, already
//! merged by `app::build_app`.

pub mod core;
pub mod graph;
