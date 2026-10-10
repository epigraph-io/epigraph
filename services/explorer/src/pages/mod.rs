//! Server-rendered HTML routes, one module per area. Each exposes
//! `routes() -> Router<AppState>`, already merged by `app::build_app`.

pub mod core;
pub mod entities;
pub mod graph;
