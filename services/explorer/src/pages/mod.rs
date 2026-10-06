//! Server-rendered HTML routes, one module per area. Each exposes
//! `routes() -> Router<AppState>`, already merged by `app::build_app`.

pub mod activity;
pub mod acts;
pub mod audit;
pub mod backlog;
pub mod candidates;
pub mod core;
pub mod entities;
pub mod graph;
