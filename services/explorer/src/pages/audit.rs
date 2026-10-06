//! `/audit`: security events the viewer may read since a time, counted by
//! type (read-only).
//!
//! Registered ahead of its body, so the route, its reserved base-path
//! segment and its module exist once and the page can be filled in without
//! touching the router again. Until then it answers 501 "not yet available"
//! to signed-in viewers and makes no upstream call.

use axum::routing::get;
use axum::Router;

use crate::auth::SignedIn;
use crate::error::AppError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/audit", get(audit))
}

async fn audit(_viewer: SignedIn) -> AppError {
    AppError::NotYetAvailable("audit")
}
