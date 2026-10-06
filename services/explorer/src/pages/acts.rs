//! `/acts`: the viewer's own admin acts, linking out to the API to confirm
//! one (read-only). Shown only when the API has the admin-acts routes.
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
    Router::new().route("/acts", get(acts))
}

async fn acts(_viewer: SignedIn) -> AppError {
    AppError::NotYetAvailable("admin acts")
}
