//! `/bff/claim/:id`, `/bff/search` (plan §3.4). OWNED BY THE CORE AREA.

use axum::routing::get;
use axum::{Json, Router};

use crate::auth::SignedIn;
use crate::error::AppError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/bff/claim/{id}", get(claim))
        .route("/bff/search", get(search))
}

// STUB: composed JSON of `/claim/:id`, with a weak ETag over the body.
async fn claim(_user: SignedIn) -> Result<Json<serde_json::Value>, AppError> {
    Err(AppError::NotBuilt("/bff/claim"))
}

// STUB: as `/search`.
async fn search(_user: SignedIn) -> Result<Json<serde_json::Value>, AppError> {
    Err(AppError::NotBuilt("/bff/search"))
}
