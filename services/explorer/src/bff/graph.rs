//! `/bff/graph/ego/:id`, `/bff/themes`, `/bff/communities`,
//! `/bff/neighborhood/:id` (plan §3.4). OWNED BY THE GRAPH AREA.

use axum::routing::get;
use axum::{Json, Router};

use crate::auth::SignedIn;
use crate::error::AppError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/bff/graph/ego/{id}", get(ego))
        .route("/bff/themes", get(themes))
        .route("/bff/communities", get(communities))
        .route("/bff/neighborhood/{id}", get(neighborhood))
}

// STUB: `/claims/:id/ego` (max_degree ≤ 80).
async fn ego(_user: SignedIn) -> Result<Json<serde_json::Value>, AppError> {
    Err(AppError::NotBuilt("/bff/graph/ego"))
}

// STUB: themes overview, 60 s cache keyed per viewer.
async fn themes(_user: SignedIn) -> Result<Json<serde_json::Value>, AppError> {
    Err(AppError::NotBuilt("/bff/themes"))
}

// STUB: communities overview, 60 s cache keyed per viewer.
async fn communities(_user: SignedIn) -> Result<Json<serde_json::Value>, AppError> {
    Err(AppError::NotBuilt("/bff/communities"))
}

// STUB: `/graph/neighborhoods/:id/expand`.
async fn neighborhood(_user: SignedIn) -> Result<Json<serde_json::Value>, AppError> {
    Err(AppError::NotBuilt("/bff/neighborhood"))
}
