//! `/claim/:id/history`, `/claim/:id/provenance`, `/agent/:id`, `/frame/:id`,
//! `/evidence/:id` (plan §3.4). OWNED BY THE ENTITIES AREA.

use axum::response::Html;
use axum::routing::get;
use axum::Router;

use crate::auth::SignedIn;
use crate::error::AppError;
use crate::state::AppState;
use crate::view::stub_page;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/claim/{id}/history", get(history))
        .route("/claim/{id}/provenance", get(provenance))
        .route("/agent/{id}", get(agent))
        .route("/frame/{id}", get(frame))
        .route("/evidence/{id}", get(evidence))
}

// STUB: `/claims/:id/history`.
async fn history(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Claim history", "entities")
}

// STUB: `/claims/:id/provenance-chain`.
async fn provenance(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Claim provenance", "entities")
}

// STUB: `/agents/:id`, `/agents/:id/claims`, `/agents/:id/epistemic-profile`.
async fn agent(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Agent", "entities")
}

// STUB: `/frames/:id`, `/frames/:id/claims`.
async fn frame(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Frame", "entities")
}

// STUB: `/evidence/:id`.
async fn evidence(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Evidence", "entities")
}
