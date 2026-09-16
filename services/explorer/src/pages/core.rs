//! `/`, `/search`, `/claim/:id` (plan §3.4). OWNED BY THE CORE AREA.

use axum::response::Html;
use axum::routing::get;
use axum::Router;

use crate::auth::{Caller, SignedIn};
use crate::error::AppError;
use crate::state::AppState;
use crate::view::stub_page;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(landing))
        .route("/search", get(search))
        .route("/claim/{id}", get(claim))
}

// STUB: `/api/v1/stats` + theme/community overviews.
async fn landing(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "EpiGraph Explorer", "core")
}

// STUB: semantic / label / evidence search.
async fn search(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Search", "core")
}

// STUB: the claim page. Anonymous viewers get 200 + a sign-in prompt and OG
// tags (plan §3.3), hence `Caller`, not `SignedIn`.
async fn claim(caller: Caller) -> Result<Html<String>, AppError> {
    stub_page(caller.ctx, "Claim", "core")
}
