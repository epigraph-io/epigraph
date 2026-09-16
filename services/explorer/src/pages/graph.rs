//! `/claim/:id/graph`, `/theme/:id`, `/community/:id`, `/neighborhood/:id`
//! (plan §3.4). OWNED BY THE GRAPH AREA.

use axum::response::Html;
use axum::routing::get;
use axum::Router;

use crate::auth::SignedIn;
use crate::error::AppError;
use crate::state::AppState;
use crate::view::stub_page;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/claim/{id}/graph", get(claim_graph))
        .route("/theme/{id}", get(theme))
        .route("/community/{id}", get(community))
        .route("/neighborhood/{id}", get(neighborhood))
}

// STUB: page shell; the canvas reads `/bff/graph/ego/:id`.
async fn claim_graph(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Claim graph", "graph")
}

// STUB: `/graph/themes/:id/expand`.
async fn theme(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Theme", "graph")
}

// STUB: `/graph/communities/:id/expand`.
async fn community(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Community", "graph")
}

// STUB: `/graph/neighborhoods/:id/expand?mode=`.
async fn neighborhood(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Neighborhood", "graph")
}
