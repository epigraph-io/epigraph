//! `/bff/audit`: the audit page's counted window as JSON (J4).
//!
//! Serves exactly what `/audit` renders (the composition lives in
//! [`crate::pages::audit`]): the window it read, and a `result` whose
//! `status` is `counted` (types, events read, capped / partial markers, and a
//! drill-down's rows), `not_granted` or `unavailable`. A window the page would
//! refuse is a 400 here; anonymous callers get the JSON 401. Like every
//! response without its own policy, it is sent `private, no-store`
//! (`security::security_headers`).

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;

use crate::auth::SignedIn;
use crate::error::AppError;
use crate::pages::audit::{compose, parse_window, AuditView, RawAuditQuery};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/bff/audit", get(audit))
}

async fn audit(
    State(state): State<AppState>,
    user: SignedIn,
    Query(raw): Query<RawAuditQuery>,
) -> Result<Json<AuditView>, AppError> {
    let filter = parse_window(&raw, Utc::now()).map_err(AppError::BadRequest)?;
    Ok(Json(compose(&state, &user, &filter).await?))
}
