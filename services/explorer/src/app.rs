//! Router assembly, `/health`, and background housekeeping.

use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tower::{service_fn, ServiceExt};
use tower_http::trace::TraceLayer;

use crate::error::{self, AppError};
use crate::state::AppState;
use crate::{assets, auth, security};

/// Forms and redeem bodies are tiny; nothing legitimate comes near this.
pub const MAX_REQUEST_BODY: usize = 64 * 1024;
/// Sessions older than the upstream refresh-token lifetime are dead.
pub const SESSION_MAX_AGE: chrono::Duration = chrono::Duration::days(30);

/// The whole app, ready to serve.
///
/// Routes are mounted twice: at the root, for a proxy that strips the base
/// path (Caddy `handle_path /explorer*`, plan §3.7), and under the base
/// path, for one that does not (or direct local access). Links always use
/// the base path (`crate::links`).
pub fn build_app(state: AppState) -> Router {
    build_app_with(state, Router::new())
}

/// [`build_app`] plus `extra` routes, which get the same base-path mounting,
/// error rendering and security headers. Used by integration tests to mount
/// probe handlers; production passes nothing extra.
pub fn build_app_with(state: AppState, extra: Router<AppState>) -> Router {
    let routes: Router<AppState> = Router::new()
        .route("/health", get(health))
        .route("/static/{*path}", get(assets::serve))
        .merge(auth::routes())
        .merge(extra);

    let base = state.config.base_path.clone();
    let router = if base.is_empty() {
        routes
    } else {
        // axum 0.8 `nest` maps the nested "/" to exactly `{base}`, not
        // `{base}/` — but `{base}/` is the canonical home link. Route it to
        // the same table as "/". `OriginalUri` (set by the outer router)
        // still carries the browser's path.
        let slash_home = routes.clone().with_state(state.clone());
        Router::new()
            .nest(&base, routes.clone())
            .merge(routes)
            .route_service(
                &format!("{base}/"),
                service_fn(move |mut req: Request| {
                    let svc = slash_home.clone();
                    async move {
                        let target = match req.uri().query() {
                            Some(q) => format!("/?{q}"),
                            None => "/".to_string(),
                        };
                        *req.uri_mut() = target.parse().expect("'/' plus a valid query parses");
                        svc.oneshot(req).await
                    }
                }),
            )
    };

    router
        .fallback(fallback)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY))
        .layer(from_fn_with_state(state.clone(), error::render_errors))
        .layer(from_fn_with_state(
            state.clone(),
            security::security_headers,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn fallback() -> AppError {
    AppError::NotFound("page".into())
}

/// Purge expired sessions, pending logins, handoff codes and cache entries
/// once a minute.
pub fn spawn_housekeeping(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let sessions = state.sessions.purge_older_than(SESSION_MAX_AGE);
            let flow = state.auth_flow.purge_expired();
            let cached = state.cache.purge_expired();
            if sessions + flow + cached > 0 {
                tracing::debug!(sessions, flow, cached, "housekeeping purged entries");
            }
        }
    })
}
