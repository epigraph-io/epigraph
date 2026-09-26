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
use crate::{assets, auth, bff, pages, security};

/// Forms and redeem bodies are tiny; nothing legitimate comes near this.
pub const MAX_REQUEST_BODY: usize = 64 * 1024;
/// First path segment of every route [`build_app_with`] mounts at the root.
///
/// The app is mounted twice — nested under the base path *and* at the root —
/// so a base path whose first segment is one of these makes `nest` and
/// `merge` claim the same path and axum panics while building the router
/// ("Overlapping method route"). [`crate::config::Config::from_lookup`]
/// refuses such a base path so the process exits 2 with a clear message
/// instead, which is what the systemd unit's `RestartPreventExitStatus=2`
/// needs to stop restart-looping on a config typo.
///
/// KEEP IN SYNC with the `.route(..)` / `.merge(..)` calls below and in
/// `auth::routes`, `pages::{core,entities,graph}::routes` and
/// `bff::{core,graph}::routes`. Adding a top-level route whose first segment
/// is new means adding it here too.
pub const RESERVED_BASE_PATH_SEGMENTS: &[&str] = &[
    "agent",
    "auth",
    "bff",
    "claim",
    "community",
    "evidence",
    "frame",
    "health",
    "neighborhood",
    "search",
    "static",
    "theme",
];
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
        .merge(pages::core::routes())
        .merge(pages::entities::routes())
        .merge(pages::graph::routes())
        .merge(bff::core::routes())
        .merge(bff::graph::routes())
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

/// The first path segment of every route the app router claims at the root.
///
/// Test-only: `Router` cannot be enumerated, so this walks the same route
/// tables `build_app_with` merges. It is what keeps
/// [`RESERVED_BASE_PATH_SEGMENTS`] honest.
#[cfg(test)]
fn top_level_segments() -> Vec<String> {
    // Every `.route(path, _)` literal mounted at the root, in one place.
    const ROUTE_PATHS: &[&str] = &[
        "/",
        "/health",
        "/static/{*path}",
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
        "/auth/redeem",
        "/search",
        "/claim/{id}",
        "/claim/{id}/history",
        "/claim/{id}/provenance",
        "/claim/{id}/graph",
        "/agent/{id}",
        "/frame/{id}",
        "/evidence/{id}",
        "/theme/{id}",
        "/community/{id}",
        "/neighborhood/{id}",
        "/bff/claim/{id}",
        "/bff/search",
        "/bff/graph/ego/{id}",
        "/bff/themes",
        "/bff/communities",
        "/bff/neighborhood/{id}",
    ];
    let mut segments: Vec<String> = ROUTE_PATHS
        .iter()
        .filter_map(|p| p.split('/').nth(1).filter(|s| !s.is_empty()))
        .map(str::to_string)
        .collect();
    segments.sort();
    segments.dedup();
    segments
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `RESERVED_BASE_PATH_SEGMENTS` is what stops a colliding base path from
    /// panicking the router build, so it must list exactly the segments the
    /// root-mounted routes claim — no more (which would refuse a usable base
    /// path) and no fewer (which would let the panic back in).
    #[test]
    fn reserved_segments_match_the_routers_top_level() {
        let mut reserved: Vec<String> = RESERVED_BASE_PATH_SEGMENTS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        reserved.sort();
        assert_eq!(
            reserved,
            top_level_segments(),
            "RESERVED_BASE_PATH_SEGMENTS has drifted from the app's routes"
        );
    }
}
