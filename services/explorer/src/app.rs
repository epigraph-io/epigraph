//! Router assembly, `/health`, and background housekeeping.

use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::{Json, Router};
use futures::StreamExt;
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
/// `auth::routes`, `pages::{core,entities,graph}::routes`,
/// `pages::{backlog,audit,activity,candidates,acts}::routes` and
/// `bff::{core,graph}::routes`. Adding a top-level route whose first segment
/// is new means adding it here too.
pub const RESERVED_BASE_PATH_SEGMENTS: &[&str] = &[
    "activity",
    "acts",
    "agent",
    "audit",
    "auth",
    "backlog",
    "bff",
    "candidates",
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
/// Sessions are dropped this long after sign-in (the session cookie's
/// max-age), and the refresh token each still holds is revoked then.
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
        .merge(pages::backlog::routes())
        .merge(pages::audit::routes())
        .merge(pages::activity::routes())
        .merge(pages::candidates::routes())
        .merge(pages::acts::routes())
        .merge(bff::core::routes())
        .merge(bff::audit::routes())
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
            auth::clear_duplicated_session_cookies,
        ))
        .layer(from_fn_with_state(
            state.clone(),
            security::security_headers,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
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

/// The span every request runs in: method, version and the path only.
///
/// `TraceLayer`'s default span records the whole URI, query included, and
/// the OAuth callback's query carries a live authorization code and
/// `state`. Same level (`DEBUG`) as the default; `path` replaces its `uri`.
pub fn request_span(req: &Request) -> tracing::Span {
    tracing::debug_span!(
        "request",
        method = %req.method(),
        path = %req.uri().path(),
        version = ?req.version(),
    )
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
        "/backlog",
        "/audit",
        "/activity",
        "/candidates",
        "/acts",
        "/bff/claim/{id}",
        "/bff/search",
        "/bff/graph/ego/{id}",
        "/bff/themes",
        "/bff/communities",
        "/bff/neighborhood/{id}",
        "/bff/audit",
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

/// Run [`housekeep`] once a minute.
pub fn spawn_housekeeping(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            housekeep(&state, SESSION_MAX_AGE).await;
        }
    })
}

/// Revocations one housekeeping pass runs at once.
const HOUSEKEEPING_REVOKE_CONCURRENCY: usize = 4;

/// One housekeeping pass: purge sessions created more than
/// `session_max_age` ago, expired pending logins and handoff codes, and
/// expired cache entries, then revoke the refresh tokens the purged
/// sessions and the expired handoffs still held (nothing will present them
/// again; a session's may have been rotated recently and still be live).
/// The revocations are awaited, a few at a time, before the pass returns.
pub async fn housekeep(state: &AppState, session_max_age: chrono::Duration) {
    let purged = state.sessions.purge_older_than(session_max_age);
    let (flow, unredeemed) = state.auth_flow.purge_expired();
    let cached = state.cache.purge_expired();
    let sessions = purged.len();
    if sessions + flow + cached > 0 {
        tracing::debug!(sessions, flow, cached, "housekeeping purged entries");
    }
    let abandoned = purged
        .into_iter()
        .map(|s| (s.refresh_token, "purged session"))
        .chain(
            unredeemed
                .into_iter()
                .map(|t| (t.refresh_token, "expired handoff")),
        );
    futures::stream::iter(abandoned)
        .for_each_concurrent(
            HOUSEKEEPING_REVOKE_CONCURRENCY,
            |(refresh_token, held_by)| async move {
                auth::oauth::revoke_abandoned(state, &refresh_token, held_by).await;
            },
        )
        .await;
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

    /// Every field value of every span opened while it is the subscriber.
    #[derive(Clone, Default)]
    struct SpanFields(std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanFields {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visit<'a>(&'a mut Vec<(String, String)>);
            impl tracing::field::Visit for Visit<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0
                        .push((field.name().to_string(), format!("{value:?}")));
                }
            }
            let mut fields = self.0.lock().unwrap_or_else(|p| p.into_inner());
            attrs.record(&mut Visit(&mut fields));
        }
    }

    /// The OAuth callback carries a live authorization code and `state` in
    /// its query, so the request span must record the path alone.
    #[test]
    fn request_span_omits_the_query() {
        use tracing_subscriber::layer::SubscriberExt;

        let seen = SpanFields::default();
        let subscriber = tracing_subscriber::registry().with(seen.clone());
        let req = Request::builder()
            .uri("/auth/callback?code=x&state=y")
            .body(axum::body::Body::empty())
            .unwrap();
        tracing::subscriber::with_default(subscriber, || {
            let _span = request_span(&req);
        });

        let fields = seen.0.lock().unwrap().clone();
        let path = fields
            .iter()
            .find(|(name, _)| name == "path")
            .map(|(_, v)| v.as_str());
        assert_eq!(path, Some("/auth/callback"), "{fields:?}");
        assert!(
            fields
                .iter()
                .all(|(_, v)| !v.contains('?') && !v.contains("code=") && !v.contains("state=")),
            "a recorded field carries the query: {fields:?}"
        );
        assert!(
            fields
                .iter()
                .any(|(name, v)| name == "method" && v == "GET"),
            "the method is still recorded: {fields:?}"
        );
    }
}
