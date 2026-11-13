//! The Atlas fixture preview (backlog W11). OWNED BY THE ATLAS AREA.
//!
//! An opt-in way to try the nested Atlas levels with no database and no
//! kernel: `epigraph-explorer --atlas-fixture-preview <port | loopback-ip:port>`
//! serves the committed synthetic level documents
//! (`contract/atlas_level/v1/preview/` and the contract fixtures) by level id,
//! and a preview page that draws them.
//!
//! It cannot be switched on by accident in production:
//! - off unless the flag is on the command line (no environment variable
//!   enables it, so an env file cannot);
//! - it binds an IP-literal loopback address only, and refuses `0.0.0.0`,
//!   `::`, any other address and any host name;
//! - it builds its own router: health, static assets, the preview page and
//!   the preview level route. No upstream route is mounted, the API URL is a
//!   dead loopback port, and `build_app` never mounts the preview;
//! - it logs a warning at start, every page carries a banner, and every
//!   response carries `x-atlas-preview: synthetic-fixtures`.
//!
//! The data is compiled in, so the binary needs nothing else to run. Bodies are
//! served exactly as committed: the store indexes each document by its
//! `level_id` and never re-encodes it.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{header, HeaderName, HeaderValue};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Extension, Router};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::auth::PageCtx;
use crate::config::{
    Config, ConfigError, ENV_API_URL, ENV_FRAME_ANCESTORS, ENV_INSECURE_COOKIES, ENV_PORT,
    ENV_PUBLIC_BASE_URL,
};
use crate::error::{self, AppError};
use crate::state::AppState;
use crate::upstream::atlas_level::AtlasLevel;
use crate::view::render;
use crate::{assets, security};

/// The command-line flag that starts the preview instead of the Explorer.
pub const FLAG: &str = "--atlas-fixture-preview";
/// The header every preview response carries.
pub const PREVIEW_HEADER: &str = "x-atlas-preview";
pub const PREVIEW_HEADER_VALUE: &str = "synthetic-fixtures";
/// The page and the level route.
pub const PAGE_PATH: &str = "/atlas/preview";
pub const LEVEL_PREFIX: &str = "/bff/atlas/preview/level/";
/// A loopback port nothing listens on: the preview never calls the API, and
/// if a future change made it try, the call fails instead of reaching one.
const DEAD_API_URL: &str = "http://127.0.0.1:9";

const MANIFEST: &str = include_str!("../contract/atlas_level/v1/preview/manifest.json");
const PREVIEW_LEVELS: &str = include_str!("../contract/atlas_level/v1/preview/levels.jsonl");
/// The contract fixtures, served by id too (they link nowhere: their
/// breadcrumbs and targets name ids no fixture holds).
const CONTRACT_FIXTURES: &[&str] = &[
    include_str!("../contract/atlas_level/v1/fixtures/team_theme_root.json"),
    include_str!("../contract/atlas_level/v1/fixtures/team_group_deep.json"),
    include_str!("../contract/atlas_level/v1/fixtures/team_leaf_dense.json"),
    include_str!("../contract/atlas_level/v1/fixtures/public_leaf.json"),
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreviewError {
    #[error("{FLAG} needs a port or a loopback ip:port, e.g. {FLAG} 8097")]
    MissingAddress,
    #[error("{FLAG} {0}: not a port or an ip:port")]
    BadAddress(String),
    #[error("{FLAG} {0}: refused, the preview binds a loopback address only (127.0.0.0/8 or ::1)")]
    NotLoopback(String),
    #[error("{FLAG} {0}: port 0 is not allowed")]
    PortZero(String),
    #[error("preview configuration: {0}")]
    Config(String),
}

impl From<ConfigError> for PreviewError {
    fn from(e: ConfigError) -> Self {
        PreviewError::Config(e.to_string())
    }
}

/// The preview's bind address from the command line, or `None` when the flag
/// is absent (the normal Explorer). Accepts `FLAG VALUE` and `FLAG=VALUE`.
pub fn preview_bind(args: &[String]) -> Result<Option<SocketAddr>, PreviewError> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == FLAG {
            return match it.next() {
                Some(v) if !v.starts_with("--") => parse_bind(v).map(Some),
                _ => Err(PreviewError::MissingAddress),
            };
        }
        if let Some(v) = a.strip_prefix(FLAG).and_then(|r| r.strip_prefix('=')) {
            return parse_bind(v).map(Some);
        }
    }
    Ok(None)
}

/// A bare port means `127.0.0.1:<port>`; otherwise an IP-literal loopback
/// `ip:port` (`[::1]:<port>` for IPv6). Host names are refused, since what
/// they resolve to is not known here.
pub fn parse_bind(v: &str) -> Result<SocketAddr, PreviewError> {
    let v = v.trim();
    if v.is_empty() {
        return Err(PreviewError::MissingAddress);
    }
    let addr = if v.bytes().all(|b| b.is_ascii_digit()) {
        let port: u16 = v
            .parse()
            .map_err(|_| PreviewError::BadAddress(v.to_string()))?;
        SocketAddr::from(([127, 0, 0, 1], port))
    } else {
        v.parse::<SocketAddr>()
            .map_err(|_| PreviewError::BadAddress(v.to_string()))?
    };
    if !is_loopback(addr.ip()) {
        return Err(PreviewError::NotLoopback(v.to_string()));
    }
    if addr.port() == 0 {
        return Err(PreviewError::PortZero(v.to_string()));
    }
    Ok(addr)
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback(),
        // `::ffff:127.0.0.1` binds the IPv4 loopback; accept it only as such.
        IpAddr::V6(a) => a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    }
}

/// The Explorer configuration the preview runs with: built here, never read
/// from the environment, so nothing in an env file reaches it.
pub fn config(addr: SocketAddr) -> Result<Config, PreviewError> {
    let public = format!("http://{addr}");
    let port = addr.port().to_string();
    let vars: HashMap<&str, String> = HashMap::from([
        (ENV_PUBLIC_BASE_URL, public),
        (ENV_API_URL, DEAD_API_URL.to_string()),
        (ENV_PORT, port),
        (ENV_INSECURE_COOKIES, "true".to_string()),
        (ENV_FRAME_ANCESTORS, String::new()),
    ]);
    Ok(Config::from_lookup(|k| vars.get(k).cloned())?)
}

/// The embedded level documents, by level id, served as committed.
#[derive(Debug)]
pub struct PreviewStore {
    levels: HashMap<Uuid, &'static str>,
}

impl PreviewStore {
    /// Index the compiled-in documents. Each must decode as a v1 level (the
    /// mirror types), and ids must be unique; the committed data is checked
    /// by the contract crate's tests, so a failure here is a build defect.
    pub fn embedded() -> Self {
        let docs = PREVIEW_LEVELS
            .lines()
            .filter(|l| !l.trim().is_empty())
            .chain(CONTRACT_FIXTURES.iter().copied());
        let mut levels = HashMap::new();
        for body in docs {
            let doc: AtlasLevel =
                serde_json::from_str(body).expect("an embedded preview level decodes");
            let id = match &doc {
                AtlasLevel::Group(g) => g.level_id,
                AtlasLevel::Leaf(l) => l.level_id,
            };
            assert!(
                levels.insert(id, body).is_none(),
                "embedded preview level {id} is duplicated"
            );
        }
        PreviewStore { levels }
    }

    pub fn get(&self, id: Uuid) -> Option<&'static str> {
        self.levels.get(&id).copied()
    }

    pub fn len(&self) -> usize {
        self.levels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.levels.is_empty()
    }

    /// The maps and theme roots the page offers (`data-atlas-maps`).
    pub fn manifest(&self) -> &'static str {
        MANIFEST
    }
}

#[derive(Template)]
#[template(path = "atlas/preview.html")]
struct PreviewPage {
    ctx: PageCtx,
    level_prefix: String,
    maps_json: &'static str,
    level_count: usize,
}

/// The preview router: health, static, the page and the level route, with the
/// app's error rendering and security headers, and the preview header on
/// every response. It mounts nothing that calls the API.
pub fn router(state: AppState, store: Arc<PreviewStore>) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to(PAGE_PATH) }))
        .route("/health", get(health))
        .route("/static/{*path}", get(assets::serve))
        .route(PAGE_PATH, get(page))
        .route(&format!("{LEVEL_PREFIX}{{id}}"), get(level))
        .fallback(|| async { AppError::NotFound("page".into()) })
        .layer(Extension(store))
        .layer(from_fn_with_state(state.clone(), error::render_errors))
        .layer(from_fn_with_state(
            state.clone(),
            security::security_headers,
        ))
        .layer(from_fn(mark_preview))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn mark_preview(req: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        HeaderName::from_static(PREVIEW_HEADER),
        HeaderValue::from_static(PREVIEW_HEADER_VALUE),
    );
    resp
}

async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "status": "ok", "mode": "atlas-fixture-preview" }))
}

async fn page(
    State(state): State<AppState>,
    Extension(store): Extension<Arc<PreviewStore>>,
) -> Result<Html<String>, AppError> {
    let links = &state.links;
    render(&PreviewPage {
        ctx: PageCtx::new(links.clone(), links.path(PAGE_PATH), false),
        level_prefix: links.path(LEVEL_PREFIX),
        maps_json: store.manifest(),
        level_count: store.len(),
    })
}

/// One level by id, as committed; an absent or malformed id gets the
/// contract's BFF not-found body (the same for both).
async fn level(
    Path(id): Path<String>,
    Extension(store): Extension<Arc<PreviewStore>>,
) -> Result<Response, AppError> {
    let body = Uuid::parse_str(&id)
        .ok()
        .and_then(|id| store.get(id))
        .ok_or_else(|| AppError::NotFound("atlas level".into()))?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, security::PAGE_CACHE_CONTROL),
        ],
        body,
    )
        .into_response())
}

/// Serve the preview until Ctrl-C or SIGTERM.
pub async fn serve(
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let config = config(addr)?;
    let state = AppState::new(config)?;
    let store = Arc::new(PreviewStore::embedded());
    tracing::warn!(
        %addr,
        levels = store.len(),
        "ATLAS FIXTURE PREVIEW: serving SYNTHETIC fixture levels only, with no API, no \
         database and no sign-in. This is not the Explorer. Open http://{addr}{PAGE_PATH}"
    );
    let router = router(state, store);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::warn!(%addr, "atlas fixture preview listening (loopback only)");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
