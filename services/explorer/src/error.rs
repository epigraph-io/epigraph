//! [`AppError`]: the one error type handlers return.
//!
//! Handlers return `Result<_, AppError>` and never format error pages
//! themselves. `AppError::into_response` tags the response; the
//! [`render_errors`] layer then renders it by path:
//!
//! - `/bff/*` → JSON `{"error": "<kind>", "message": "…"}` with the status.
//! - pages → `templates/error.html`, except `Unauthorized` and
//!   `SessionExpired`, which 303 to `/auth/login?return_to=<this page>`
//!   (`SessionExpired` also clears the cookie).
//!
//! The same layer turns axum's bare rejections (unknown route, 405, bad
//! `Path`/`Query`) into the same pages, so nothing text/plain leaks out.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

use crate::auth::{self, PageCtx};
use crate::state::AppState;
use crate::upstream::UpstreamError;
use crate::view::ErrorPage;

#[derive(Debug, Clone, Error)]
pub enum AppError {
    /// Not found (404). The string names what was missing ("claim",
    /// "agent", …) and is shown to the viewer.
    #[error("not found: {0}")]
    NotFound(String),
    /// Bad request (400). Shown to the viewer.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// Sign-in required: pages redirect to login, `/bff/*` returns 401.
    #[error("sign-in required")]
    Unauthorized,
    /// The session ended (upstream 401 after refresh + retry): like
    /// `Unauthorized`, and the cookie is cleared.
    #[error("session expired")]
    SessionExpired,
    /// Forbidden (403). Shown to the viewer.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// A required upstream call failed: 504 on timeout, else 502. Only the
    /// error's `user_message()` is shown; the detail is logged.
    #[error("upstream: {0}")]
    Upstream(UpstreamError),
    /// 503: the page as a whole cannot be served right now.
    #[error("degraded: {0}")]
    Degraded(String),
    /// 501 from `/bff/*` stubs that an area has not built yet.
    #[error("not built yet: {0}")]
    NotBuilt(&'static str),
    /// Internal error (500). The detail is logged, never shown.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<UpstreamError> for AppError {
    fn from(e: UpstreamError) -> Self {
        match e {
            UpstreamError::NotFound { .. } => AppError::NotFound("page".into()),
            UpstreamError::Unauthorized { .. } => AppError::Unauthorized,
            UpstreamError::SessionExpired => AppError::SessionExpired,
            UpstreamError::Forbidden { .. } => {
                AppError::Forbidden("You do not have access to this.".into())
            }
            other => AppError::Upstream(other),
        }
    }
}

/// `map_err` adaptor naming what a 404 means on this page:
/// `api.claim(id).await.map_err(not_found_as("claim"))?`. Every other error
/// converts as `From<UpstreamError>` does.
pub fn not_found_as(what: &'static str) -> impl Fn(UpstreamError) -> AppError {
    move |e| match e {
        UpstreamError::NotFound { .. } => AppError::NotFound(what.into()),
        other => other.into(),
    }
}

impl From<askama::Error> for AppError {
    fn from(e: askama::Error) -> Self {
        AppError::Internal(format!("template: {e}"))
    }
}

impl AppError {
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized | AppError::SessionExpired => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::Upstream(UpstreamError::Timeout) => StatusCode::GATEWAY_TIMEOUT,
            AppError::Upstream(_) => StatusCode::BAD_GATEWAY,
            AppError::Degraded(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::NotBuilt(_) => StatusCode::NOT_IMPLEMENTED,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable machine-readable kind for `/bff/*` JSON.
    pub fn kind(&self) -> &'static str {
        match self {
            AppError::NotFound(_) => "not_found",
            AppError::BadRequest(_) => "bad_request",
            AppError::Unauthorized => "unauthorized",
            AppError::SessionExpired => "session_expired",
            AppError::Forbidden(_) => "forbidden",
            AppError::Upstream(UpstreamError::Timeout) => "upstream_timeout",
            AppError::Upstream(_) => "upstream_unavailable",
            AppError::Degraded(_) => "degraded",
            AppError::NotBuilt(_) => "not_built",
            AppError::Internal(_) => "internal",
        }
    }

    /// Short page heading.
    pub fn title(&self) -> &'static str {
        match self {
            AppError::NotFound(_) => "Not found",
            AppError::BadRequest(_) => "Bad request",
            AppError::Unauthorized => "Sign in required",
            AppError::SessionExpired => "Session expired",
            AppError::Forbidden(_) => "No access",
            AppError::Upstream(_) => "EpiGraph is unavailable",
            AppError::Degraded(_) => "Temporarily unavailable",
            AppError::NotBuilt(_) => "Not built yet",
            AppError::Internal(_) => "Something went wrong",
        }
    }

    /// Viewer-safe explanation.
    pub fn public_message(&self) -> String {
        match self {
            AppError::NotFound(what) => format!("We could not find that {what}."),
            AppError::BadRequest(m) | AppError::Forbidden(m) | AppError::Degraded(m) => m.clone(),
            AppError::Unauthorized => "Sign in to continue.".into(),
            AppError::SessionExpired => "Your session has expired. Sign in again.".into(),
            AppError::Upstream(e) => e.user_message().into(),
            AppError::NotBuilt(what) => format!("{what} is not built yet."),
            AppError::Internal(_) => "An unexpected error occurred.".into(),
        }
    }

    /// Map a bare status (axum rejection, unknown route) to an error.
    pub fn from_status(status: StatusCode) -> Self {
        match status {
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => {
                AppError::NotFound("page".into())
            }
            StatusCode::UNAUTHORIZED => AppError::Unauthorized,
            StatusCode::FORBIDDEN => AppError::Forbidden("You do not have access to this.".into()),
            s if s.is_client_error() => AppError::BadRequest("The request was malformed.".into()),
            _ => AppError::Internal(format!("unmarked {status} response")),
        }
    }
}

/// Marker the render layer looks for.
#[derive(Clone)]
struct ErrorMarker(Arc<AppError>);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match &self {
            AppError::Internal(detail) => tracing::error!(%detail, "internal error"),
            AppError::Upstream(e) => tracing::warn!(error = %e, "required upstream call failed"),
            _ => {}
        }
        // Plain-text fallback, replaced by `render_errors` in the real app.
        let mut resp = (self.status(), self.public_message()).into_response();
        resp.extensions_mut().insert(ErrorMarker(Arc::new(self)));
        resp
    }
}

/// Middleware (installed by `app::build_app`) that renders every error
/// response as HTML or JSON; see the module docs.
pub async fn render_errors(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let received = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let headers = req.headers().clone();

    let resp = next.run(req).await;

    let err = match resp.extensions().get::<ErrorMarker>() {
        Some(m) => Arc::clone(&m.0),
        None if is_unmarked_error(&resp) => Arc::new(AppError::from_status(resp.status())),
        None => return resp,
    };

    let path_only = received.split('?').next().unwrap_or("/");
    let route_path = state.links.strip_base(path_only);
    let is_bff = route_path == "/bff" || route_path.starts_with("/bff/");
    let clear_cookie = matches!(*err, AppError::SessionExpired);

    let mut out = if is_bff {
        (
            err.status(),
            Json(json!({ "error": err.kind(), "message": err.public_message() })),
        )
            .into_response()
    } else if matches!(*err, AppError::Unauthorized | AppError::SessionExpired) {
        let browser = state.links.browser_path(&received);
        Redirect::to(&state.links.login(Some(&browser))).into_response()
    } else {
        let signed_in = auth::read_session_cookie(&headers)
            .is_some_and(|id| state.sessions.get(&id).is_some())
            || state.config.dev_bearer.is_some();
        let ctx = PageCtx::new(
            state.links.clone(),
            state.links.browser_path(&received),
            signed_in,
        );
        let page = ErrorPage {
            ctx,
            status: err.status().as_u16(),
            title: err.title().to_string(),
            message: err.public_message(),
        };
        match askama::Template::render(&page) {
            Ok(html) => (err.status(), Html(html)).into_response(),
            Err(e) => {
                tracing::error!(error = %e, "error page failed to render");
                (err.status(), err.public_message()).into_response()
            }
        }
    };

    if clear_cookie {
        out.headers_mut().append(
            header::SET_COOKIE,
            auth::clear_session_cookie(&state.config),
        );
    }
    out.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    out
}

/// An error status whose body is not ours to keep: axum rejections are
/// text/plain or empty. HTML/JSON bodies are left alone.
fn is_unmarked_error(resp: &Response) -> bool {
    if !(resp.status().is_client_error() || resp.status().is_server_error()) {
        return false;
    }
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    !(ct.starts_with("text/html") || ct.starts_with("application/json"))
}
