//! How `bin/server.rs` serves: the listen address, the per-request timeout, the
//! global body limit, the request-id and trace layers, and the shutdown drain
//! (backlog ebd7952c).
//!
//! Before this module the binary bound `0.0.0.0` unconditionally, had a 10 MiB
//! body limit written into `main`, no request timeout (a handler stuck on a
//! lock held its connection for as long as the lock lasted), no per-request
//! log line or request id, and no shutdown handling at all: SIGTERM killed the
//! process mid-response.
//!
//! The settings are read once, at the top of `main`, next to the rate-limit
//! settings and before any database connection, so a malformed value refuses
//! to start even when the database is down. Every default is what the binary
//! did before, except the timeout and the drain, which did not exist; see
//! [`DEFAULT_REQUEST_TIMEOUT_SECS`] and [`DEFAULT_SHUTDOWN_GRACE_SECS`].
//!
//! CORS is deliberately NOT here: which origins may call this API is the
//! operator's policy, set at the reverse proxy.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use axum::http::{Request, Response, StatusCode};
use axum::Router;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{
    MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// The address the application listener binds (an IP address; the port is
/// `EPIGRAPH_PORT`).
pub const BIND_ADDR_ENV: &str = "EPIGRAPH_BIND_ADDR";
/// Seconds a request may take before it is answered 408; `0` turns the
/// timeout off.
pub const REQUEST_TIMEOUT_ENV: &str = "EPIGRAPH_REQUEST_TIMEOUT_SECS";
/// Seconds the server keeps serving in-flight requests after SIGTERM.
pub const SHUTDOWN_GRACE_ENV: &str = "EPIGRAPH_SHUTDOWN_GRACE_SECS";
/// The global request-body limit, in bytes.
pub const MAX_REQUEST_BYTES_ENV: &str = "EPIGRAPH_MAX_REQUEST_BYTES";

/// The bind address before this setting existed, kept as the default so a
/// deployment that does not set the variable is unchanged.
pub const DEFAULT_BIND_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Five minutes. Generous on purpose: the slowest handlers (ingestion,
/// synthesis, belief propagation) call out to models or walk large parts of
/// the graph, and a timeout that fires after a handler has committed answers
/// 408 for a write that happened, which a client may retry. The default is
/// meant to end a request that is stuck, not to bound a slow one.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 300;

/// Thirty seconds: below systemd's default stop timeout (90 s), so the drain
/// ends on its own before the unit is killed.
pub const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 30;

/// 10 MiB, the limit `main` hardcoded before: figure evidence carries base64
/// images.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 10 * 1024 * 1024;

/// The header that carries the request id, in and out.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// The longest incoming request id that is kept.
pub const MAX_INCOMING_REQUEST_ID_LEN: usize = 64;

/// The serving settings, read once at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeSettings {
    /// The application listener's IP address.
    pub bind_ip: IpAddr,
    /// The per-request timeout; `None` when turned off.
    pub request_timeout: Option<Duration>,
    /// How long in-flight requests may run after SIGTERM.
    pub shutdown_grace: Duration,
    /// The global request-body limit.
    pub max_request_bytes: usize,
}

impl Default for ServeSettings {
    fn default() -> Self {
        Self {
            bind_ip: DEFAULT_BIND_IP,
            request_timeout: Some(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS)),
            shutdown_grace: Duration::from_secs(DEFAULT_SHUTDOWN_GRACE_SECS),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
        }
    }
}

fn blank_is_unset(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|v| !v.is_empty())
}

fn whole_number(name: &str, raw: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|_| format!("{name}={raw:?} is not a whole number"))
}

impl ServeSettings {
    /// Parse the raw variable values (`None` = unset; blank = unset).
    ///
    /// A value that does not parse is an error, not a default: a typo in the
    /// bind address must not quietly listen on every interface, and a typo in
    /// a limit must not quietly serve a different one.
    pub fn parse(
        bind_addr: Option<&str>,
        request_timeout_secs: Option<&str>,
        shutdown_grace_secs: Option<&str>,
        max_request_bytes: Option<&str>,
    ) -> Result<Self, String> {
        let mut settings = Self::default();
        if let Some(raw) = blank_is_unset(bind_addr) {
            settings.bind_ip = raw.parse::<IpAddr>().map_err(|_| {
                format!(
                    "{BIND_ADDR_ENV}={raw:?} is not an IP address (for example 127.0.0.1, \
                     0.0.0.0 or ::1; the port is EPIGRAPH_PORT)"
                )
            })?;
        }
        if let Some(raw) = blank_is_unset(request_timeout_secs) {
            settings.request_timeout = match whole_number(REQUEST_TIMEOUT_ENV, raw)? {
                0 => None,
                secs => Some(Duration::from_secs(secs)),
            };
        }
        if let Some(raw) = blank_is_unset(shutdown_grace_secs) {
            settings.shutdown_grace = Duration::from_secs(whole_number(SHUTDOWN_GRACE_ENV, raw)?);
        }
        if let Some(raw) = blank_is_unset(max_request_bytes) {
            settings.max_request_bytes =
                raw.parse::<usize>()
                    .ok()
                    .filter(|n| *n >= 1)
                    .ok_or_else(|| {
                        format!("{MAX_REQUEST_BYTES_ENV}={raw:?} is not a positive whole number")
                    })?;
        }
        Ok(settings)
    }

    /// Read and parse the variables from the process environment.
    pub fn from_env() -> Result<Self, String> {
        let var = |name: &str| std::env::var(name).ok();
        Self::parse(
            var(BIND_ADDR_ENV).as_deref(),
            var(REQUEST_TIMEOUT_ENV).as_deref(),
            var(SHUTDOWN_GRACE_ENV).as_deref(),
            var(MAX_REQUEST_BYTES_ENV).as_deref(),
        )
    }
}

/// The request pool's maximum number of connections.
pub const DB_MAX_CONNECTIONS_ENV: &str = "EPIGRAPH_DB_MAX_CONNECTIONS";
/// The request pool's per-connection `statement_timeout`, in milliseconds;
/// `0` (like unset) leaves the database's own setting in place.
pub const DB_STATEMENT_TIMEOUT_ENV: &str = "EPIGRAPH_DB_STATEMENT_TIMEOUT_MS";

/// The request pool's size before this setting existed (sqlx's
/// `PgPool::connect` default, which `epigraph_db::ScopedPoolOptions::default`
/// reproduces), kept as the default.
pub const DEFAULT_DB_MAX_CONNECTIONS: u32 = 10;

/// The request pool's sizing and statement timeout (backlog b4c4337f), read
/// once at boot like [`ServeSettings`].
///
/// Before these existed `bin/server.rs` built its pool with
/// `ScopedPoolOptions::default()`: ten connections and no statement timeout,
/// so the pool could not be sized to the host or to Postgres'
/// `max_connections` without a code change, and a runaway query held one of
/// the ten for as long as it ran. Every default is that behaviour.
///
/// The timeout is a session `SET statement_timeout` issued once on each new
/// connection, so it holds only on a session-mode endpoint: behind a
/// transaction-mode pooler (`EPIGRAPH_SESSION_GUC_MODE=transaction`) the
/// setting lands on whichever server connection the pooler handed out and is
/// not reliable. A handler that sets its own timeout (`SET LOCAL`, or a
/// session `SET` it restores) overrides it for that statement.
///
/// The "request pool" is the process's only pool, so the timeout bounds every
/// statement on it, not only request handlers: the webhook dispatcher, the
/// tenancy gauge and canary sampler and the boot checks share it. Time a
/// statement spends waiting on a lock counts against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPoolSettings {
    /// The most connections the request pool holds open.
    pub max_connections: u32,
    /// Each connection's `statement_timeout`; `None` leaves the database's.
    pub statement_timeout: Option<Duration>,
}

impl Default for RequestPoolSettings {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_DB_MAX_CONNECTIONS,
            statement_timeout: None,
        }
    }
}

impl RequestPoolSettings {
    /// Parse the raw variable values (`None` = unset; blank = unset). A value
    /// that does not parse is an error, not a default.
    pub fn parse(
        max_connections: Option<&str>,
        statement_timeout_ms: Option<&str>,
    ) -> Result<Self, String> {
        let mut settings = Self::default();
        if let Some(raw) = blank_is_unset(max_connections) {
            settings.max_connections =
                raw.parse::<u32>().ok().filter(|n| *n >= 1).ok_or_else(|| {
                    format!("{DB_MAX_CONNECTIONS_ENV}={raw:?} is not a positive whole number")
                })?;
        }
        if let Some(raw) = blank_is_unset(statement_timeout_ms) {
            settings.statement_timeout = match whole_number(DB_STATEMENT_TIMEOUT_ENV, raw)? {
                0 => None,
                ms => Some(Duration::from_millis(ms)),
            };
        }
        Ok(settings)
    }

    /// Read and parse the variables from the process environment.
    pub fn from_env() -> Result<Self, String> {
        let var = |name: &str| std::env::var(name).ok();
        Self::parse(
            var(DB_MAX_CONNECTIONS_ENV).as_deref(),
            var(DB_STATEMENT_TIMEOUT_ENV).as_deref(),
        )
    }

    /// The pool options these settings describe; everything else (the
    /// acquire timeout) is `ScopedPoolOptions::default()`'s.
    #[cfg(feature = "db")]
    #[must_use]
    pub fn pool_options(&self) -> epigraph_db::ScopedPoolOptions {
        epigraph_db::ScopedPoolOptions {
            max_connections: self.max_connections,
            statement_timeout: self.statement_timeout,
            ..epigraph_db::ScopedPoolOptions::default()
        }
    }
}

/// Wrap the application router in the request-id, trace, timeout and
/// panic-catching layers.
///
/// Outermost first: a request id is set (an incoming `x-request-id` is kept
/// when [`is_acceptable_request_id`] passes it, otherwise a UUID is minted),
/// the request is traced in a span carrying that id, the id is copied onto the
/// response, the handler runs under the timeout, and a panic in it is caught.
/// So a 408 from the timeout is traced and carries the id too.
///
/// The panic layer (backlog b4c4337f) is innermost: a handler that panics is
/// answered `500` with the body `Service panicked` (the panic message is
/// logged at ERROR inside the request span, never sent), traced and carrying
/// the request id. Without it the panic unwound into hyper, which dropped the
/// connection with no response at all.
///
/// Every response is logged once at INFO (status and latency) by
/// [`log_response`], and a 408 at WARN: tower-http's default response event is
/// DEBUG, which the default filter drops, and a timeout that fired after a
/// handler committed must not be invisible to the operator.
///
/// The span records the method, the path (through [`loggable_path`]) and the
/// request id, and nothing else. Not the query string (`/oauth/authorize` and
/// `/oauth/callback` carry authorization codes and state there), no headers
/// (bearer tokens), and not the passkey ceremonies' path credentials.
pub fn apply_layers(router: Router, settings: &ServeSettings) -> Router {
    let router = router.layer(CatchPanicLayer::new());
    let router = match settings.request_timeout {
        Some(timeout) => router.layer(TimeoutLayer::new(timeout)),
        None => router,
    };
    router.layer(
        ServiceBuilder::new()
            .map_request(drop_unacceptable_request_id::<axum::body::Body>)
            .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(request_span)
                    .on_response(log_response),
            )
            .layer(PropagateRequestIdLayer::x_request_id()),
    )
}

/// Whether a client-supplied request id is kept: 1 to
/// [`MAX_INCOMING_REQUEST_ID_LEN`] characters of `[A-Za-z0-9._-]`.
///
/// The id is recorded into the request span, which every event the request
/// emits carries, and the text log writes span fields unquoted. A header like
/// `x path=/api/v1/admin method=DELETE` would forge fields into each of those
/// lines, and a header of many KiB would be copied into each of them. Anything
/// else is replaced by a minted UUID, so a request is still traceable.
#[must_use]
pub fn is_acceptable_request_id(raw: &[u8]) -> bool {
    (1..=MAX_INCOMING_REQUEST_ID_LEN).contains(&raw.len())
        && raw
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Remove an incoming `x-request-id` that [`is_acceptable_request_id`]
/// refuses (every one, when the header is repeated and any copy is refused), so
/// `SetRequestIdLayer` mints one instead.
fn drop_unacceptable_request_id<B>(mut request: Request<B>) -> Request<B> {
    let headers = request.headers_mut();
    if headers
        .get_all(REQUEST_ID_HEADER)
        .iter()
        .any(|v| !is_acceptable_request_id(v.as_bytes()))
        || headers.get_all(REQUEST_ID_HEADER).iter().count() > 1
    {
        headers.remove(REQUEST_ID_HEADER);
    }
    request
}

/// The per-request log line, inside the request span (method, path, id).
fn log_response<B>(response: &Response<B>, latency: Duration, _span: &tracing::Span) {
    let status = response.status();
    let latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
    if status == StatusCode::REQUEST_TIMEOUT {
        tracing::warn!(
            status = status.as_u16(),
            latency_ms,
            "request timed out and was answered 408; a write its handler had already \
             committed stands"
        );
    } else {
        tracing::info!(status = status.as_u16(), latency_ms, "request finished");
    }
}

/// The trace span for one request: method, path and request id only.
fn request_span<B>(request: &Request<B>) -> tracing::Span {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .unwrap_or("-");
    tracing::info_span!(
        "request",
        method = %request.method(),
        path = %loggable_path(request.uri().path()),
        request_id = %request_id,
    )
}

/// The path as the request span records it: as received, except that the
/// passkey ceremonies' path segments are replaced by their route parameter.
///
/// `/elevate/enroll/:id`, `/elevate/:ticket` and `/elevate/act/:id` carry the
/// ceremony's own credential in the path (an enrollment id, a ticket id, an
/// act id: random, short-lived, single-use; `routes/mod.rs` documents them as
/// the ceremony's credentials together with the authenticator). The span is
/// attached to every event a request emits, so recording them would copy a
/// live credential into each of those log lines. The static assets under
/// `/elevate/assets/` are kept as they are.
pub fn loggable_path(path: &str) -> std::borrow::Cow<'_, str> {
    let Some(rest) = path.strip_prefix("/elevate/") else {
        return std::borrow::Cow::Borrowed(path);
    };
    let mut segments = rest.split('/');
    let (head, credential) = match segments.next() {
        Some("assets") => return std::borrow::Cow::Borrowed(path),
        Some(kind @ ("enroll" | "act")) => (Some(kind), segments.next()),
        first => (None, first),
    };
    if matches!(credential, None | Some("")) {
        return std::borrow::Cow::Borrowed(path);
    }
    let mut out = String::from("/elevate/");
    match head {
        Some(kind) => {
            out.push_str(kind);
            out.push_str("/:id");
        }
        None => out.push_str(":ticket"),
    }
    for tail in segments {
        out.push('/');
        out.push_str(tail);
    }
    std::borrow::Cow::Owned(out)
}

/// Resolves when the process receives SIGTERM (systemd's stop) or SIGINT
/// (Ctrl-C). If a handler cannot be installed, that signal is not waited for
/// and the failure is logged; the process then stops on the other signal, or
/// by being killed, as it did before this existed.
pub async fn shutdown_signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "cannot listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => tracing::info!("SIGINT received: shutting down"),
        () = terminate => tracing::info!("SIGTERM received: shutting down"),
    }
}

/// Serve `app` on `listener` until SIGTERM or SIGINT, then stop accepting,
/// let in-flight requests finish for at most `grace`, and return.
///
/// Served with connect info: the rate limiter keys an anonymous request on
/// its TCP peer, and without it every such request shares one bucket.
///
/// The grace bound matters because a graceful drain alone waits for every
/// open connection, and one slow or streaming response would hold the
/// process until systemd kills it, which is the abrupt stop this replaces.
pub async fn serve_until_signal(
    listener: tokio::net::TcpListener,
    app: Router,
    grace: Duration,
) -> std::io::Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop_tx.send(true);
    });
    let mut drain_rx = stop_rx.clone();
    let mut graceful_rx = stop_rx;
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = graceful_rx.wait_for(|stop| *stop).await;
    });
    let deadline = async move {
        let _ = drain_rx.wait_for(|stop| *stop).await;
        tokio::time::sleep(grace).await;
    };
    tokio::select! {
        served = std::future::IntoFuture::into_future(serve) => {
            served?;
            tracing::info!("server stopped: every in-flight request finished");
            Ok(())
        }
        () = deadline => {
            tracing::warn!(
                grace_secs = grace.as_secs(),
                "shutdown grace elapsed with requests still in flight; exiting without them"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower::ServiceExt;

    #[test]
    fn the_ceremony_credentials_never_reach_the_span() {
        for (raw, logged) in [
            (
                "/elevate/enroll/4f1c2a/finish",
                "/elevate/enroll/:id/finish",
            ),
            ("/elevate/enroll/4f1c2a", "/elevate/enroll/:id"),
            ("/elevate/act/9b7e/assert", "/elevate/act/:id/assert"),
            ("/elevate/act/9b7e", "/elevate/act/:id"),
            ("/elevate/t1ck3t/challenge", "/elevate/:ticket/challenge"),
            ("/elevate/t1ck3t", "/elevate/:ticket"),
        ] {
            assert_eq!(loggable_path(raw), logged, "{raw}");
        }
        for kept in [
            "/elevate/assets/elevate.js",
            "/elevate/",
            "/oauth/token",
            "/api/v1/claims/0b6f",
            "/health",
        ] {
            assert_eq!(loggable_path(kept), kept);
        }
    }

    #[test]
    fn unset_and_blank_are_the_pre_existing_behaviour() {
        let unset = ServeSettings::parse(None, None, None, None).expect("defaults");
        assert_eq!(unset.bind_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(unset.max_request_bytes, 10 * 1024 * 1024);
        assert_eq!(unset.request_timeout, Some(Duration::from_secs(300)));
        assert_eq!(unset.shutdown_grace, Duration::from_secs(30));
        let blank = ServeSettings::parse(Some(" "), Some(""), Some(" "), Some("")).expect("blank");
        assert_eq!(blank, unset);
    }

    #[test]
    fn values_are_read() {
        let s = ServeSettings::parse(Some("127.0.0.1"), Some("45"), Some("5"), Some("2048"))
            .expect("valid");
        assert_eq!(s.bind_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(s.request_timeout, Some(Duration::from_secs(45)));
        assert_eq!(s.shutdown_grace, Duration::from_secs(5));
        assert_eq!(s.max_request_bytes, 2048);
        let v6 = ServeSettings::parse(Some("::1"), None, None, None).expect("v6");
        assert_eq!(v6.bind_ip, "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_zero_timeout_turns_it_off_and_a_zero_grace_is_allowed() {
        let s = ServeSettings::parse(None, Some("0"), Some("0"), None).expect("zeros");
        assert_eq!(s.request_timeout, None);
        assert_eq!(s.shutdown_grace, Duration::ZERO);
    }

    #[test]
    fn malformed_values_are_refused_and_named() {
        for (bind, timeout, grace, bytes, var) in [
            (Some("localhost"), None, None, None, BIND_ADDR_ENV),
            (Some("0.0.0.0:8080"), None, None, None, BIND_ADDR_ENV),
            (None, Some("5m"), None, None, REQUEST_TIMEOUT_ENV),
            (None, Some("-1"), None, None, REQUEST_TIMEOUT_ENV),
            (None, None, Some("soon"), None, SHUTDOWN_GRACE_ENV),
            (None, None, None, Some("0"), MAX_REQUEST_BYTES_ENV),
            (None, None, None, Some("10MB"), MAX_REQUEST_BYTES_ENV),
        ] {
            let err = ServeSettings::parse(bind, timeout, grace, bytes)
                .expect_err("a malformed value must refuse, not default");
            assert!(err.contains(var), "the refusal must name {var}: {err}");
        }
    }

    #[test]
    fn the_request_pool_defaults_are_the_pre_existing_pool() {
        let unset = RequestPoolSettings::parse(None, None).expect("defaults");
        assert_eq!(unset, RequestPoolSettings::default());
        assert_eq!(
            RequestPoolSettings::parse(Some(" "), Some("")).expect("blank"),
            unset
        );
        #[cfg(feature = "db")]
        assert_eq!(
            unset.pool_options(),
            epigraph_db::ScopedPoolOptions::default(),
            "unset must build exactly the pool the server built before"
        );
    }

    #[test]
    fn the_request_pool_values_are_read_and_a_zero_timeout_is_off() {
        let s = RequestPoolSettings::parse(Some("25"), Some("15000")).expect("valid");
        assert_eq!(s.max_connections, 25);
        assert_eq!(s.statement_timeout, Some(Duration::from_millis(15_000)));
        #[cfg(feature = "db")]
        {
            let o = s.pool_options();
            assert_eq!(o.max_connections, 25);
            assert_eq!(o.statement_timeout, Some(Duration::from_millis(15_000)));
            assert_eq!(
                o.acquire_timeout,
                epigraph_db::ScopedPoolOptions::default().acquire_timeout
            );
        }
        let off = RequestPoolSettings::parse(None, Some("0")).expect("zero");
        assert_eq!(off.statement_timeout, None);
    }

    #[test]
    fn malformed_request_pool_values_are_refused_and_named() {
        for (max, timeout, var) in [
            (Some("0"), None, DB_MAX_CONNECTIONS_ENV),
            (Some("ten"), None, DB_MAX_CONNECTIONS_ENV),
            (Some("-1"), None, DB_MAX_CONNECTIONS_ENV),
            (None, Some("30s"), DB_STATEMENT_TIMEOUT_ENV),
            (None, Some("-5"), DB_STATEMENT_TIMEOUT_ENV),
        ] {
            let err = RequestPoolSettings::parse(max, timeout)
                .expect_err("a malformed value must refuse, not default");
            assert!(err.contains(var), "the refusal must name {var}: {err}");
        }
    }

    fn slow_router() -> Router {
        Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    "late"
                }),
            )
            .route("/fast", get(|| async { "ok" }))
    }

    async fn call(
        router: Router,
        path: &str,
        request_id: Option<&str>,
    ) -> axum::response::Response {
        let mut request = Request::builder().uri(path);
        if let Some(id) = request_id {
            request = request.header(REQUEST_ID_HEADER, id);
        }
        router
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .expect("infallible")
    }

    #[tokio::test]
    async fn a_request_past_the_timeout_is_answered_408_with_its_request_id() {
        let settings = ServeSettings {
            request_timeout: Some(Duration::from_millis(100)),
            ..ServeSettings::default()
        };
        let started = std::time::Instant::now();
        let response = call(apply_layers(slow_router(), &settings), "/slow", None).await;
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the handler ran to completion: the timeout did not fire"
        );
        assert!(
            response.headers().contains_key(REQUEST_ID_HEADER),
            "the 408 must carry the request id"
        );
        // Calibration: a request inside the timeout is served.
        let fast = call(apply_layers(slow_router(), &settings), "/fast", None).await;
        assert_eq!(fast.status(), StatusCode::OK);
    }

    /// b4c4337f: a panicking handler is answered 500, with the request id and
    /// without the panic message, and the router keeps serving. Without the
    /// panic layer the panic unwinds out of `oneshot` and fails this test.
    #[tokio::test]
    async fn a_panicking_handler_is_answered_500_with_its_request_id() {
        let router = slow_router().route(
            "/panic",
            get(|| async {
                if std::hint::black_box(true) {
                    panic!("handler exploded: secret-detail-7731");
                }
                "unreachable"
            }),
        );
        let app = apply_layers(router, &ServeSettings::default());
        let response = call(app.clone(), "/panic", Some("req-panic-1")).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(REQUEST_ID_HEADER).unwrap(),
            "req-panic-1",
            "the 500 carries the request id"
        );
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("body");
        let body = String::from_utf8_lossy(&body);
        assert!(
            !body.contains("secret-detail-7731"),
            "the panic message must not reach the client: {body}"
        );
        // The service is still up after the panic.
        let fast = call(app, "/fast", None).await;
        assert_eq!(fast.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn every_response_carries_a_request_id_and_an_incoming_one_is_kept() {
        let settings = ServeSettings::default();
        let minted = call(apply_layers(slow_router(), &settings), "/fast", None).await;
        let id = minted
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("a minted request id")
            .to_str()
            .unwrap()
            .to_string();
        assert!(uuid::Uuid::parse_str(&id).is_ok(), "not a UUID: {id}");
        let kept = call(
            apply_layers(slow_router(), &settings),
            "/fast",
            Some("abc-123"),
        )
        .await;
        assert_eq!(kept.headers().get(REQUEST_ID_HEADER).unwrap(), "abc-123");
    }

    #[tokio::test]
    async fn an_incoming_request_id_that_could_forge_log_fields_is_replaced() {
        let settings = ServeSettings::default();
        let long = "a".repeat(MAX_INCOMING_REQUEST_ID_LEN + 1);
        for forged in [
            "x path=/api/v1/admin method=DELETE",
            "a\"b",
            "id%0a",
            long.as_str(),
        ] {
            let response = call(
                apply_layers(slow_router(), &settings),
                "/fast",
                Some(forged),
            )
            .await;
            let id = response
                .headers()
                .get(REQUEST_ID_HEADER)
                .expect("a request id")
                .to_str()
                .unwrap();
            assert_ne!(id, forged, "an unsafe incoming id was kept");
            assert!(
                uuid::Uuid::parse_str(id).is_ok(),
                "{forged:?} -> {id}: not minted"
            );
        }
        // The boundary that is kept.
        let at_limit = "a".repeat(MAX_INCOMING_REQUEST_ID_LEN);
        for ok in ["req.1_A-z", at_limit.as_str()] {
            let response = call(apply_layers(slow_router(), &settings), "/fast", Some(ok)).await;
            assert_eq!(response.headers().get(REQUEST_ID_HEADER).unwrap(), ok);
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn a_timed_out_request_is_logged_at_warn_and_a_finished_one_at_info() {
        let settings = ServeSettings {
            request_timeout: Some(Duration::from_millis(100)),
            ..ServeSettings::default()
        };
        let slow = call(apply_layers(slow_router(), &settings), "/slow", None).await;
        assert_eq!(slow.status(), StatusCode::REQUEST_TIMEOUT);
        let fast = call(apply_layers(slow_router(), &settings), "/fast", None).await;
        assert_eq!(fast.status(), StatusCode::OK);
        logs_assert(|lines: &[&str]| {
            let timed_out = lines.iter().any(|l| {
                l.contains(" WARN ") && l.contains("request timed out") && l.contains("408")
            });
            let finished = lines.iter().any(|l| {
                l.contains(" INFO ") && l.contains("request finished") && l.contains("200")
            });
            match (timed_out, finished) {
                (true, true) => Ok(()),
                _ => Err(format!(
                    "timed_out={timed_out} finished={finished}:\n{}",
                    lines.join("\n")
                )),
            }
        });
    }
}
