//! Source-text lint over `bin/server.rs`: the production listeners are wired
//! so the rate limiter can see who is calling.
//!
//! `bin/server.rs::main` cannot be driven from a test (it reads the process
//! environment, binds ports and connects to Postgres), so its wiring is pinned
//! here as text, the same way `public_router_allowlist.rs` pins the router.
//!
//! # What is pinned
//!
//! Both application listeners — the plain `axum::serve` one and the
//! `#[cfg(feature = "tls")]` `axum_server::bind_rustls` one — serve with
//! `into_make_service_with_connect_info::<std::net::SocketAddr>()`. That is
//! what puts `ConnectInfo<SocketAddr>` into request extensions, and the
//! rate-limit middleware keys anonymous traffic on it. A listener served with
//! plain `into_make_service()` (or `axum::serve(listener, app)`) delivers no
//! peer address, and every anonymous request on it goes unlimited. The
//! internal metrics listener is deliberately NOT required to carry connect
//! info: it serves `metrics_app`, which has no rate-limit layer.
//!
//! And the operator settings reach the state: the three env vars are read and
//! handed to `rate_limiter_from_settings`, whose result is installed with
//! `with_rate_limiter`. Until that call existed, no production code installed a
//! limiter and the middleware let every request through. What the settings
//! MEAN is tested where they are parsed (`security::rate_limit` unit tests);
//! this only proves `main` passes them through rather than dropping them.

mod lint_text;

use lint_text::strip_comments;

const SERVER_RS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/server.rs");

fn server_source() -> String {
    let raw = std::fs::read_to_string(SERVER_RS).expect("read src/bin/server.rs");
    strip_comments(&raw)
}

/// Collapse all whitespace so a rustfmt reflow cannot hide or fake a match.
fn squash(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

#[test]
fn both_application_listeners_serve_with_connect_info() {
    let src = squash(&server_source());

    let with_connect_info = src
        .matches("app.into_make_service_with_connect_info::<std::net::SocketAddr>()")
        .count();
    assert_eq!(
        with_connect_info, 2,
        "expected exactly two `app.into_make_service_with_connect_info::<std::net::SocketAddr>()` \
         call sites in bin/server.rs (the plain listener and the TLS listener); found \
         {with_connect_info}. Without ConnectInfo the rate limiter cannot identify anonymous \
         clients and lets them through unlimited."
    );

    assert!(
        !src.contains("app.into_make_service()"),
        "bin/server.rs serves the application router with plain `into_make_service()`, \
         which carries no peer address; use \
         `into_make_service_with_connect_info::<std::net::SocketAddr>()`"
    );
    assert!(
        !src.contains("axum::serve(listener,app)"),
        "bin/server.rs serves the application router as `axum::serve(listener, app)`, \
         which carries no peer address; use \
         `app.into_make_service_with_connect_info::<std::net::SocketAddr>()`"
    );
}

#[test]
fn the_rate_limit_settings_are_read_and_installed() {
    let src = squash(&server_source());

    let call = "epigraph_api::security::rate_limit::rate_limiter_from_settings(\
                std::env::var(\"EPIGRAPH_RATE_LIMIT_RPM\").ok().as_deref(),\
                std::env::var(\"EPIGRAPH_RATE_LIMIT_GLOBAL_RPM\").ok().as_deref(),\
                std::env::var(\"EPIGRAPH_TRUSTED_PROXIES\").ok().as_deref(),)";
    assert_eq!(
        src.matches(call).count(),
        1,
        "bin/server.rs must pass EPIGRAPH_RATE_LIMIT_RPM, EPIGRAPH_RATE_LIMIT_GLOBAL_RPM and \
         EPIGRAPH_TRUSTED_PROXIES, in that order, to rate_limiter_from_settings exactly once"
    );

    let installs = src.matches("state.with_rate_limiter(limiter)").count();
    assert_eq!(
        installs, 1,
        "the limiter rate_limiter_from_settings returns must be installed with \
         `state.with_rate_limiter(limiter)`; found {installs} install sites"
    );

    let call_at = src.find(call).expect("asserted above");
    let install_at = src
        .find("state.with_rate_limiter(limiter)")
        .expect("asserted above");
    let router_at = src
        .find("create_router(")
        .expect("bin/server.rs builds the router with create_router");
    assert!(
        call_at < install_at && install_at < router_at,
        "the limiter must be installed on the state BEFORE create_router consumes it"
    );
}
