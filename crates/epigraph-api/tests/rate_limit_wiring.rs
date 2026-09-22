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
