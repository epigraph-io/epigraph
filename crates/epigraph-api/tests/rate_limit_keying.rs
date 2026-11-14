//! Rate-limit bucket keying through the real `create_router` (backlog
//! bd5c0f40, with 966164c8).
//!
//! The limiter must charge each request to a bucket the client cannot choose:
//!
//! - an authenticated request to its principal (the token's agent, else its
//!   client), which needs the limiter INSIDE the bearer layers;
//! - an anonymous request to its TCP peer, or, when the peer is a configured
//!   trusted proxy, to the right-most `X-Forwarded-For` hop that is not itself
//!   a trusted proxy.
//!
//! Before this fix the key was the FIRST `X-Forwarded-For` hop (written by the
//! client, so rotating it bought a fresh bucket per request), and a request
//! without forwarding headers fell into one shared nil bucket, so the first
//! client to spend it locked out every other un-proxied client.
//!
//! The anonymous tests need no database: the pool is lazy and the routes they
//! drive (`/.well-known/oauth-authorization-server`) never touch it. The
//! principal tests need `DATABASE_URL`, because both bearer layers consult the
//! revocation table before the limiter sees the request.
//!
//! Addresses are documentation ranges only (RFC 5737, RFC 3849).

#![cfg(feature = "db")]

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use epigraph_api::TrustedProxies;
use epigraph_api::{create_router, AgentRateLimiter, ApiConfig, AppState, RateLimitConfig};
use tower::ServiceExt;
use uuid::Uuid;

/// Requests per key before a 429. Small, and the refill (LIMIT per minute)
/// is far slower than a test, so no request in a burst is refunded.
const LIMIT: u32 = 3;

fn limiter() -> AgentRateLimiter {
    AgentRateLimiter::new(RateLimitConfig {
        default_rpm: LIMIT,
        global_rpm: 1_000_000,
        replenish_interval_secs: 60,
        enable_global_limit: false,
    })
}

/// A router over a lazy pool that is never connected.
fn anonymous_router(limiter: AgentRateLimiter) -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://ratelimit:unused@127.0.0.1:1/unused")
        .expect("lazy pool");
    create_router(AppState::with_db(pool, ApiConfig::default()).with_rate_limiter(limiter))
}

/// One anonymous discovery request, as `axum::serve` with
/// `into_make_service_with_connect_info` would deliver it from `peer`.
async fn discovery(router: &Router, peer: &str, xff: Option<&str>) -> StatusCode {
    let peer: SocketAddr = peer.parse().expect("peer address");
    let mut req = Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-authorization-server");
    if let Some(xff) = xff {
        req = req.header("X-Forwarded-For", xff);
    }
    let mut req = req.body(Body::empty()).unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    router.clone().oneshot(req).await.unwrap().status()
}

/// A client that writes a fresh first `X-Forwarded-For` hop on every request
/// still exhausts ITS bucket: the header is not believed from an untrusted
/// peer. Before the fix every request was charged to the spoofed hop, so this
/// never saw a 429.
#[tokio::test]
async fn rotating_a_spoofed_forwarded_for_does_not_buy_fresh_buckets() {
    let router = anonymous_router(limiter());
    for i in 0..LIMIT {
        let spoof = format!("198.51.100.{}", i + 1);
        assert_eq!(
            discovery(&router, "203.0.113.7:40000", Some(&spoof)).await,
            StatusCode::OK,
            "request {i} is within the limit"
        );
    }
    assert_eq!(
        discovery(&router, "203.0.113.7:40001", Some("198.51.100.250")).await,
        StatusCode::TOO_MANY_REQUESTS,
        "request {LIMIT} from the same peer must be refused whatever X-Forwarded-For says"
    );
}

/// Two un-proxied clients get two buckets. Before the fix both fell into the
/// nil bucket, so the second client's FIRST request was refused.
#[tokio::test]
async fn unproxied_clients_do_not_share_one_bucket() {
    let router = anonymous_router(limiter());
    for _ in 0..LIMIT {
        assert_eq!(
            discovery(&router, "203.0.113.10:5000", None).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        discovery(&router, "203.0.113.10:5001", None).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the first client has spent its bucket"
    );
    assert_eq!(
        discovery(&router, "203.0.113.11:5000", None).await,
        StatusCode::OK,
        "a different client must not be charged for the first one's requests"
    );
}

/// Behind a trusted proxy the key is the right-most hop that the proxy did
/// not write itself; everything to its left is client-written and ignored.
#[tokio::test]
async fn behind_a_trusted_proxy_the_rightmost_untrusted_hop_is_the_key() {
    let trusted = TrustedProxies::parse("192.0.2.1, 192.0.2.2").unwrap();
    let router = anonymous_router(limiter().with_trusted_proxies(trusted));
    for i in 0..LIMIT {
        // client-written junk, then the real client, then a second trusted hop
        let xff = format!("198.51.100.{}, 203.0.113.20, 192.0.2.2", i + 1);
        assert_eq!(
            discovery(&router, "192.0.2.1:443", Some(&xff)).await,
            StatusCode::OK,
            "request {i} is within the limit"
        );
    }
    assert_eq!(
        discovery(
            &router,
            "192.0.2.1:443",
            Some("198.51.100.99, 203.0.113.20")
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS,
        "203.0.113.20 has spent its bucket whatever it prepends"
    );
    assert_eq!(
        discovery(&router, "192.0.2.1:443", Some("203.0.113.21")).await,
        StatusCode::OK,
        "another client behind the same proxy has its own bucket"
    );
}

/// An IPv6 client holds a whole /64; keying the full address would hand it
/// 2^64 buckets.
#[tokio::test]
async fn ipv6_clients_are_keyed_by_their_slash_64() {
    let router = anonymous_router(limiter());
    for i in 0..LIMIT {
        let peer = format!("[2001:db8:1:2::{}]:5000", i + 1);
        assert_eq!(discovery(&router, &peer, None).await, StatusCode::OK);
    }
    assert_eq!(
        discovery(&router, "[2001:db8:1:2:ffff::9]:5000", None).await,
        StatusCode::TOO_MANY_REQUESTS,
        "a new address in the same /64 is the same client"
    );
    assert_eq!(
        discovery(&router, "[2001:db8:1:3::1]:5000", None).await,
        StatusCode::OK,
        "a different /64 is a different client"
    );
}

// ---------------------------------------------------------------------------
// Principal keying (needs DATABASE_URL: bearer auth reads the revocation table)
// ---------------------------------------------------------------------------

fn db_router(limiter: AgentRateLimiter) -> (Router, AppState) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect_lazy(&url)
        .expect("lazy pool");
    let state = AppState::with_db(pool, ApiConfig::default()).with_rate_limiter(limiter);
    (create_router(state.clone()), state)
}

fn token_for(state: &AppState, agent: Uuid) -> String {
    state
        .jwt_config
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".into()],
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(10),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("token")
        .0
}

async fn authed(router: &Router, method: &str, uri: &str, token: &str) -> StatusCode {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    // Every request comes from the SAME peer: only the principal tells them apart.
    req.extensions_mut().insert(ConnectInfo(
        "203.0.113.30:6000".parse::<SocketAddr>().unwrap(),
    ));
    router.clone().oneshot(req).await.unwrap().status()
}

/// Two principals behind one address (one NAT, one proxy, one agent host)
/// have separate buckets, on the anonymous allowlist router and on the
/// protected router alike. With the limiter outside the bearer layers it could
/// only key on the address, so the second principal's first request was
/// refused.
#[tokio::test(flavor = "multi_thread")]
async fn authenticated_requests_are_charged_to_their_principal() {
    for (method, uri) in [
        ("GET", "/api/v1/openapi.json"),
        // Protected: the empty body fails the handler's extractor, which is
        // fine; only whether the LIMITER refused (429) is asserted.
        ("POST", "/api/v1/claims"),
    ] {
        let (router, state) = db_router(limiter());
        let a = token_for(&state, Uuid::new_v4());
        let b = token_for(&state, Uuid::new_v4());
        for i in 0..LIMIT {
            let status = authed(&router, method, uri, &a).await;
            assert_ne!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "{method} {uri}: request {i} of principal A is within the limit"
            );
            assert!(
                status != StatusCode::UNAUTHORIZED && status != StatusCode::SERVICE_UNAVAILABLE,
                "{method} {uri}: the token must authenticate (got {status}; 503 means the \
                 revocation lookup could not reach DATABASE_URL)"
            );
        }
        assert_eq!(
            authed(&router, method, uri, &a).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{method} {uri}: principal A has spent its bucket"
        );
        assert_ne!(
            authed(&router, method, uri, &b).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{method} {uri}: principal B from the same address has its own bucket"
        );
    }
}
