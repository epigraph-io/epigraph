#![cfg(feature = "db")]
//! The `server` binary SERVES with its rate limiter installed and keyed on the
//! TCP peer (backlog 966164c8, with bd5c0f40's keying).
//!
//! `boot_rate_limit_test.rs` only reads the boot log written before the
//! database connection, so it cannot see the two lines that make the limiter
//! real: `state.with_rate_limiter(limiter)` and serving with
//! `into_make_service_with_connect_info`. This file boots the compiled binary
//! against a fresh migrated database, waits for it to serve, and sends
//! anonymous requests over real sockets:
//!
//! - from 127.0.0.1, the first `RPM` requests are answered normally (the
//!   calibration: the route is not refusing for some other reason) and the
//!   next one is 429;
//! - that refused client stays refused when it writes its own
//!   `X-Forwarded-For` (no proxy is trusted here);
//! - a request from 127.0.0.2 is NOT 429: a second peer has its own bucket.
//!
//! And, for the operator's ruling of 2026-11-16, with `EPIGRAPH_GUEST_READS=on`:
//!
//! - with no limiter configured, a guest route is refused 429 past #841's
//!   default limit from one peer, a second peer is served, and an anonymous
//!   non-guest route is never refused;
//! - with `EPIGRAPH_RATE_LIMIT=off`, the guest routes are never refused.
//!
//! And, for backlog 20210eaa, with `EPIGRAPH_RATE_LIMIT_ADDRESS_RPM`: 401s
//! and unknown-path 404s from one peer are refused 429 past the per-address
//! limit, before the bearer layer runs.
//!
//! Verified to fail: without the `with_rate_limiter` install in `main` the
//! fourth request is answered normally; serving with plain
//! `axum::serve(listener, app)` (no connect info) puts both peers in one
//! bucket and the 127.0.0.2 request is 429.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Logged once the listener is bound, followed by the bound address.
const SERVING: &str = "Server listening on ";

/// The per-key limit the server is started with.
const RPM: usize = 3;

/// An anonymous route on the OAuth router, which the limiter wraps.
const PATH: &str = "/.well-known/oauth-authorization-server";

/// Kills and reaps the server this test started (and only it), including
/// when an assertion panics first, so the per-test database can be dropped.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn providers_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rate-limit-served-providers-{}.toml",
        std::process::id()
    ));
    std::fs::write(&path, "# no external identity providers\n").expect("providers file");
    path
}

/// Start the server against `db_url`, with `env` on top of the fixed
/// environment, and wait until it serves; return it and the port it bound.
fn start_server(db_url: &str, env: &[(&str, &str)]) -> (Server, u16) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_server"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EPIGRAPH_ALLOW_INSECURE_SECRET", "1")
        .env("EPIGRAPH_ENV", "test")
        .env("EPIGRAPH_PORT", "0")
        .env("EPIGRAPH_METRICS_ADDR", "127.0.0.1:0")
        .env("EPIGRAPH_PROVIDERS_CONFIG", providers_file())
        .env("EPIGRAPH_TRUSTED_PROXIES", "none")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env("DATABASE_URL", db_url)
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn the server binary");
    let (tx, rx) = mpsc::channel::<String>();
    for pipe in [
        Box::new(child.stdout.take().expect("stdout")) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().expect("stderr")),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    let mut server = Server(child);

    let deadline = Instant::now() + Duration::from_secs(90);
    let mut log = String::new();
    loop {
        while let Ok(line) = rx.try_recv() {
            if let Some(port) = serving_port(&line) {
                // Keep reading the server's output, so its log writes never
                // fail or block on a closed or full pipe while it serves.
                std::thread::spawn(move || rx.into_iter().for_each(drop));
                return (server, port);
            }
            log.push_str(&line);
            log.push('\n');
        }
        if let Some(status) = server.0.try_wait().expect("try_wait") {
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                log.push_str(&line);
                log.push('\n');
            }
            panic!("the server exited {status} before serving:\n{log}");
        }
        assert!(
            Instant::now() < deadline,
            "the server did not serve within 90s:\n{log}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The port in a `Server listening on 0.0.0.0:<port>` line: the run of ASCII
/// digits after the last `:`.
fn serving_port(line: &str) -> Option<u16> {
    let rest = &line[line.find(SERVING)? + SERVING.len()..];
    let after_colon = &rest[rest.rfind(':')? + 1..];
    let digits: String = after_colon
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok().filter(|p| *p != 0)
}

/// One anonymous GET of [`PATH`] from the local address `from`; the response
/// status.
async fn get_from(from: Ipv4Addr, port: u16, extra_header: Option<&str>) -> u16 {
    get_path_from(from, port, PATH, extra_header).await
}

/// One anonymous GET of `path` from the local address `from`; the response
/// status.
async fn get_path_from(from: Ipv4Addr, port: u16, path: &str, extra_header: Option<&str>) -> u16 {
    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket
        .bind(SocketAddr::new(IpAddr::V4(from), 0))
        .unwrap_or_else(|e| panic!("bind the client socket to {from}: {e}"));
    let mut stream = socket
        .connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .await
        .expect("connect to the server");
    let extra = extra_header.map(|h| format!("{h}\r\n")).unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut response))
        .await
        .expect("response within 30s")
        .expect("read response");
    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or_default();
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in response: {text:?}"))
}

#[test]
fn serving_port_reads_the_bound_port() {
    assert_eq!(
        serving_port("2026-11-14T00:00:00Z  INFO server: Server listening on 0.0.0.0:41234"),
        Some(41234)
    );
    assert_eq!(serving_port("Server listening on 0.0.0.0:0"), None);
    assert_eq!(
        serving_port("Starting EpiGraph API server on 0.0.0.0:0"),
        None
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_served_binary_limits_each_anonymous_peer_separately(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let (_server, port) = tokio::task::spawn_blocking(move || {
        start_server(&db_url, &[("EPIGRAPH_RATE_LIMIT_RPM", &RPM.to_string())])
    })
    .await
    .expect("join");

    let a = Ipv4Addr::new(127, 0, 0, 1);
    let b = Ipv4Addr::new(127, 0, 0, 2);

    for n in 1..=RPM {
        let status = get_from(a, port, None).await;
        assert_eq!(
            status, 200,
            "CALIBRATION: request {n} of {RPM} from {a} must be served normally, or the \
             refusal below proves nothing"
        );
    }
    assert_eq!(
        get_from(a, port, None).await,
        429,
        "request {} from one anonymous peer must be refused: the limiter is installed",
        RPM + 1
    );
    assert_eq!(
        get_from(a, port, Some("X-Forwarded-For: 198.51.100.7")).await,
        429,
        "a refused peer must not escape by writing its own X-Forwarded-For when no proxy \
         is trusted"
    );
    assert_eq!(
        get_from(b, port, None).await,
        200,
        "a second peer ({b}) must have its own bucket: the served router sees the TCP peer"
    );
}

// ---------------------------------------------------------------------------
// The per-address limiter (backlog 20210eaa)
// ---------------------------------------------------------------------------

/// With `EPIGRAPH_RATE_LIMIT_ADDRESS_RPM` set (and no principal limiter), the
/// served binary charges every request to its TCP peer OUTSIDE the bearer
/// layer and routing:
///
/// - a peer that floods a protected route with a junk bearer gets `RPM` 401s
///   (the calibration: the bearer layer refused them), then 429: refused
///   before the bearer layer read the token;
/// - a second peer that floods unknown paths gets `RPM` 404s, then 429;
/// - the throttled peer's `/health` is still 200 (the liveness probe is
///   exempt), and a third peer is served.
///
/// Fails on the parent commit (no per-address limiter: the 401s and 404s go
/// on forever), and with the per-address layer moved inside the protected
/// router's bearer layer (the 401s never become 429).
#[sqlx::test(migrations = "../../migrations")]
async fn the_served_binary_limits_401s_and_unknown_paths_per_address(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let (_server, port) = tokio::task::spawn_blocking(move || {
        start_server(
            &db_url,
            &[("EPIGRAPH_RATE_LIMIT_ADDRESS_RPM", &RPM.to_string())],
        )
    })
    .await
    .expect("join");

    let a = Ipv4Addr::new(127, 0, 0, 1);
    let b = Ipv4Addr::new(127, 0, 0, 2);
    let c = Ipv4Addr::new(127, 0, 0, 3);
    let junk = Some("Authorization: Bearer not-a-token");

    for n in 1..=RPM {
        assert_eq!(
            get_path_from(a, port, "/api/v1/claims", junk).await,
            401,
            "CALIBRATION: junk-bearer request {n} of {RPM} from {a} is refused by the \
             bearer layer"
        );
    }
    assert_eq!(
        get_path_from(a, port, "/api/v1/claims", junk).await,
        429,
        "junk-bearer request {} from {a} must be refused by the per-address limiter, \
         before the bearer layer",
        RPM + 1
    );
    assert_eq!(
        get_path_from(a, port, "/health", None).await,
        200,
        "the liveness probe is exempt from the per-address limiter"
    );

    for n in 1..=RPM {
        assert_eq!(
            get_path_from(b, port, &format!("/no-such-route/{n}"), None).await,
            404,
            "CALIBRATION: unknown path {n} of {RPM} from {b} is a 404"
        );
    }
    assert_eq!(
        get_path_from(b, port, "/no-such-route/again", None).await,
        429,
        "unknown-path request {} from {b} must be refused by the per-address limiter",
        RPM + 1
    );

    assert_eq!(
        get_path_from(c, port, "/no-such-route/c", None).await,
        404,
        "a third peer ({c}) has its own address bucket"
    );
}

// ---------------------------------------------------------------------------
// Guest reads (the operator's ruling of 2026-11-16)
// ---------------------------------------------------------------------------

/// A guest route, served whether or not the corpus holds a theme.
const GUEST_PATH: &str = "/api/v1/guest/graph/themes/overview";

/// #841's default per-key limit, which the guest reads get by default.
const DEFAULT_RPM: usize = 600;

/// More requests than the default limit allows in a burst, with room for the
/// refill (10 a second) while they are sent.
const PAST_DEFAULT: usize = 3 * DEFAULT_RPM;

/// Send GETs of `path` from `from` until one is refused 429 or `cap` were
/// sent; the statuses of the answered ones, and whether a 429 came.
async fn until_refused(from: Ipv4Addr, port: u16, path: &str, cap: usize) -> (Vec<u16>, bool) {
    let mut answered = Vec::new();
    for _ in 0..cap {
        match get_path_from(from, port, path, None).await {
            429 => return (answered, true),
            status => answered.push(status),
        }
    }
    (answered, false)
}

/// Guest reads on and no limiter configured: the served binary limits the
/// guest routes at the default limit per TCP peer, and leaves the other
/// routes unlimited.
///
/// Fails without the guest-default install in `main` (no 429 on the guest
/// route), or with the default installed router-wide (a 429 on discovery).
#[sqlx::test(migrations = "../../migrations")]
async fn the_served_binary_limits_the_guest_reads_by_default(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let (_server, port) = tokio::task::spawn_blocking(move || {
        start_server(&db_url, &[("EPIGRAPH_GUEST_READS", "on")])
    })
    .await
    .expect("join");

    let a = Ipv4Addr::new(127, 0, 0, 1);
    let b = Ipv4Addr::new(127, 0, 0, 2);

    let (answered, refused) = until_refused(a, port, GUEST_PATH, PAST_DEFAULT).await;
    assert!(
        answered.iter().all(|s| *s == 200),
        "CALIBRATION: every guest read under the limit must be served normally; got {:?}",
        answered.iter().filter(|s| **s != 200).collect::<Vec<_>>()
    );
    assert!(
        refused,
        "{PAST_DEFAULT} guest reads from one peer must meet a 429: the default limiter is \
         installed"
    );
    assert!(
        answered.len() >= DEFAULT_RPM,
        "the default limit is {DEFAULT_RPM} a minute after a full burst, but the peer was \
         refused after {}",
        answered.len()
    );
    assert_eq!(
        get_path_from(b, port, GUEST_PATH, None).await,
        200,
        "a second peer ({b}) has its own guest bucket"
    );

    // The peer whose guest bucket is spent is not limited elsewhere.
    let (answered, refused) = until_refused(a, port, PATH, PAST_DEFAULT).await;
    assert!(
        !refused && answered.iter().all(|s| *s == 200),
        "{PATH} from {a} must not be rate limited: the guest default limits the guest \
         routes only"
    );
}

/// Guest reads on with `EPIGRAPH_RATE_LIMIT=off`: the operator's explicit
/// choice is respected, so the served guest routes are unlimited.
#[sqlx::test(migrations = "../../migrations")]
async fn explicit_off_serves_the_guest_reads_unlimited(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let (_server, port) = tokio::task::spawn_blocking(move || {
        start_server(
            &db_url,
            &[
                ("EPIGRAPH_GUEST_READS", "on"),
                ("EPIGRAPH_RATE_LIMIT", "off"),
            ],
        )
    })
    .await
    .expect("join");

    let (answered, refused) =
        until_refused(Ipv4Addr::LOCALHOST, port, GUEST_PATH, PAST_DEFAULT).await;
    assert!(
        !refused && answered.iter().all(|s| *s == 200),
        "{PAST_DEFAULT} guest reads under EPIGRAPH_RATE_LIMIT=off must all be served"
    );
}
