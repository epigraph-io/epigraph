#![cfg(feature = "db")]
//! The `server` binary's TLS serve path (backlog a65cc870 (2)).
//!
//! With `EPIGRAPH_TLS_CERT` and `EPIGRAPH_TLS_KEY` set (in a `tls` build),
//! `main` serves through `axum_server::bind_rustls` with a `Handle` instead of
//! `serving::serve_until_signal`, so the plain path's boot tests
//! (`boot_rate_limit_served.rs`, `boot_serving_settings.rs`) say nothing about
//! it. This file boots the compiled binary over TLS, with a certificate chain
//! generated per run (OpenSSL, as `tls_pem_loading.rs` does; no key material
//! is committed), against a fresh migrated database, and talks HTTPS to it
//! over real sockets:
//!
//! - the rate limiter is installed and keyed on the TCP peer: from 127.0.0.1
//!   the first `RPM` requests are served (the calibration) and the next is
//!   429, while 127.0.0.2 is served;
//! - SIGTERM drains: a request in flight at the signal is answered, and the
//!   process exits 0;
//! - the drain is bounded: a request still in flight when the grace ends
//!   does not hold the exit, which comes no sooner than the grace.
//!
//! Run: `cargo test -p epigraph-api --features tls --test boot_tls_served`.
//!
//! Verified to fail: serving the TLS path with `into_make_service()` (no
//! connect info) puts both peers in one bucket and 127.0.0.2 is 429; with
//! `graceful_shutdown(None)` the bounded-drain test is still running 20 s
//! after SIGTERM; and with the signal task removed SIGTERM kills the process
//! (no exit code, no response to the in-flight request).

#[path = "common/served.rs"]
mod served;

#[path = "viewer_fixture.rs"]
mod fixture;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509Name, X509};
use rustls::pki_types::{CertificateDer, ServerName};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::client::TlsStream;

/// The per-key limit the rate-limit test starts the server with.
const RPM: usize = 3;

/// An anonymous route on the OAuth router, which the limiter wraps.
const PATH: &str = "/.well-known/oauth-authorization-server";

// ---------------------------------------------------------------------------
// The certificate fixture
// ---------------------------------------------------------------------------

fn name(cn: &str) -> X509Name {
    let mut n = X509Name::builder().unwrap();
    n.append_entry_by_text("CN", cn).unwrap();
    n.build()
}

fn p256_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

/// A certificate for `subject_key`: a CA when `issuer` is `None`, else a leaf
/// for `localhost` signed by `issuer`.
fn cert(
    cn: &str,
    subject_key: &PKeyRef<Private>,
    issuer: Option<(&X509, &PKeyRef<Private>)>,
) -> X509 {
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name(cn)).unwrap();
    b.set_pubkey(subject_key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    let signing_key = match issuer {
        Some((ca, ca_key)) => {
            b.set_issuer_name(ca.subject_name()).unwrap();
            let san = SubjectAlternativeName::new()
                .dns("localhost")
                .build(&b.x509v3_context(Some(ca), None))
                .unwrap();
            b.append_extension(san).unwrap();
            ca_key
        }
        None => {
            b.set_issuer_name(&name(cn)).unwrap();
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            subject_key
        }
    };
    b.sign(signing_key, MessageDigest::sha256()).unwrap();
    b.build()
}

/// A test CA and a `localhost` leaf it signed, written as PEM files the
/// server loads. Removed on drop.
struct Pki {
    dir: PathBuf,
    root: X509,
}

impl Pki {
    fn new() -> Self {
        let ca_key = p256_key();
        let root = cert("epigraph tls boot test root", &ca_key, None);
        let leaf_key = p256_key();
        let leaf = cert("localhost", &leaf_key, Some((&root, &ca_key)));
        let dir = std::env::temp_dir().join(format!("epigraph-tls-boot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut chain = leaf.to_pem().unwrap();
        chain.extend(root.to_pem().unwrap());
        std::fs::write(dir.join("cert.pem"), chain).unwrap();
        std::fs::write(
            dir.join("key.pem"),
            leaf_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        Self { dir, root }
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join("cert.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("key.pem")
    }

    /// A client that trusts only this root and speaks HTTP/1.1 (the server
    /// offers h2 first over ALPN; a raw HTTP/1.1 request needs http/1.1).
    fn connector(&self) -> tokio_rustls::TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.root.to_der().unwrap()))
            .unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Booting and talking HTTPS
// ---------------------------------------------------------------------------

/// Boot the server over TLS with `extra` on top of the served fixture's
/// environment (whose rate limiter is OFF); `remove` unsets fixture
/// variables first.
async fn start_tls(
    pool: &PgPool,
    pki: &Pki,
    remove: &'static [&'static str],
    extra: &'static [(&'static str, &'static str)],
) -> served::Server {
    let db_url = fixture::database_url_for(pool).await;
    let (cert, key) = (pki.cert_path(), pki.key_path());
    tokio::task::spawn_blocking(move || {
        let mut cmd = served::base_command(&db_url);
        for k in remove {
            cmd.env_remove(k);
        }
        cmd.env("EPIGRAPH_TLS_CERT", cert)
            .env("EPIGRAPH_TLS_KEY", key)
            .env("EPIGRAPH_TRUSTED_PROXIES", "none");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let server = served::boot(cmd).serving();
        assert!(
            server.boot_log.contains("TLS enabled"),
            "CALIBRATION: the server must have taken the TLS path:\n{}",
            server.boot_log
        );
        server
    })
    .await
    .expect("join")
}

/// A TLS connection to the server from the local address `from`.
async fn connect_from(pki: &Pki, from: Ipv4Addr, port: u16) -> TlsStream<tokio::net::TcpStream> {
    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket
        .bind(SocketAddr::new(IpAddr::V4(from), 0))
        .unwrap_or_else(|e| panic!("bind the client socket to {from}: {e}"));
    let tcp = socket
        .connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .await
        .expect("connect to the server");
    pki.connector()
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("TLS handshake with the server")
}

/// Everything the server sends until it closes (a close without
/// `close_notify` ends the read like EOF), within `within`.
async fn read_all(stream: &mut TlsStream<tokio::net::TcpStream>, within: Duration) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(within, async {
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

/// One anonymous HTTPS GET of [`PATH`] from `from`; the status.
async fn get_from(pki: &Pki, from: Ipv4Addr, port: u16) -> u16 {
    let mut tls = connect_from(pki, from, port).await;
    let request = format!("GET {PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes())
        .await
        .expect("write request");
    let text = read_all(&mut tls, Duration::from_secs(30)).await;
    text.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in response: {text:?}"))
}

/// Open a `POST /oauth/token` over TLS and send its head plus only half its
/// body, so the request is in flight until the rest is written.
async fn half_sent_request(
    pki: &Pki,
    port: u16,
) -> (TlsStream<tokio::net::TcpStream>, &'static [u8]) {
    const BODY: &[u8] = b"grant_type=client_credentials&client_id=tls-drain-probe";
    let (first, rest) = BODY.split_at(BODY.len() / 2);
    let mut tls = connect_from(pki, Ipv4Addr::LOCALHOST, port).await;
    let head = format!(
        "POST /oauth/token HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        BODY.len()
    );
    tls.write_all(head.as_bytes()).await.expect("write head");
    tls.write_all(first).await.expect("write half the body");
    tls.flush().await.expect("flush");
    // CALIBRATION: nothing is answered while the body is incomplete, so the
    // request really is waiting (a handler that answered early would make
    // the drain tests vacuous).
    let mut probe = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(800), tls.read(&mut probe))
            .await
            .is_err(),
        "answered or closed before the body was complete"
    );
    (tls, rest)
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_tls_path_serves_with_the_rate_limiter_keyed_on_the_peer(pool: PgPool) {
    let pki = Pki::new();
    let server = start_tls(
        &pool,
        &pki,
        &["EPIGRAPH_RATE_LIMIT"],
        &[("EPIGRAPH_RATE_LIMIT_RPM", "3")],
    )
    .await;
    let a = Ipv4Addr::new(127, 0, 0, 1);
    let b = Ipv4Addr::new(127, 0, 0, 2);
    for n in 1..=RPM {
        assert_eq!(
            get_from(&pki, a, server.port).await,
            200,
            "CALIBRATION: HTTPS request {n} of {RPM} from {a} must be served normally"
        );
    }
    assert_eq!(
        get_from(&pki, a, server.port).await,
        429,
        "HTTPS request {} from one peer must be refused: the TLS path installs the limiter",
        RPM + 1
    );
    assert_eq!(
        get_from(&pki, b, server.port).await,
        200,
        "a second peer ({b}) has its own bucket: the TLS path serves with connect info"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_request_in_flight_at_sigterm_is_answered_over_tls(pool: PgPool) {
    let pki = Pki::new();
    let mut server = start_tls(&pool, &pki, &[], &[("EPIGRAPH_SHUTDOWN_GRACE_SECS", "20")]).await;
    let (mut tls, rest) = half_sent_request(&pki, server.port).await;

    let terminated = tokio::task::spawn_blocking(move || server.terminate(Duration::from_secs(40)));
    // The signal is handled and the drain has begun; the request is still
    // open. Finish it: a server that stopped on the signal without draining
    // has closed this connection, and there is no response.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = tls.write_all(rest).await;
    let _ = tls.flush().await;
    let text = read_all(&mut tls, Duration::from_secs(15)).await;

    let (status, log) = terminated.await.expect("join");
    assert!(
        text.starts_with("HTTP/1.1 "),
        "the in-flight HTTPS request got no response after SIGTERM: {text:?}\n{log}"
    );
    let status = status.unwrap_or_else(|| panic!("still running 40s after SIGTERM:\n{log}"));
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM must end in a clean exit ({status}):\n{log}"
    );
    assert!(log.contains("SIGTERM received"), "{log}");
    assert!(log.contains("server stopped"), "{log}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_request_still_in_flight_when_the_grace_ends_does_not_hold_the_tls_exit(pool: PgPool) {
    let pki = Pki::new();
    let mut server = start_tls(&pool, &pki, &[], &[("EPIGRAPH_SHUTDOWN_GRACE_SECS", "2")]).await;
    // Never finished: without the grace bound the drain waits for it until
    // the 300 s request timeout.
    let (_tls, _rest) = half_sent_request(&pki, server.port).await;

    let started = Instant::now();
    let (status, log) =
        tokio::task::spawn_blocking(move || server.terminate(Duration::from_secs(20)))
            .await
            .expect("join");
    let took = started.elapsed();
    let status = status.unwrap_or_else(|| {
        panic!(
            "still running 20s after SIGTERM with a 2s grace: the TLS drain is unbounded:\n{log}"
        )
    });
    assert_eq!(status.code(), Some(0), "{status}:\n{log}");
    assert!(
        took >= Duration::from_secs(2),
        "exited {took:?} after SIGTERM, before the 2s grace: it did not drain:\n{log}"
    );
    assert!(log.contains("SIGTERM received"), "{log}");
}
