#![cfg(feature = "db")]
//! Backlog 07ed8d4d, end to end: the compiled `server` binary, SERVING with
//! its own edge signing key, stops when that key is revoked under it, so no
//! HTTP write after the revocation is signed with it (the server no longer
//! accepts any). `api_signing_key_admission_watch.rs` pins the watch's
//! verdict in process; this pins that `bin/server.rs` actually runs the watch
//! and exits on it.
//!
//! Drives the binary against a real `#[sqlx::test]` database (unarmed, so the
//! privileged test DSN serves; see `privileged_dsn_boot_refusal.rs`), with
//! `EPIGRAPH_API_SIGNING_KEY_FILE` naming a key that is an ACTIVE `signing`
//! row of its signer agent and a 1 s re-check:
//!
//! 1. CALIBRATION: the server boots on the key (its boot line names the
//!    signer agent), answers `/health` on the port it logs, and is still
//!    serving after several re-checks;
//! 2. the row is revoked (as a maintenance session would): the server exits 1
//!    with the stop text naming the key, and the same port no longer answers.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use epigraph_crypto::AgentSigner;
use sqlx::PgPool;
use uuid::Uuid;

/// Spelled here, not imported: a test that shares its subject's constant
/// cannot detect a change to it.
const STOP: &str = "is no longer admitted by the edge verifier, or stops being admitted within \
                    the stop lead";

/// Logged by `edge_signer::boot` once the key is admitted.
const SIGNING: &str = "HTTP edge writers attest their edges with the API's signing key";

/// Logged once the listener is bound, followed by the bound address.
const SERVING: &str = "Server listening on";

/// The spawned server, killed (by its own handle, never by name) on every
/// path out of the test.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// An empty (valid) providers file, so the server boots past its providers
/// registry (as in `privileged_dsn_boot_refusal.rs`).
fn providers_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "api-signing-key-watch-providers-{}.toml",
        std::process::id()
    ));
    std::fs::write(&path, "# no external identity providers\n").expect("providers file");
    path
}

/// Spawn the server against `db_url` with `extra_env`, its stdout (the
/// tracing layer) and stderr (the stop text) merged into one line channel.
fn spawn_server(db_url: &str, extra_env: &[(&str, &str)]) -> (Server, mpsc::Receiver<String>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_server"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EPIGRAPH_ALLOW_INSECURE_SECRET", "1")
        .env("EPIGRAPH_ENV", "test")
        .env("EPIGRAPH_PORT", "0")
        .env("EPIGRAPH_METRICS_ADDR", "127.0.0.1:0")
        .env("EPIGRAPH_PROVIDERS_CONFIG", providers_file())
        .env("RUST_LOG", "info")
        .env("DATABASE_URL", db_url)
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
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
    (Server(child), rx)
}

fn drain(rx: &mpsc::Receiver<String>, log: &mut String) {
    while let Ok(line) = rx.try_recv() {
        log.push_str(&line);
        log.push('\n');
    }
}

/// Wait up to `within` for the server to exit; `Some(code)` if it did. The
/// server is left running otherwise (the caller's [`Server`] kills it).
fn wait_exit(
    server: &mut Server,
    rx: &mpsc::Receiver<String>,
    log: &mut String,
    within: Duration,
) -> Option<Option<i32>> {
    let deadline = Instant::now() + within;
    loop {
        drain(rx, log);
        if let Some(status) = server.0.try_wait().expect("try_wait") {
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                log.push_str(&line);
                log.push('\n');
            }
            return Some(status.code());
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait up to 90 s for `marker`; panics (with the log) if the server exits
/// first or never logs it.
fn wait_for_line(server: &mut Server, rx: &mpsc::Receiver<String>, log: &mut String, marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        drain(rx, log);
        if log.contains(marker) {
            return;
        }
        if let Some(status) = server.0.try_wait().expect("try_wait") {
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                log.push_str(&line);
                log.push('\n');
            }
            assert!(
                log.contains(marker),
                "CALIBRATION: the server exited {:?} before logging {marker:?}:\n{log}",
                status.code()
            );
            return;
        }
        assert!(
            Instant::now() <= deadline,
            "the server did not log {marker:?} within 90s:\n{log}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `log` without its ANSI colour sequences (`ESC [ ... m`).
fn strip_ansi(log: &str) -> String {
    let mut out = String::with_capacity(log.len());
    let mut chars = log.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The address the server logged after [`SERVING`].
fn bound_addr(log: &str) -> SocketAddr {
    let plain = strip_ansi(log);
    let line = plain
        .lines()
        .find(|l| l.contains(SERVING))
        .unwrap_or_else(|| panic!("no {SERVING:?} line:\n{plain}"));
    let rest = &line[line.find(SERVING).unwrap() + SERVING.len()..];
    rest.split_whitespace()
        .next()
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("no address after {SERVING:?}: {line}"))
}

async fn health(addr: SocketAddr) -> Result<reqwest::StatusCode, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .map(|r| r.status())
}

/// Verified to fail: the `spawn_admission_watch` call removed from
/// `bin/server.rs::main` -> the server keeps serving after the revocation
/// (no exit within 30 s), and `/health` still answers.
#[sqlx::test(migrations = "../../migrations")]
async fn the_server_stops_when_its_signing_key_is_revoked_under_it(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let key = AgentSigner::generate();
    let signer_id = epigraph_api::edge_signer::resolve_signer_agent(&pool, &key)
        .await
        .expect("a signer agent for the key");
    let row = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'signing', 'active', now() - interval '1 minute')",
    )
    .bind(row)
    .bind(signer_id)
    .bind(key.public_key().as_slice())
    .execute(&pool)
    .await
    .expect("register the API key as an active signing row (test superuser)");
    let key_file =
        std::env::temp_dir().join(format!("api-signing-key-watch-{}.hex", Uuid::new_v4()));
    std::fs::write(&key_file, hex::encode(key.secret_key())).expect("key file");
    let key_path = key_file.to_str().expect("utf-8 path").to_string();

    // 1. Boots on the key and serves.
    let (mut server, rx, mut log) = tokio::task::spawn_blocking(move || {
        let (mut server, rx) = spawn_server(
            &db_url,
            &[
                ("EPIGRAPH_API_SIGNING_KEY_FILE", key_path.as_str()),
                ("EPIGRAPH_API_SIGNING_KEY_RECHECK_SECS", "1"),
            ],
        );
        let mut log = String::new();
        wait_for_line(&mut server, &rx, &mut log, SERVING);
        (server, rx, log)
    })
    .await
    .expect("join");
    let plain = strip_ansi(&log);
    assert!(
        plain.contains(SIGNING) && plain.contains(&signer_id.to_string()),
        "CALIBRATION: the server boots signing as agent {signer_id}:\n{plain}"
    );
    let addr = bound_addr(&log);
    assert!(
        health(addr)
            .await
            .expect("CALIBRATION: /health answers")
            .is_success(),
        "CALIBRATION: /health on {addr}"
    );
    // Several 1 s re-checks of an admitted key: still serving.
    let (mut server, rx, mut log) = tokio::task::spawn_blocking(move || {
        let exited = wait_exit(&mut server, &rx, &mut log, Duration::from_secs(3));
        assert_eq!(
            exited, None,
            "CALIBRATION: the server stopped on an admitted key:\n{log}"
        );
        (server, rx, log)
    })
    .await
    .expect("join");

    // 2. Revoked under it: exit 1, the stop text, and the port is gone.
    sqlx::query(
        "UPDATE agent_keys SET status = 'revoked', valid_until = now(), \
                revocation_reason = 'suspected exposure' WHERE id = $1",
    )
    .bind(row)
    .execute(&pool)
    .await
    .expect("revoke the row (test superuser)");
    let (code, log) = tokio::task::spawn_blocking(move || {
        let code = wait_exit(&mut server, &rx, &mut log, Duration::from_secs(30));
        drop(server);
        (code, log)
    })
    .await
    .expect("join");
    std::fs::remove_file(&key_file).ok();
    assert_eq!(
        code,
        Some(Some(1)),
        "a server whose signing key is revoked under it exits 1:\n{log}"
    );
    let plain = strip_ansi(&log);
    assert!(
        plain.contains(STOP) && plain.contains(&hex::encode(key.public_key())),
        "the stop names the key and why:\n{plain}"
    );
    assert!(
        health(addr).await.is_err(),
        "the stopped server's port {addr} still answers"
    );
}
