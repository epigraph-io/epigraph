//! Backlog 526f7508: the MCP HTTP transport had no graceful shutdown.
//! `serve_with_listener` ended in a bare `axum::serve(..).await` and nothing
//! listened for SIGTERM, so a restart killed the process by the signal, with
//! the runtime dropped under the detached work its tools had answered ahead
//! of (a queued `ingest_document` walk, post-commit embedding). The stdio
//! path already waited for that work (backlog b928ccc1); HTTP now does too
//! (`serve_with_listener_until`).
//!
//! The in-process tests drive `serve_with_listener_until` on a unix socket
//! with a gated `BackgroundTasks` task, as the template's tracker that every
//! HTTP session shares. The binary test drives `main`: SIGTERM (sent to the
//! PID this test spawned) now ends the listener with exit status 0, where the
//! old binary died by the signal (no exit code).
//!
//! Mutations: the `wait_idle` in `stop_gracefully` removed ->
//! `a_signalled_listener_waits_for_its_background_work` fails (it returns
//! with the task still gated); the session-ending call removed ->
//! `an_open_request_is_cut_off_at_the_drain_bound_after_the_sessions_end`
//! fails; `main` back on `serve_with_listener` -> the binary test fails
//! (killed by SIGTERM, no exit code).

#![cfg(unix)]

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use epigraph_mcp::background::BackgroundTasks;
use epigraph_mcp::{serve_with_listener_until, GracefulShutdown};
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;

fn socket_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "epg-mcp-stop-{tag}-{}-{nanos}.sock",
        std::process::id()
    ))
}

fn accepts(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

async fn wait_accepting(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !accepts(socket) {
        assert!(Instant::now() < deadline, "the listener never bound");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Serve `router` on a fresh socket until the returned sender fires.
fn spawn_listener(
    tag: &str,
    router: axum::Router,
    plan: GracefulShutdown,
) -> (
    PathBuf,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let socket = socket_path(tag);
    let listen = format!("unix:{}", socket.display());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        serve_with_listener_until(
            &listen,
            router,
            async move {
                let _ = stopped.await;
            },
            plan,
        )
        .await
    });
    (socket, stop, served)
}

/// The listener, once signalled, does not return while a tracked detached
/// task is running, and returns once it has finished (and only then, so the
/// task ran to completion rather than being dropped with the runtime).
#[tokio::test]
async fn a_signalled_listener_waits_for_its_background_work() {
    let tasks = BackgroundTasks::default();
    let (release, gate) = tokio::sync::oneshot::channel::<()>();
    let done = Arc::new(AtomicBool::new(false));
    {
        let done = done.clone();
        // A clone, as a session's server spawns it.
        tasks.clone().spawn(async move {
            let _ = gate.await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            done.store(true, Ordering::SeqCst);
        });
    }
    let (socket, stop, mut served) = spawn_listener(
        "wait",
        axum::Router::new(),
        GracefulShutdown::new(tasks.clone(), Duration::from_secs(30)),
    );
    wait_accepting(&socket).await;

    stop.send(()).expect("signal");
    assert!(
        tokio::time::timeout(Duration::from_millis(700), &mut served)
            .await
            .is_err(),
        "the listener returned (and the runtime would drop) with its background work still \
         running"
    );
    assert!(!done.load(Ordering::SeqCst), "CALIBRATION: still gated");

    release.send(()).expect("release");
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("returns once the work is done")
        .expect("join")
        .expect("served");
    assert!(
        done.load(Ordering::SeqCst),
        "returned before the work finished"
    );
    assert_eq!(tasks.active(), 0);
    let _ = std::fs::remove_file(&socket);
}

/// The wait is bounded: a task that never finishes is abandoned at the drain
/// bound (measured from the signal), not waited for forever.
#[tokio::test]
async fn background_work_is_abandoned_at_the_drain_bound() {
    let tasks = BackgroundTasks::default();
    tasks.spawn(std::future::pending::<()>());
    let (socket, stop, served) = spawn_listener(
        "bound",
        axum::Router::new(),
        GracefulShutdown::new(tasks.clone(), Duration::from_secs(1)),
    );
    wait_accepting(&socket).await;
    let t0 = Instant::now();
    stop.send(()).expect("signal");
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("returns at the bound")
        .expect("join")
        .expect("served");
    assert!(
        t0.elapsed() >= Duration::from_millis(900),
        "{:?}",
        t0.elapsed()
    );
    assert_eq!(tasks.active(), 1, "CALIBRATION: the task never finished");
    let _ = std::fs::remove_file(&socket);
}

/// A request still open when the request grace (bounded by the drain) has
/// passed does not hold the listener: the MCP sessions are ended (rmcp's
/// token, here a flag) and the listener returns at the bound.
#[tokio::test]
async fn an_open_request_is_cut_off_at_the_drain_bound_after_the_sessions_end() {
    let ended = Arc::new(AtomicBool::new(false));
    let plan = GracefulShutdown::new(BackgroundTasks::default(), Duration::from_secs(2))
        .ending_sessions_with({
            let ended = ended.clone();
            move || ended.store(true, Ordering::SeqCst)
        });
    let router = axum::Router::new().route(
        "/hang",
        axum::routing::get(std::future::pending::<&'static str>),
    );
    let (socket, stop, mut served) = spawn_listener("hang", router, plan);
    wait_accepting(&socket).await;
    let mut conn = tokio::net::UnixStream::connect(&socket)
        .await
        .expect("connect");
    conn.write_all(b"GET /hang HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let t0 = Instant::now();
    stop.send(()).expect("signal");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut served)
            .await
            .is_err(),
        "CALIBRATION: the open request holds the graceful wait"
    );
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("returns at the bound")
        .expect("join")
        .expect("served");
    assert!(
        ended.load(Ordering::SeqCst),
        "the sessions were not ended before giving up on the open request"
    );
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    drop(conn);
    let _ = std::fs::remove_file(&socket);
}

/// Logged by `main` just before it binds the listener.
const SERVING: &str = "Starting EpiGraph MCP server";
/// Spelled here, not imported: a test sharing its subject's text cannot
/// detect a change to it.
const SIGTERM_RECEIVED: &str = "SIGTERM received";

struct Running {
    child: Child,
    socket: PathBuf,
    log: Arc<Mutex<String>>,
}

impl Running {
    fn log(&self) -> String {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn start_listener(db_url: &str) -> Running {
    let socket = socket_path("bin");
    let listen = format!("unix:{}", socket.display());
    let key = hex::encode([0x5Du8; 32]);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "info")
        .env("EPIGRAPH_MCP_STDIO_DRAIN_SECS", "3");
    for (name, value) in std::env::vars_os() {
        if name.to_str().is_some_and(|n| n.starts_with("PG")) {
            cmd.env(name, value);
        }
    }
    let mut child = cmd
        .args([
            "--database-url",
            db_url,
            "--agent-key",
            key.as_str(),
            "--listen",
            listen.as_str(),
            "--allow-unauthenticated-http",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn epigraph-mcp-full");
    let stderr = child.stderr.take().expect("stderr");
    let log = Arc::new(Mutex::new(String::new()));
    {
        let log = log.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Ok(mut l) = log.lock() {
                    l.push_str(&line);
                    l.push('\n');
                }
            }
        });
    }
    let mut running = Running { child, socket, log };
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if running.log().contains(SERVING) && accepts(&running.socket) {
            return running;
        }
        if let Some(status) = running.child.try_wait().expect("try_wait") {
            std::thread::sleep(Duration::from_millis(300));
            panic!("exited {status} before serving:\n{}", running.log());
        }
        assert!(
            Instant::now() < deadline,
            "did not serve within 90s:\n{}",
            running.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// SIGTERM (systemd's stop) ends the binary's HTTP listener with status 0
/// after its graceful stop, with an MCP session open (the old binary died by
/// the signal: no exit code).
#[sqlx::test(migrations = "../../migrations")]
async fn sigterm_stops_the_binarys_http_listener_gracefully(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let mut running = tokio::task::spawn_blocking(move || start_listener(&url))
        .await
        .expect("join");

    // An initialized session, so there is one to end.
    let client = reqwest::Client::builder()
        .unix_socket(running.socket.as_path())
        .build()
        .expect("client");
    let resp = client
        .post("http://localhost/mcp")
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "graceful-shutdown-test", "version": "0"}}
        }))
        .send()
        .await
        .expect("initialize");
    assert_eq!(resp.status().as_u16(), 200, "CALIBRATION: serving");
    drop(resp);

    rustix::process::kill_process(
        rustix::process::Pid::from_child(&running.child),
        rustix::process::Signal::TERM,
    )
    .expect("SIGTERM the child this test spawned");
    let status = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = running.child.try_wait().expect("try_wait") {
                std::thread::sleep(Duration::from_millis(300));
                return (status, running.log());
            }
            assert!(
                Instant::now() < deadline,
                "still running 30s after SIGTERM:\n{}",
                running.log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    })
    .await
    .expect("join");
    let (status, log) = status;
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM must stop the listener gracefully, not kill it ({status}):\n{log}"
    );
    assert!(log.contains(SIGTERM_RECEIVED), "{log}");
}
