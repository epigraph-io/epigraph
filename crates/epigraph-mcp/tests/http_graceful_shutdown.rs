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
//!
//! Two more binary tests pin `main`'s wiring (review of 526f7508): a queued
//! `ingest_document_inline` walk of an HTTP session delays the exit until it
//! commits (fails when `main` hands the listener a fresh tracker), and a
//! client's open GET SSE stream is closed by ending the sessions rather than
//! cut off (fails without `ending_sessions_with` in `main`).

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
    start_listener_with(db_url, 3, &[])
}

/// The compiled binary on a fresh unix socket, `--allow-unauthenticated-http`,
/// with a drain bound of `drain_secs` and `extra` arguments.
fn start_listener_with(db_url: &str, drain_secs: u64, extra: &[&str]) -> Running {
    let socket = socket_path("bin");
    let listen = format!("unix:{}", socket.display());
    let key = hex::encode([0x5Du8; 32]);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "info")
        .env("EPIGRAPH_MCP_STDIO_DRAIN_SECS", drain_secs.to_string());
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
        .args(extra)
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

const ACCEPT: &str = "application/json, text/event-stream";
const SESSION_HEADER: &str = "Mcp-Session-Id";
/// Logged by `stop_gracefully` when it ends the sessions still open.
const ENDING_SESSIONS: &str = "ending the MCP sessions still open";
/// Logged by `stop_gracefully` when every connection closed in time.
const STOPPED_CLEAN: &str = "no connection left open";
/// Logged by `stop_gracefully` when it gives up on open connections.
const STOPPED_CUT_OFF: &str = "connections still open";

fn unix_client(socket: &Path) -> reqwest::Client {
    reqwest::Client::builder()
        .unix_socket(socket)
        .build()
        .expect("client")
}

async fn post_mcp(
    client: &reqwest::Client,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut req = client
        .post("http://localhost/mcp")
        .header("Accept", ACCEPT)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header(SESSION_HEADER, s);
    }
    req.send().await.expect("POST over the unix socket")
}

async fn read_sse_data(resp: &mut reqwest::Response) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut acc = String::new();
    loop {
        match tokio::time::timeout_at(deadline, resp.chunk()).await {
            Ok(Ok(Some(bytes))) => {
                acc.push_str(&String::from_utf8_lossy(&bytes));
                if acc
                    .lines()
                    .any(|l| l.starts_with("data:") && l.trim_end().len() > 5)
                {
                    return acc;
                }
            }
            _ => return acc,
        }
    }
}

/// `initialize` + `notifications/initialized`; returns the session id.
async fn handshake(client: &reqwest::Client) -> String {
    let mut resp = post_mcp(
        client,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "graceful-shutdown-test", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "CALIBRATION: serving");
    let session = resp
        .headers()
        .get(SESSION_HEADER)
        .expect("session header")
        .to_str()
        .expect("ascii")
        .to_owned();
    let _ = read_sse_data(&mut resp).await;
    let notif = post_mcp(
        client,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    session
}

fn sigterm(running: &Running) {
    rustix::process::kill_process(
        rustix::process::Pid::from_child(&running.child),
        rustix::process::Signal::TERM,
    )
    .expect("SIGTERM the child this test spawned");
}

/// Wait (blocking) up to `within` for the child to exit; its status (None if
/// still running) and log.
fn wait_exit(
    running: &mut Running,
    within: Duration,
) -> (Option<std::process::ExitStatus>, String) {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = running.child.try_wait().expect("try_wait") {
            std::thread::sleep(Duration::from_millis(300));
            return (Some(status), running.log());
        }
        if Instant::now() >= deadline {
            return (None, running.log());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

const DETACHED_DOI: &str = "10.1234/graceful-http-drain";

/// The BINARY's stop waits for the detached work of its HTTP sessions (review
/// of 526f7508: the in-process tests pass any tracker, so `main` handing the
/// listener a tracker no session spawns into went unnoticed).
///
/// A queued `ingest_document_inline` walk is held on a `SHARE` lock on
/// `papers` (the preflight's read passes; the walk's insert waits). After
/// SIGTERM, with no connection left open, the process must still be running,
/// and once the lock is released it must exit 0 with the walk committed.
///
/// Mutation: `main` passing `BackgroundTasks::default()` instead of the
/// template's tracker -> the process exits at once after SIGTERM and the walk
/// is dropped; this test fails.
#[sqlx::test(migrations = "../../migrations")]
async fn sigterm_waits_for_a_queued_walk_of_an_http_session(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let mut running = tokio::task::spawn_blocking(move || {
        start_listener_with(&url, 60, &["--allow-unauthenticated-writes"])
    })
    .await
    .expect("join");

    let mut lock = pool.begin().await.expect("begin");
    sqlx::query("LOCK TABLE papers IN SHARE MODE")
        .execute(&mut *lock)
        .await
        .expect("hold the walk's insert");

    {
        let client = unix_client(&running.socket);
        let session = handshake(&client).await;
        let extraction = serde_json::json!({
            "source": {
                "title": "Graceful HTTP drain",
                "doi": DETACHED_DOI,
                "source_type": "Paper",
                "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
            },
            "thesis": "A stopping listener waits for its queued walks",
            "thesis_derivation": "TopDown",
            "sections": [{
                "title": "Intro",
                "paragraphs": [{
                    "text": "A restart must not drop a queued walk",
                    "atoms": ["A restart must not drop a queued walk"],
                    "generality": [3],
                    "confidence": 0.8
                }]
            }],
            "relationships": []
        });
        let mut resp = post_mcp(
            &client,
            Some(&session),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "ingest_document_inline",
                           "arguments": {"extraction": extraction, "wait": false}}
            }),
        )
        .await;
        let answer = read_sse_data(&mut resp).await;
        assert!(
            answer.contains("queued"),
            "CALIBRATION: the walk was queued:\n{answer}\n--- log ---\n{}",
            running.log()
        );
        // Dropped: no connection stays open to hold the request grace.
    }

    // CALIBRATION: the walk is waiting on this test's lock.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation \
              WHERE c.relname = 'papers' AND NOT l.granted",
        )
        .fetch_one(&pool)
        .await
        .expect("pg_locks");
        if waiting > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CALIBRATION: the walk never reached the papers insert:\n{}",
            running.log()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    sigterm(&running);
    let (mut running, status, log) = tokio::task::spawn_blocking(move || {
        let (status, log) = wait_exit(&mut running, Duration::from_secs(4));
        (running, status, log)
    })
    .await
    .expect("join");
    assert!(
        status.is_none(),
        "the binary exited ({status:?}) with its HTTP session's queued walk still running:\n{log}"
    );
    assert!(log.contains(SIGTERM_RECEIVED), "{log}");

    lock.commit().await.expect("release the lock");
    let (status, log) =
        tokio::task::spawn_blocking(move || wait_exit(&mut running, Duration::from_secs(40)))
            .await
            .expect("join");
    let status =
        status.unwrap_or_else(|| panic!("still running after the walk could finish:\n{log}"));
    assert_eq!(status.code(), Some(0), "{status}:\n{log}");
    let papers: i64 = sqlx::query_scalar("SELECT count(*) FROM papers WHERE doi = $1")
        .bind(DETACHED_DOI)
        .fetch_one(&pool)
        .await
        .expect("papers");
    assert_eq!(
        papers, 1,
        "the walk ran to its commit before the exit:\n{log}"
    );
}

/// A client's standalone GET SSE stream (rmcp's server-to-client channel) is
/// CLOSED by the stop, not abandoned: after the request grace the binary ends
/// the MCP sessions (rmcp's cancellation token), rmcp ends the stream, and the
/// listener stops with no connection left open, then exits 0 (review of
/// 526f7508: the in-process test only showed a mock closure was called).
///
/// Mutations: `main`'s session-ending closure made a no-op -> the stream is
/// still open when the session-end grace runs out, the listener logs that it
/// stops with connections still open, and this test fails; without
/// `.ending_sessions_with(..)` at all it fails too. (The stop is bounded at
/// request grace + session-end grace either way, about 15 s, not by the drain
/// bound.)
#[sqlx::test(migrations = "../../migrations")]
async fn ending_the_sessions_closes_an_open_sse_stream(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let mut running = tokio::task::spawn_blocking(move || start_listener_with(&url, 60, &[]))
        .await
        .expect("join");
    let client = unix_client(&running.socket);
    let session = handshake(&client).await;
    let stream = client
        .get("http://localhost/mcp")
        .header("Accept", "text/event-stream")
        .header(SESSION_HEADER, &session)
        .send()
        .await
        .expect("GET the standalone stream");
    assert_eq!(
        stream.status().as_u16(),
        200,
        "CALIBRATION: the standalone SSE stream is open"
    );

    let t0 = Instant::now();
    sigterm(&running);
    let (status, log) =
        tokio::task::spawn_blocking(move || wait_exit(&mut running, Duration::from_secs(30)))
            .await
            .expect("join");
    let elapsed = t0.elapsed();
    let status = status.unwrap_or_else(|| {
        panic!("an open SSE stream held the stop past 30 s of a 60 s bound:\n{log}")
    });
    assert_eq!(status.code(), Some(0), "{status}:\n{log}");
    assert!(
        elapsed >= epigraph_mcp::HTTP_REQUEST_GRACE - Duration::from_millis(500),
        "CALIBRATION: the stream held the stop for the request grace ({elapsed:?}):\n{log}"
    );
    assert!(log.contains(ENDING_SESSIONS), "{log}");
    assert!(
        log.contains(STOPPED_CLEAN) && !log.contains(STOPPED_CUT_OFF),
        "ending the sessions must close the SSE stream, so the listener stops with no \
         connection open rather than cutting it off ({elapsed:?}):\n{log}"
    );
    drop(stream);
}
