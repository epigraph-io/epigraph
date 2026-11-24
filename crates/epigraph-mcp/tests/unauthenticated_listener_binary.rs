//! Backlog c80597de: the COMPILED `epigraph-mcp-full` binary, started as an
//! `--allow-unauthenticated-http` listener, reads PUBLIC rows only.
//!
//! `unauthenticated_listener_public_only.rs` drives a router built the way
//! `main` builds it, through the same `listener_principal`. That pins the
//! function but not `main`'s call to it: an edit to `main` that injected the
//! server agent instead (the wiring before backlog fe514fc3) would give every
//! caller of the listener the server agent's group set, and that file would
//! still pass. This file starts the real binary on a unix socket against a
//! `#[sqlx::test]` database and reads over that socket with no credential.
//!
//! One database, two runs of the binary under the SAME signer key:
//!
//! 1. the read-only listener (the default): a public claim is served
//!    (calibration: the listener reads at all), a claim in the server agent's
//!    personal group reads as not found, and the dedicated reader agent
//!    (reserved by migration 241, looked up by `listener_principal`) is still
//!    the one row with that key, with no membership;
//! 2. CALIBRATION, `--allow-unauthenticated-writes`: the listener's principal
//!    is the server agent, and the same group claim IS served. So the group row
//!    is one the binary's server principal reads with, and its absence in run 1
//!    is the listener's principal, not a seeding mistake.
//!
//! Superuser harness (BYPASSRLS), as in the sibling file: what is pinned is the
//! in-query visibility predicate each read splices from its viewer.
//!
//! Verified to fail, by mutating `main`'s `listener_principal(...)` call:
//! * `UnauthenticatedWrites::AsListenerSigner` passed in place of
//!   `unauthenticated_writes` (the server agent as the read-only listener's
//!   principal): the group claim is served in run 1;
//! * the pre-fe514fc3 shape, `UnauthenticatedPrincipal::lazily_from(probe)
//!   .with_writes(unauthenticated_writes)`: the public claim is refused in run 1
//!   (`request_viewer` refuses a grouped principal-less viewer). (Before
//!   migration 241 that shape also left no reader agent; 241 now reserves the
//!   row, so that half no longer distinguishes it.)

#![cfg(unix)]

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use epigraph_crypto::AgentSigner;
use sqlx::PgPool;
use uuid::Uuid;

const ACCEPT: &str = "application/json, text/event-stream";
const SESSION_HEADER: &str = "Mcp-Session-Id";

/// Logged by `main` just before it binds the listener.
const SERVING: &str = "Starting EpiGraph MCP server";

/// The reader agent's public key. Spelled here, not imported from
/// `unauthenticated_reader::READER_PUBLIC_KEY`: a test that shares its
/// subject's constant cannot detect a change to it.
const READER_PUBLIC_KEY: &[u8; 32] = b"epigraph-mcp:unauthenticated-rdr";

/// A running `epigraph-mcp-full`, killed (by the `Child` this test spawned,
/// never by name) when dropped, so a failed assertion does not leave it
/// holding connections to the test database.
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

/// A fresh socket path per run: short (well under the 108-byte limit) and
/// unique to this process and moment.
fn socket_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "epg-mcp-unauth-{tag}-{}-{nanos}.sock",
        std::process::id()
    ))
}

/// Start `epigraph-mcp-full --listen unix:<socket> --allow-unauthenticated-http`
/// (plus `extra` flags) against `db_url`, signing as `key_hex`, and wait until
/// the socket accepts a connection.
fn start_listener(db_url: &str, key_hex: &str, tag: &str, extra: &[&str]) -> Running {
    let socket = socket_path(tag);
    let _ = std::fs::remove_file(&socket);
    let listen = format!("unix:{}", socket.display());
    let mut args = vec![
        "--database-url",
        db_url,
        "--agent-key",
        key_hex,
        "--listen",
        listen.as_str(),
        "--allow-unauthenticated-http",
    ];
    args.extend_from_slice(extra);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    // Only what this test sets reaches the child: an exported EPIGRAPH_* (agent
    // identity, operator, tokens, allowed hosts, ...) in the shell running the
    // tests must not change which principal the binary serves with. The one
    // exception is the libpq-style PG* connection variables, which sqlx reads
    // when `db_url` leaves a part out; forwarding them lets the child reach the
    // database exactly as this test's own pool does.
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "info");
    for (name, value) in std::env::vars_os() {
        if name.to_str().is_some_and(|n| n.starts_with("PG")) {
            cmd.env(name, value);
        }
    }
    let mut child = cmd
        .args(&args)
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
            panic!(
                "epigraph-mcp-full exited {status} before serving on {}:\n{}",
                running.socket.display(),
                running.log()
            );
        }
        if Instant::now() > deadline {
            panic!(
                "epigraph-mcp-full did not serve on {} within 90s:\n{}",
                running.socket.display(),
                running.log()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn accepts(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

/// A client that dials `socket` for every request. The listener validates no
/// credential, so no request below carries an `Authorization` header.
fn client_for(socket: &Path) -> reqwest::Client {
    reqwest::Client::builder()
        .unix_socket(socket)
        .build()
        .expect("unix-socket client")
}

/// The host part is ignored on a unix socket (and a unix listener applies no
/// Host allowlist); the path is the one `main` mounts the service at.
const URL: &str = "http://localhost/mcp";

async fn read_sse_data(resp: &mut reqwest::Response) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
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

async fn post(
    client: &reqwest::Client,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut req = client
        .post(URL)
        .header("Accept", ACCEPT)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header(SESSION_HEADER, s);
    }
    req.send().await.expect("POST over the unix socket")
}

async fn handshake(client: &reqwest::Client) -> String {
    let mut resp = post(
        client,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "unauthenticated-binary-test", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "initialize");
    let session = resp
        .headers()
        .get(SESSION_HEADER)
        .expect("session header")
        .to_str()
        .expect("ascii")
        .to_owned();
    let _ = read_sse_data(&mut resp).await;
    let notif = post(
        client,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    session
}

async fn get_claim(client: &reqwest::Client, session: &str, id: u32, claim: Uuid) -> String {
    let mut resp = post(
        client,
        Some(session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "get_claim", "arguments": {"claim_id": claim.to_string()}}
        }),
    )
    .await;
    read_sse_data(&mut resp).await
}

async fn agents_with_key(pool: &PgPool, key: &[u8]) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(key.to_vec())
        .fetch_all(pool)
        .await
        .expect("agents by public key")
}

async fn live_memberships(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("membership count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_unauthenticated_listener_serves_public_rows_only(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;

    // The listener's signer, registered under its public key so the binary
    // resolves THIS row as its server agent, with its personal group.
    let signer = AgentSigner::from_bytes(&[0x5c; 32]).expect("signer");
    let server_agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(server_agent)
        .bind(signer.public_key().to_vec())
        .execute(&pool)
        .await
        .expect("register the signer agent");
    let group = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::ensure_personal_group(&mut conn, server_agent)
            .await
            .expect("the signer's personal group")
    };
    let key = "5c".repeat(32);

    let public = fixture::seed_public_claim(&pool, server_agent, "c80597de public row").await;
    let private =
        fixture::seed_group_claim(&pool, server_agent, group, "c80597de server-group row").await;
    // Since migration 241 the reader's row is reserved by the migration (a
    // binary only looks it up), so it exists, alone and in no group, before
    // the binary runs.
    let reserved = agents_with_key(&pool, READER_PUBLIC_KEY).await;
    assert_eq!(
        reserved.len(),
        1,
        "CALIBRATION: migration 241 reserves exactly one reader agent"
    );
    assert_eq!(live_memberships(&pool, reserved[0]).await, 0);

    // 1. The read-only listener: public only.
    let (url, k) = (db_url.clone(), key.clone());
    let read_only = tokio::task::spawn_blocking(move || start_listener(&url, &k, "ro", &[]))
        .await
        .expect("join");
    let client = client_for(&read_only.socket);
    let session = handshake(&client).await;

    let served = get_claim(&client, &session, 2, public).await;
    assert!(
        served.contains("c80597de public row"),
        "CALIBRATION: the read-only listener must serve a public claim:\n{served}\n\
         --- listener log ---\n{}",
        read_only.log()
    );
    let hidden = get_claim(&client, &session, 3, private).await;
    assert!(
        !hidden.contains("c80597de server-group row")
            && hidden.contains(&format!("claim {private} not found")),
        "a claim in the server agent's group must read as NOT FOUND to an unauthenticated \
         caller of the binary's read-only listener:\n{hidden}\n--- listener log ---\n{}",
        read_only.log()
    );
    drop(read_only);

    // The principal `main` installed is the dedicated reader, in no group.
    let readers = agents_with_key(&pool, READER_PUBLIC_KEY).await;
    assert_eq!(
        readers, reserved,
        "main must install `listener_principal`'s reader, the one reserved row (no second one)"
    );
    assert_ne!(readers[0], server_agent);
    assert_eq!(live_memberships(&pool, readers[0]).await, 0);

    // 2. CALIBRATION: the write opt-in reads with the server agent, so the same
    // group claim is served. Without this, run 1's "not found" could be a
    // group the binary's server principal never belonged to.
    let (url, k) = (db_url.clone(), key.clone());
    let opt_in = tokio::task::spawn_blocking(move || {
        start_listener(&url, &k, "rw", &["--allow-unauthenticated-writes"])
    })
    .await
    .expect("join");
    let client = client_for(&opt_in.socket);
    let session = handshake(&client).await;
    let shown = get_claim(&client, &session, 2, private).await;
    assert!(
        shown.contains("c80597de server-group row"),
        "CALIBRATION: the --allow-unauthenticated-writes listener reads with the server agent's \
         group, so it must serve the group claim:\n{shown}\n--- listener log ---\n{}",
        opt_in.log()
    );
    drop(opt_in);

    // Both runs resolved the ONE pre-registered signer row.
    assert_eq!(
        agents_with_key(&pool, &signer.public_key()).await,
        vec![server_agent],
        "the binary resolved the registered signer, not a second server agent"
    );
}
