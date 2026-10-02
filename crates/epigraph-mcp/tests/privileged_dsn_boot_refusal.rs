//! Operator ruling OQ-7 (b): `epigraph-mcp` REFUSES TO START, on every
//! transport, when its DSN is privileged (`epigraph_bypass()` is true: a
//! superuser or maintenance login) on a database armed for operator binding.
//! On such a DSN the claims trigger checks the author column alone and
//! relieves the cross-human scope, and agents never elevate.
//!
//! Driven through the COMPILED BINARY against a real `#[sqlx::test]` database
//! on the test cluster's superuser DSN, which is privileged. One database, in
//! order, because arming is one-way:
//!
//! 1. CALIBRATION, unarmed: an HTTP listener on that DSN starts serving, so
//!    the refusal below is the arming, not a listener that cannot start. That
//!    an unarmed database serves a privileged DSN is the CURRENT reading of
//!    OQ-7 (b) (`request_unit_may_serve`: armed only), which review
//!    R2-OQ-SEC-1 put back to the operator; it is pinned here as that
//!    reading, not as a requirement;
//! 2. a listener and a stdio server started on that unarmed database and left
//!    SERVING both exit 1 once the database is armed under them (review
//!    R2-OQ-COR-1: the deploy order starts request units before arming);
//! 3. armed: the same listener exits non-zero with the refusal;
//! 4. armed, stdio transport: refused too (stdin is closed, so a missing gate
//!    would serve and exit 0 on EOF instead).
//!
//! The application-role control is not driven here (`epigraph_app` is NOLOGIN
//! on a throwaway CI cluster); `request_unit_may_serve` is unit-tested in
//! `epigraph_db::operator_binding`.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use epigraph_crypto::AgentSigner;
use sqlx::PgPool;
use uuid::Uuid;

/// Spelled here, not imported: a test that shares its subject's constant
/// cannot detect a change to it.
const REFUSAL: &str = "refusing to start: a request unit never serves an armed database on a \
                       privileged DSN (operator ruling OQ-7 (b)); connect it as epigraph_app";

/// A test-only HMAC secret, never used outside this file.
const TEST_JWT_SECRET: &str = "privileged-dsn-boot-refusal-test-secret-not-for-any-deployment";

/// Printed by a SERVING request unit that a re-read finds on a privileged DSN
/// of a database armed after it started. Spelled here, like [`REFUSAL`].
const STOP: &str = "stopping: a request unit never serves an armed database on a privileged \
                    DSN (operator ruling OQ-7 (b))";

/// Logged once the HTTP listener is up.
const SERVING: &str = "Starting EpiGraph MCP server";

/// Logged on both transports after the boot check, before stdio's handshake
/// (which waits on stdin): a stdio server that logs it is past the check.
const PAST_THE_CHECK: &str = "Agent identity ready";

enum Outcome {
    Exited { code: Option<i32>, stderr: String },
    Serving { stderr: String },
}

/// Spawn `epigraph-mcp-full` against `db_url` signing as `key_hex` (an HTTP
/// listener when `listen`, stdio otherwise), and wait until it exits or logs
/// that it is serving; kill it in the second case. On stdio its stdin is
/// closed, so a missing gate would serve and exit 0 on EOF.
fn spawn_mcp(db_url: &str, key_hex: &str, listen: bool) -> Outcome {
    let (mut child, rx) = start_mcp(db_url, key_hex, listen, Stdio::null(), &[]);
    let mut log = String::new();
    let outcome = wait_serving(&mut child, &rx, SERVING, &mut log);
    let _ = child.kill();
    let _ = child.wait();
    outcome
}

/// Spawn `epigraph-mcp-full` (see [`spawn_mcp`]) with `stdin`, its stderr
/// as a line channel.
fn start_mcp(
    db_url: &str,
    key_hex: &str,
    listen: bool,
    stdin: Stdio,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, mpsc::Receiver<String>) {
    let mut args = vec!["--database-url", db_url, "--agent-key", key_hex];
    if listen {
        args.extend(["--listen", "127.0.0.1:0", "--jwt-secret", TEST_JWT_SECRET]);
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .args(&args)
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env_remove("EPIGRAPH_OPERATOR_ID")
        .env_remove("EPIGRAPH_MCP_EXTENSIONS")
        .env_remove("EPIGRAPH_SESSION_GUC_MODE")
        .env_remove("EPIGRAPH_OPERATOR_LINK_ENFORCEMENT")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env_remove("OPENAI_API_KEY")
        .env("RUST_LOG", "info")
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp bin");
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    (child, rx)
}

/// Wait until `child` exits or logs `marker` (left running then). An exit
/// after `marker` was logged still counts as reaching it: the reader thread
/// may deliver the line after `try_wait` sees the exit (review R2-OQ-TST-5).
fn wait_serving(
    child: &mut std::process::Child,
    rx: &mpsc::Receiver<String>,
    marker: &str,
    log: &mut String,
) -> Outcome {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        while let Ok(line) = rx.try_recv() {
            log.push_str(&line);
            log.push('\n');
        }
        if log.contains(marker) {
            return Outcome::Serving {
                stderr: log.clone(),
            };
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                log.push_str(&line);
                log.push('\n');
            }
            if log.contains(marker) {
                return Outcome::Serving {
                    stderr: log.clone(),
                };
            }
            return Outcome::Exited {
                code: status.code(),
                stderr: log.clone(),
            };
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("epigraph-mcp neither exited nor logged {marker:?} within 90s:\n{log}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The harness itself (review R2-OQ-TST-5): a process that logged the
/// marker and exited before its reader delivered the line is still past the
/// marker, not a false "exited". Deterministic: the process has exited before
/// `wait_serving` starts, and the line arrives 200 ms later, inside the drain.
///
/// Verified to fail: the re-check after the drain removed -> `Exited`.
#[test]
fn a_marker_drained_after_the_exit_still_counts() {
    let mut child = Command::new("sh")
        .args(["-c", "exit 101"])
        .spawn()
        .expect("spawn sh");
    while child.try_wait().expect("try_wait").is_none() {
        std::thread::sleep(Duration::from_millis(10));
    }
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        let _ = tx.send(SERVING.to_string());
    });
    let mut log = String::new();
    match wait_serving(&mut child, &rx, SERVING, &mut log) {
        Outcome::Serving { .. } => {}
        Outcome::Exited { code, stderr } => {
            panic!("a late marker line was read as an exit {code:?}:\n{stderr}")
        }
    }
}

/// Wait up to `within` for `child` to exit; its code (`None`: still running,
/// then killed).
fn wait_for_exit(
    child: &mut std::process::Child,
    rx: &mpsc::Receiver<String>,
    log: &mut String,
    within: Duration,
) -> Option<Option<i32>> {
    let deadline = Instant::now() + within;
    loop {
        while let Ok(line) = rx.try_recv() {
            log.push_str(&line);
            log.push('\n');
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                log.push_str(&line);
                log.push('\n');
            }
            return Some(status.code());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Verified to fail: `main`'s boot check reverted to the log-only call (no
/// refusal) -> the armed listener serves; `spawn_request_unit_watch` not
/// called in `main` -> the listener and the stdio server started unarmed keep
/// serving after the arming (step 2).
#[sqlx::test(migrations = "../../migrations")]
async fn epigraph_mcp_refuses_a_privileged_dsn_on_an_armed_database(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let privileged: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(&pool)
        .await
        .expect("bypass");
    assert!(privileged, "CALIBRATION: the test DSN is privileged");
    let signer = AgentSigner::from_bytes(&[0x71; 32]).expect("signer");
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(Uuid::new_v4())
        .bind(signer.public_key().to_vec())
        .execute(&pool)
        .await
        .expect("register the signer agent");
    let key = "71".repeat(32);

    // 1. Unarmed: the listener serves.
    let (url, k) = (db_url.clone(), key.clone());
    match tokio::task::spawn_blocking(move || spawn_mcp(&url, &k, true))
        .await
        .expect("join")
    {
        Outcome::Serving { stderr } => assert!(!stderr.contains(REFUSAL), "{stderr}"),
        Outcome::Exited { code, stderr } => panic!(
            "CALIBRATION: on an UNARMED database the listener must start, or the refusal below \
             proves nothing; exited {code:?}:\n{stderr}"
        ),
    }

    // 2. Unarmed and running (a listener serving; a stdio server past the
    // boot check, waiting on its open stdin for the handshake), then armed
    // under them: the re-read stops both.
    let (url, k) = (db_url.clone(), key.clone());
    let running = tokio::task::spawn_blocking(move || {
        [true, false].map(|listen| {
            let (mut child, rx) = start_mcp(
                &url,
                &k,
                listen,
                Stdio::piped(),
                &[("EPIGRAPH_REQUEST_UNIT_RECHECK_SECS", "1")],
            );
            let mut log = String::new();
            let marker = if listen { SERVING } else { PAST_THE_CHECK };
            match wait_serving(&mut child, &rx, marker, &mut log) {
                Outcome::Serving { .. } => (listen, child, rx, log),
                Outcome::Exited { code, stderr } => panic!(
                    "CALIBRATION: listen={listen} on an UNARMED database must serve; exited \
                     {code:?}:\n{stderr}"
                ),
            }
        })
    })
    .await
    .expect("join");

    // 3. and 4. Armed: the listener and stdio are both refused.
    let armed: bool = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let armed: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("arm");
        (conn, armed)
    })
    .await;
    assert!(armed, "the database arms");
    let stopped = tokio::task::spawn_blocking(move || {
        running.map(|(listen, mut child, rx, mut log)| {
            let code = wait_for_exit(&mut child, &rx, &mut log, Duration::from_secs(30));
            (listen, code, log)
        })
    })
    .await
    .expect("join");
    for (listen, code, log) in stopped {
        assert_eq!(
            code,
            Some(Some(1)),
            "listen={listen}: a unit serving a privileged DSN exits 1 once its database is \
             armed:\n{log}"
        );
        assert!(
            log.contains(STOP),
            "listen={listen}: it names the ruling:\n{log}"
        );
    }
    for listen in [true, false] {
        let (url, k) = (db_url.clone(), key.clone());
        match tokio::task::spawn_blocking(move || spawn_mcp(&url, &k, listen))
            .await
            .expect("join")
        {
            Outcome::Exited { code, stderr } => {
                assert_eq!(code, Some(1), "listen={listen}: a failing exit:\n{stderr}");
                assert!(
                    stderr.contains(REFUSAL),
                    "listen={listen}: the refusal names the ruling:\n{stderr}"
                );
            }
            Outcome::Serving { stderr } => panic!(
                "listen={listen}: epigraph-mcp SERVED an armed database on a privileged DSN:\n\
                 {stderr}"
            ),
        }
    }
}
