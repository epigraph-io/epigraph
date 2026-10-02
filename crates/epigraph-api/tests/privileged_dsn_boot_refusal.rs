#![cfg(feature = "db")]
//! Operator ruling OQ-7 (b): the API `server` REFUSES TO START when its DSN is
//! privileged (`epigraph_bypass()` is true: a superuser or maintenance login)
//! on a database armed for operator binding. On such a DSN the claims trigger
//! checks the author column alone and relieves the cross-human scope, so any
//! caller could write as any author its request body names (delta review
//! round 4 SEC-R4-3, review SEC-MTC-4).
//!
//! Drives the compiled binary against a real `#[sqlx::test]` database on the
//! test cluster's superuser DSN, which is privileged. One database, in order,
//! because arming is one-way:
//!
//! 1. CALIBRATION, unarmed: the same binary and DSN get PAST the check (the
//!    log line the boot writes after it appears), so the refusal below is the
//!    arming, not a process that cannot start for another reason. That an
//!    unarmed database serves a privileged DSN is the CURRENT reading of
//!    OQ-7 (b) (`request_unit_may_serve`: armed only), which review
//!    R2-OQ-SEC-1 put back to the operator; it is pinned here as that
//!    reading, not as a requirement;
//! 2. a server started on that unarmed database and left SERVING exits 1
//!    once the database is armed under it (review R2-OQ-COR-1: the deploy
//!    order starts request units before arming, and the boot check alone let
//!    such a unit keep serving);
//! 3. armed: exit 1, the refusal on stderr, before the boot reaches the line
//!    of step 1;
//! 4. armed with the valve open (`EPIGRAPH_OPERATOR_LINK_ENFORCEMENT=off`):
//!    still refused; the valve never makes a privileged DSN a request DSN.
//!
//! The application-role control is NOT driven here: `epigraph_app` is NOLOGIN
//! on a throwaway CI cluster, so a DSN for it does not exist there. The pure
//! mapping (`request_unit_may_serve`, every other state serves) is unit-tested
//! in `epigraph_db::operator_binding`, and `operator_binding.rs`'s
//! `the_boot_line_names_a_privileged_dsn` pins that the application role on
//! the same armed database reads `Enforced`.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sqlx::PgPool;

/// Spelled here, not imported: a test that shares its subject's constant
/// cannot detect a change to it.
const REFUSAL: &str = "refusing to start: a request unit never serves an armed database on a \
                       privileged DSN (operator ruling OQ-7 (b)); connect it as epigraph_app";

/// Logged by `server` right after the boot check, once the entity-type cache
/// is loaded: its presence means the check was passed.
const PAST_THE_CHECK: &str = "entity_types registry cache loaded";

/// Logged once the listener is bound: the server is serving.
const SERVING: &str = "Server listening on";

/// Printed by a SERVING request unit that a re-read finds on a privileged DSN
/// of a database armed after it started. Spelled here, like [`REFUSAL`].
const STOP: &str = "stopping: a request unit never serves an armed database on a privileged \
                    DSN (operator ruling OQ-7 (b))";

enum Outcome {
    Exited { code: Option<i32>, log: String },
    PastTheCheck { log: String },
}

/// An empty (valid) providers file, so the test server boots past its
/// providers registry instead of panicking there for want of one (review
/// R2-OQ-TST-5) and can reach [`SERVING`].
fn providers_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "privileged-dsn-providers-{}.toml",
        std::process::id()
    ));
    std::fs::write(&path, "# no external identity providers\n").expect("providers file");
    path
}

/// Spawn the server against `db_url`, its stdout (the tracing layer) and
/// stderr (the refusal) merged into one line channel.
fn spawn_server(
    db_url: &str,
    valve_off: bool,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, mpsc::Receiver<String>) {
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
    if valve_off {
        cmd.env("EPIGRAPH_OPERATOR_LINK_ENFORCEMENT", "off");
    }
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
    (child, rx)
}

/// Wait until `child` either exits or logs `marker` (left running in the
/// second case). An exit after the marker was logged still counts as the
/// marker: the reader threads may deliver the line after `try_wait` sees the
/// exit (review R2-OQ-TST-5), so the drained log is checked again.
fn wait_for(
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
            return Outcome::PastTheCheck { log: log.clone() };
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            // Drain what the reader threads still hold.
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                log.push_str(&line);
                log.push('\n');
            }
            if log.contains(marker) {
                return Outcome::PastTheCheck { log: log.clone() };
            }
            return Outcome::Exited {
                code: status.code(),
                log: log.clone(),
            };
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the server neither exited nor logged {marker:?} within 90s:\n{log}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The harness itself (review R2-OQ-TST-5): a process that logged the
/// marker and exited before its reader delivered the line is still past the
/// marker, not a false "exited". Deterministic: the process has exited before
/// `wait_for` starts, and the line arrives 200 ms later, inside the drain.
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
        let _ = tx.send(PAST_THE_CHECK.to_string());
    });
    let mut log = String::new();
    match wait_for(&mut child, &rx, PAST_THE_CHECK, &mut log) {
        Outcome::PastTheCheck { .. } => {}
        Outcome::Exited { code, log } => {
            panic!("a late marker line was read as an exit {code:?}:\n{log}")
        }
    }
}

/// Run the server against `db_url` and wait until it either exits or logs
/// [`PAST_THE_CHECK`]; kill it in the second case.
fn run_server(db_url: &str, valve_off: bool) -> Outcome {
    let (mut child, rx) = spawn_server(db_url, valve_off, &[]);
    let mut log = String::new();
    let outcome = wait_for(&mut child, &rx, PAST_THE_CHECK, &mut log);
    let _ = child.kill();
    let _ = child.wait();
    outcome
}

/// Wait up to `within` for `child` to exit; its code and the whole log.
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

async fn arm(pool: &PgPool) {
    let armed: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let armed: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("arm");
        (conn, armed)
    })
    .await;
    assert!(armed, "the database arms");
}

/// Verified to fail: the server's boot check reverted to the log-only call
/// (no refusal) -> the armed run passes the check and serves;
/// `spawn_request_unit_watch` not called in `main` -> the server started
/// unarmed keeps serving after the arming (step 2).
#[sqlx::test(migrations = "../../migrations")]
async fn the_server_refuses_a_privileged_dsn_on_an_armed_database(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let privileged: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(&pool)
        .await
        .expect("bypass");
    assert!(privileged, "CALIBRATION: the test DSN is privileged");

    // 1. Unarmed: past the check.
    let url = db_url.clone();
    match tokio::task::spawn_blocking(move || run_server(&url, false))
        .await
        .expect("join")
    {
        Outcome::PastTheCheck { log } => assert!(
            !log.contains(REFUSAL),
            "CALIBRATION: an unarmed database is not refused:\n{log}"
        ),
        Outcome::Exited { code, log } => panic!(
            "CALIBRATION: on an UNARMED database the privileged DSN must get past the boot \
             check, or the refusal below proves nothing; exited {code:?}:\n{log}"
        ),
    }

    // 2. Unarmed and SERVING, then armed under it: the re-read stops it.
    let url = db_url.clone();
    let (mut child, rx) = tokio::task::spawn_blocking(move || {
        let (mut child, rx) =
            spawn_server(&url, false, &[("EPIGRAPH_REQUEST_UNIT_RECHECK_SECS", "1")]);
        let mut log = String::new();
        match wait_for(&mut child, &rx, SERVING, &mut log) {
            Outcome::PastTheCheck { .. } => (child, rx),
            Outcome::Exited { code, log } => panic!(
                "CALIBRATION: on an UNARMED database the server must reach serving; exited \
                 {code:?}:\n{log}"
            ),
        }
    })
    .await
    .expect("join");
    arm(&pool).await;
    let (code, log) = tokio::task::spawn_blocking(move || {
        let mut log = String::new();
        let code = wait_for_exit(&mut child, &rx, &mut log, Duration::from_secs(30));
        (code, log)
    })
    .await
    .expect("join");
    assert_eq!(
        code,
        Some(Some(1)),
        "a server serving a privileged DSN exits 1 once its database is armed:\n{log}"
    );
    assert!(log.contains(STOP), "it names the ruling:\n{log}");

    // 3. and 4. Armed, valve closed and open: refused.
    for valve_off in [false, true] {
        let url = db_url.clone();
        match tokio::task::spawn_blocking(move || run_server(&url, valve_off))
            .await
            .expect("join")
        {
            Outcome::Exited { code, log } => {
                assert_eq!(
                    code,
                    Some(1),
                    "valve_off={valve_off}: a failing exit:\n{log}"
                );
                assert!(
                    log.contains(REFUSAL),
                    "valve_off={valve_off}: the refusal names the ruling:\n{log}"
                );
                assert!(
                    log.contains(
                        "operator binding NOT ENFORCED for the writer on this privileged DSN:"
                    ),
                    "valve_off={valve_off}: and says why:\n{log}"
                );
            }
            Outcome::PastTheCheck { log } => panic!(
                "valve_off={valve_off}: a request unit SERVED an armed database on a privileged \
                 DSN:\n{log}"
            ),
        }
    }
}
