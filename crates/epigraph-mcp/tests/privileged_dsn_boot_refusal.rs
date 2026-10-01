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
//!    the refusal below is the arming, not a listener that cannot start;
//! 2. armed: the same listener exits non-zero with the refusal;
//! 3. armed, stdio transport: refused too (stdin is closed, so a missing gate
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

enum Outcome {
    Exited { code: Option<i32>, stderr: String },
    Serving { stderr: String },
}

/// Spawn `epigraph-mcp-full` against `db_url` signing as `key_hex` (an HTTP
/// listener when `listen`, stdio otherwise, stdin closed), and wait until it
/// exits or logs that it is serving; kill it in the second case.
fn spawn_mcp(db_url: &str, key_hex: &str, listen: bool) -> Outcome {
    let mut args = vec!["--database-url", db_url, "--agent-key", key_hex];
    if listen {
        args.extend(["--listen", "127.0.0.1:0", "--jwt-secret", TEST_JWT_SECRET]);
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"))
        .args(&args)
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env_remove("EPIGRAPH_OPERATOR_ID")
        .env_remove("EPIGRAPH_MCP_EXTENSIONS")
        .env_remove("EPIGRAPH_SESSION_GUC_MODE")
        .env_remove("EPIGRAPH_OPERATOR_LINK_ENFORCEMENT")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env_remove("OPENAI_API_KEY")
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
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

    let deadline = Instant::now() + Duration::from_secs(90);
    let mut log = String::new();
    loop {
        while let Ok(line) = rx.try_recv() {
            log.push_str(&line);
            log.push('\n');
        }
        if log.contains("Starting EpiGraph MCP server") {
            let _ = child.kill();
            let _ = child.wait();
            return Outcome::Serving { stderr: log };
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                log.push_str(&line);
                log.push('\n');
            }
            return Outcome::Exited {
                code: status.code(),
                stderr: log,
            };
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("epigraph-mcp neither exited nor started serving within 90s:\n{log}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Verified to fail: `main`'s boot check reverted to the log-only call (no
/// refusal) -> the armed listener serves.
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

    // 2. and 3. Armed: the listener and stdio are both refused.
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
