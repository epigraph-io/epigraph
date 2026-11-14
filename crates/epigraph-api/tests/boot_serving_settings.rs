//! The `server` binary's serving envelope (backlog ebd7952c), driven through
//! the compiled binary so the wiring in `main` is what is tested:
//!
//! - a malformed `EPIGRAPH_BIND_ADDR`, `EPIGRAPH_REQUEST_TIMEOUT_SECS`,
//!   `EPIGRAPH_SHUTDOWN_GRACE_SECS` or `EPIGRAPH_MAX_REQUEST_BYTES` refuses to
//!   start, before any connection;
//! - the listener binds `EPIGRAPH_BIND_ADDR`;
//! - every response carries an `x-request-id`;
//! - the anonymous routers hold a body to 64 KiB (413 above it);
//! - SIGTERM drains and exits 0 instead of killing the process.
//!
//! The parsing rules and the timeout's 408 are unit-tested next to them in
//! `src/serving.rs`.
//!
//! Verified to fail on the parent commit: the bad values boot and fail later on
//! the database; the listener reports `0.0.0.0`; `/health` has no request id;
//! a 100 KiB `/oauth/token` body is parsed (400), not refused; and SIGTERM
//! ends the process by signal (`status.code() == None`).

#[path = "common/served.rs"]
mod served;

#[cfg(feature = "db")]
#[path = "viewer_fixture.rs"]
mod fixture;

use std::process::Command;
use std::time::{Duration, Instant};

const MISCONFIGURED: &str = "serving is misconfigured";

fn unreachable_boot(extra: &[(&str, &str)]) -> (Option<i32>, String, Duration) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_server"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EPIGRAPH_ALLOW_INSECURE_SECRET", "1")
        .env("EPIGRAPH_ENV", "test")
        .env("EPIGRAPH_PORT", "0")
        .env("RUST_LOG", "warn")
        .env(
            "DATABASE_URL",
            "postgres://nobody:nothing@127.0.0.1:1/unreachable",
        )
        .current_dir(std::env::temp_dir());
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let started = Instant::now();
    let out = cmd.output().expect("run the server binary");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        started.elapsed(),
    )
}

#[test]
fn a_malformed_serving_setting_refuses_to_start_before_any_connection() {
    for (var, value) in [
        ("EPIGRAPH_BIND_ADDR", "localhost"),
        ("EPIGRAPH_BIND_ADDR", "0.0.0.0:8080"),
        ("EPIGRAPH_REQUEST_TIMEOUT_SECS", "5m"),
        ("EPIGRAPH_SHUTDOWN_GRACE_SECS", "soon"),
        ("EPIGRAPH_MAX_REQUEST_BYTES", "0"),
    ] {
        let (code, stderr, took) = unreachable_boot(&[(var, value)]);
        assert_eq!(code, Some(1), "{var}={value:?}: {stderr}");
        assert!(
            stderr.contains(MISCONFIGURED) && stderr.contains(var),
            "{var}={value:?} must be refused by name: {stderr}"
        );
        assert!(
            took < Duration::from_secs(10),
            "{var}={value:?}: refused after {took:?}, so after a connection attempt"
        );
    }
}

/// The control: well-formed values get past the check and fail later, on the
/// unreachable database. So the refusals above are the values.
#[test]
fn well_formed_serving_settings_get_past_the_check() {
    let (code, stderr, _) = unreachable_boot(&[
        ("EPIGRAPH_BIND_ADDR", "127.0.0.1"),
        ("EPIGRAPH_REQUEST_TIMEOUT_SECS", "0"),
        ("EPIGRAPH_SHUTDOWN_GRACE_SECS", "5"),
        ("EPIGRAPH_MAX_REQUEST_BYTES", "1048576"),
    ]);
    assert_ne!(code, Some(0), "it cannot serve an unreachable database");
    assert!(!stderr.contains(MISCONFIGURED), "{stderr}");
}

#[cfg(feature = "db")]
mod served_binary {
    use super::{fixture, served};
    use sqlx::PgPool;
    use std::time::Duration;

    async fn start(
        pool: &PgPool,
        extra: &'static [(&'static str, &'static str)],
    ) -> served::Server {
        let db_url = fixture::database_url_for(pool).await;
        tokio::task::spawn_blocking(move || {
            let mut cmd = served::base_command(&db_url);
            for (k, v) in extra {
                cmd.env(k, v);
            }
            served::boot(cmd).serving()
        })
        .await
        .expect("join")
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn it_binds_the_configured_address_and_ids_every_response(pool: PgPool) {
        let server = start(&pool, &[("EPIGRAPH_BIND_ADDR", "127.0.0.1")]).await;
        assert!(
            server
                .boot_log
                .contains(&format!("{}127.0.0.1:{}", served::SERVING, server.port)),
            "the listener must bind EPIGRAPH_BIND_ADDR, not 0.0.0.0:\n{}",
            server.boot_log
        );

        let health = served::request(server.port, "GET", "/health", "text/plain", b"").await;
        assert_eq!(health.status, 200, "{}", health.body);
        let id = health
            .header("x-request-id")
            .unwrap_or_else(|| panic!("no x-request-id on /health: {:?}", health.headers));
        assert!(uuid::Uuid::parse_str(id).is_ok(), "not a minted UUID: {id}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_anonymous_body_over_64_kib_is_refused_413(pool: PgPool) {
        let server = start(&pool, &[]).await;
        let form = "application/x-www-form-urlencoded";

        // CALIBRATION: a small malformed grant reaches the handler and is
        // answered there (not 413), so the 413 below is the size alone.
        let small = served::request(server.port, "POST", "/oauth/token", form, &[b'a'; 1024]).await;
        assert_ne!(small.status, 413, "a 1 KiB body must reach the handler");
        assert!(
            small.status >= 400,
            "a junk grant is refused: {}",
            small.status
        );

        let big = served::request(
            server.port,
            "POST",
            "/oauth/token",
            form,
            &vec![b'a'; 100 * 1024],
        )
        .await;
        assert_eq!(
            big.status, 413,
            "a 100 KiB anonymous body must be refused by the 64 KiB limit, not read: {}",
            big.body
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn sigterm_drains_and_exits_zero(pool: PgPool) {
        let mut server = start(&pool, &[("EPIGRAPH_SHUTDOWN_GRACE_SECS", "5")]).await;
        // It is serving before the signal.
        let health = served::request(server.port, "GET", "/health", "text/plain", b"").await;
        assert_eq!(health.status, 200);

        let (status, log) =
            tokio::task::spawn_blocking(move || server.terminate(Duration::from_secs(20)))
                .await
                .expect("join");
        let status = status.unwrap_or_else(|| panic!("still running 20s after SIGTERM:\n{log}"));
        assert_eq!(
            status.code(),
            Some(0),
            "SIGTERM must end in a clean exit, not death by signal ({status}):\n{log}"
        );
        assert!(log.contains("SIGTERM received"), "{log}");
        assert!(
            log.contains("server stopped"),
            "the drain must finish and say so:\n{log}"
        );
    }
}
