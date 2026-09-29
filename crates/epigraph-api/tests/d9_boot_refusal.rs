//! Operator decision D9 (batch W12a): the API `server` refuses to start when
//! `MAINTENANCE_DATABASE_URL` is set, in every environment, with no override.
//! Drives the compiled binary so it exercises the real `main`: the refusal must
//! come before any other gate and before any connection, so the DSNs here
//! point at a port nothing listens on and the process must still exit 1 with
//! the D9 text, promptly.
//!
//! The pure predicate's cases (absent, empty, set) are unit-tested next to it
//! (`state.rs::request_unit_boot_tests`); this is the wiring.

use std::process::Command;
use std::time::{Duration, Instant};

const D9: &str = "MAINTENANCE_DATABASE_URL is set; a request-serving process never holds the \
                  maintenance DSN (operator decision D9)";

fn server(maintenance: Option<&str>) -> (Option<i32>, String, Duration) {
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
    if let Some(m) = maintenance {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
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
fn the_server_refuses_to_start_holding_the_maintenance_dsn() {
    // Any value refuses: a maintenance login, or even the application DSN.
    for value in [
        "postgres://maint:secret@127.0.0.1:1/unreachable",
        "postgres://nobody:nothing@127.0.0.1:1/unreachable",
    ] {
        let (code, stderr, took) = server(Some(value));
        assert_eq!(code, Some(1), "{stderr}");
        assert!(
            stderr.contains(D9),
            "the refusal is not the D9 text: {stderr}"
        );
        assert!(
            !stderr.contains("secret"),
            "the refusal echoed the DSN it was given: {stderr}"
        );
        assert!(
            took < Duration::from_secs(10),
            "the refusal came after a connection attempt ({took:?}), not before it"
        );
    }
}

/// The control: without the variable (or with it exported empty, which holds
/// no credential) the binary gets past the D9 check and fails later, on the
/// unreachable database. So the refusal above is the variable, not the DSNs.
#[test]
fn without_the_variable_the_server_gets_past_the_d9_check() {
    for maintenance in [None, Some("")] {
        let (code, stderr, _) = server(maintenance);
        assert_ne!(code, Some(0), "it cannot serve an unreachable database");
        assert!(
            !stderr.contains(D9),
            "refused for D9 with MAINTENANCE_DATABASE_URL={maintenance:?}: {stderr}"
        );
    }
}
