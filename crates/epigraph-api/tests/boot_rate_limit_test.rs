//! Boot-time rate-limit installation (backlog 966164c8): the `server` binary
//! builds its rate limiter from `EPIGRAPH_RATE_LIMIT*` and
//! `EPIGRAPH_TRUSTED_PROXIES`, says at boot whether it is on, and refuses to
//! start on a malformed value.
//!
//! Before the fix the binary never built a limiter at all, so it logged
//! nothing about one and accepted any value of these variables. Drives the
//! compiled binary as a subprocess (as `boot_secret_gate_test.rs` does), so
//! it exercises the real `main`. The database URL points at a closed port:
//! the rate-limit lines are written before any connection, and the process
//! then exits on the unreachable database.

use std::process::{Command, Output};

const VARS: [&str; 4] = [
    "EPIGRAPH_RATE_LIMIT",
    "EPIGRAPH_RATE_LIMIT_RPM",
    "EPIGRAPH_RATE_LIMIT_GLOBAL_RPM",
    "EPIGRAPH_TRUSTED_PROXIES",
];

fn boot(env: &[(&str, &str)]) -> (Output, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_server"));
    for var in VARS {
        cmd.env_remove(var);
    }
    cmd.env_remove("MAINTENANCE_DATABASE_URL")
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env("EPIGRAPH_ALLOW_INSECURE_SECRET", "1")
        .env("EPIGRAPH_PORT", "0")
        .env("EPIGRAPH_METRICS_ADDR", "127.0.0.1:0")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env(
            "DATABASE_URL",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
        );
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run server bin");
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out, text)
}

#[test]
fn the_limiter_is_on_by_default_and_says_so() {
    let (_, log) = boot(&[]);
    assert!(
        log.contains("rate limiter ON"),
        "the boot log must say the limiter is on; got:\n{log}"
    );
    assert!(
        log.contains("per_key_rpm=600") && log.contains("trusted_proxies=127.0.0.0/8,::1/128"),
        "the boot log must state the effective limits and trusted proxies; got:\n{log}"
    );
}

#[test]
fn the_configured_limits_are_the_ones_logged() {
    let (_, log) = boot(&[
        ("EPIGRAPH_RATE_LIMIT_RPM", "42"),
        ("EPIGRAPH_RATE_LIMIT_GLOBAL_RPM", "9000"),
        ("EPIGRAPH_TRUSTED_PROXIES", "192.0.2.10"),
    ]);
    assert!(
        log.contains("rate limiter ON")
            && log.contains("per_key_rpm=42")
            && log.contains("global_rpm=Some(9000)")
            && log.contains("trusted_proxies=192.0.2.10/32"),
        "got:\n{log}"
    );
}

#[test]
fn off_is_logged_as_a_warning() {
    let (_, log) = boot(&[("EPIGRAPH_RATE_LIMIT", "off")]);
    assert!(log.contains("rate limiter OFF"), "got:\n{log}");
    assert!(!log.contains("rate limiter ON"), "got:\n{log}");
}

#[test]
fn a_malformed_value_refuses_to_start() {
    for (var, value) in [
        ("EPIGRAPH_RATE_LIMIT_RPM", "fast"),
        ("EPIGRAPH_TRUSTED_PROXIES", "proxy.internal"),
    ] {
        let (out, log) = boot(&[(var, value)]);
        assert!(!out.status.success(), "{var}={value} must not boot");
        assert!(
            log.contains("rate limiting is misconfigured") && log.contains(var),
            "{var}={value}: the refusal must name the variable; got:\n{log}"
        );
    }
}
