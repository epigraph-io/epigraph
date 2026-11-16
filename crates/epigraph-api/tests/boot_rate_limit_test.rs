//! Boot-time rate-limit installation (backlog 966164c8): the `server` binary
//! builds its rate limiter from `EPIGRAPH_RATE_LIMIT*` and
//! `EPIGRAPH_TRUSTED_PROXIES`, says at boot whether it is on, and refuses to
//! start on a malformed value. It is OFF unless one of the rate-limit
//! variables is set (the operator's ruling on #841).
//!
//! Before the fix the binary never built a limiter at all, so it logged
//! nothing about one and accepted any value of these variables. Drives the
//! compiled binary as a subprocess (as `boot_secret_gate_test.rs` does), so
//! it exercises the real `main`. The database URL points at a closed port:
//! the rate-limit lines are written before any connection, and the process
//! then exits on the unreachable database.

use std::process::{Command, Output};

const VARS: [&str; 5] = [
    "EPIGRAPH_RATE_LIMIT",
    "EPIGRAPH_RATE_LIMIT_RPM",
    "EPIGRAPH_RATE_LIMIT_GLOBAL_RPM",
    "EPIGRAPH_TRUSTED_PROXIES",
    "EPIGRAPH_GUEST_READS",
];

/// The boot line that says the guest reads got the default limiter.
const GUEST_DEFAULT: &str = "guest routes are rate limited by default";
/// The boot warning for guest reads left unlimited by an explicit `off`.
const GUEST_UNLIMITED: &str = "the guest reads under /api/v1/guest/ are UNLIMITED";

/// The log line containing `needle`, or a panic naming it.
fn line_with<'a>(log: &'a str, needle: &str) -> &'a str {
    log.lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no boot line contains {needle:?}; got:\n{log}"))
}

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

/// The operator's ruling: a deployment that sets none of the variables does
/// not rate limit, and the boot log says so.
#[test]
fn the_limiter_is_off_by_default_and_says_so() {
    let (_, log) = boot(&[]);
    assert!(
        log.contains("rate limiter OFF") && log.contains("EPIGRAPH_RATE_LIMIT_RPM is not set"),
        "the boot log must say the limiter is off and how to turn it on; got:\n{log}"
    );
    assert!(!log.contains("rate limiter ON"), "got:\n{log}");
    // Guest reads are off by default, so the ruling of 2026-11-16 changes
    // nothing here.
    assert!(
        !log.contains(GUEST_DEFAULT) && !log.contains(GUEST_UNLIMITED),
        "got:\n{log}"
    );
}

/// A trusted-proxy list keys a limiter; it does not install one.
#[test]
fn a_proxy_list_alone_does_not_turn_it_on() {
    let (_, log) = boot(&[("EPIGRAPH_TRUSTED_PROXIES", "192.0.2.10")]);
    assert!(log.contains("rate limiter OFF"), "got:\n{log}");
    assert!(!log.contains("rate limiter ON"), "got:\n{log}");
}

#[test]
fn on_alone_uses_the_default_limit_and_loopback_proxies() {
    let (_, log) = boot(&[("EPIGRAPH_RATE_LIMIT", "on")]);
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
    let (_, log) = boot(&[
        ("EPIGRAPH_RATE_LIMIT", "off"),
        ("EPIGRAPH_RATE_LIMIT_RPM", "42"),
    ]);
    assert!(
        log.contains("rate limiter OFF (EPIGRAPH_RATE_LIMIT=off)"),
        "got:\n{log}"
    );
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

// ---------------------------------------------------------------------------
// Guest reads (the operator's ruling of 2026-11-16)
// ---------------------------------------------------------------------------

/// Guest reads on, no limiter configured: the guest routes get #841's
/// default limit, keyed on the client address, and the boot log says so,
/// naming the variable that changes it. The other routes stay unlimited.
#[test]
fn guest_reads_on_alone_limit_the_guest_routes_by_default() {
    let (_, log) = boot(&[("EPIGRAPH_GUEST_READS", "on")]);
    let line = line_with(&log, GUEST_DEFAULT);
    assert!(
        line.contains("INFO")
            && line.contains("per_key_rpm=600")
            && line.contains("trusted_proxies=127.0.0.0/8,::1/128")
            && line.contains("EPIGRAPH_RATE_LIMIT_RPM")
            && line.contains("EPIGRAPH_RATE_LIMIT=off"),
        "the guest-default line must state the limit and name the variables that change \
         it; got:\n{line}"
    );
    assert!(
        log.contains("rate limiter OFF except on the guest reads"),
        "the other routes are still unlimited, and the log must say so; got:\n{log}"
    );
    assert!(!log.contains("rate limiter ON"), "got:\n{log}");
    assert!(!log.contains(GUEST_UNLIMITED), "got:\n{log}");
}

/// The guest default honours `EPIGRAPH_TRUSTED_PROXIES`, which still does not
/// install a limiter on the other routes.
#[test]
fn the_guest_default_is_keyed_through_the_trusted_proxies() {
    let (_, log) = boot(&[
        ("EPIGRAPH_GUEST_READS", "on"),
        ("EPIGRAPH_TRUSTED_PROXIES", "192.0.2.10"),
    ]);
    assert!(
        line_with(&log, GUEST_DEFAULT).contains("trusted_proxies=192.0.2.10/32"),
        "got:\n{log}"
    );
    assert!(!log.contains("rate limiter ON"), "got:\n{log}");
}

/// Guest reads on with a configured limiter: the guest routes use it (it is
/// ON for every route), and no separate default is installed.
#[test]
fn a_configured_limiter_covers_the_guest_reads() {
    for config in [
        ("EPIGRAPH_RATE_LIMIT_RPM", "42"),
        ("EPIGRAPH_RATE_LIMIT", "on"),
        ("EPIGRAPH_RATE_LIMIT_GLOBAL_RPM", "9000"),
    ] {
        let (_, log) = boot(&[("EPIGRAPH_GUEST_READS", "on"), config]);
        assert!(log.contains("rate limiter ON"), "{config:?}: got:\n{log}");
        assert!(
            !log.contains(GUEST_DEFAULT) && !log.contains(GUEST_UNLIMITED),
            "{config:?}: the configured limiter covers the guest routes; got:\n{log}"
        );
    }
}

/// Guest reads on with `EPIGRAPH_RATE_LIMIT=off`: the operator's explicit
/// choice is respected (no limiter at all), and a WARN says the guest reads
/// are unlimited.
#[test]
fn explicit_off_with_guest_reads_on_warns_that_they_are_unlimited() {
    let (_, log) = boot(&[
        ("EPIGRAPH_GUEST_READS", "on"),
        ("EPIGRAPH_RATE_LIMIT", "off"),
    ]);
    assert!(
        line_with(&log, GUEST_UNLIMITED).contains("WARN"),
        "the unlimited guest reads must be a warning; got:\n{log}"
    );
    assert!(
        log.contains("rate limiter OFF (EPIGRAPH_RATE_LIMIT=off)"),
        "got:\n{log}"
    );
    assert!(
        !log.contains(GUEST_DEFAULT) && !log.contains("rate limiter ON"),
        "an explicit off installs no limiter, not even the guest default; got:\n{log}"
    );

    // With guest reads off, an explicit off has nothing to warn about.
    let (_, log) = boot(&[("EPIGRAPH_RATE_LIMIT", "off")]);
    assert!(!log.contains(GUEST_UNLIMITED), "got:\n{log}");
}
