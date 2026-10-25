//! `epigraph-mcp-full`'s `main` must install [`log_filter::init_stderr`], the
//! subscriber that holds rmcp at INFO. `log_filter_caps_rmcp.rs` proves the
//! constructor caps rmcp; this file proves the compiled binary actually uses
//! it. A merge that restores an inline `tracing_subscriber::fmt()` block in
//! `main` would leave every constructor test green while the cap is gone.
//!
//! The observable is the boot WARN that only `init_stderr` emits when
//! [`log_filter::PAYLOAD_LOGGING_ENV`] opts in. `init_stderr` runs before
//! `Cli::parse()`, so `--help` reaches it with no database and exits 0. The
//! companion run without the variable pins that the WARN is not printed
//! unconditionally (which would make the first test pass vacuously).

use std::process::Command;

use epigraph_mcp::log_filter::PAYLOAD_LOGGING_ENV;

/// Run `epigraph-mcp-full --help` with a cleared environment (no `RUST_LOG`,
/// so the default filter applies) plus `extra`, returning (exit code, stderr).
fn help_stderr(extra: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("--help")
        .current_dir(std::env::temp_dir());
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run epigraph-mcp-full --help");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The WARN `init_stderr` logs when the cap is lifted: it names the variable
/// and says it is set.
fn payload_warn() -> String {
    format!("{PAYLOAD_LOGGING_ENV} is set")
}

#[test]
fn main_installs_log_filter_init_stderr() {
    let (code, stderr) = help_stderr(&[(PAYLOAD_LOGGING_ENV, "1")]);
    assert_eq!(code, Some(0), "--help must exit 0: {stderr}");
    assert!(
        stderr.contains(&payload_warn()) && stderr.contains("WARN"),
        "with {PAYLOAD_LOGGING_ENV}=1 the binary must log init_stderr's boot WARN; \
         its absence means main does not install log_filter::init_stderr \
         (the rmcp INFO cap is not in force):\n{stderr}"
    );
}

#[test]
fn payload_warn_absent_without_the_opt_in() {
    let (code, stderr) = help_stderr(&[]);
    assert_eq!(code, Some(0), "--help must exit 0: {stderr}");
    assert!(
        !stderr.contains(PAYLOAD_LOGGING_ENV),
        "without {PAYLOAD_LOGGING_ENV} the payload WARN must not be logged:\n{stderr}"
    );
}
