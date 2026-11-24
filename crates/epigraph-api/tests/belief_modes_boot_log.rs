//! A belief-mode flag set to a value none of its spellings match runs the
//! flag's default (SPEC §10.2), so the only sign of the typo is the boot
//! journal. The API `server` must log it under its DEFAULT log filter (an
//! operator unit sets no `RUST_LOG`).
//!
//! Driven through the compiled binary with no `RUST_LOG`. The maintenance DSN
//! is set so the process exits at the D9 refusal right after the boot lines,
//! before any connection. The server's log layer writes to stdout, so both
//! streams are searched.
//!
//! The job runner (`drain_jobs`, the process that runs the queue since D9)
//! journals the same at boot (backlog a7ab715d), so the log shows the modes a
//! job ran under once a job acts on a flag. It is driven with no
//! `DATABASE_URL`, so it exits 1 right after its boot lines.

use std::process::Command;

fn boot(atom_fold: &str) -> (Option<i32>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_server"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EPIGRAPH_ALLOW_INSECURE_SECRET", "1")
        .env("EPIGRAPH_ENV", "test")
        .env("EPIGRAPH_PORT", "0")
        .env("EPIGRAPH_ATOM_FOLD", atom_fold)
        .env(
            "DATABASE_URL",
            "postgres://nobody:nothing@127.0.0.1:1/unreachable",
        )
        .env(
            "MAINTENANCE_DATABASE_URL",
            "postgres://nobody:nothing@127.0.0.1:1/unreachable",
        )
        .current_dir(std::env::temp_dir());
    let out = cmd.output().expect("run the server binary");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn an_unrecognised_flag_value_is_logged_at_boot_under_the_default_filter() {
    let (code, log) = boot("aef-standalone");
    assert_eq!(code, Some(1), "expected the D9 exit after boot: {log}");
    for needle in ["EPIGRAPH_ATOM_FOLD", "aef-standalone"] {
        assert!(
            log.contains(needle),
            "the boot log must name the unrecognised flag and its value \
             (missing {needle:?}):\n{log}"
        );
    }
}

/// Control: a recognised value is journalled in the boot summary and is not
/// reported as unrecognised.
#[test]
fn a_recognised_flag_value_is_in_the_boot_summary_and_not_reported() {
    let (code, log) = boot("aef_standalone");
    assert_eq!(code, Some(1), "expected the D9 exit after boot: {log}");
    assert!(
        log.contains("atom_fold=aef_standalone"),
        "the boot summary must show the mode read: {log}"
    );
    assert!(
        !log.contains("EPIGRAPH_ATOM_FOLD"),
        "a recognised value must not be reported as unrecognised: {log}"
    );
}

fn drain_boot(atom_fold: &str) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_drain_jobs"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EPIGRAPH_ATOM_FOLD", atom_fold)
        .current_dir(std::env::temp_dir())
        .output()
        .expect("run the drain_jobs binary");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The job runner journals the modes it read, under the default filter,
/// before anything can stop it (here: no `DATABASE_URL`).
#[test]
fn the_job_runner_logs_its_belief_modes_at_boot() {
    let (code, log) = drain_boot("aef_standalone");
    assert_eq!(code, Some(1), "expected the DATABASE_URL refusal: {log}");
    assert!(
        log.contains("DATABASE_URL is not set"),
        "the run stopped for another reason: {log}"
    );
    assert!(
        log.contains("atom_fold=aef_standalone") && log.contains("bp_apply=off"),
        "the boot summary must show every mode read: {log}"
    );
    assert!(
        !log.contains("EPIGRAPH_ATOM_FOLD"),
        "a recognised value must not be reported as unrecognised: {log}"
    );
}

/// A typo runs the flag's default; the job runner names it at boot.
#[test]
fn the_job_runner_logs_an_unrecognised_flag_value_at_boot() {
    let (code, log) = drain_boot("aef-standalone");
    assert_eq!(code, Some(1), "expected the DATABASE_URL refusal: {log}");
    assert!(
        log.contains("atom_fold=legacy"),
        "the boot summary must show the default the typo fell back to: {log}"
    );
    for needle in ["EPIGRAPH_ATOM_FOLD", "aef-standalone"] {
        assert!(
            log.contains(needle),
            "the boot log must name the unrecognised flag and its value \
             (missing {needle:?}):\n{log}"
        );
    }
}
