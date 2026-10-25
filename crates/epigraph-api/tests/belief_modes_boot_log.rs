//! A belief-mode flag set to a value none of its spellings match runs the
//! flag's default (SPEC §10.2), so the only sign of the typo is the boot
//! journal. The API `server` must log it under its DEFAULT log filter (an
//! operator unit sets no `RUST_LOG`).
//!
//! Driven through the compiled binary with no `RUST_LOG`. The maintenance DSN
//! is set so the process exits at the D9 refusal right after the boot lines,
//! before any connection. The server's log layer writes to stdout, so both
//! streams are searched.

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
