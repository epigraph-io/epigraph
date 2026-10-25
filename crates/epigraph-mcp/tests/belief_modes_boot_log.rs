//! A belief-mode flag set to a value none of its spellings match runs the
//! flag's default (SPEC §10.2), so the only sign of the typo is the boot
//! journal. `epigraph-mcp-full` must therefore log it under a target its own
//! DEFAULT log filter keeps: an operator unit sets no `RUST_LOG`, and a warning
//! the default filter drops is a typo nobody sees while the process reports
//! the default as though it were chosen.
//!
//! Driven through the compiled binary with no `RUST_LOG`. The maintenance DSN
//! is set so the process exits at the D9 refusal right after the boot lines,
//! before any connection.

use std::process::Command;

fn boot(atom_fold: &str) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EPIGRAPH_ATOM_FOLD", atom_fold)
        .env(
            "MAINTENANCE_DATABASE_URL",
            "postgres://nobody:nothing@127.0.0.1:1/unreachable",
        )
        .args([
            "--database-url",
            "postgres://nobody:nothing@127.0.0.1:1/unreachable",
        ])
        .current_dir(std::env::temp_dir());
    let out = cmd.output().expect("run epigraph-mcp-full");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn an_unrecognised_flag_value_is_logged_at_boot_under_the_default_filter() {
    let (code, stdout, stderr) = boot("aef-standalone");
    assert_eq!(code, Some(1), "expected the D9 exit after boot: {stderr}");
    for needle in ["EPIGRAPH_ATOM_FOLD", "aef-standalone"] {
        assert!(
            stderr.contains(needle),
            "the boot log must name the unrecognised flag and its value \
             (missing {needle:?}):\n{stderr}"
        );
    }
    assert!(
        stdout.is_empty(),
        "boot logging wrote to stdout, the JSON-RPC stream on stdio: {stdout}"
    );
}

/// Control: a recognised value is journalled in the boot summary under the
/// same default filter, and is not reported as unrecognised.
#[test]
fn a_recognised_flag_value_is_in_the_boot_summary_and_not_reported() {
    let (code, _, stderr) = boot("aef_standalone");
    assert_eq!(code, Some(1), "expected the D9 exit after boot: {stderr}");
    assert!(
        stderr.contains("atom_fold=aef_standalone"),
        "the boot summary must show the mode read: {stderr}"
    );
    assert!(
        !stderr.contains("EPIGRAPH_ATOM_FOLD"),
        "a recognised value must not be reported as unrecognised: {stderr}"
    );
}
