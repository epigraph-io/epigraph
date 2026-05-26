//! T18: smoke check that `cross_source_sweep --help` advertises the expected
//! flag surface, and that running without `--dry-run` / `--apply` rejects with
//! a clear error (spec §Failure Modes: don't write edges silently).

#![cfg(feature = "genai")]

use std::process::Command;

fn bin_path() -> std::path::PathBuf {
    // Built by cargo before the test runs.
    let me = std::env::current_exe().unwrap();
    let target_dir = me.parent().unwrap().parent().unwrap();
    target_dir.join("cross_source_sweep")
}

#[test]
fn help_lists_expected_flags() {
    let out = Command::new(bin_path()).arg("--help").output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "--help exit code: {:?}", out.status);
    for flag in &["--limit", "--dry-run", "--apply"] {
        assert!(s.contains(flag), "--help missing {flag}: {s}");
    }
}

#[test]
fn requires_dry_run_or_apply() {
    // Without DATABASE_URL the binary would later fail at connect, but the
    // mutual-exclusion check fires first because clap parses argv before
    // main() touches env. Pass --limit so we exercise the validation path.
    let out = Command::new(bin_path())
        .args(["--limit", "1"])
        .env_remove("DATABASE_URL")
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected nonzero exit");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--dry-run") || err.contains("--apply"),
        "stderr should mention the missing flags: {err}"
    );
}

#[test]
fn mutually_exclusive_flags_rejected() {
    let out = Command::new(bin_path())
        .args(["--dry-run", "--apply"])
        .env_remove("DATABASE_URL")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("mutually exclusive"),
        "stderr should explain mutual exclusion: {err}"
    );
}
