//! T18: smoke check that `cross_source_sweep --help` advertises the expected
//! flag surface, and that running without `--dry-run` / `--apply` rejects with
//! a clear error (spec §Failure Modes: don't write edges silently).

#![cfg(feature = "genai")]

use std::process::Command;

fn bin_path() -> std::path::PathBuf {
    // Cargo builds the binary before the test and tells us where it put it.
    // Walking up from `current_exe()` assumed test executables live in
    // `target/debug/deps`, which cargo's build-dir layout v2 (1.100) changed.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_cross_source_sweep"))
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
    // Without a DSN the binary would later fail at connect, but the
    // mutual-exclusion check fires first because clap parses argv before
    // main() touches env. Pass --limit so we exercise the validation path.
    //
    // BOTH DSN variables are removed. PR-15 gave this binary a maintenance
    // pool, which prefers MAINTENANCE_DATABASE_URL; leaving that inherited
    // would let the process connect and turn an argv test into a database
    // test. Removing both keeps the assertion about argv ordering, which is
    // the contract this file exists to pin.
    let out = Command::new(bin_path())
        .args(["--limit", "1"])
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
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
        .env_remove("MAINTENANCE_DATABASE_URL")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("mutually exclusive"),
        "stderr should explain mutual exclusion: {err}"
    );
}
