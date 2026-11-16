//! The `replay_beta_track` binary's refusals, which all come before it opens a
//! database connection, so no database is needed: the DSNs point at a port
//! nothing listens on, and a refusal that came after a connection attempt
//! would show up as a connection error instead of the refusal's own text.
//!
//! Each run gets an empty environment and a fresh working directory, so no
//! `.env` file (which the binary loads from the working directory up) and no
//! exported `MAINTENANCE_DATABASE_URL` reaches it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Names the same database in both DSNs (the maintenance resolver refuses two
/// different names); nothing listens on port 1.
const UNREACHABLE_DSN: &str = "postgres://nobody@127.0.0.1:1/b96_refusals";

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("b96-refusals-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn run(dir: &Path, maintenance: bool, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_replay_beta_track"));
    cmd.env_clear()
        .current_dir(dir)
        .env("DATABASE_URL", UNREACHABLE_DSN)
        .args(args);
    if maintenance {
        cmd.env("MAINTENANCE_DATABASE_URL", UNREACHABLE_DSN);
    }
    cmd.output().expect("run replay_beta_track")
}

fn refused_with(out: &Output, text: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must be refused; stderr: {stderr}");
    assert!(
        stderr.contains(text),
        "refused for the wrong reason (wanted {text:?}); stderr: {stderr}"
    );
}

#[test]
fn an_apply_without_a_manifest_is_refused() {
    let dir = scratch_dir();
    let out = run(&dir, true, &["--apply"]);
    refused_with(&out, "--apply needs --manifest");
}

#[test]
fn a_batch_out_of_range_is_refused() {
    let dir = scratch_dir();
    for batch in ["0", "10001"] {
        let out = run(&dir, true, &["--batch", batch]);
        refused_with(&out, "--batch must be between 1 and 10000");
    }
}

/// With MAINTENANCE_DATABASE_URL unset the binary refuses before it creates
/// the manifest or connects on the application DSN.
#[test]
fn an_unset_maintenance_dsn_is_refused_before_a_manifest_is_created() {
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let manifest_arg = manifest.to_str().expect("utf-8 path");
    for args in [
        vec!["--apply", "--manifest", manifest_arg],
        vec!["--dry-run"],
    ] {
        let out = run(&dir, false, &args);
        refused_with(&out, "explicitly configured MAINTENANCE_DATABASE_URL");
        assert!(
            !manifest.exists(),
            "a refused run must not leave a manifest behind"
        );
    }
}

/// An existing manifest (an older run's record) is refused, before any
/// connection, and is not touched.
#[test]
fn an_existing_manifest_is_refused_and_left_alone() {
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let older = "an older run's record\n";
    std::fs::write(&manifest, older).expect("write the older manifest");
    let out = run(
        &dir,
        true,
        &[
            "--apply",
            "--manifest",
            manifest.to_str().expect("utf-8 path"),
        ],
    );
    refused_with(&out, "create the manifest");
    assert_eq!(
        std::fs::read_to_string(&manifest).expect("read the manifest"),
        older,
        "the older manifest must be left as it was"
    );
}
