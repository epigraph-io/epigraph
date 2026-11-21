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

/// A replay `--apply` is retired (backlog candidate
/// 913-cold-start-divergence): refused first, with or without a manifest,
/// before any file or connection, and with the reason. Before the refusal,
/// `--apply --manifest <new>` created the manifest and went on to connect.
#[test]
fn a_replay_apply_is_refused_before_any_file_or_connection() {
    let dir = scratch_dir();
    let fresh = dir.join("fresh.jsonl");
    let older = dir.join("older.jsonl");
    let older_text = "an older run's record\n";
    std::fs::write(&older, older_text).expect("write the older manifest");
    for args in [
        vec!["--apply"],
        vec!["--apply", "--manifest", fresh.to_str().expect("utf-8 path")],
        vec!["--apply", "--manifest", older.to_str().expect("utf-8 path")],
    ] {
        let out = run(&dir, true, &args);
        refused_with(&out, "replay_beta_track --apply is retired");
        refused_with(&out, "cold-start update records no divergence row");
    }
    assert!(
        !fresh.exists(),
        "a refused apply must not create a manifest"
    );
    assert_eq!(
        std::fs::read_to_string(&older).expect("read the older manifest"),
        older_text,
        "an older manifest must be left as it was"
    );
}

/// The reversal of an earlier run is not retired: `--reverse <PATH> --apply`
/// passes the refusal and stops only at the (unreachable) database. A guard
/// against the refusal catching too much; it passes on the pre-refusal binary
/// too, so it is not a proof of the refusal.
#[test]
fn a_reverse_apply_is_not_refused_as_retired() {
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    std::fs::write(&manifest, "").expect("write an empty manifest");
    let out = run(
        &dir,
        true,
        &[
            "--reverse",
            manifest.to_str().expect("utf-8 path"),
            "--apply",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the database is unreachable: {stderr}"
    );
    assert!(
        !stderr.contains("is retired"),
        "a reversal must not be refused as a retired replay: {stderr}"
    );
}

#[test]
fn a_batch_out_of_range_is_refused() {
    let dir = scratch_dir();
    for batch in ["0", "10001"] {
        let out = run(&dir, true, &["--batch", batch]);
        refused_with(&out, "--batch must be between 1 and 10000");
    }
}

/// With MAINTENANCE_DATABASE_URL unset the binary refuses before it connects
/// on the application DSN (the refusal's own text, not a connection error).
/// No run here writes a manifest any more (a replay `--apply` is retired, and
/// a reversal only reads one), so there is no manifest to check for.
#[test]
fn an_unset_maintenance_dsn_is_refused_before_a_connection() {
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    std::fs::write(&manifest, "").expect("write an empty manifest");
    let manifest_arg = manifest.to_str().expect("utf-8 path");
    for args in [
        vec!["--reverse", manifest_arg, "--apply"],
        vec!["--dry-run"],
    ] {
        let out = run(&dir, false, &args);
        refused_with(&out, "explicitly configured MAINTENANCE_DATABASE_URL");
    }
}
