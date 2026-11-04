//! The `supersede_belief_delta` binary's calibration guard for the `r173`
//! item (ruling R-173, Tier B): driven as the real process an operator runs.
//!
//! The plan's guard is "refuse to start if the served calibration has a
//! startup problem", because F (the fold under the shipped calibration) is
//! only the shipped calibration when the process loaded it. A
//! `CALIBRATION_PATH` that cannot be loaded is such a problem
//! (`CalibrationConfig::startup_problems`). Pinned here:
//!
//! * `--items r173` with that problem: refused BEFORE the report file is
//!   created or a connection is attempted (no `DATABASE_URL` is set, so a
//!   run that got that far would fail on it instead, with another message);
//! * the same problem without `r173` in `--items`: no calibration refusal
//!   (the guard is r173's alone); the run goes on and stops at the missing
//!   `DATABASE_URL`;
//! * `--items r173` with `CALIBRATION_PATH` unset (the embedded, shipped
//!   calibration): the guard passes; the run stops at the missing
//!   `DATABASE_URL`.
//!
//! No database is needed. The environment is CLEARED and the working
//! directory is a fresh temp dir: the binary loads a `.env`, and an inherited
//! `DATABASE_URL` or `CALIBRATION_PATH` would change what it does.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_supersede_belief_delta");
const REFUSAL: &str = "r173 refuses to measure";
const NO_DSN: &str = "DATABASE_URL not set";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("r173-guard-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).expect("create a temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(dir: &Path, items: &str, calibration_path: Option<&str>) -> (Output, String) {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .current_dir(dir)
        .args(["--json", "out.json", "--items", items]);
    if let Some(p) = calibration_path {
        cmd.env("CALIBRATION_PATH", p);
    }
    let out = cmd.output().expect("run the binary");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (out, stderr)
}

#[test]
fn r173_refuses_a_calibration_with_a_startup_problem_before_writing_or_connecting() {
    let dir = TempDir::new();
    let (out, stderr) = run(&dir.0, "r173", Some("/nonexistent/calibration.toml"));
    assert!(!out.status.success(), "refused: {stderr}");
    assert!(
        stderr.contains(REFUSAL),
        "the refusal is the guard's: {stderr}"
    );
    assert!(
        stderr.contains("/nonexistent/calibration.toml"),
        "the refusal names the failed path: {stderr}"
    );
    assert!(
        !stderr.contains(NO_DSN),
        "refused before any connection was attempted: {stderr}"
    );
    assert!(
        !dir.0.join("out.json").exists(),
        "refused before the report file was created"
    );
}

#[test]
fn the_guard_is_r173s_alone_and_passes_the_shipped_calibration() {
    let dir = TempDir::new();
    // Without r173 the same broken calibration is not refused on.
    let (out, stderr) = run(&dir.0, "r131", Some("/nonexistent/calibration.toml"));
    assert!(!out.status.success(), "{stderr}");
    assert!(!stderr.contains(REFUSAL), "{stderr}");
    assert!(
        stderr.contains(NO_DSN),
        "the run went past the guard to the connection: {stderr}"
    );
    assert!(
        !dir.0.join("out.json").exists(),
        "a failed run removes the report it created"
    );

    // With r173 and the embedded calibration the guard passes.
    let (out, stderr) = run(&dir.0, "r173", None);
    assert!(!out.status.success(), "{stderr}");
    assert!(!stderr.contains(REFUSAL), "{stderr}");
    assert!(stderr.contains(NO_DSN), "{stderr}");
}
