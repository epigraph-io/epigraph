//! `MatcherConfig::load_default` (the cross-source matcher's `[matcher]`
//! settings) must come from the calibration the process SERVES, never from a
//! `calibration.toml` in the working directory (backlog 26a12f41, part 2).
//!
//! It read `Path::new("calibration.toml")`, so the cross-source sweep's
//! weights, bands and fan-out depended on the directory it was started from:
//! from anywhere but a checkout it failed outright, and from a checkout it
//! took that branch's file, whatever `CALIBRATION_PATH` said.
//!
//! The working directory is process-wide, so this file is its own test binary
//! with ONE test that walks both directories in sequence, and
//! `CALIBRATION_PATH` is removed before anything resolves the served
//! calibration (so the expected `[matcher]` is the compiled-in one, which is
//! the workspace file this test reads by absolute path).

use std::path::{Path, PathBuf};

use epigraph_engine::matching::calibration::MatcherConfig;
use uuid::Uuid;

fn workspace_calibration() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration.toml")
}

fn fresh_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("26a12f41-matcher-{tag}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create the working directory");
    dir
}

#[test]
fn load_default_serves_the_resolved_calibration_not_the_cwd_file() {
    std::env::remove_var("CALIBRATION_PATH");
    let shipped = MatcherConfig::load_from(&workspace_calibration()).expect("workspace [matcher]");

    // 1. A working directory with no calibration.toml (every deploy that does
    //    not run from a checkout): the old cwd read failed here.
    let empty = fresh_dir("empty");
    std::env::set_current_dir(&empty).expect("enter the empty directory");
    assert!(!Path::new("calibration.toml").exists());
    let got = MatcherConfig::load_default()
        .expect("load_default must not need calibration.toml in the working directory");
    assert!((got.weights.embed_cosine - shipped.weights.embed_cosine).abs() < 1e-6);
    assert!((got.bands.mid - shipped.bands.mid).abs() < 1e-6);
    assert_eq!(got.fan_out.max_per_claim, shipped.fan_out.max_per_claim);

    // 2. A working directory whose calibration.toml has a different [matcher]
    //    (a process started from another branch's checkout): ignored.
    const VARIANT_FAN_OUT: usize = 7;
    assert_ne!(shipped.fan_out.max_per_claim, VARIANT_FAN_OUT);
    let text = std::fs::read_to_string(workspace_calibration()).expect("workspace file");
    let mut section = String::new();
    let mut replaced = 0;
    let variant: String = text
        .lines()
        .map(|line| {
            let t = line.trim();
            if t.starts_with('[') {
                section = t.to_string();
            }
            if section == "[matcher.fan_out]" && t.starts_with("max_per_claim") {
                replaced += 1;
                format!("max_per_claim = {VARIANT_FAN_OUT}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        replaced, 1,
        "exactly one [matcher.fan_out] max_per_claim line"
    );
    let other = fresh_dir("cwd-file");
    std::fs::write(other.join("calibration.toml"), variant + "\n").expect("write the cwd file");
    assert_eq!(
        MatcherConfig::load_from(&other.join("calibration.toml"))
            .expect("the cwd variant loads")
            .fan_out
            .max_per_claim,
        VARIANT_FAN_OUT
    );
    std::env::set_current_dir(&other).expect("enter the directory with a calibration.toml");
    let got = MatcherConfig::load_default().expect("load_default");
    assert_eq!(
        got.fan_out.max_per_claim, shipped.fan_out.max_per_claim,
        "load_default took [matcher] from the working directory's calibration.toml"
    );
}
