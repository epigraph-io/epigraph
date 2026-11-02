//! Backlog 7cb71243: a process whose `calibration.toml` cannot be read must
//! still combine with the shipped evidence-type vocabulary.
//!
//! This is the agent-container condition: the host-built `epigraph-mcp` is
//! bind-mounted into a container where neither `CALIBRATION_PATH` nor the
//! build machine's source path exists. `CalibrationConfig::cached` used to
//! install `default_for_phase2_fallback()` there, whose `evidence_type_weights`
//! is EMPTY, so every typed BBA combined at the 0.5 unknown-type weight
//! (empirical 1.0 -> 0.5, Bel 0.60 -> 0.30) and `submit_ds_evidence` warned
//! "Known keys: ." with a blank list.
//!
//! ONE test in this file, on purpose: each integration-test file is its own
//! process, and `cached()` is a process-wide `LazyLock`, so the env var must be
//! set before anything in the process touches it.

use epigraph_engine::calibration::CalibrationConfig;

#[test]
fn unreachable_calibration_file_still_serves_the_shipped_vocabulary() {
    // Edition 2021: `set_var` is safe, and this process has no other thread
    // reading the environment yet.
    std::env::set_var("CALIBRATION_PATH", "/nonexistent/7cb71243/calibration.toml");
    let cfg = CalibrationConfig::cached();
    assert_eq!(
        cfg.evidence_type_weights.get("empirical"),
        Some(&1.0),
        "empty vocabulary: every typed BBA would combine at the 0.5 unknown-type weight"
    );
    assert_eq!(
        cfg.evidence_type_aliases
            .get("observation")
            .map(String::as_str),
        Some("empirical"),
        "the alias table ships with the vocabulary"
    );
    assert_eq!(
        cfg.methodology_profiles.get("meta_analysis"),
        Some(&[0.80, 0.05, 0.15]),
        "methodology profiles ship too"
    );
    assert!(
        (cfg.get_evidence_type_weight("observation") - 1.0).abs() < f64::EPSILON,
        "the served lookup resolves an alias to its calibrated weight, not 0.5"
    );

    // The failed override is not silent: the boot report names the path.
    let source = CalibrationConfig::cached_source().to_string();
    assert!(
        source.contains("embedded") && source.contains("/nonexistent/7cb71243/calibration.toml"),
        "{source}"
    );
    let problems = CalibrationConfig::startup_problems();
    assert_eq!(
        problems.len(),
        1,
        "exactly the failed override; the vocabulary is not empty: {problems:?}"
    );
    assert!(
        problems[0].contains("/nonexistent/7cb71243/calibration.toml"),
        "{problems:?}"
    );
}
