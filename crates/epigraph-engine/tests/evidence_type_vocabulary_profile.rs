//! The evidence-type vocabulary verdict (is this key one the recompute
//! resolves to a real weight?) is read from the belief profile the recompute
//! folds under, so the verdict cannot disagree with the combine when a
//! `[belief_profiles]` override adds or removes a weight.

use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::{is_known_evidence_type_key, is_known_evidence_type_key_in};

const KEYS: &[&str] = &[
    "empirical",
    "EMPIRICAL",
    "logical",
    "testimony",
    "observation",
    "derived_support",
    "supports",
    "corroborates",
    "refutes",
    "replication",
    "mystery_type",
    "",
];

#[test]
fn the_profile_vocabulary_agrees_with_the_calibration_it_is_built_from() {
    let cal = CalibrationConfig::cached();
    let p = BeliefProfile::from_calibration(cal);
    for key in KEYS {
        assert_eq!(
            is_known_evidence_type_key_in(key, &p),
            is_known_evidence_type_key(key, cal),
            "{key}"
        );
    }
}

#[test]
fn a_weight_the_profile_adds_or_removes_moves_the_verdict_with_the_fold() {
    let cal = CalibrationConfig::cached();
    let global = BeliefProfile::from_calibration(cal);
    assert!(!is_known_evidence_type_key("replication", cal));
    assert!(is_known_evidence_type_key("empirical", cal));

    let p = global
        .with_overrides(&serde_json::json!({
            "reliability": { "evidence_type_weights": { "replication": 0.7, "empirical": null } }
        }))
        .expect("valid override");
    // The verdict is exactly "the fold resolves this key to a calibrated
    // weight under this profile" (or it is an edge relationship name).
    assert!(is_known_evidence_type_key_in("replication", &p));
    assert!(p.evidence_type_weight_present("replication"));
    assert!(!is_known_evidence_type_key_in("empirical", &p));
    assert!(!p.evidence_type_weight_present("empirical"));
}
