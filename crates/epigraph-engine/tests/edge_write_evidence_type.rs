//! The evidence type an edge-factor BBA is stored under follows the belief
//! profile's alias table, so a relationship is weighted the same whether its
//! row was written by an edge (canonical key stored) or carries the raw
//! relationship (alias resolved at fold time).
//!
//! `auto_wire_ds_for_edge` stores `edge_evidence_type(relationship,
//! BeliefProfile::served())`; these tests drive that function with profiles
//! whose aliases differ from the calibration's.

use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::edge_evidence_type;

/// The relationships the edge write path emits.
const RELATIONSHIPS: &[&str] = &[
    "supports",
    "corroborates",
    "refutes",
    "contradicts",
    "supersedes",
    "elaborates",
    "informs",
    "Supports",
    "no_such_relationship",
];

fn global() -> BeliefProfile {
    BeliefProfile::from_calibration(CalibrationConfig::cached())
}

#[test]
fn the_stored_type_is_weighted_like_the_raw_relationship_under_any_profile() {
    // The property the alias exists for: storing the resolved key must not
    // change the weight the fold gives the relationship. Checked under the
    // global profile and under one that re-aliases a relationship.
    let moved = global()
        .with_overrides(&serde_json::json!({
            "reliability": { "evidence_type_aliases": { "supports": "logical" } }
        }))
        .expect("valid override");
    for profile in [global(), moved] {
        for rel in RELATIONSHIPS {
            let stored = edge_evidence_type(rel, &profile);
            assert_eq!(
                profile.evidence_type_weight(&stored).to_bits(),
                profile.evidence_type_weight(rel).to_bits(),
                "{rel} stored as {stored}"
            );
        }
    }
}

#[test]
fn the_stored_type_follows_the_profiles_alias_not_the_calibrations() {
    let cal = CalibrationConfig::cached();
    let calibration_alias = cal
        .evidence_type_aliases
        .get("supports")
        .cloned()
        .expect("calibration.toml aliases `supports`");
    assert_ne!(calibration_alias, "logical", "the override must differ");

    let moved = global()
        .with_overrides(&serde_json::json!({
            "reliability": { "evidence_type_aliases": { "supports": "logical" } }
        }))
        .expect("valid override");
    assert_eq!(edge_evidence_type("supports", &moved), "logical");
    assert_eq!(edge_evidence_type("Supports", &moved), "logical");

    // An alias the profile removes is stored as the raw relationship.
    let removed = global()
        .with_overrides(&serde_json::json!({
            "reliability": { "evidence_type_aliases": { "supports": null } }
        }))
        .expect("valid override");
    assert_eq!(edge_evidence_type("supports", &removed), "supports");
}
