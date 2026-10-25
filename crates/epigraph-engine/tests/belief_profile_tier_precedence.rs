//! Belief profile, tier precedence for MAP-valued parameters.
//!
//! The chain is perspective → per-frame → global → built-in for every
//! parameter, scalars and map entries alike. A frame carries evidence-type
//! weights two ways (its older dedicated `evidence_type_weights` key, and the
//! generic `belief_profile` object); a perspective's generic
//! `belief_profile.reliability.evidence_type_weights` entry sits ABOVE both,
//! so for the evidence types it names it decides the per-BBA weight, on the
//! global branch (no perspective reliability map touches the row) and on the
//! perspective branch (a perspective `locality_reliability` entry does).
//!
//! Each assertion reads the reliability α of one stored row under a resolved
//! profile; the frame's dedicated weight and the perspective's weight are
//! chosen far apart so the winner is unambiguous.

#[path = "support/belief_fixtures.rs"]
mod fixtures;

use std::collections::HashMap;

use epigraph_db::MassFunctionRow;
use epigraph_engine::belief_profile::{BeliefProfile, FrameTier, PerspectiveTier};
use epigraph_engine::edge_factor::{effective_source_strength_profiled, PerspectiveReliability};

/// The frame's dedicated per-frame weight for `empirical` (and `logical`).
const FRAME_EMPIRICAL: f64 = 0.9;
const FRAME_LOGICAL: f64 = 0.4;
/// The perspective's generic-object weight for `empirical`.
const PERSPECTIVE_EMPIRICAL: f64 = 0.2;

/// One stored row with no stored strength, so its α is decided by the weight
/// tiers alone.
fn row(evidence_type: &'static str, locality_tag: &'static str) -> MassFunctionRow {
    let case = fixtures::Case {
        name: "tier_precedence",
        rows: vec![fixtures::RowSpec {
            evidence_type: Some(evidence_type),
            locality_tag,
            source_strength: None,
            shape: fixtures::shape(0.6, 0.0, 0.0),
            source: None,
        }],
        per_frame_intra: None,
        per_frame_weights: None,
        perspective: None,
    };
    fixtures::rows(&case).remove(0)
}

fn frame_weights() -> HashMap<String, f64> {
    HashMap::from([
        ("empirical".to_string(), FRAME_EMPIRICAL),
        ("logical".to_string(), FRAME_LOGICAL),
    ])
}

fn resolve(
    perspective_overrides: Option<&serde_json::Value>,
    perspective_maps: Option<&PerspectiveReliability>,
) -> BeliefProfile {
    let weights = frame_weights();
    BeliefProfile::builtin().resolve(
        FrameTier {
            overrides: None,
            intra_evidence_locality_factor: None,
            evidence_type_weights: Some(&weights),
        },
        PerspectiveTier {
            overrides: perspective_overrides,
            reliability: perspective_maps,
        },
    )
}

fn empirical_override(value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "reliability": { "evidence_type_weights": { "empirical": value } } })
}

#[test]
fn a_perspective_weight_override_beats_the_frames_dedicated_weight_on_the_global_branch() {
    let over = empirical_override(serde_json::json!(PERSPECTIVE_EMPIRICAL));
    let p = resolve(Some(&over), None);
    let alpha = effective_source_strength_profiled(&row("empirical", "cross"), &p);
    assert_eq!(
        alpha,
        PERSPECTIVE_EMPIRICAL * p.reliability.cross_locality_factor,
        "the perspective tier sits above the per-frame tier: α must come from the \
         perspective's weight, not the frame's {FRAME_EMPIRICAL}"
    );
}

#[test]
fn a_perspective_weight_override_beats_the_frames_dedicated_weight_on_the_perspective_branch() {
    // A perspective locality entry for `cross` routes the row through the
    // perspective branch; its base weight must still be the perspective's.
    let locality = 0.5;
    let maps = PerspectiveReliability {
        source_reliability: HashMap::new(),
        locality_reliability: HashMap::from([("cross".to_string(), locality)]),
    };
    let over = empirical_override(serde_json::json!(PERSPECTIVE_EMPIRICAL));
    let p = resolve(Some(&over), Some(&maps));
    let alpha = effective_source_strength_profiled(&row("empirical", "cross"), &p);
    assert_eq!(alpha, PERSPECTIVE_EMPIRICAL * locality);
}

#[test]
fn a_perspective_null_removes_the_weight_at_every_tier_below_it() {
    // `null` removes the entry: the perspective says this type has no
    // calibrated weight, so neither the frame's dedicated key nor the global
    // table may answer for it, and the row falls to the unknown-type weight.
    let over = empirical_override(serde_json::Value::Null);
    let p = resolve(Some(&over), None);
    let alpha = effective_source_strength_profiled(&row("empirical", "cross"), &p);
    assert_eq!(
        alpha,
        p.reliability.unknown_evidence_type_weight * p.reliability.cross_locality_factor
    );
}

#[test]
fn a_type_the_perspective_does_not_name_keeps_the_frames_dedicated_weight() {
    let over = empirical_override(serde_json::json!(PERSPECTIVE_EMPIRICAL));
    let p = resolve(Some(&over), None);
    let alpha = effective_source_strength_profiled(&row("logical", "cross"), &p);
    assert_eq!(alpha, FRAME_LOGICAL * p.reliability.cross_locality_factor);
}

#[test]
fn a_rejected_perspective_tier_leaves_the_frames_dedicated_weight_in_force() {
    // Whole-tier rejection: the valid half of an invalid object (here the
    // empirical weight) must not take effect in any form, including by
    // displacing the frame's key.
    let over = serde_json::json!({
        "reliability": { "evidence_type_weights": { "empirical": PERSPECTIVE_EMPIRICAL } },
        "no_such_parameter": 1
    });
    let p = resolve(Some(&over), None);
    let alpha = effective_source_strength_profiled(&row("empirical", "cross"), &p);
    assert_eq!(alpha, FRAME_EMPIRICAL * p.reliability.cross_locality_factor);
}

#[test]
fn a_mis_cased_perspective_key_displaces_nothing() {
    // The fold looks weights up lowercased, so a perspective entry spelled
    // `Empirical` is inert in the merged table, as a mis-cased key is
    // everywhere else. It must not take the frame's `empirical` weight away
    // either, or the row would fall to a tier nobody chose.
    let over = serde_json::json!({
        "reliability": { "evidence_type_weights": { "Empirical": PERSPECTIVE_EMPIRICAL } }
    });
    let p = resolve(Some(&over), None);
    let alpha = effective_source_strength_profiled(&row("empirical", "cross"), &p);
    assert_eq!(alpha, FRAME_EMPIRICAL * p.reliability.cross_locality_factor);
}
