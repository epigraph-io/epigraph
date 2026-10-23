//! Belief profile hash: BLAKE3 over the RESOLVED parameters.
//!
//! Property: the hash changes when any resolved parameter changes, and does
//! not change otherwise. "Any parameter" is not a hand-kept list here: the
//! test walks every leaf of the profile's serialized form (every scalar, every
//! enum, every map entry and every array element), perturbs that one leaf,
//! rebuilds a profile from it, and demands a different hash. A parameter
//! added later is covered without touching this file.
//!
//! "Not otherwise" covers what must NOT move the hash: re-resolving from the
//! same inputs, map inputs inserted in a different order, an override that
//! restates current values, a serialization round trip, and `-0.0` for `0.0`.

#[path = "support/belief_fixtures.rs"]
mod fixtures;

use std::collections::HashMap;

use epigraph_engine::belief_profile::{BeliefProfile, FrameTier, PerspectiveTier};
use epigraph_engine::edge_factor::PerspectiveReliability;
use serde_json::{json, Value};

/// A profile with every map populated: the global tables from the workspace
/// calibration plus non-empty frame and perspective reliability maps, so the
/// walk below has entries in every map to perturb.
fn populated(order_reversed: bool) -> BeliefProfile {
    let mut weights: Vec<(&str, f64)> = vec![("empirical", 0.4), ("logical", 0.9), ("zeta", 0.2)];
    let mut src: Vec<(&str, f64)> = vec![("testimony", 0.9), ("mystery_type", 0.35)];
    let mut loc: Vec<(&str, f64)> = vec![("cross", 0.6), ("intra_self_cite", 0.15)];
    if order_reversed {
        weights.reverse();
        src.reverse();
        loc.reverse();
    }
    let weights: HashMap<String, f64> = weights.into_iter().map(|(k, v)| (k.into(), v)).collect();
    let persp = PerspectiveReliability {
        source_reliability: src.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        locality_reliability: loc.into_iter().map(|(k, v)| (k.into(), v)).collect(),
    };
    BeliefProfile::from_calibration(&fixtures::golden_calibration()).resolve(
        FrameTier {
            overrides: None,
            intra_evidence_locality_factor: Some(0.45),
            evidence_type_weights: Some(&weights),
        },
        PerspectiveTier {
            overrides: None,
            reliability: Some(&persp),
        },
    )
}

fn hash_of(v: &Value) -> Option<String> {
    serde_json::from_value::<BeliefProfile>(v.clone())
        .ok()
        .map(|p| p.profile_hash())
}

/// Every leaf path of a JSON value, as a list of steps.
#[derive(Clone, Debug)]
enum Step {
    Key(String),
    Index(usize),
}

fn leaves(v: &Value, path: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                path.push(Step::Key(k.clone()));
                leaves(child, path, out);
                path.pop();
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                path.push(Step::Index(i));
                leaves(child, path, out);
                path.pop();
            }
        }
        _ => out.push(path.clone()),
    }
}

fn objects(v: &Value, path: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
    if let Value::Object(m) = v {
        out.push(path.clone());
        for (k, child) in m {
            path.push(Step::Key(k.clone()));
            objects(child, path, out);
            path.pop();
        }
    }
}

fn at<'a>(v: &'a mut Value, path: &[Step]) -> &'a mut Value {
    path.iter().fold(v, |node, step| match step {
        Step::Key(k) => node.get_mut(k.as_str()).expect("path exists"),
        Step::Index(i) => node.get_mut(*i).expect("path exists"),
    })
}

/// Values a string leaf may take: every enum spelling the profile uses, plus
/// a free string for string-valued maps.
const STRING_CANDIDATES: &[&str] = &[
    "suppress",
    "ceiling",
    "class",
    "owner",
    "max_same_dempster_opposite",
    "dempster",
    "explicit",
    "model",
    "some_other_key",
];

/// Replacement candidates for one leaf, all different from the current value.
fn perturbations(leaf: &Value) -> Vec<Value> {
    match leaf {
        Value::Number(n) if n.is_u64() => vec![json!(n.as_u64().unwrap() + 1)],
        Value::Number(n) => {
            let x = n.as_f64().unwrap();
            let y = if x <= 0.5 { x + 0.0625 } else { x - 0.0625 };
            vec![json!(y)]
        }
        Value::String(s) => STRING_CANDIDATES
            .iter()
            .filter(|c| **c != s.as_str())
            .map(|c| json!(c))
            .chain(std::iter::once(json!({ "weight": 0.5 })))
            .collect(),
        Value::Bool(b) => vec![json!(!b)],
        Value::Null => vec![],
        _ => unreachable!("leaves are scalars"),
    }
}

#[test]
fn changing_any_single_resolved_parameter_changes_the_hash() {
    let base = populated(false);
    let base_value = serde_json::to_value(&base).unwrap();
    let base_hash = base.profile_hash();
    assert_eq!(hash_of(&base_value).as_deref(), Some(base_hash.as_str()));

    let mut paths = Vec::new();
    leaves(&base_value, &mut Vec::new(), &mut paths);
    // Non-vacuity: the populated profile carries the calibration tables and
    // the lens maps, so there are far more leaves than top-level groups.
    assert!(paths.len() > 100, "only {} leaves walked", paths.len());

    let mut unperturbable = Vec::new();
    for path in &paths {
        let leaf = at(&mut base_value.clone(), path).clone();
        let mut moved = false;
        for candidate in perturbations(&leaf) {
            let mut v = base_value.clone();
            *at(&mut v, path) = candidate;
            if let Some(h) = hash_of(&v) {
                assert_ne!(h, base_hash, "changing {path:?} must change the hash");
                moved = true;
                break;
            }
        }
        if !moved {
            unperturbable.push(path.clone());
        }
    }
    assert!(
        unperturbable.is_empty(),
        "no valid perturbation found for {unperturbable:?}: the walk cannot vouch for them"
    );
}

#[test]
fn adding_or_removing_a_map_entry_changes_the_hash() {
    let base = populated(false);
    let base_value = serde_json::to_value(&base).unwrap();
    let base_hash = base.profile_hash();

    let mut objs = Vec::new();
    objects(&base_value, &mut Vec::new(), &mut objs);
    let mut maps_seen = 0;
    for path in &objs {
        // A map accepts a new key; a parameter struct rejects it
        // (unknown field). Only maps are exercised here.
        let node = at(&mut base_value.clone(), path).clone();
        let sample = node
            .as_object()
            .and_then(|m| m.values().next().cloned())
            .unwrap_or(json!(0.5));
        let mut v = base_value.clone();
        at(&mut v, path)
            .as_object_mut()
            .unwrap()
            .insert("zz_added_key".into(), sample);
        let Some(h) = hash_of(&v) else { continue };
        maps_seen += 1;
        assert_ne!(
            h, base_hash,
            "adding an entry to {path:?} must change the hash"
        );

        if let Some(first) = node.as_object().and_then(|m| m.keys().next().cloned()) {
            let mut v = base_value.clone();
            at(&mut v, path).as_object_mut().unwrap().remove(&first);
            let h = hash_of(&v).expect("a map minus an entry is still a profile");
            assert_ne!(
                h, base_hash,
                "removing {first} from {path:?} must change the hash"
            );
        }
    }
    // evidence-type weights + aliases, journal table, methodology profiles +
    // aliases, and the three lens maps.
    assert!(maps_seen >= 8, "only {maps_seen} maps exercised");
}

#[test]
fn the_hash_does_not_move_when_no_parameter_moves() {
    let a = populated(false);
    // Same inputs, resolved again.
    assert_eq!(a.profile_hash(), populated(false).profile_hash());
    // Same inputs, HashMap insertion order reversed.
    assert_eq!(a.profile_hash(), populated(true).profile_hash());
    // Serialization round trip.
    let round: BeliefProfile = serde_json::from_value(serde_json::to_value(&a).unwrap()).unwrap();
    assert_eq!(a.profile_hash(), round.profile_hash());
    // An override object that restates current values.
    let restated = json!({
        "reliability": {
            "unknown_evidence_type_weight": a.reliability.unknown_evidence_type_weight,
            "intra_evidence_locality_factor": a.reliability.intra_evidence_locality_factor,
        },
        "testimonial_ceiling": a.testimonial_ceiling,
        "testimonial_grouping": serde_json::to_value(a.testimonial_grouping).unwrap(),
    });
    let same = a.resolve(
        FrameTier::default(),
        PerspectiveTier {
            overrides: Some(&restated),
            reliability: None,
        },
    );
    assert_eq!(a.profile_hash(), same.profile_hash());
    // -0.0 is the same parameter value as 0.0.
    let mut v = serde_json::to_value(&a).unwrap();
    assert_eq!(v["necessity"]["default_strength"], json!(0.0));
    v["necessity"]["default_strength"] = json!(-0.0);
    assert_eq!(hash_of(&v).unwrap(), a.profile_hash());
}

#[test]
fn the_hash_is_a_blake3_hex_digest_and_differs_between_distinct_profiles() {
    let builtin = BeliefProfile::builtin();
    let h = builtin.profile_hash();
    assert_eq!(h.len(), 64);
    assert!(h
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    // The built-in table carries no calibration tables; the calibrated
    // profile does, so their hashes must differ.
    assert_ne!(h, populated(false).profile_hash());
}
