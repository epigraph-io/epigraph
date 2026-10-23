//! Shared, DB-free belief-fold fixtures for the belief-profile tests.
//!
//! Every case is a set of stored BBA rows on the binary frame plus the lens
//! inputs a framed read resolves (per-frame intra factor, per-frame
//! evidence-type weights, optional perspective reliability maps). Together the
//! cases walk every tier of the per-BBA reliability chain: NULL type with and
//! without a stored strength, an alias, a calibrated key, an uncalibrated key
//! with and without a stored strength, intra and cross locality, a per-frame
//! strict-key override, an empty and a partial perspective, an upper-case
//! locality tag, same-source repeats, open-world (`~`) mass and a single row.
//!
//! [`legacy_fold`] folds a case with the public functions the framed read
//! composed before the belief profile existed, so the golden values recorded
//! from it pin the pre-profile behaviour.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{TimeZone, Utc};
use epigraph_db::MassFunctionRow;
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::{
    effective_source_strength, effective_source_strength_with_perspective, PerspectiveReliability,
};
use epigraph_engine::source_dependence::SourceKey;
use uuid::Uuid;

/// The binary frame every fixture row lives on.
pub fn frame() -> FrameOfDiscernment {
    FrameOfDiscernment::new("binary_truth", vec!["TRUE".into(), "FALSE".into()]).unwrap()
}

/// Shape of one stored BBA: masses on {T}, {F}, open-world `~`; the rest is Θ.
#[derive(Clone, Copy)]
pub struct Shape {
    pub t: f64,
    pub f: f64,
    pub ow: f64,
}

pub const fn shape(t: f64, f: f64, ow: f64) -> Shape {
    Shape { t, f, ow }
}

/// One stored BBA row of a fixture.
pub struct RowSpec {
    pub evidence_type: Option<&'static str>,
    pub locality_tag: &'static str,
    pub source_strength: Option<f64>,
    pub shape: Shape,
    /// `(agent seed, source_url)`; `None` = no source identity (independent).
    pub source: Option<(u8, &'static str)>,
}

const fn r(
    evidence_type: Option<&'static str>,
    locality_tag: &'static str,
    source_strength: Option<f64>,
    shape: Shape,
    source: Option<(u8, &'static str)>,
) -> RowSpec {
    RowSpec {
        evidence_type,
        locality_tag,
        source_strength,
        shape,
        source,
    }
}

/// A perspective's `(source_reliability, locality_reliability)` entries.
pub type ReliabilityMaps = (Vec<(&'static str, f64)>, Vec<(&'static str, f64)>);

/// One fold fixture: rows plus the lens inputs.
pub struct Case {
    pub name: &'static str,
    pub rows: Vec<RowSpec>,
    pub per_frame_intra: Option<f64>,
    pub per_frame_weights: Option<Vec<(&'static str, f64)>>,
    /// `Some` = a lensed read under a perspective with these maps
    /// (`source_reliability`, `locality_reliability`).
    pub perspective: Option<ReliabilityMaps>,
}

fn tier_rows() -> Vec<RowSpec> {
    vec![
        r(
            Some("empirical"),
            "intra_self_cite",
            Some(1.0),
            shape(0.8, 0.0, 0.0),
            None,
        ),
        r(Some("logical"), "cross", None, shape(0.6, 0.0, 0.0), None),
        r(
            Some("testimony"),
            "unknown",
            Some(0.6),
            shape(0.0, 0.5, 0.0),
            None,
        ),
        r(None, "unknown", Some(0.7), shape(0.4, 0.0, 0.0), None),
        r(None, "unknown", None, shape(0.3, 0.0, 0.0), None),
        r(
            Some("CORROBORATES"),
            "cross",
            Some(0.65),
            shape(0.5, 0.0, 0.0),
            None,
        ),
        r(
            Some("mystery_type"),
            "unknown",
            None,
            shape(0.0, 0.2, 0.0),
            None,
        ),
        r(
            Some("supports"),
            "intra_methodological_overlap",
            Some(0.7),
            shape(0.55, 0.05, 0.0),
            None,
        ),
    ]
}

/// Every fold fixture.
pub fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "tier_mix_global",
            rows: tier_rows(),
            per_frame_intra: None,
            per_frame_weights: None,
            perspective: None,
        },
        Case {
            name: "tier_mix_per_frame",
            rows: tier_rows(),
            per_frame_intra: Some(0.5),
            per_frame_weights: Some(vec![("empirical", 0.4), ("logical", 0.9)]),
            perspective: None,
        },
        Case {
            name: "tier_mix_perspective_partial",
            rows: tier_rows(),
            per_frame_intra: Some(0.45),
            per_frame_weights: Some(vec![("logical", 0.9)]),
            perspective: Some((
                vec![("testimony", 0.9), ("mystery_type", 0.35)],
                vec![("cross", 0.6)],
            )),
        },
        Case {
            name: "tier_mix_perspective_empty",
            rows: tier_rows(),
            per_frame_intra: None,
            per_frame_weights: None,
            perspective: Some((vec![], vec![])),
        },
        Case {
            name: "upper_case_locality",
            rows: vec![
                r(
                    Some("empirical"),
                    "INTRA_SELF_CITE",
                    None,
                    shape(0.7, 0.0, 0.0),
                    None,
                ),
                r(
                    Some("logical"),
                    "Intra_self_cite",
                    None,
                    shape(0.0, 0.4, 0.0),
                    None,
                ),
            ],
            per_frame_intra: None,
            per_frame_weights: None,
            perspective: Some((vec![("empirical", 0.8)], vec![])),
        },
        Case {
            name: "same_source_repeats",
            rows: vec![
                r(
                    Some("empirical"),
                    "cross",
                    None,
                    shape(0.6, 0.0, 0.0),
                    Some((1, "https://example.org/a")),
                ),
                r(
                    Some("empirical"),
                    "cross",
                    None,
                    shape(0.7, 0.0, 0.0),
                    Some((1, "https://example.org/a")),
                ),
                r(
                    Some("empirical"),
                    "cross",
                    None,
                    shape(0.0, 0.4, 0.0),
                    Some((1, "https://example.org/a")),
                ),
                r(Some("logical"), "cross", None, shape(0.5, 0.0, 0.0), None),
                r(
                    Some("statistical"),
                    "cross",
                    None,
                    shape(0.45, 0.0, 0.0),
                    Some((2, "https://example.org/b")),
                ),
            ],
            per_frame_intra: None,
            per_frame_weights: None,
            perspective: None,
        },
        Case {
            name: "open_world",
            rows: vec![
                r(Some("empirical"), "cross", None, shape(0.5, 0.0, 0.3), None),
                r(
                    Some("logical"),
                    "intra_self_cite",
                    None,
                    shape(0.0, 0.3, 0.1),
                    None,
                ),
                r(None, "unknown", None, shape(0.2, 0.1, 0.2), None),
            ],
            per_frame_intra: None,
            per_frame_weights: None,
            perspective: None,
        },
        Case {
            name: "single_row",
            rows: vec![r(
                Some("observation"),
                "cross",
                None,
                shape(0.5, 0.0, 0.0),
                None,
            )],
            per_frame_intra: None,
            per_frame_weights: None,
            perspective: None,
        },
    ]
}

/// Deterministic agent id for a source seed.
pub fn agent(seed: u8) -> Uuid {
    Uuid::from_bytes([seed; 16])
}

/// The masses of one row as a stored JSON value.
pub fn masses(s: Shape) -> serde_json::Value {
    let fr = frame();
    let mut m = BTreeMap::new();
    if s.t > 0.0 {
        m.insert(FocalElement::positive(BTreeSet::from([0])), s.t);
    }
    if s.f > 0.0 {
        m.insert(FocalElement::positive(BTreeSet::from([1])), s.f);
    }
    if s.ow > 0.0 {
        m.insert(FocalElement::missing(&fr), s.ow);
    }
    let theta = 1.0 - s.t - s.f - s.ow;
    if theta > 0.0 {
        m.insert(FocalElement::theta(&fr), theta);
    }
    MassFunction::new(fr, m).unwrap().masses_to_json()
}

/// The stored rows of a case, with deterministic ids.
pub fn rows(case: &Case) -> Vec<MassFunctionRow> {
    case.rows
        .iter()
        .enumerate()
        .map(|(i, spec)| MassFunctionRow {
            id: Uuid::from_u128(i as u128 + 1),
            claim_id: Uuid::from_u128(0xC1A1),
            frame_id: Uuid::from_u128(0xF4A3),
            source_agent_id: spec.source.map(|(seed, _)| agent(seed)),
            perspective_id: None,
            masses: masses(spec.shape),
            conflict_k: None,
            combination_method: Some("fixture".to_string()),
            source_strength: spec.source_strength,
            evidence_type: spec.evidence_type.map(String::from),
            locality_tag: spec.locality_tag.to_string(),
            evidence_id: None,
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        })
        .collect()
}

/// The source keys of a case, one per row.
pub fn source_keys(case: &Case) -> Vec<Option<SourceKey>> {
    case.rows
        .iter()
        .map(|spec| {
            spec.source.map(|(seed, url)| SourceKey {
                agent_id: agent(seed),
                source_url: url.to_string(),
            })
        })
        .collect()
}

pub fn per_frame_weights(case: &Case) -> Option<HashMap<String, f64>> {
    case.per_frame_weights
        .as_ref()
        .map(|v| v.iter().map(|(k, w)| ((*k).to_string(), *w)).collect())
}

pub fn perspective(case: &Case) -> Option<PerspectiveReliability> {
    case.perspective
        .as_ref()
        .map(|(src, loc)| PerspectiveReliability {
            source_reliability: src.iter().map(|(k, w)| ((*k).to_string(), *w)).collect(),
            locality_reliability: loc.iter().map(|(k, w)| ((*k).to_string(), *w)).collect(),
        })
}

/// The observable outputs of one fold, as exact bit patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldBits {
    pub alphas: Vec<u64>,
    pub bel: u64,
    pub pl: u64,
    pub betp: u64,
    pub conflict: u64,
    pub missing: u64,
}

/// Bits of a combined mass function and its fold conflict, read on TRUE.
pub fn bits_of(alphas: &[f64], combined: &MassFunction, conflict: f64) -> FoldBits {
    let target = FocalElement::positive(BTreeSet::from([0]));
    FoldBits {
        alphas: alphas.iter().map(|a| a.to_bits()).collect(),
        bel: measures::belief(combined, &target).to_bits(),
        pl: measures::plausibility(combined, &target).to_bits(),
        betp: measures::pignistic_probability(combined, 0).to_bits(),
        conflict: conflict.to_bits(),
        missing: combined.mass_of_missing().to_bits(),
    }
}

/// Fold a case the way the framed read composed it before the belief profile:
/// per-row reliability from the calibration-taking functions, Shafer discount,
/// then the source-dependence fold with its conflict threshold.
pub fn legacy_fold(case: &Case, cal: &CalibrationConfig) -> FoldBits {
    let fr = frame();
    let rows = rows(case);
    let pfw = per_frame_weights(case);
    let persp = perspective(case);
    let mut alphas = Vec::new();
    let mut items = Vec::new();
    for (row, key) in rows.iter().zip(source_keys(case)) {
        let mf = MassFunction::from_json_masses(fr.clone(), &row.masses).unwrap();
        let alpha = match persp.as_ref() {
            Some(p) => effective_source_strength_with_perspective(
                row,
                case.per_frame_intra,
                pfw.as_ref(),
                cal,
                p,
            ),
            None => effective_source_strength(row, case.per_frame_intra, pfw.as_ref(), cal),
        };
        alphas.push(alpha);
        items.push((key, combination::discount(&mf, alpha).unwrap()));
    }
    let (combined, conflict) =
        epigraph_engine::source_dependence::combine_with_source_dependence(items, 0.9).unwrap();
    bits_of(&alphas, &combined, conflict)
}

/// `calibration.toml` as it stood on the commit the belief-profile work
/// started from, snapshotted beside this file. The golden fold values were
/// recorded under it, so they pin the CODE, not whatever the workspace
/// calibration holds today: a later calibration tune, or an active
/// `[belief_profiles]` table in the workspace file, cannot turn them red.
pub fn golden_calibration() -> CalibrationConfig {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/golden_calibration.toml");
    CalibrationConfig::load(&path).expect("the golden calibration snapshot loads")
}

/// The golden calibration snapshot's text, for tests that append a TOML table.
pub fn golden_calibration_text() -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/support/golden_calibration.toml"),
    )
    .expect("the golden calibration snapshot reads")
}
