//! Guard: the extraction evidence-type vocabulary must stay a subset of the
//! calibration `[evidence_type_weights]` keys.
//!
//! `effective_source_strength` and the per-perspective frame function both
//! resolve a BBA's `evidence_type` through `calibration.toml`; a tag outside
//! the calibrated vocabulary silently hits the 0.5 unknown-key fallback. The
//! ingest crate hardcodes its set (it has no calibration dependency), so this
//! test — in a crate that depends on both — is what stops the two from
//! drifting apart.

use epigraph_engine::calibration::CalibrationConfig;
use epigraph_ingest::common::evidence_type::EVIDENCE_TYPES;

#[test]
fn extraction_vocabulary_is_a_calibration_subset() {
    let calibration =
        CalibrationConfig::from_workspace_root().expect("load workspace calibration.toml");

    for &etype in EVIDENCE_TYPES {
        assert!(
            calibration.evidence_type_weight_present(etype),
            "evidence type {etype:?} is in EVIDENCE_TYPES but missing from \
             calibration.toml [evidence_type_weights] — it would hit the 0.5 \
             unknown-key fallback. Add it to calibration or remove it from the set."
        );
    }
}
