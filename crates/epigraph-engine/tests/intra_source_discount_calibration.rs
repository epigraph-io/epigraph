//! Calibration canary — trips if the locality-discount defaults are moved
//! without re-tuning the 19-supporter regression. This is intentionally
//! adversarial: a future PR that adjusts the calibration must update the
//! regression test together, and this canary fails fast if only one side
//! changes.

use epigraph_engine::calibration::CalibrationConfig;

#[test]
fn intra_source_strength_in_documented_band() {
    let config = CalibrationConfig::from_workspace_root().expect("calibration.toml should load");
    let intra = config.evidence_locality.intra_source_support_strength;
    assert!(
        (0.15..=0.45).contains(&intra),
        "intra_source_support_strength out of documented band [0.15, 0.45]: got {intra}. \
         If you intend to retune, update intra_source_19_supporters_betp_in_band as well."
    );
}

#[test]
fn cross_source_strength_is_one() {
    let config = CalibrationConfig::from_workspace_root().expect("calibration.toml should load");
    let cross = config.evidence_locality.cross_source_support_strength;
    assert!(
        (cross - 1.0).abs() < 1e-9,
        "cross_source_support_strength must remain 1.0 (got {cross}); \
         lowering it changes baseline BetP across the entire graph."
    );
}
