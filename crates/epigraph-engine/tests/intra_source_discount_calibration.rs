//! Calibration canary — trips if the locality-discount factor is moved
//! without re-tuning the 19-supporter regression. This is intentionally
//! adversarial: a future PR that adjusts the calibration must update the
//! regression test together, and this canary fails fast if only one side
//! changes.

use epigraph_engine::calibration::CalibrationConfig;

#[test]
fn intra_evidence_locality_factor_in_documented_band() {
    let config = CalibrationConfig::from_workspace_root().expect("calibration.toml should load");
    let factor = config.evidence_locality.intra_evidence_locality_factor;
    assert!(
        (0.15..=0.45).contains(&factor),
        "intra_evidence_locality_factor out of documented band [0.15, 0.45]: got {factor}. \
         If you intend to retune, update intra_source_19_supporters_betp_in_band as well."
    );
}
