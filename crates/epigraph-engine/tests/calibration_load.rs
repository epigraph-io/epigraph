use epigraph_engine::matching::calibration::MatcherConfig;

#[test]
fn loads_weights_and_bands_from_default_calibration_toml() {
    // The default path is relative; tests run from crate root, but the
    // calibration.toml is at workspace root. Use a workspace-relative path.
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration.toml");
    let cfg = MatcherConfig::load_from(&p).expect("load calibration.toml");
    assert!((cfg.weights.embed_cosine - 0.40).abs() < 1e-6);
    assert!((cfg.bands.high - 0.85).abs() < 1e-6);
    assert!((cfg.bands.mid - 0.60).abs() < 1e-6);
    assert_eq!(cfg.embedding.model_version, "v1");
    assert!(!cfg.filter.include_agent_id);
    assert_eq!(cfg.fan_out.max_per_claim, 32);
}
