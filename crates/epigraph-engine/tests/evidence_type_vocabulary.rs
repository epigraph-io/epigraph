//! `edge_factor::is_known_evidence_type_key` — the engine's evidence-type
//! vocabulary check, made public so MCP write tools can report an unknown key
//! to the caller instead of only logging it (backlog 86ee2d30, G12).
//!
//! The check is only worth exposing if its verdict is TRUE of the combine, so
//! the second test cross-checks it against `effective_source_strength`: every
//! key it calls unknown really does fall through to the 0.5 unknown-type weight
//! on a BBA with no stored `source_strength` (the shape `submit_ds_evidence`
//! writes), and every calibrated key it calls known really gets its weight.

use chrono::Utc;
use epigraph_db::MassFunctionRow;
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::{effective_source_strength, is_known_evidence_type_key};
use uuid::Uuid;

fn cfg() -> CalibrationConfig {
    CalibrationConfig::from_workspace_root().expect("calibration.toml should load")
}

fn bba(evidence_type: &str) -> MassFunctionRow {
    MassFunctionRow {
        id: Uuid::new_v4(),
        claim_id: Uuid::new_v4(),
        frame_id: Uuid::new_v4(),
        source_agent_id: None,
        perspective_id: None,
        masses: serde_json::json!({"0": 0.5, "0,1": 0.5}),
        conflict_k: None,
        combination_method: None,
        source_strength: None,
        evidence_type: Some(evidence_type.to_string()),
        locality_tag: "unknown".to_string(),
        evidence_id: None,
        created_at: Utc::now(),
    }
}

#[test]
fn the_vocabulary_is_calibration_keys_aliases_and_relationship_names() {
    let c = cfg();
    for known in [
        "empirical",
        "Empirical",
        "testimonial",
        "observation",
        "supports",
        "refutes",
        "derived_support",
    ] {
        assert!(
            is_known_evidence_type_key(known, &c),
            "{known} should be known"
        );
    }
    for unknown in ["anecdote", "western_clinical", "", "empirical "] {
        assert!(
            !is_known_evidence_type_key(unknown, &c),
            "{unknown:?} should be unknown"
        );
    }
}

#[test]
fn an_unknown_verdict_means_the_combine_uses_the_unknown_type_weight() {
    let c = cfg();
    for key in ["anecdote", "western_clinical", "made_up"] {
        assert!(!is_known_evidence_type_key(key, &c));
        let w = effective_source_strength(&bba(key), None, None, &c);
        assert!(
            (w - 0.5).abs() < 1e-12,
            "{key}: called unknown but the combine gave it {w}, not the 0.5 fallback"
        );
    }
    for key in c.evidence_type_weights.keys() {
        assert!(is_known_evidence_type_key(key, &c), "{key}");
        let w = effective_source_strength(&bba(key), None, None, &c);
        let want = c.get_evidence_type_weight(key);
        assert!(
            (w - want).abs() < 1e-12,
            "{key}: called known but the combine gave {w}, not its calibrated {want}"
        );
    }
}
