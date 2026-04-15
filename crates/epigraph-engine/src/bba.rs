//! BBA (Basic Belief Assignment) directed builder.
//!
//! Ports `build_bba_directed()` from `scripts/lib/cdst_bba.py` to Rust.
//! Produces SciFact-calibrated mass functions over the binary frame
//! `["supported", "unsupported"]` with optional open-world mass.

use crate::calibration::CalibrationConfig;
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use std::collections::{BTreeMap, BTreeSet};

// ── Parameters ─────────────────────────────────────────────────────────────

/// Parameters for building a directed BBA.
#[derive(Debug, Clone)]
pub struct BbaParams {
    /// Evidence type key (e.g. "empirical", "statistical").
    pub evidence_type: String,
    /// Methodology key (e.g. "instrumental", "deductive_logic").
    pub methodology: String,
    /// Extraction/evidence confidence in [0, 1].
    pub confidence: f64,
    /// True if evidence supports the claim, false if it contradicts.
    pub supports: bool,
    /// Optional section tier for discount (e.g. "results", "methods").
    pub section_tier: Option<String>,
    /// Optional journal reliability in [0, 1].
    pub journal_reliability: Option<f64>,
    /// Fraction of total mass allocated to open-world ignorance, in [0, 0.5].
    pub open_world_fraction: f64,
    /// Optional parsed uncertainty from error bars in [0, 1].
    /// 0 = precise, 1 = total ignorance. None = no discount.
    pub uncertainty: Option<f64>,
}

impl Default for BbaParams {
    fn default() -> Self {
        Self {
            evidence_type: "circumstantial".to_string(),
            methodology: "extraction".to_string(),
            confidence: 0.5,
            supports: true,
            section_tier: None,
            journal_reliability: None,
            open_world_fraction: 0.0,
            uncertainty: None,
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

/// Errors from BBA construction.
#[derive(Debug, thiserror::Error)]
pub enum BbaError {
    #[error("confidence must be in [0, 1], got {0}")]
    InvalidConfidence(f64),

    #[error("open_world_fraction must be in [0, 0.5], got {0}")]
    InvalidOpenWorld(f64),

    #[error("DS error: {0}")]
    DsError(String),
}

// ── Builder ────────────────────────────────────────────────────────────────

/// Build a directed BBA using SciFact-calibrated methodology profiles.
///
/// Returns masses over frame `["supported", "unsupported"]` with optional
/// open-world mass. The algorithm matches `build_bba_directed()` in
/// `scripts/lib/cdst_bba.py` exactly.
///
/// # Errors
/// - [`BbaError::InvalidConfidence`] if confidence is outside [0, 1]
/// - [`BbaError::InvalidOpenWorld`] if open_world_fraction is outside [0, 0.5]
/// - [`BbaError::DsError`] if the resulting mass function fails validation
pub fn build_bba_directed(
    params: &BbaParams,
    config: &CalibrationConfig,
) -> Result<MassFunction, BbaError> {
    // 1. Validate inputs
    if !(0.0..=1.0).contains(&params.confidence) {
        return Err(BbaError::InvalidConfidence(params.confidence));
    }
    if !(0.0..=0.5).contains(&params.open_world_fraction) {
        return Err(BbaError::InvalidOpenWorld(params.open_world_fraction));
    }

    let confidence = params.confidence.clamp(0.0, 1.0);
    let open_world_fraction = params.open_world_fraction.clamp(0.0, 0.5);

    // 2. Load methodology profile
    let (base_support, base_against, _base_ignorance) =
        config.get_methodology_profile(&params.methodology);

    // 3. Load evidence type weight
    let type_weight = config.get_evidence_type_weight(&params.evidence_type);

    // 4. Compute directed masses
    let (mut m_sup, mut m_against) = if params.supports {
        (
            (base_support * type_weight * confidence).min(0.95),
            (base_against * (1.0 - confidence * 0.5)).min(0.3),
        )
    } else {
        (
            (base_against * (1.0 - confidence * 0.5)).min(0.3),
            (base_support * type_weight * confidence).min(0.95),
        )
    };

    // 5. Compute theta (closed-world ignorance)
    let mut m_theta = (1.0 - m_sup - m_against).max(0.0);

    // 6. Section tier discount: shift fraction of PRIMARY informative mass to theta
    if let Some(ref section) = params.section_tier {
        let retention = config.get_section_tier_weight(section);
        if retention < 1.0 {
            if params.supports {
                let shift = m_sup * (1.0 - retention);
                m_sup -= shift;
                m_theta += shift;
            } else {
                let shift = m_against * (1.0 - retention);
                m_against -= shift;
                m_theta += shift;
            }
        }
    }

    // 7. Journal reliability discount
    if let Some(reliability) = params.journal_reliability {
        if reliability < 1.0 {
            let unreliable = 1.0 - reliability;
            if params.supports {
                let shift = m_sup * unreliable;
                m_sup -= shift;
                m_theta += shift;
            } else {
                let shift = m_against * unreliable;
                m_against -= shift;
                m_theta += shift;
            }
        }
    }

    // 8. Uncertainty discount
    if let Some(uncertainty) = params.uncertainty {
        let unc = uncertainty.clamp(0.0, 1.0);
        if params.supports {
            let shift = m_sup * unc;
            m_sup -= shift;
            m_theta += shift;
        } else {
            let shift = m_against * unc;
            m_against -= shift;
            m_theta += shift;
        }
    }

    // 9. Normalize for open world
    let total = m_sup + m_against + m_theta;
    let total = if total <= 0.0 { 1.0 } else { total };

    let closed_scale = if open_world_fraction > 0.0 {
        (1.0 - open_world_fraction) / total
    } else {
        1.0 / total
    };

    m_sup *= closed_scale;
    m_against *= closed_scale;
    m_theta *= closed_scale;

    // 10. Open-world mass
    let m_open = if open_world_fraction > 0.0 {
        open_world_fraction
    } else {
        0.0
    };

    // 11. Fix floating-point drift: adjust largest mass so sum = 1.0 exactly
    //     Collect into a vec to find + fix the largest entry.
    let epsilon = 1e-10;
    let mut entries: Vec<(&str, f64)> = Vec::with_capacity(4);
    if m_sup > epsilon {
        entries.push(("sup", m_sup));
    }
    if m_against > epsilon {
        entries.push(("against", m_against));
    }
    if m_theta > epsilon {
        entries.push(("theta", m_theta));
    }
    if m_open > epsilon {
        entries.push(("open", m_open));
    }

    let sum: f64 = entries.iter().map(|(_, v)| v).sum();
    if !entries.is_empty() && (sum - 1.0).abs() > 1e-15 {
        // Find the largest mass and adjust it
        let max_idx = entries
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.1.partial_cmp(&b.1).unwrap())
            .map(|(i, _)| i)
            .unwrap();
        entries[max_idx].1 += 1.0 - sum;
    }

    // Unpack back
    for &(label, val) in &entries {
        match label {
            "sup" => m_sup = val,
            "against" => m_against = val,
            "theta" => m_theta = val,
            "open" => {
                // m_open is handled below via entries
                let _ = val;
            }
            _ => {}
        }
    }
    // Re-read m_open from entries if present
    let m_open = entries
        .iter()
        .find(|(l, _)| *l == "open")
        .map_or(0.0, |(_, v)| *v);

    // 12. Build frame: ["supported", "unsupported"]
    let frame = FrameOfDiscernment::new(
        "claim_support",
        vec!["supported".into(), "unsupported".into()],
    )
    .map_err(|e| BbaError::DsError(e.to_string()))?;

    // 13. Build focal element map
    let mut masses: BTreeMap<FocalElement, f64> = BTreeMap::new();

    if m_sup > epsilon {
        // {0} = supported
        masses.insert(FocalElement::positive(BTreeSet::from([0])), m_sup);
    }
    if m_against > epsilon {
        // {1} = unsupported
        masses.insert(FocalElement::positive(BTreeSet::from([1])), m_against);
    }
    if m_theta > epsilon {
        // {0,1} = theta (closed-world ignorance)
        masses.insert(FocalElement::theta(&frame), m_theta);
    }
    if m_open > epsilon {
        // (~, empty) = open-world vacuous = (empty, complement=true)
        masses.insert(FocalElement::vacuous(), m_open);
    }

    // 14. Construct validated MassFunction
    MassFunction::new(frame, masses).map_err(|e| BbaError::DsError(e.to_string()))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn calibration_path() -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("calibration.toml")
    }

    fn load_config() -> CalibrationConfig {
        CalibrationConfig::load(&calibration_path())
            .expect("calibration.toml should load successfully")
    }

    /// Helper: sum all masses in a MassFunction.
    fn mass_sum(mf: &MassFunction) -> f64 {
        mf.masses().values().sum()
    }

    /// Helper: get mass for a specific focal element key string.
    fn get_mass(mf: &MassFunction, key: &str) -> f64 {
        use epigraph_ds::focal_serde::focal_to_key;
        for (fe, &m) in mf.masses() {
            if focal_to_key(fe) == key {
                return m;
            }
        }
        0.0
    }

    // ── Basic supporting evidence ──────────────────────────────────────

    #[test]
    fn test_basic_supporting_evidence() {
        let cfg = load_config();
        let params = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "instrumental".into(),
            confidence: 0.9,
            supports: true,
            ..Default::default()
        };
        let mf = build_bba_directed(&params, &cfg).unwrap();

        let m_sup = get_mass(&mf, "0");
        let m_against = get_mass(&mf, "1");
        let m_theta = get_mass(&mf, "0,1");

        // Supported mass should be dominant
        assert!(m_sup > 0.5, "m_sup should be > 0.5, got {m_sup}");
        assert!(m_sup > m_against, "m_sup should exceed m_against");
        assert!(m_theta > 0.0, "theta should be non-zero");
        assert!((mass_sum(&mf) - 1.0).abs() < 1e-9, "masses must sum to 1.0");
    }

    // ── Contradicting evidence ─────────────────────────────────────────

    #[test]
    fn test_contradicting_evidence() {
        let cfg = load_config();
        let params = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "instrumental".into(),
            confidence: 0.9,
            supports: false,
            ..Default::default()
        };
        let mf = build_bba_directed(&params, &cfg).unwrap();

        let m_sup = get_mass(&mf, "0");
        let m_against = get_mass(&mf, "1");

        // Against mass should be dominant when !supports
        assert!(
            m_against > 0.5,
            "m_against should be > 0.5, got {m_against}"
        );
        assert!(m_against > m_sup, "m_against should exceed m_sup");
        assert!((mass_sum(&mf) - 1.0).abs() < 1e-9);
    }

    // ── All discounts applied ──────────────────────────────────────────

    #[test]
    fn test_all_discounts_shift_to_theta() {
        let cfg = load_config();

        // Without discounts
        let params_base = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "instrumental".into(),
            confidence: 0.9,
            supports: true,
            ..Default::default()
        };
        let mf_base = build_bba_directed(&params_base, &cfg).unwrap();
        let theta_base = get_mass(&mf_base, "0,1");

        // With all discounts
        let params_disc = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "instrumental".into(),
            confidence: 0.9,
            supports: true,
            section_tier: Some("introduction".into()), // 0.50 retention
            journal_reliability: Some(0.70),
            uncertainty: Some(0.3),
            ..Default::default()
        };
        let mf_disc = build_bba_directed(&params_disc, &cfg).unwrap();
        let theta_disc = get_mass(&mf_disc, "0,1");

        // Discounted theta should be larger (mass shifted from m_sup)
        assert!(
            theta_disc > theta_base,
            "discounts should shift mass to theta: {theta_disc} vs {theta_base}"
        );
        assert!((mass_sum(&mf_disc) - 1.0).abs() < 1e-9);
    }

    // ── Open world fraction ────────────────────────────────────────────

    #[test]
    fn test_open_world_fraction() {
        let cfg = load_config();
        let params = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "instrumental".into(),
            confidence: 0.9,
            supports: true,
            open_world_fraction: 0.05,
            ..Default::default()
        };
        let mf = build_bba_directed(&params, &cfg).unwrap();

        let m_open = get_mass(&mf, "~");
        assert!(
            (m_open - 0.05).abs() < 0.01,
            "open-world mass should be ~0.05, got {m_open}"
        );
        assert!((mass_sum(&mf) - 1.0).abs() < 1e-9, "sum must be 1.0");
    }

    // ── Edge case: confidence = 0 ─────────────────────────────────────

    #[test]
    fn test_confidence_zero_all_to_theta() {
        let cfg = load_config();
        let params = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "instrumental".into(),
            confidence: 0.0,
            supports: true,
            ..Default::default()
        };
        let mf = build_bba_directed(&params, &cfg).unwrap();

        let m_sup = get_mass(&mf, "0");
        let m_theta = get_mass(&mf, "0,1");

        // With confidence=0, m_sup should be 0 (base_support * type_weight * 0)
        assert!(
            m_sup < 1e-10,
            "m_sup should be ~0 with confidence=0, got {m_sup}"
        );
        // Most mass should be in theta (and small m_against from base_against * 1.0)
        assert!(
            m_theta > 0.5,
            "theta should dominate with confidence=0, got {m_theta}"
        );
        assert!((mass_sum(&mf) - 1.0).abs() < 1e-9);
    }

    // ── Edge case: confidence = 1 ─────────────────────────────────────

    #[test]
    fn test_confidence_one_max_informative() {
        let cfg = load_config();
        let params = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "deductive_logic".into(),
            confidence: 1.0,
            supports: true,
            ..Default::default()
        };
        let mf = build_bba_directed(&params, &cfg).unwrap();

        let m_sup = get_mass(&mf, "0");
        // deductive_logic base_support=0.85, empirical type_weight=1.0
        // m_sup = min(0.85 * 1.0 * 1.0, 0.95) = 0.85
        assert!(
            m_sup > 0.8,
            "m_sup should be high with confidence=1, got {m_sup}"
        );
        assert!((mass_sum(&mf) - 1.0).abs() < 1e-9);
    }

    // ── Sum = 1.0 for various inputs ──────────────────────────────────

    #[test]
    fn test_sum_one_various_inputs() {
        let cfg = load_config();

        let test_cases = vec![
            ("empirical", "instrumental", 0.5, true, 0.0),
            ("statistical", "bayesian_inference", 0.7, false, 0.03),
            ("testimonial", "expert_elicitation", 0.3, true, 0.10),
            ("circumstantial", "extraction", 1.0, false, 0.20),
            ("logical", "deductive_logic", 0.01, true, 0.0),
            ("conversational", "extraction", 0.99, true, 0.5),
        ];

        for (et, meth, conf, supports, owf) in test_cases {
            let params = BbaParams {
                evidence_type: et.into(),
                methodology: meth.into(),
                confidence: conf,
                supports,
                open_world_fraction: owf,
                ..Default::default()
            };
            let mf = build_bba_directed(&params, &cfg).unwrap();
            let s = mass_sum(&mf);
            assert!(
                (s - 1.0).abs() < 1e-9,
                "sum should be 1.0 for ({et}, {meth}, {conf}, {supports}, {owf}), got {s}"
            );
        }
    }

    // ── Validation errors ──────────────────────────────────────────────

    #[test]
    fn test_invalid_confidence() {
        let cfg = load_config();
        let params = BbaParams {
            confidence: 1.5,
            ..Default::default()
        };
        assert!(matches!(
            build_bba_directed(&params, &cfg),
            Err(BbaError::InvalidConfidence(_))
        ));

        let params = BbaParams {
            confidence: -0.1,
            ..Default::default()
        };
        assert!(matches!(
            build_bba_directed(&params, &cfg),
            Err(BbaError::InvalidConfidence(_))
        ));
    }

    #[test]
    fn test_invalid_open_world() {
        let cfg = load_config();
        let params = BbaParams {
            open_world_fraction: 0.6,
            ..Default::default()
        };
        assert!(matches!(
            build_bba_directed(&params, &cfg),
            Err(BbaError::InvalidOpenWorld(_))
        ));
    }

    // ── Cross-validate against Python outputs ──────────────────────────

    #[test]
    fn test_python_cross_validation_basic() {
        // Python: build_bba_directed("empirical", "instrumental", 0.9, True)
        // base_support=0.80, base_against=0.05, type_weight=1.0
        // m_sup = min(0.80 * 1.0 * 0.9, 0.95) = 0.72
        // m_against = min(0.05 * (1.0 - 0.9*0.5), 0.3) = min(0.05 * 0.55, 0.3) = 0.0275
        // m_theta = max(1.0 - 0.72 - 0.0275, 0.0) = 0.2525
        // total = 1.0, closed_scale = 1.0
        let cfg = load_config();
        let params = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "instrumental".into(),
            confidence: 0.9,
            supports: true,
            ..Default::default()
        };
        let mf = build_bba_directed(&params, &cfg).unwrap();

        let m_sup = get_mass(&mf, "0");
        let m_against = get_mass(&mf, "1");
        let m_theta = get_mass(&mf, "0,1");

        assert!(
            (m_sup - 0.72).abs() < 1e-9,
            "m_sup: expected 0.72, got {m_sup}"
        );
        assert!(
            (m_against - 0.0275).abs() < 1e-9,
            "m_against: expected 0.0275, got {m_against}"
        );
        assert!(
            (m_theta - 0.2525).abs() < 1e-9,
            "m_theta: expected 0.2525, got {m_theta}"
        );
    }

    #[test]
    fn test_python_cross_validation_with_discounts() {
        // Python: build_bba_directed("empirical", "instrumental", 0.9, True,
        //             section_tier="introduction", journal_reliability=0.88)
        // Step 4: m_sup=0.72, m_against=0.0275, m_theta=0.2525
        // Step 6: section=introduction, retention=0.50
        //   shift = 0.72 * 0.50 = 0.36
        //   m_sup = 0.72 - 0.36 = 0.36, m_theta = 0.2525 + 0.36 = 0.6125
        // Step 7: journal_reliability=0.88, unreliable=0.12
        //   shift = 0.36 * 0.12 = 0.0432
        //   m_sup = 0.36 - 0.0432 = 0.3168, m_theta = 0.6125 + 0.0432 = 0.6557
        // total = 0.3168 + 0.0275 + 0.6557 = 1.0
        let cfg = load_config();
        let params = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "instrumental".into(),
            confidence: 0.9,
            supports: true,
            section_tier: Some("introduction".into()),
            journal_reliability: Some(0.88),
            ..Default::default()
        };
        let mf = build_bba_directed(&params, &cfg).unwrap();

        let m_sup = get_mass(&mf, "0");
        let m_against = get_mass(&mf, "1");
        let m_theta = get_mass(&mf, "0,1");

        assert!(
            (m_sup - 0.3168).abs() < 1e-9,
            "m_sup: expected 0.3168, got {m_sup}"
        );
        assert!(
            (m_against - 0.0275).abs() < 1e-9,
            "m_against: expected 0.0275, got {m_against}"
        );
        assert!(
            (m_theta - 0.6557).abs() < 1e-9,
            "m_theta: expected 0.6557, got {m_theta}"
        );
    }

    #[test]
    fn test_python_cross_validation_open_world() {
        // Python: build_bba_directed("empirical", "instrumental", 0.9, True,
        //             open_world_fraction=0.03)
        // m_sup=0.72, m_against=0.0275, m_theta=0.2525, total=1.0
        // closed_scale = (1.0 - 0.03) / 1.0 = 0.97
        // m_sup = 0.72 * 0.97 = 0.6984
        // m_against = 0.0275 * 0.97 = 0.026675
        // m_theta = 0.2525 * 0.97 = 0.244925
        // m_open = 0.03
        let cfg = load_config();
        let params = BbaParams {
            evidence_type: "empirical".into(),
            methodology: "instrumental".into(),
            confidence: 0.9,
            supports: true,
            open_world_fraction: 0.03,
            ..Default::default()
        };
        let mf = build_bba_directed(&params, &cfg).unwrap();

        let m_sup = get_mass(&mf, "0");
        let m_against = get_mass(&mf, "1");
        let m_theta = get_mass(&mf, "0,1");
        let m_open = get_mass(&mf, "~");

        assert!(
            (m_sup - 0.6984).abs() < 1e-9,
            "m_sup: expected 0.6984, got {m_sup}"
        );
        assert!(
            (m_against - 0.026675).abs() < 1e-9,
            "m_against: expected 0.026675, got {m_against}"
        );
        assert!(
            (m_theta - 0.244925).abs() < 1e-9,
            "m_theta: expected 0.244925, got {m_theta}"
        );
        assert!(
            (m_open - 0.03).abs() < 1e-9,
            "m_open: expected 0.03, got {m_open}"
        );
    }
}
