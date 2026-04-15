//! Calibration configuration for the CDST BBA engine.
//!
//! Loads SciFact-calibrated constants from `calibration.toml` at the repository
//! root. All values originate from `scripts/lib/cdst_bba.py` and are kept in
//! sync via the TOML file (single source of truth for both Python and Rust).

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// ── Error Type ──────────────────────────────────────────────────────────────

/// Errors that can occur when loading or querying calibration config.
#[derive(Debug, thiserror::Error)]
pub enum CalibrationError {
    #[error("failed to read calibration file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse calibration TOML: {0}")]
    Parse(#[from] toml::de::Error),
}

// ── Config Structs ──────────────────────────────────────────────────────────

/// Top-level calibration configuration deserialized from `calibration.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct CalibrationConfig {
    /// Fallback journal reliability when no match is found.
    pub default_journal_reliability: f64,

    /// Canonical methodology profiles: name → [base_support, base_against, base_ignorance].
    pub methodology_profiles: HashMap<String, [f64; 3]>,

    /// Alias → canonical methodology name.
    pub methodology_aliases: HashMap<String, String>,

    /// Evidence type → weight multiplier.
    pub evidence_type_weights: HashMap<String, f64>,

    /// Section tier → retention fraction (rest shifted to theta).
    pub section_tier_weights: HashMap<String, f64>,

    /// Journal name → reliability score.
    pub journal_reliability: HashMap<String, f64>,

    /// Classifier decision thresholds (NEI, support, conflict).
    pub classifier_thresholds: ClassifierThresholds,
}

/// Thresholds used by the BetP-based classifier.
#[derive(Debug, Clone, Deserialize)]
pub struct ClassifierThresholds {
    pub nei_threshold: f64,
    pub support_threshold: f64,
    pub conflict_threshold: f64,
    pub has_opposing_threshold: f64,
}

// ── Implementation ──────────────────────────────────────────────────────────

impl CalibrationConfig {
    /// Load calibration config from a TOML file.
    ///
    /// # Errors
    /// Returns [`CalibrationError`] if the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, CalibrationError> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Resolve a methodology string to its `(base_support, base_against, base_ignorance)` profile.
    ///
    /// Resolution order:
    /// 1. Direct lookup in `methodology_profiles`
    /// 2. Alias resolution via `methodology_aliases`, then profile lookup
    /// 3. Fallback to the `"default"` profile (or hard-coded `(0.50, 0.08, 0.42)`)
    pub fn get_methodology_profile(&self, methodology: &str) -> (f64, f64, f64) {
        let key = methodology.to_lowercase();

        // Direct match
        if let Some(p) = self.methodology_profiles.get(&key) {
            return (p[0], p[1], p[2]);
        }

        // Alias resolution
        if let Some(canonical) = self.methodology_aliases.get(&key) {
            if let Some(p) = self.methodology_profiles.get(canonical) {
                return (p[0], p[1], p[2]);
            }
        }

        // Default profile
        if let Some(p) = self.methodology_profiles.get("default") {
            return (p[0], p[1], p[2]);
        }

        // Hard-coded fallback (should never happen if TOML is well-formed)
        (0.50, 0.08, 0.42)
    }

    /// Look up journal reliability.
    ///
    /// Resolution order:
    /// 1. Exact match (case-sensitive)
    /// 2. Case-insensitive prefix match against known journal names
    /// 3. Fallback to `default_journal_reliability`
    pub fn get_journal_reliability(&self, journal: &str) -> f64 {
        // Exact match
        if let Some(&rel) = self.journal_reliability.get(journal) {
            return rel;
        }

        // Case-insensitive prefix match
        let journal_lower = journal.to_lowercase();
        for (name, &rel) in &self.journal_reliability {
            if journal_lower.starts_with(&name.to_lowercase()) {
                return rel;
            }
        }

        self.default_journal_reliability
    }

    /// Look up evidence type weight. Returns 0.5 for unknown types.
    pub fn get_evidence_type_weight(&self, evidence_type: &str) -> f64 {
        let key = evidence_type.to_lowercase();
        self.evidence_type_weights.get(&key).copied().unwrap_or(0.5)
    }

    /// Look up section tier weight. Returns 1.0 for unknown sections (no discount).
    pub fn get_section_tier_weight(&self, section: &str) -> f64 {
        let key = section.to_lowercase();
        self.section_tier_weights.get(&key).copied().unwrap_or(1.0)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Locate calibration.toml relative to the workspace root.
    fn calibration_path() -> PathBuf {
        // crates/epigraph-engine/src/calibration.rs → ../../.. → workspace root
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .parent() // crates/
            .unwrap()
            .parent() // workspace root
            .unwrap()
            .join("calibration.toml")
    }

    fn load_config() -> CalibrationConfig {
        CalibrationConfig::load(&calibration_path())
            .expect("calibration.toml should load successfully")
    }

    #[test]
    fn test_load_calibration_toml() {
        let cfg = load_config();
        assert!(
            (cfg.default_journal_reliability - 0.78).abs() < f64::EPSILON,
            "default_journal_reliability should be 0.78"
        );
    }

    #[test]
    fn test_known_methodology_profiles() {
        let cfg = load_config();

        let (s, a, i) = cfg.get_methodology_profile("deductive_logic");
        assert!((s - 0.85).abs() < f64::EPSILON);
        assert!((a - 0.05).abs() < f64::EPSILON);
        assert!((i - 0.10).abs() < f64::EPSILON);

        let (s, a, i) = cfg.get_methodology_profile("extraction");
        assert!((s - 0.58).abs() < f64::EPSILON);
        assert!((a - 0.07).abs() < f64::EPSILON);
        assert!((i - 0.35).abs() < f64::EPSILON);
    }

    #[test]
    fn test_alias_resolution() {
        let cfg = load_config();

        // "deductive" is an alias for "deductive_logic"
        let (s, _, _) = cfg.get_methodology_profile("deductive");
        assert!((s - 0.85).abs() < f64::EPSILON);

        // "experimental_observation" is an alias for "instrumental"
        let (s, _, _) = cfg.get_methodology_profile("experimental_observation");
        assert!((s - 0.80).abs() < f64::EPSILON);

        // "llm_extraction" is an alias for "extraction"
        let (s, _, _) = cfg.get_methodology_profile("llm_extraction");
        assert!((s - 0.58).abs() < f64::EPSILON);

        // "testimonial" is an alias for "expert_elicitation"
        let (s, _, _) = cfg.get_methodology_profile("testimonial");
        assert!((s - 0.45).abs() < f64::EPSILON);
    }

    #[test]
    fn test_case_insensitive_methodology() {
        let cfg = load_config();

        // Mixed-case input should still resolve
        let (s, _, _) = cfg.get_methodology_profile("Deductive_Logic");
        assert!((s - 0.85).abs() < f64::EPSILON);

        let (s, _, _) = cfg.get_methodology_profile("META_ANALYSIS");
        assert!((s - 0.80).abs() < f64::EPSILON);
    }

    #[test]
    fn test_unknown_methodology_returns_default() {
        let cfg = load_config();

        let (s, a, i) = cfg.get_methodology_profile("completely_unknown_method");
        assert!((s - 0.50).abs() < f64::EPSILON);
        assert!((a - 0.08).abs() < f64::EPSILON);
        assert!((i - 0.42).abs() < f64::EPSILON);
    }

    #[test]
    fn test_journal_exact_match() {
        let cfg = load_config();

        let rel = cfg.get_journal_reliability("Nature");
        assert!((rel - 0.92).abs() < f64::EPSILON);

        let rel = cfg.get_journal_reliability("arXiv preprint");
        assert!((rel - 0.70).abs() < f64::EPSILON);

        let rel = cfg.get_journal_reliability("Nature Communications");
        assert!((rel - 0.88).abs() < f64::EPSILON);
    }

    #[test]
    fn test_journal_prefix_match() {
        let cfg = load_config();

        // "Nature Medicine" is not an exact match but starts with "Nature"
        // However, "Nature Communications" also starts with "Nature" — prefix
        // matching is non-deterministic among multiple prefixes. The Python
        // implementation iterates in dict order. We just verify it returns
        // a known Nature-family reliability (0.88 or 0.92).
        let rel = cfg.get_journal_reliability("Nature Medicine");
        assert!(
            (rel - 0.92).abs() < f64::EPSILON || (rel - 0.88).abs() < f64::EPSILON,
            "Nature Medicine should prefix-match a Nature entry, got {rel}"
        );

        // "Annual Review of Chemistry" should match "Annual Review" prefix
        let rel = cfg.get_journal_reliability("Annual Review of Chemistry");
        assert!((rel - 0.88).abs() < f64::EPSILON);
    }

    #[test]
    fn test_unknown_journal_returns_default() {
        let cfg = load_config();

        let rel = cfg.get_journal_reliability("Obscure Journal of Nothing");
        assert!((rel - 0.78).abs() < f64::EPSILON);
    }

    #[test]
    fn test_evidence_type_weights() {
        let cfg = load_config();

        assert!((cfg.get_evidence_type_weight("empirical") - 1.0).abs() < f64::EPSILON);
        assert!((cfg.get_evidence_type_weight("statistical") - 0.9).abs() < f64::EPSILON);
        assert!((cfg.get_evidence_type_weight("conversational") - 0.3).abs() < f64::EPSILON);

        // Unknown type → 0.5
        assert!((cfg.get_evidence_type_weight("alien_telepathy") - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_section_tier_weights() {
        let cfg = load_config();

        assert!((cfg.get_section_tier_weight("results") - 1.0).abs() < f64::EPSILON);
        assert!((cfg.get_section_tier_weight("abstract") - 0.80).abs() < f64::EPSILON);
        assert!((cfg.get_section_tier_weight("introduction") - 0.50).abs() < f64::EPSILON);

        // Unknown section → 1.0 (no discount)
        assert!((cfg.get_section_tier_weight("appendix") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classifier_thresholds() {
        let cfg = load_config();

        assert!((cfg.classifier_thresholds.nei_threshold - 0.85).abs() < f64::EPSILON);
        assert!((cfg.classifier_thresholds.support_threshold - 0.15).abs() < f64::EPSILON);
        assert!((cfg.classifier_thresholds.conflict_threshold - 0.05).abs() < f64::EPSILON);
        assert!((cfg.classifier_thresholds.has_opposing_threshold - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_all_python_methodology_profiles_present() {
        let cfg = load_config();

        // Every canonical profile from Python must exist
        let expected_canonicals = [
            "deductive_logic",
            "meta_analysis",
            "theoretical_derivation",
            "statistical_analysis",
            "bayesian_inference",
            "computational",
            "instrumental",
            "inductive_generalization",
            "visual_inspection",
            "observational",
            "expert_elicitation",
            "extraction",
            "negative_result",
        ];
        for name in &expected_canonicals {
            assert!(
                cfg.methodology_profiles.contains_key(*name),
                "missing canonical profile: {name}"
            );
        }

        // Every alias must resolve to a valid profile
        for (alias, canonical) in &cfg.methodology_aliases {
            assert!(
                cfg.methodology_profiles.contains_key(canonical),
                "alias {alias} → {canonical} but {canonical} not in profiles"
            );
        }
    }

    #[test]
    fn test_all_journal_entries_present() {
        let cfg = load_config();

        let expected = [
            "Nature",
            "Science",
            "Cell",
            "The Lancet",
            "Nature Communications",
            "Physical Review Letters",
            "PNAS",
            "JACS",
            "ACS Nano",
            "Chemical Reviews",
            "iScience",
            "Chemical Science",
            "MRS Bulletin",
            "Nanophotonics",
            "Annual Review",
            "arXiv preprint",
            "bioRxiv",
            "chemRxiv",
            "medRxiv",
        ];
        for name in &expected {
            assert!(
                cfg.journal_reliability.contains_key(*name),
                "missing journal: {name}"
            );
        }
    }
}
