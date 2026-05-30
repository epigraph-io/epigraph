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

    /// Alias → canonical evidence-type key. Bridges the DB's
    /// `evidence.evidence_type` vocabulary onto the SciFact-calibrated
    /// canonical keys in `evidence_type_weights`.
    #[serde(default)]
    pub evidence_type_aliases: HashMap<String, String>,

    /// Section tier → retention fraction (rest shifted to theta).
    pub section_tier_weights: HashMap<String, f64>,

    /// Journal name → reliability score.
    pub journal_reliability: HashMap<String, f64>,

    /// Multiplicative Shafer reliability factor for intra-source BBAs.
    ///
    /// Composes with the per-BBA evidence_type weight rather than replacing
    /// it: a logical/intra BBA becomes 0.85 * factor, an empirical/intra
    /// BBA becomes 1.0 * factor. Cross-source (or no detectable intra-source
    /// evidence on the supporting claim) leaves source_strength unchanged.
    ///
    /// Detection lives in the evidence table:
    /// `evidence.properties->>'doi'` matching the paper that asserts the
    /// BBA's target claim via the `asserts` edge.
    #[serde(default = "default_evidence_locality")]
    pub evidence_locality: EvidenceLocality,

    /// Classifier decision thresholds (NEI, support, conflict).
    pub classifier_thresholds: ClassifierThresholds,
}

/// Multiplicative locality factor for intra-source evidential BBAs.
///
/// Cross-source BBAs implicitly use factor 1.0 (no discount). Storing only
/// the intra factor avoids a useless `cross_factor = 1.0` field that the
/// composition formula already assumes.
#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceLocality {
    /// Multiplier applied to per-BBA source_strength when the supporting
    /// evidence is intra-source. `source_strength_new = source_strength_old
    /// * intra_evidence_locality_factor`.
    pub intra_evidence_locality_factor: f64,
}

fn default_evidence_locality() -> EvidenceLocality {
    EvidenceLocality {
        intra_evidence_locality_factor: 0.3,
    }
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

    /// Loads `calibration.toml` from the `CALIBRATION_PATH` env var if set,
    /// otherwise from the workspace root via `CARGO_MANIFEST_DIR` (best effort).
    ///
    /// Falls back to the literal path `"calibration.toml"` (cwd-relative) when
    /// neither env var is present at runtime. Returns the same
    /// [`CalibrationError`] variants as [`Self::load`].
    ///
    /// Production hot-path callers should treat I/O failure as recoverable
    /// (e.g. `.ok().map(...).unwrap_or((defaults))`) rather than propagating —
    /// the engine has reasonable defaults for every locality / weight key.
    ///
    /// Backed by a process-wide cache (see [`Self::cached`]): `calibration.toml`
    /// is read and parsed once, and this returns a clone — the previous per-call
    /// `fs::read` + TOML parse on hot paths was backlog 03cb3167. On load
    /// failure the cache holds [`Self::default_for_phase2_fallback`], so this
    /// returns `Ok(default)` rather than `Err` — matching what every hot-path
    /// caller already did via `.ok()` / `.unwrap_or_else(default)`.
    pub fn from_workspace_root() -> Result<Self, CalibrationError> {
        Ok(Self::cached().clone())
    }

    /// Process-wide cached calibration config: `calibration.toml` is read and
    /// parsed exactly once per process, then reused. Hot paths (belief queries,
    /// edge factors, DS auto-wiring) hit this every request. On load failure
    /// falls back to [`Self::default_for_phase2_fallback`].
    ///
    /// NOTE: changes to `calibration.toml` require a process restart to take
    /// effect (this is a deploy-time config, not a runtime-tunable).
    #[must_use]
    pub fn cached() -> &'static Self {
        static CACHED: std::sync::LazyLock<CalibrationConfig> = std::sync::LazyLock::new(|| {
            CalibrationConfig::load_from_workspace_root_uncached()
                .unwrap_or_else(|_| CalibrationConfig::default_for_phase2_fallback())
        });
        &CACHED
    }

    /// Uncached load: resolve `calibration.toml` (`CALIBRATION_PATH` env →
    /// workspace root via `CARGO_MANIFEST_DIR` → cwd-relative fallback) and
    /// parse it. Hot paths should use [`Self::cached`] / [`Self::from_workspace_root`].
    ///
    /// # Errors
    /// Returns [`CalibrationError`] if the file cannot be read or parsed.
    fn load_from_workspace_root_uncached() -> Result<Self, CalibrationError> {
        let path = if let Ok(explicit) = std::env::var("CALIBRATION_PATH") {
            std::path::PathBuf::from(explicit)
        } else if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
            // crates/epigraph-engine/ → workspace root is two levels up.
            std::path::PathBuf::from(manifest_dir)
                .parent()
                .and_then(|p| p.parent())
                .map(|root| root.join("calibration.toml"))
                .unwrap_or_else(|| std::path::PathBuf::from("calibration.toml"))
        } else {
            std::path::PathBuf::from("calibration.toml")
        };
        Self::load(&path)
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
    ///
    /// Resolution order:
    /// 1. Direct match against `evidence_type_weights` (canonical keys)
    /// 2. Alias lookup → canonical → `evidence_type_weights`
    /// 3. Fallback to 0.5
    pub fn get_evidence_type_weight(&self, evidence_type: &str) -> f64 {
        let key = evidence_type.to_lowercase();
        if let Some(&w) = self.evidence_type_weights.get(&key) {
            return w;
        }
        if let Some(canonical) = self.evidence_type_aliases.get(&key) {
            if let Some(&w) = self.evidence_type_weights.get(canonical) {
                return w;
            }
        }
        0.5
    }

    /// True iff `evidence_type` resolves to a calibrated weight (either
    /// directly via `evidence_type_weights` or transitively via
    /// `evidence_type_aliases`).
    ///
    /// Used by `effective_source_strength` (Phase 2 of issue #197) to
    /// disambiguate a real 0.5 calibration entry from the unknown-key
    /// fallback. Without this, the helper can't tell whether
    /// `get_evidence_type_weight("supports") = 0.5` means "supports is
    /// the unknown-key sentinel, fall back to row.source_strength" or
    /// "supports is genuinely calibrated at 0.5".
    pub fn evidence_type_weight_present(&self, evidence_type: &str) -> bool {
        let key = evidence_type.to_lowercase();
        if self.evidence_type_weights.contains_key(&key) {
            return true;
        }
        if let Some(canonical) = self.evidence_type_aliases.get(&key) {
            if self.evidence_type_weights.contains_key(canonical) {
                return true;
            }
        }
        false
    }

    /// Synthetic `CalibrationConfig` for the Phase 2 helper's failure
    /// path. Returned when `from_workspace_root()` fails (missing
    /// `calibration.toml`, malformed TOML, …) so the combine path can
    /// still produce numbers that match the pre-Phase-2 fallback
    /// hard-codes:
    ///   * `evidence_locality.intra_evidence_locality_factor = 0.3`
    ///     (the same value `auto_wire_ds_for_edge` falls back to)
    ///   * `get_evidence_type_weight("anything") = 0.5` (because the
    ///     empty `evidence_type_weights` map makes every lookup hit the
    ///     0.5 fallback at the bottom of the resolution chain)
    ///
    /// All other maps are empty. Callers that need a real calibration
    /// (e.g. classifier thresholds) must propagate the original
    /// `CalibrationError` instead of using this fallback.
    pub fn default_for_phase2_fallback() -> Self {
        Self {
            default_journal_reliability: 0.78,
            methodology_profiles: HashMap::new(),
            methodology_aliases: HashMap::new(),
            evidence_type_weights: HashMap::new(),
            evidence_type_aliases: HashMap::new(),
            section_tier_weights: HashMap::new(),
            journal_reliability: HashMap::new(),
            evidence_locality: EvidenceLocality {
                intra_evidence_locality_factor: 0.3,
            },
            classifier_thresholds: ClassifierThresholds {
                nei_threshold: 0.85,
                support_threshold: 0.15,
                conflict_threshold: 0.05,
                has_opposing_threshold: 0.1,
            },
        }
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
    fn test_evidence_locality_loads() {
        let config = load_config();
        assert!(
            (config.evidence_locality.intra_evidence_locality_factor - 0.3).abs() < 1e-9,
            "intra_evidence_locality_factor = {}",
            config.evidence_locality.intra_evidence_locality_factor
        );
    }

    #[test]
    fn cached_returns_stable_singleton_with_loaded_values() {
        // Hot paths (belief queries, edge factors, DS auto-wiring) call the
        // workspace-root accessor per request; it must parse calibration.toml
        // once and reuse it, not read+parse on every call (backlog 03cb3167).
        let a = CalibrationConfig::cached();
        let b = CalibrationConfig::cached();
        assert!(
            std::ptr::eq(a, b),
            "cached() must return the same process-wide instance (parsed once)"
        );
        assert!(
            (a.default_journal_reliability - 0.78).abs() < f64::EPSILON,
            "cached() should carry loaded calibration.toml values (0.78), got {}",
            a.default_journal_reliability
        );
    }

    #[test]
    fn from_workspace_root_matches_cached() {
        // from_workspace_root now delegates to the cache; it must still return
        // the loaded values (Ok) so existing callers are unaffected.
        let owned = CalibrationConfig::from_workspace_root().expect("loads");
        assert!(
            (owned.default_journal_reliability
                - CalibrationConfig::cached().default_journal_reliability)
                .abs()
                < f64::EPSILON
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
    fn test_evidence_type_aliases_resolve_to_canonical_weights() {
        let cfg = load_config();

        // DB-vocab values that should resolve via the alias table.
        assert!(
            (cfg.get_evidence_type_weight("observation") - 1.0).abs() < f64::EPSILON,
            "observation → empirical (1.0)"
        );
        assert!(
            (cfg.get_evidence_type_weight("computation") - 0.9).abs() < f64::EPSILON,
            "computation → statistical (0.9)"
        );
        assert!(
            (cfg.get_evidence_type_weight("document") - 0.85).abs() < f64::EPSILON,
            "document → logical (0.85)"
        );
        assert!(
            (cfg.get_evidence_type_weight("reference") - 0.85).abs() < f64::EPSILON,
            "reference → logical (0.85)"
        );
        assert!(
            (cfg.get_evidence_type_weight("testimony") - 0.6).abs() < f64::EPSILON,
            "testimony → testimonial (0.6)"
        );
    }

    #[test]
    fn test_evidence_type_alias_is_case_insensitive() {
        let cfg = load_config();
        assert!((cfg.get_evidence_type_weight("OBSERVATION") - 1.0).abs() < f64::EPSILON);
        assert!((cfg.get_evidence_type_weight("Reference") - 0.85).abs() < f64::EPSILON);
    }

    /// Phase 2 (issue #197): `evidence_type_weight_present` lets the
    /// `effective_source_strength` helper distinguish a real 0.5
    /// calibrated weight from the unknown-key 0.5 fallback.
    #[test]
    fn test_evidence_type_weight_present() {
        let cfg = load_config();

        // Canonical keys present.
        assert!(cfg.evidence_type_weight_present("empirical"));
        assert!(cfg.evidence_type_weight_present("conversational"));

        // Aliases resolve to canonical, so present.
        assert!(cfg.evidence_type_weight_present("observation")); // → empirical
        assert!(cfg.evidence_type_weight_present("document")); // → logical
        assert!(cfg.evidence_type_weight_present("testimony")); // → testimonial

        // Phase 2 alias additions: relationship strings now resolve.
        assert!(cfg.evidence_type_weight_present("supports")); // → derived_support
        assert!(cfg.evidence_type_weight_present("CORROBORATES")); // case-insensitive
        assert!(cfg.evidence_type_weight_present("refutes"));
        assert!(cfg.evidence_type_weight_present("supersedes"));

        // Genuinely unknown keys absent.
        assert!(!cfg.evidence_type_weight_present("alien_telepathy"));
        assert!(!cfg.evidence_type_weight_present(""));
    }

    /// Phase 2 (issue #197): the fallback config used when calibration.toml
    /// can't be loaded must keep the combine path's pre-Phase-2 invariants
    /// (intra factor 0.3, unknown-key weight 0.5).
    #[test]
    fn test_default_for_phase2_fallback_values() {
        let cfg = CalibrationConfig::default_for_phase2_fallback();
        assert!(
            (cfg.evidence_locality.intra_evidence_locality_factor - 0.3).abs() < f64::EPSILON,
            "fallback intra factor must equal pre-Phase-2 hardcoded 0.3"
        );
        // Empty map → every lookup hits the 0.5 fallback at the bottom
        // of `get_evidence_type_weight`'s resolution chain.
        assert!((cfg.get_evidence_type_weight("empirical") - 0.5).abs() < f64::EPSILON);
        assert!((cfg.get_evidence_type_weight("anything_at_all") - 0.5).abs() < f64::EPSILON);
        // `evidence_type_weight_present` returns false for every key
        // (the empty-map fallback config means everything is unknown).
        assert!(!cfg.evidence_type_weight_present("empirical"));
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
