//! Calibration configuration for the CDST BBA engine.
//!
//! Loads SciFact-calibrated constants from `calibration.toml` at the repository
//! root. All values originate from `scripts/lib/cdst_bba.py` and are kept in
//! sync via the TOML file (single source of truth for both Python and Rust).

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The workspace `calibration.toml`, compiled into every binary that links
/// this crate. It is what [`CalibrationConfig::cached`] serves when
/// `CALIBRATION_PATH` is unset or cannot be loaded, so a process never depends
/// on the build machine's source tree existing at run time (backlog 7cb71243:
/// agent containers run the host-built binary without the file, and silently
/// served an EMPTY evidence-type vocabulary). `include_str!` rebuilds the
/// crate whenever the file changes.
const EMBEDDED_CALIBRATION: &str = include_str!("../../../calibration.toml");

/// Where the process-wide calibration ([`CalibrationConfig::cached`]) came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalibrationSource {
    /// Loaded from the file `CALIBRATION_PATH` names.
    Path(PathBuf),
    /// The copy compiled into this binary ([`CalibrationConfig::embedded`]).
    /// `failed_override` is the `CALIBRATION_PATH` that was set but could not
    /// be loaded, with the error; `None` when the variable was unset.
    Embedded {
        failed_override: Option<(PathBuf, String)>,
    },
}

impl std::fmt::Display for CalibrationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(p) => write!(f, "CALIBRATION_PATH={}", p.display()),
            Self::Embedded {
                failed_override: None,
            } => f.write_str("embedded calibration.toml (CALIBRATION_PATH unset)"),
            Self::Embedded {
                failed_override: Some((p, _)),
            } => write!(
                f,
                "embedded calibration.toml (CALIBRATION_PATH={} failed to load)",
                p.display()
            ),
        }
    }
}

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

    /// Split-conformal per-class nonconformity quantiles (issue: backlog
    /// d5ba91a5). Optional: absent `[conformal]` parses to the default
    /// (every quantile 1.0 -> include-always, i.e. the trivial coverage-1
    /// set), so the set-valued classifier degrades to "return all classes"
    /// rather than panicking when calibration.toml predates this feature.
    #[serde(default)]
    pub conformal: ConformalConfig,

    /// Named belief-profile override tables (`[belief_profiles.<name>]`),
    /// kept as raw JSON values. Each is a merge patch over the profile built
    /// from the sections above; see `crate::belief_profile`.
    ///
    /// Deliberately untyped here: a typo inside a profile table must not fail
    /// the parse of this whole file (which would drop every calibration table
    /// to the load-failure fallback). The profile resolver validates each
    /// table on its own and ignores, with a warning, one that does not fit.
    #[serde(default)]
    pub belief_profiles: HashMap<String, serde_json::Value>,
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
        intra_evidence_locality_factor:
            crate::belief_profile::defaults::INTRA_EVIDENCE_LOCALITY_FACTOR,
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

/// Split-conformal calibration for set-valued classification.
///
/// `quantiles.<class>` is the calibrated nonconformity threshold q_c fit
/// offline by `scripts/calibrate_conformal.py` over the labelled SciFact
/// fixtures. The set-valued classifier includes class c iff its
/// nonconformity score `score_c <= q_c`. With the conventional
/// nonconformity score `score_c = 1 - BetP_c` (or `1 - theta` for NEI),
/// this yields marginal (1 - alpha) coverage on the calibration
/// distribution.
#[derive(Debug, Clone, Deserialize)]
pub struct ConformalConfig {
    /// Target miscoverage rate the quantiles were fit at (informational;
    /// the quantiles already encode it). 0.1 => 90% marginal coverage.
    #[serde(default = "default_conformal_alpha")]
    pub alpha: f64,
    /// Per-class nonconformity quantiles q_c, keyed by the classifier's
    /// label string (`supported` | `contradicted` | `not_enough_info`).
    #[serde(default)]
    pub quantiles: ConformalQuantiles,
}

/// Per-class conformal quantiles. Default 1.0 = include-always (trivial
/// coverage-1 set), the safe degenerate value when `[conformal]` is absent.
#[derive(Debug, Clone, Deserialize)]
pub struct ConformalQuantiles {
    #[serde(default = "default_quantile")]
    pub supported: f64,
    #[serde(default = "default_quantile")]
    pub contradicted: f64,
    #[serde(default = "default_quantile")]
    pub not_enough_info: f64,
}

fn default_conformal_alpha() -> f64 {
    0.1
}

fn default_quantile() -> f64 {
    1.0
}

impl Default for ConformalQuantiles {
    fn default() -> Self {
        Self {
            supported: default_quantile(),
            contradicted: default_quantile(),
            not_enough_info: default_quantile(),
        }
    }
}

impl Default for ConformalConfig {
    fn default() -> Self {
        Self {
            alpha: default_conformal_alpha(),
            quantiles: ConformalQuantiles::default(),
        }
    }
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

    /// The process-wide calibration ([`Self::cached`]), cloned.
    ///
    /// Resolution: the file `CALIBRATION_PATH` names, when set and loadable;
    /// otherwise the calibration compiled into this binary
    /// ([`Self::embedded`]). There is no build-path or cwd-relative tier: a
    /// binary built on one machine and run on another (an agent container, a
    /// deploy host after a worktree prune) must not change calibration because
    /// a source tree is or is not present. A set-but-unloadable
    /// `CALIBRATION_PATH` is logged at ERROR naming the path, and reported by
    /// [`Self::startup_problems`] for the binaries to journal at boot.
    ///
    /// Always `Ok`; the `Result` is kept for the existing callers. Changes to
    /// the file need a process restart (read once, then cached; the per-call
    /// read + parse on hot paths was backlog 03cb3167).
    pub fn from_workspace_root() -> Result<Self, CalibrationError> {
        Ok(Self::cached().clone())
    }

    /// Process-wide cached calibration config, resolved once per process as
    /// [`Self::from_workspace_root`] describes. Hot paths (belief queries, edge
    /// factors, DS auto-wiring) hit this every request.
    ///
    /// NOTE: changes to `calibration.toml` require a process restart to take
    /// effect (this is a deploy-time config, not a runtime-tunable).
    #[must_use]
    pub fn cached() -> &'static Self {
        &Self::cached_with_source().0
    }

    /// Where [`Self::cached`] came from.
    #[must_use]
    pub fn cached_source() -> &'static CalibrationSource {
        &Self::cached_with_source().1
    }

    fn cached_with_source() -> &'static (CalibrationConfig, CalibrationSource) {
        static CACHED: std::sync::LazyLock<(CalibrationConfig, CalibrationSource)> =
            std::sync::LazyLock::new(|| {
                CalibrationConfig::resolve(std::env::var_os("CALIBRATION_PATH").map(PathBuf::from))
            });
        &CACHED
    }

    /// Resolve the served calibration from an optional explicit path (the
    /// value of `CALIBRATION_PATH`).
    fn resolve(explicit: Option<PathBuf>) -> (Self, CalibrationSource) {
        let Some(path) = explicit else {
            return (
                Self::embedded(),
                CalibrationSource::Embedded {
                    failed_override: None,
                },
            );
        };
        match Self::load(&path) {
            Ok(cfg) => (cfg, CalibrationSource::Path(path)),
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "CALIBRATION_PATH could not be loaded; serving the calibration compiled into this binary"
                );
                (
                    Self::embedded(),
                    CalibrationSource::Embedded {
                        failed_override: Some((path, e.to_string())),
                    },
                )
            }
        }
    }

    /// The workspace `calibration.toml` this binary was built with.
    ///
    /// # Panics
    /// Never in a tested build: `embedded_calibration_matches_the_workspace_file`
    /// parses the same text, so a malformed `calibration.toml` fails the test
    /// suite before it can ship.
    #[must_use]
    pub fn embedded() -> Self {
        toml::from_str(EMBEDDED_CALIBRATION)
            .expect("the calibration.toml compiled into this binary parses (pinned by a unit test)")
    }

    /// What a serving process should report at boot about its calibration, one
    /// message per problem; empty when there is none (backlog 7cb71243, "fail
    /// loudly"). Two problems are possible: a `CALIBRATION_PATH` that was set
    /// but could not be loaded (the shipped calibration is served instead),
    /// and an empty `[evidence_type_weights]` table, which makes every typed
    /// BBA combine at the 0.5 unknown-type reliability. The second can only
    /// come from an explicit `CALIBRATION_PATH` file now, since the embedded
    /// copy is non-empty.
    ///
    /// Reported, not fatal: refusing to start would take every agent
    /// container's memory tools down, which is worse than the defect.
    #[must_use]
    pub fn problems(cfg: &Self, source: &CalibrationSource) -> Vec<String> {
        let mut out = Vec::new();
        if let CalibrationSource::Embedded {
            failed_override: Some((path, error)),
        } = source
        {
            out.push(format!(
                "CALIBRATION_PATH={} could not be loaded ({error}); serving the calibration \
                 compiled into this binary instead",
                path.display()
            ));
        }
        if cfg.evidence_type_weights.is_empty() {
            out.push(format!(
                "the evidence-type vocabulary is EMPTY ([evidence_type_weights] in {source}): \
                 every typed BBA combines at the 0.5 unknown-type reliability"
            ));
        }
        out
    }

    /// [`Self::problems`] for the process-wide calibration. Calling it forces
    /// the cache, so a server that calls it at boot resolves its calibration
    /// before the first request.
    #[must_use]
    pub fn startup_problems() -> Vec<String> {
        Self::problems(Self::cached(), Self::cached_source())
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

        // Built-in fallback (should never happen if TOML is well-formed)
        let [s, a, i] = crate::belief_profile::defaults::METHODOLOGY_FALLBACK;
        (s, a, i)
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
        crate::belief_profile::defaults::UNKNOWN_EVIDENCE_TYPE_WEIGHT
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

    /// The key a BBA writer stores in `mass_functions.evidence_type` for a
    /// type it was handed (backlog bc06ec6f).
    ///
    /// Trimmed and lowercased. A canonical `[evidence_type_weights]` key is
    /// returned as is; a DB-vocabulary tag (`observation`, `testimony`,
    /// `reference`, ...) or relationship string resolves through
    /// `[evidence_type_aliases]` to its canonical key. A key the calibration
    /// does not know is KEPT, lowercased: per-frame `evidence_type_weights`
    /// overrides and perspective `source_reliability` maps may key on it on
    /// purpose, and both readers lowercase before looking it up. Blank input
    /// is `None`, never a guess.
    #[must_use]
    pub fn canonical_evidence_type(&self, raw: &str) -> Option<String> {
        let key = raw.trim().to_lowercase();
        if key.is_empty() {
            return None;
        }
        if self.evidence_type_weights.contains_key(&key) {
            return Some(key);
        }
        if let Some(canonical) = self.evidence_type_aliases.get(&key) {
            if self.evidence_type_weights.contains_key(canonical) {
                return Some(canonical.clone());
            }
        }
        Some(key)
    }

    /// Synthetic `CalibrationConfig` for the Phase 2 helper's failure
    /// path, and a test fixture for the pre-Phase-2 invariants. The served
    /// calibration no longer falls back to it ([`Self::cached`] falls back to
    /// [`Self::embedded`]; backlog 7cb71243), so the callers' `.unwrap_or_else`
    /// on [`Self::from_workspace_root`] never reaches it. It still produces
    /// numbers that match the pre-Phase-2 fallback hard-codes:
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
        use crate::belief_profile::defaults as d;
        Self {
            default_journal_reliability: d::DEFAULT_JOURNAL_RELIABILITY,
            methodology_profiles: HashMap::new(),
            methodology_aliases: HashMap::new(),
            evidence_type_weights: HashMap::new(),
            evidence_type_aliases: HashMap::new(),
            section_tier_weights: HashMap::new(),
            journal_reliability: HashMap::new(),
            evidence_locality: EvidenceLocality {
                intra_evidence_locality_factor: d::INTRA_EVIDENCE_LOCALITY_FACTOR,
            },
            classifier_thresholds: ClassifierThresholds {
                nei_threshold: d::CLASSIFIER_NEI_THRESHOLD,
                support_threshold: d::CLASSIFIER_SUPPORT_THRESHOLD,
                conflict_threshold: d::CLASSIFIER_CONFLICT_THRESHOLD,
                has_opposing_threshold: d::CLASSIFIER_HAS_OPPOSING_THRESHOLD,
            },
            conformal: ConformalConfig::default(),
            belief_profiles: HashMap::new(),
        }
    }

    /// Look up section tier weight. Returns 1.0 for unknown sections (no discount).
    pub fn get_section_tier_weight(&self, section: &str) -> f64 {
        let key = section.to_lowercase();
        self.section_tier_weights.get(&key).copied().unwrap_or(1.0)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// [`CalibrationConfig::canonical_evidence_type`] against the process-wide
/// calibration ([`CalibrationConfig::cached`]), for writers that hold no
/// config of their own. `None` in, `None` out.
///
/// If `calibration.toml` could not be loaded, the cached fallback has no
/// weights and no aliases, so a tag is stored trimmed and lowercased but
/// unresolved: exactly what the writers stored before, minus the case.
#[must_use]
pub fn canonical_evidence_type(raw: Option<&str>) -> Option<String> {
    CalibrationConfig::cached().canonical_evidence_type(raw?)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The compiled-in copy is the workspace file, parsed: guards the
    /// `embedded()` `.expect` and any drift between what ships and what the
    /// file says (backlog 7cb71243).
    #[test]
    fn embedded_calibration_matches_the_workspace_file() {
        let embedded = CalibrationConfig::embedded();
        let file = load_config();
        assert!(
            !embedded.evidence_type_weights.is_empty(),
            "the shipped vocabulary must not be empty"
        );
        assert_eq!(embedded.evidence_type_weights, file.evidence_type_weights);
        assert_eq!(embedded.evidence_type_aliases, file.evidence_type_aliases);
        assert_eq!(embedded.methodology_profiles, file.methodology_profiles);
        assert_eq!(embedded.methodology_aliases, file.methodology_aliases);
        assert_eq!(embedded.journal_reliability, file.journal_reliability);
        assert_eq!(embedded.section_tier_weights, file.section_tier_weights);
        assert!(
            (embedded.default_journal_reliability - file.default_journal_reliability).abs()
                < f64::EPSILON
        );
    }

    /// `CALIBRATION_PATH` still overrides, and a set-but-unloadable one falls
    /// back to the shipped calibration (not the empty one) and says which path
    /// failed. Driven through `resolve` so it does not depend on this test
    /// binary's process-wide cache.
    #[test]
    fn resolve_prefers_an_explicit_path_and_falls_back_to_embedded() {
        let (cfg, src) = CalibrationConfig::resolve(Some(calibration_path()));
        assert_eq!(src, CalibrationSource::Path(calibration_path()));
        assert!(CalibrationConfig::problems(&cfg, &src).is_empty());

        let missing = PathBuf::from("/nonexistent/7cb71243/calibration.toml");
        let (cfg, src) = CalibrationConfig::resolve(Some(missing.clone()));
        assert_eq!(cfg.evidence_type_weights.get("empirical"), Some(&1.0));
        match &src {
            CalibrationSource::Embedded {
                failed_override: Some((p, _)),
            } => assert_eq!(p, &missing),
            other => panic!("expected an embedded fallback naming the path, got {other:?}"),
        }
        let problems = CalibrationConfig::problems(&cfg, &src);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("/nonexistent/7cb71243/calibration.toml"));

        let (cfg, src) = CalibrationConfig::resolve(None);
        assert_eq!(
            src,
            CalibrationSource::Embedded {
                failed_override: None
            }
        );
        assert!(CalibrationConfig::problems(&cfg, &src).is_empty());
    }

    /// An explicit calibration whose vocabulary is empty is the one way left
    /// to serve the 0.5-everywhere combine; it must be reported.
    #[test]
    fn an_empty_vocabulary_is_reported() {
        let cfg = CalibrationConfig::default_for_phase2_fallback();
        let src = CalibrationSource::Path(PathBuf::from("/etc/epigraph/calibration.toml"));
        let problems = CalibrationConfig::problems(&cfg, &src);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("EMPTY") && problems[0].contains("0.5 unknown-type"),
            "{}",
            problems[0]
        );
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

    /// Backlog bc06ec6f: the key a BBA writer stores in
    /// `mass_functions.evidence_type`. Canonical keys pass through, DB-vocab
    /// tags resolve through `[evidence_type_aliases]`, both case-insensitively.
    #[test]
    fn canonical_evidence_type_resolves_aliases_case_insensitively() {
        let cfg = load_config();
        let c = |raw: &str| cfg.canonical_evidence_type(raw);
        assert_eq!(c("empirical").as_deref(), Some("empirical"));
        assert_eq!(c(" Logical ").as_deref(), Some("logical"));
        assert_eq!(c("observation").as_deref(), Some("empirical"));
        assert_eq!(c("Testimony").as_deref(), Some("testimonial"));
        assert_eq!(c("reference").as_deref(), Some("logical"));
        assert_eq!(c("document").as_deref(), Some("logical"));
        assert_eq!(c("computation").as_deref(), Some("statistical"));
        assert_eq!(c("supports").as_deref(), Some("derived_support"));
    }

    /// A key the calibration does not know is kept (trimmed, lowercased: every
    /// reader lowercases), because per-frame overrides and perspective maps may
    /// key on it deliberately. Blank input is "no type".
    #[test]
    fn canonical_evidence_type_keeps_unknown_keys_and_drops_blank() {
        let cfg = load_config();
        assert_eq!(
            cfg.canonical_evidence_type(" Western_Clinical ").as_deref(),
            Some("western_clinical")
        );
        assert_eq!(cfg.canonical_evidence_type(""), None);
        assert_eq!(cfg.canonical_evidence_type("   "), None);
        assert_eq!(canonical_evidence_type(None), None);
        assert_eq!(
            canonical_evidence_type(Some("Observation")).as_deref(),
            Some("empirical")
        );
    }
}
