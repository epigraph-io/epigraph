//! Loader for `[matcher.*]` sections in `calibration.toml`.

use crate::matching::scorer::Weights;
use crate::matching::source_key::SourceFilterConfig;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Bands {
    pub high: f32,
    pub mid: f32,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct FanOut {
    pub max_per_claim: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Embedding {
    pub model_version: String,
}

fn default_exclude_labels() -> Vec<String> {
    vec!["workflow_step".to_string(), "telemetry".to_string()]
}

/// Candidate-hygiene config: which claims are too non-substantive to match.
///
/// Claims carrying ANY `exclude_labels` (or a host-provenance
/// `properties->>'event'` marker) are dropped from candidate generation before
/// scoring. Empirically, `workflow_step` artifacts (e.g. claims whose content
/// is just "Body") dominate the high-cosine candidate pool — 806 of 838
/// `embed_cosine>=0.90` pairs on prod — without being substantive cross-source
/// claims; `telemetry` is host-provenance noise. Tunable / disablable
/// (`exclude_labels = []`).
#[derive(Debug, Clone, Deserialize)]
pub struct EligibilityConfig {
    #[serde(default = "default_exclude_labels")]
    pub exclude_labels: Vec<String>,
}

impl Default for EligibilityConfig {
    fn default() -> Self {
        Self {
            exclude_labels: default_exclude_labels(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatcherConfig {
    pub weights: Weights,
    pub bands: Bands,
    pub embedding: Embedding,
    #[serde(default)]
    pub filter: SourceFilterConfig,
    #[serde(default)]
    pub eligibility: EligibilityConfig,
    pub fan_out: FanOut,
}

#[derive(Debug, Deserialize)]
struct CalibrationFile {
    matcher: MatcherConfig,
}

impl MatcherConfig {
    /// `[matcher]` of the calibration the process serves: the file
    /// `CALIBRATION_PATH` names when it loads, else the copy compiled into the
    /// binary ([`crate::calibration::CalibrationConfig::served_matcher`]). It
    /// used to read `calibration.toml` relative to the working directory, so
    /// the matcher's settings depended on where the process was started
    /// (backlog 26a12f41).
    ///
    /// # Errors
    /// When the served file has no (or a malformed) `[matcher]` section; the
    /// error names the source.
    pub fn load_default() -> anyhow::Result<Self> {
        crate::calibration::CalibrationConfig::served_matcher()
    }

    /// `[matcher]` of the calibration file at `p` (an explicit operator path,
    /// e.g. `cross_source_sweep --calibration`).
    ///
    /// # Errors
    /// When the file cannot be read or has no valid `[matcher]` section.
    pub fn load_from(p: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(p)?;
        Self::from_toml_str(&raw)
    }

    /// `[matcher]` of a calibration file's text.
    ///
    /// # Errors
    /// When the text has no valid `[matcher]` section.
    pub fn from_toml_str(raw: &str) -> anyhow::Result<Self> {
        let file: CalibrationFile = toml::from_str(raw)?;
        Ok(file.matcher)
    }
}
