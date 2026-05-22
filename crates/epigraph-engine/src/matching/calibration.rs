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

#[derive(Debug, Clone, Deserialize)]
pub struct MatcherConfig {
    pub weights: Weights,
    pub bands: Bands,
    pub embedding: Embedding,
    #[serde(default)]
    pub filter: SourceFilterConfig,
    pub fan_out: FanOut,
}

#[derive(Debug, Deserialize)]
struct CalibrationFile {
    matcher: MatcherConfig,
}

impl MatcherConfig {
    pub fn load_default() -> anyhow::Result<Self> {
        Self::load_from(Path::new("calibration.toml"))
    }
    pub fn load_from(p: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(p)?;
        let file: CalibrationFile = toml::from_str(&raw)?;
        Ok(file.matcher)
    }
}
