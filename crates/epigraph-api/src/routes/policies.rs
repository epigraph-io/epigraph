//! /api/v1/policies/* — labeled-claim view over network access policies.
//!
//! All policies are stored as ordinary claims with `policy:active` and
//! `policy:network` labels and `host`/`port`/`protocol`/`decay_exempt`
//! fields in `properties`. Challenges are claims with `policy:challenge`
//! and a `status` field in `properties`.
//!
//! Reference implementation: `epigraph-nano/src/persistence.rs:7332-7530`.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ListPoliciesQuery {
    #[serde(default = "default_min_truth")]
    pub min_truth: f64,
}
const fn default_min_truth() -> f64 {
    0.5
}

#[derive(Debug, Deserialize)]
pub struct OutcomeRequest {
    pub supports: bool,
    pub strength: f64,
}

#[derive(Debug, Deserialize)]
pub struct CreateChallengeRequest {
    pub host: String,
    pub port: i64,
    pub protocol: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveChallengeRequest {
    pub approved: bool,
}
