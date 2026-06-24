//! Client + pure mapping for the self-hosted NLI cross-encoder service.
//!
//! This is the Rust half of backlog item 97244690's BONUS path: an
//! alternate, cheap, deterministic PRODUCER for the same 3-way stance
//! signal the LLM probes in [`super::confidence`] emit. (The item's
//! CANONICAL deliverable is the DST belief path in
//! `scripts/lib/nli_stance.py`; this module feeds the parser-confidence
//! multiplier, not BetP belief ordering.) The probes hold the STRUCTURED
//! inputs (claim text, prior-claim list, evidence list), so we route at the
//! probe level -- NOT by wrapping [`super::llm_client::LlmProvider`], whose
//! only method takes a rendered English prompt (reverse-parsing it would
//! make prompt wording a parsing contract, and the process-wide provider
//! registry would risk routing unrelated relationship/rerank calls to an
//! NLI-only model).
//!
//! All judgement logic (logit->enum thresholds + multi-pair aggregation)
//! lives in the pure [`mapping`] module so it tests with no network/model.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// 3-way NLI distribution returned by the service.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NliScores {
    pub entailment: f64,
    pub neutral: f64,
    pub contradiction: f64,
}

/// Errors from the NLI client.
#[derive(Debug, thiserror::Error)]
pub enum NliError {
    #[error("NLI service not configured (set NLI_SERVICE_URL)")]
    NotConfigured,
    #[error("NLI request failed: {0}")]
    RequestFailed(String),
    #[error("NLI returned malformed response: {0}")]
    Malformed(String),
}

/// Abstract per-pair classifier so the probes can be tested against a
/// deterministic in-process fake (no HTTP), and the real client swapped in.
#[async_trait]
pub trait NliClassifier: Send + Sync {
    fn is_active(&self) -> bool;
    async fn classify(&self, premise: &str, hypothesis: &str) -> Result<NliScores, NliError>;
}

/// HTTP client for the FastAPI service behind Caddy.
#[derive(Debug, Clone)]
pub struct NliClient {
    base_url: String,
    http: reqwest::Client,
}

impl NliClient {
    /// Construct from an explicit base URL (e.g. `http://localhost/nli`).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Construct from `NLI_SERVICE_URL`; `None` when unset/empty so callers
    /// transparently fall back to the LLM probe path.
    pub fn from_env() -> Option<Self> {
        match std::env::var("NLI_SERVICE_URL") {
            Ok(u) if !u.is_empty() => Some(Self::new(u)),
            _ => None,
        }
    }
}

#[async_trait]
impl NliClassifier for NliClient {
    fn is_active(&self) -> bool {
        !self.base_url.is_empty()
    }

    async fn classify(&self, premise: &str, hypothesis: &str) -> Result<NliScores, NliError> {
        let resp = self
            .http
            .post(&self.base_url)
            .json(&serde_json::json!({ "premise": premise, "hypothesis": hypothesis }))
            .send()
            .await
            .map_err(|e| NliError::RequestFailed(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(NliError::RequestFailed(format!("HTTP {}", resp.status())));
        }
        resp.json::<NliScores>()
            .await
            .map_err(|e| NliError::Malformed(e.to_string()))
    }
}

/// Pure, network-free judgement logic. All thresholds and aggregation
/// rules live here so they are unit-testable and auditable in one place.
pub mod mapping {
    use super::NliScores;
    use crate::enrichment::confidence::{CoherenceResult, EvidenceSupport};

    /// The dominant (argmax) NLI label.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum NliLabel {
        Entailment,
        Neutral,
        Contradiction,
    }

    /// Argmax over the 3 scores. Ties resolve toward the SAFER label
    /// (Contradiction > Neutral > Entailment) so the producer never
    /// over-confidently asserts agreement on a tie.
    pub fn dominant(s: &NliScores) -> NliLabel {
        let mut best = NliLabel::Contradiction;
        let mut best_v = s.contradiction;
        if s.neutral > best_v {
            best = NliLabel::Neutral;
            best_v = s.neutral;
        }
        if s.entailment > best_v {
            best = NliLabel::Entailment;
        }
        best
    }

    /// Map a single coherence pair (prior claim = premise, new claim =
    /// hypothesis) to the existing [`CoherenceResult`] enum.
    ///
    /// Entailment -> Consistent, Contradiction -> Contradiction. Neutral is
    /// the ambiguous middle: treated as Tension only when contradiction is a
    /// meaningful runner-up (>= 0.20), else Consistent (unrelated != conflict).
    pub fn coherence_of_pair(s: &NliScores) -> CoherenceResult {
        match dominant(s) {
            NliLabel::Entailment => CoherenceResult::Consistent,
            NliLabel::Contradiction => CoherenceResult::Contradiction,
            NliLabel::Neutral => {
                if s.contradiction >= 0.20 {
                    CoherenceResult::Tension
                } else {
                    CoherenceResult::Consistent
                }
            }
        }
    }

    /// Map a single evidence pair (evidence = premise, claim = hypothesis)
    /// to the existing [`EvidenceSupport`] enum.
    pub fn support_of_pair(s: &NliScores) -> EvidenceSupport {
        match dominant(s) {
            NliLabel::Entailment => {
                if s.entailment >= 0.75 {
                    EvidenceSupport::StrongSupport
                } else {
                    EvidenceSupport::WeakSupport
                }
            }
            NliLabel::Contradiction => EvidenceSupport::Contradicts,
            NliLabel::Neutral => EvidenceSupport::Unrelated,
        }
    }

    /// Aggregate per-prior-claim coherence judgements into one result for the
    /// new claim. CONTRADICTION DOMINATES: any contradicting prior -> Contradiction;
    /// else any tension -> Tension; else Consistent. Mirrors the probe's
    /// conservative-default posture (confidence can only be lowered).
    pub fn aggregate_coherence(per_pair: &[CoherenceResult]) -> CoherenceResult {
        if per_pair.contains(&CoherenceResult::Contradiction) {
            CoherenceResult::Contradiction
        } else if per_pair.contains(&CoherenceResult::Tension) {
            CoherenceResult::Tension
        } else {
            CoherenceResult::Consistent
        }
    }

    /// Aggregate per-evidence support judgements. Take the STRONGEST stance
    /// toward the claim: StrongSupport if any strongly supports AND none
    /// contradicts; Contradicts if any contradicts and none strongly
    /// supports; on conflict (both present) downgrade to WeakSupport; else
    /// the max of the remaining.
    pub fn aggregate_support(per_pair: &[EvidenceSupport]) -> EvidenceSupport {
        if per_pair.is_empty() {
            return EvidenceSupport::Unrelated;
        }
        let strong = per_pair.contains(&EvidenceSupport::StrongSupport);
        let contra = per_pair.contains(&EvidenceSupport::Contradicts);
        match (strong, contra) {
            (true, true) => EvidenceSupport::WeakSupport,
            (true, false) => EvidenceSupport::StrongSupport,
            (false, true) => EvidenceSupport::Contradicts,
            (false, false) => {
                if per_pair.contains(&EvidenceSupport::WeakSupport) {
                    EvidenceSupport::WeakSupport
                } else {
                    EvidenceSupport::Unrelated
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mapping::*;
    use super::*;
    use crate::enrichment::confidence::{CoherenceResult, EvidenceSupport};

    fn scores(e: f64, n: f64, c: f64) -> NliScores {
        NliScores {
            entailment: e,
            neutral: n,
            contradiction: c,
        }
    }

    #[test]
    fn dominant_breaks_ties_toward_contradiction() {
        // All equal -> safer label, never silently Consistent.
        assert_eq!(dominant(&scores(0.34, 0.33, 0.33)), NliLabel::Entailment);
        assert_eq!(dominant(&scores(0.33, 0.33, 0.34)), NliLabel::Contradiction);
        assert_eq!(dominant(&scores(0.5, 0.5, 0.5)), NliLabel::Contradiction);
    }

    #[test]
    fn contradiction_argmax_maps_to_contradiction() {
        assert_eq!(
            coherence_of_pair(&scores(0.05, 0.15, 0.80)),
            CoherenceResult::Contradiction
        );
    }

    #[test]
    fn neutral_with_low_contradiction_is_not_tension() {
        // Unrelated (high neutral, tiny contradiction) must NOT be reported
        // as conflict -- that is the false-positive this threshold guards.
        assert_eq!(
            coherence_of_pair(&scores(0.05, 0.90, 0.05)),
            CoherenceResult::Consistent
        );
    }

    #[test]
    fn neutral_with_meaningful_contradiction_is_tension() {
        assert_eq!(
            coherence_of_pair(&scores(0.10, 0.60, 0.30)),
            CoherenceResult::Tension
        );
    }

    #[test]
    fn weak_entailment_is_not_strong_support() {
        // Argmax entailment but below 0.75 -> WeakSupport, not StrongSupport.
        assert_eq!(
            support_of_pair(&scores(0.55, 0.40, 0.05)),
            EvidenceSupport::WeakSupport
        );
        assert_eq!(
            support_of_pair(&scores(0.85, 0.10, 0.05)),
            EvidenceSupport::StrongSupport
        );
    }

    #[test]
    fn aggregate_coherence_lets_one_contradiction_dominate() {
        let pairs = [
            CoherenceResult::Consistent,
            CoherenceResult::Consistent,
            CoherenceResult::Contradiction,
        ];
        assert_eq!(aggregate_coherence(&pairs), CoherenceResult::Contradiction);
    }

    #[test]
    fn aggregate_support_downgrades_on_conflict() {
        // A source that strongly supports AND another that contradicts is
        // NOT reported as StrongSupport -- conflict downgrades to Weak.
        let pairs = [EvidenceSupport::StrongSupport, EvidenceSupport::Contradicts];
        assert_eq!(aggregate_support(&pairs), EvidenceSupport::WeakSupport);
    }
}
