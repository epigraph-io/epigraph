//! Cross-encoder rerank + MiniCheck-style groundedness gate over recall
//! candidates. Lives in the **engine** crate so the serving paths
//! (`epigraph-api` search, `epigraph-mcp` recall) can call it without the
//! `epigraph-cli -> epigraph-engine -> epigraph-cli` cycle that would result
//! from reusing `epigraph-cli`'s `rerank::core` (which is edge-creation-coupled
//! and claim<->claim, not query<->passage).
//!
//! # Pipeline (caller-orchestrated; see `epigraph-mcp/tools/recall.rs`)
//! 1. Widen the flat-ANN candidate pool (`limit * pool_factor`, clamped).
//! 2. Cheap content fetch for the widened ids (`ClaimRepository::contents_by_ids`).
//! 3. [`RerankClient::rerank`] scores each `(query, content)` pair -> relevance.
//! 4. [`GroundednessGate::judge`] (optional) drops passages the LLM judges
//!    NOT grounded-relevant to the query (MiniCheck-style verdict).
//! 5. Caller reorders surviving hits by rerank score (relevance), truncates to
//!    `limit`, and ONLY THEN runs the expensive structural enrichment.
//!
//! # Belief-ordering invariant
//! Reranking reorders by **relevance**. It does NOT touch the belief field:
//! [`RerankedHit::belief`] (the BetP pignistic value the caller carries through)
//! is copied verbatim. We surface `rerank_score` + `verdict` as SEPARATE
//! metadata, never overwriting belief and never introducing a `truth_value`
//! ordering. Callers that want belief ordering re-sort on `belief`; callers
//! that want relevance ordering use the merge order. (CLAUDE.md / project
//! invariant: belief ordering uses DST pignistic_prob, never Bayesian
//! truth_value.)
//!
//! # Degradation (keyless production safety)
//! - `rerank=true` but no `RERANK_API_KEY` -> [`build_rerank_client_from_env`]
//!   returns `None`; caller skips rerank and returns the flat pool truncated to
//!   `limit` (a warn, not an error). Mirrors `build_anthropic_from_env`.
//! - gate has no `LlmProvider` -> caller skips the gate.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use epigraph_interfaces::{LlmError, LlmProvider};

/// One rerank candidate: the claim id and the text to score against the query.
#[derive(Debug, Clone)]
pub struct RerankCandidate {
    pub id: Uuid,
    pub content: String,
}

/// Relevance score for one candidate, aligned by `id` (NOT by position — a
/// rerank backend may reorder or drop). Score domain is provider-defined but
/// MUST be monotonic-in-relevance; we only ever sort by it, never threshold on
/// an absolute value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RerankScore {
    pub id: Uuid,
    pub score: f64,
}

/// Groundedness verdict for one (query, passage) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Groundedness {
    /// Passage genuinely answers / is on-topic for the query.
    Grounded,
    /// Passage shares vocabulary but does not address the query.
    Ungrounded,
}

impl Groundedness {
    #[must_use]
    pub fn is_grounded(self) -> bool {
        matches!(self, Groundedness::Grounded)
    }
}

/// A recall hit decorated with rerank + gate metadata. Generic over the
/// caller's hit type via the `belief` carry-through field, so neither the API
/// `ClaimEmbeddingHit` nor the MCP `RecallHit` needs to move into the engine.
#[derive(Debug, Clone, PartialEq)]
pub struct RerankedHit {
    pub id: Uuid,
    /// Original ANN cosine similarity (carried for transparency).
    pub similarity: f64,
    /// BetP pignistic belief carried through UNCHANGED. The merge never writes
    /// here. `None` when the caller did not supply a belief.
    pub belief: Option<f64>,
    /// Relevance score from the cross-encoder, `None` if rerank was skipped.
    pub rerank_score: Option<f64>,
    /// Groundedness verdict, `None` if the gate was skipped.
    pub verdict: Option<Groundedness>,
}

/// Error surface for the rerank/gate path. NOT folded into `EngineError`
/// because that enum is `Clone + PartialEq + Eq` and `reqwest::Error` is none
/// of those.
#[derive(Debug, thiserror::Error)]
pub enum RerankError {
    #[error("rerank HTTP request failed: {0}")]
    Http(String),
    #[error("rerank response malformed: {0}")]
    Malformed(String),
    #[error("groundedness LLM error: {0}")]
    Llm(#[from] LlmError),
    #[error("rerank feature not enabled (compile with --features rerank)")]
    FeatureDisabled,
}

// =============================================================================
// CROSS-ENCODER RERANK CLIENT
// =============================================================================

/// Pluggable cross-encoder reranker. Production impl is the env-gated HTTP
/// client; tests inject [`MockRerankClient`].
#[async_trait]
pub trait RerankClient: Send + Sync {
    /// Return a relevance score per candidate, aligned by `id`. Implementations
    /// MAY return fewer entries than candidates (dropped/timed-out items); the
    /// caller treats a missing id as `rerank_score = None`.
    async fn rerank(
        &self,
        query: &str,
        candidates: &[RerankCandidate],
    ) -> Result<Vec<RerankScore>, RerankError>;
}

/// Provider knobs for the single HTTP rerank impl. ONE struct parameterized by
/// provider rather than three near-identical Cohere/Voyage/Jina structs
/// (advisor item #6). All three speak "POST a JSON body with query+documents,
/// get back scored indices"; differences are base URL, model, and the JSON
/// field names, captured here.
#[derive(Debug, Clone)]
pub struct RerankProviderConfig {
    /// Full endpoint URL, e.g. `https://api.cohere.com/v2/rerank`.
    pub endpoint: String,
    /// Model name sent in the body, e.g. `rerank-english-v3.0`.
    pub model: String,
    /// `Authorization: Bearer <api_key>`.
    pub api_key: String,
}

impl RerankProviderConfig {
    /// Build the request body. Cohere/Voyage/Jina all accept this shape
    /// (`model`, `query`, `documents`, `top_n`).
    #[must_use]
    pub fn build_body(&self, query: &str, candidates: &[RerankCandidate]) -> serde_json::Value {
        let documents: Vec<&str> = candidates.iter().map(|c| c.content.as_str()).collect();
        serde_json::json!({
            "model": self.model,
            "query": query,
            "documents": documents,
            "top_n": candidates.len(),
        })
    }
}

/// Parse a Cohere/Voyage/Jina-style rerank response into per-id scores.
///
/// Expected shape: `{ "results": [ { "index": <usize>, "relevance_score": <f64> }, ... ] }`.
/// `index` refers back into the `candidates` slice we sent. Out-of-range
/// indices are dropped with a warn (robustness mirrors
/// `epigraph-cli`'s `parse_validation_response`). Pure fn => unit-testable
/// without a network.
///
/// # Errors
/// Returns [`RerankError::Malformed`] if `results` is not an array.
pub fn parse_rerank_response(
    json: &serde_json::Value,
    candidates: &[RerankCandidate],
) -> Result<Vec<RerankScore>, RerankError> {
    let arr = json
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RerankError::Malformed("missing `results` array".to_string()))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let idx = match item.get("index").and_then(serde_json::Value::as_u64) {
            Some(i) => i as usize,
            None => {
                tracing::warn!("rerank result missing integer `index`, skipping");
                continue;
            }
        };
        let score = match item.get("relevance_score").and_then(serde_json::Value::as_f64) {
            Some(s) => s,
            None => {
                tracing::warn!(idx, "rerank result missing `relevance_score`, skipping");
                continue;
            }
        };
        match candidates.get(idx) {
            Some(c) => out.push(RerankScore { id: c.id, score }),
            None => tracing::warn!(idx, "rerank index out of range, skipping"),
        }
    }
    Ok(out)
}

/// Env-gated HTTP rerank client. Compiles to a stub returning
/// [`RerankError::FeatureDisabled`] without `--features rerank` so the keyless
/// box still builds (mirrors `JinaProvider`'s `#[cfg(feature = "jina")]`).
pub struct HttpRerankClient {
    #[allow(dead_code)]
    config: RerankProviderConfig,
    #[cfg(feature = "rerank")]
    http: reqwest::Client,
}

impl HttpRerankClient {
    /// # Errors
    /// Returns [`RerankError::FeatureDisabled`] when built without the feature.
    pub fn new(config: RerankProviderConfig) -> Result<Self, RerankError> {
        #[cfg(not(feature = "rerank"))]
        {
            let _ = &config;
            Err(RerankError::FeatureDisabled)
        }
        #[cfg(feature = "rerank")]
        {
            let http = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| RerankError::Http(e.to_string()))?;
            Ok(Self { config, http })
        }
    }
}

#[async_trait]
impl RerankClient for HttpRerankClient {
    #[cfg(not(feature = "rerank"))]
    async fn rerank(
        &self,
        _query: &str,
        _candidates: &[RerankCandidate],
    ) -> Result<Vec<RerankScore>, RerankError> {
        Err(RerankError::FeatureDisabled)
    }

    #[cfg(feature = "rerank")]
    async fn rerank(
        &self,
        query: &str,
        candidates: &[RerankCandidate],
    ) -> Result<Vec<RerankScore>, RerankError> {
        if candidates.is_empty() {
            return Ok(vec![]);
        }
        let body = self.config.build_body(query, candidates);
        let resp = self
            .http
            .post(&self.config.endpoint)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| RerankError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(RerankError::Http(format!("HTTP {}", resp.status())));
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| RerankError::Malformed(e.to_string()))?;
        parse_rerank_response(&json, candidates)
    }
}

/// Build a rerank client from env, returning `None` when no key is present so
/// the caller degrades to flat-pool order (advisor item #5). Reads
/// `RERANK_API_KEY`, `RERANK_ENDPOINT` (default Cohere v2), `RERANK_MODEL`
/// (default `rerank-english-v3.0`). Returns `None` (not Err) on absent key;
/// `Some(Err)` only on construction failure (feature off).
#[must_use]
pub fn build_rerank_client_from_env() -> Option<Result<HttpRerankClient, RerankError>> {
    let api_key = std::env::var("RERANK_API_KEY").ok().filter(|k| !k.is_empty())?;
    let endpoint = std::env::var("RERANK_ENDPOINT")
        .unwrap_or_else(|_| "https://api.cohere.com/v2/rerank".to_string());
    let model =
        std::env::var("RERANK_MODEL").unwrap_or_else(|_| "rerank-english-v3.0".to_string());
    Some(HttpRerankClient::new(RerankProviderConfig {
        endpoint,
        model,
        api_key,
    }))
}

/// Test double: returns caller-configured scores by id.
pub struct MockRerankClient {
    scores: std::collections::HashMap<Uuid, f64>,
}

impl MockRerankClient {
    #[must_use]
    pub fn new(scores: std::collections::HashMap<Uuid, f64>) -> Self {
        Self { scores }
    }
}

#[async_trait]
impl RerankClient for MockRerankClient {
    async fn rerank(
        &self,
        _query: &str,
        candidates: &[RerankCandidate],
    ) -> Result<Vec<RerankScore>, RerankError> {
        Ok(candidates
            .iter()
            .filter_map(|c| self.scores.get(&c.id).map(|s| RerankScore { id: c.id, score: *s }))
            .collect())
    }
}

// =============================================================================
// MINICHECK-STYLE GROUNDEDNESS GATE
// =============================================================================

/// Build a MiniCheck-style query<->passage groundedness prompt. FRESH prompt
/// (NOT `epigraph-cli`'s claim<->claim `build_validation_prompt`): we ask
/// whether each passage actually addresses the QUERY, not whether two claims
/// relate. Reuses only the *pattern* (LLM returns a JSON array, one entry per
/// item, parsed with bounds checks).
#[must_use]
pub fn build_groundedness_prompt(query: &str, passages: &[RerankCandidate]) -> String {
    let mut items = String::new();
    for (i, p) in passages.iter().enumerate() {
        let text: String = p.content.chars().take(400).collect();
        items.push_str(&format!("Passage {i}:\n\"{text}\"\n\n"));
    }
    format!(
        r#"You are a groundedness judge for an information-retrieval system.
Decide, for each passage, whether it GENUINELY addresses the user's query, or
whether it merely shares vocabulary with the query while being about something
else (a false positive of embedding search).

## Query
"{query}"

## Passages
{items}## Rules
1. GROUNDED only if the passage's content bears on the query's actual subject.
2. UNGROUNDED if the connection is only shared terminology in a different context.
3. If uncertain, answer ungrounded (precision over recall).

## Output
Return ONLY a JSON array, one object per passage:
- passage_index: integer (0-based)
- grounded: boolean
Include an entry for EVERY passage."#
    )
}

/// Parse the groundedness LLM response into `(index, Groundedness)` pairs.
/// Out-of-range or malformed entries are dropped (robustness mirrors
/// `parse_validation_response`). Pure => unit-testable without an LLM.
#[must_use]
pub fn parse_groundedness_response(
    json: &serde_json::Value,
    count: usize,
) -> Vec<(usize, Groundedness)> {
    let arr = match json.as_array() {
        Some(a) => a,
        None => {
            tracing::warn!("groundedness response is not a JSON array");
            return vec![];
        }
    };
    let mut out = Vec::new();
    for item in arr {
        let idx = match item.get("passage_index").and_then(serde_json::Value::as_u64) {
            Some(i) => i as usize,
            None => continue,
        };
        if idx >= count {
            tracing::warn!(idx, count, "groundedness passage_index out of range, skipping");
            continue;
        }
        let grounded = item.get("grounded").and_then(serde_json::Value::as_bool).unwrap_or(false);
        out.push((
            idx,
            if grounded { Groundedness::Grounded } else { Groundedness::Ungrounded },
        ));
    }
    out
}

/// MiniCheck-style gate over the existing `LlmProvider` judge loop.
pub struct GroundednessGate<'a> {
    llm: &'a dyn LlmProvider,
}

impl<'a> GroundednessGate<'a> {
    #[must_use]
    pub fn new(llm: &'a dyn LlmProvider) -> Self {
        Self { llm }
    }

    /// Judge each passage; return a verdict aligned by INDEX into `passages`.
    /// Indices the LLM omitted default to `Ungrounded` (conservative: an
    /// un-judged passage is not promoted as grounded).
    ///
    /// # Errors
    /// Returns [`RerankError::Llm`] if the provider call fails.
    pub async fn judge(
        &self,
        query: &str,
        passages: &[RerankCandidate],
    ) -> Result<Vec<Groundedness>, RerankError> {
        if passages.is_empty() {
            return Ok(vec![]);
        }
        let prompt = build_groundedness_prompt(query, passages);
        let json = self.llm.complete_json(&prompt).await?;
        let parsed = parse_groundedness_response(&json, passages.len());
        let mut verdicts = vec![Groundedness::Ungrounded; passages.len()];
        for (idx, v) in parsed {
            verdicts[idx] = v;
        }
        Ok(verdicts)
    }
}

// =============================================================================
// MERGE: reorder by relevance, preserve belief
// =============================================================================

/// Merge rerank scores into the hit list and reorder by relevance DESCENDING.
///
/// CONTRACT (advisor item #3):
/// - The `belief` field of each input hit is copied to the output UNCHANGED.
/// - `rerank_score` is set ONLY from `scores` (matched by id); a hit with no
///   score keeps `rerank_score = None` and sorts AFTER all scored hits,
///   preserving its relative ANN order (stable).
/// - No `truth_value` is read or written here.
///
/// `inputs` are `(id, similarity, belief)` triples in ANN order. Pure fn =>
/// unit-testable.
#[must_use]
pub fn merge_rerank_scores(
    inputs: &[(Uuid, f64, Option<f64>)],
    scores: &[RerankScore],
) -> Vec<RerankedHit> {
    let score_by_id: std::collections::HashMap<Uuid, f64> =
        scores.iter().map(|s| (s.id, s.score)).collect();
    let mut hits: Vec<RerankedHit> = inputs
        .iter()
        .map(|(id, sim, belief)| RerankedHit {
            id: *id,
            similarity: *sim,
            belief: *belief,
            rerank_score: score_by_id.get(id).copied(),
            verdict: None,
        })
        .collect();
    // Stable sort: scored hits (desc by score) first; unscored keep ANN order.
    hits.sort_by(|a, b| match (a.rerank_score, b.rerank_score) {
        (Some(x), Some(y)) => y.partial_cmp(&x).unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    hits
}

/// Apply groundedness verdicts (aligned by id) to an already-merged hit list,
/// optionally dropping ungrounded hits. Returns the kept hits in input order.
/// `drop_ungrounded = false` annotates only (verdict surfaced, nothing removed).
#[must_use]
pub fn apply_groundedness(
    mut hits: Vec<RerankedHit>,
    verdicts: &std::collections::HashMap<Uuid, Groundedness>,
    drop_ungrounded: bool,
) -> Vec<RerankedHit> {
    for h in &mut hits {
        h.verdict = verdicts.get(&h.id).copied();
    }
    if drop_ungrounded {
        // Keep hits with no verdict (gate skipped them) and hits judged
        // Grounded; drop only those explicitly judged Ungrounded. `matches!`
        // (not `Option::map_or`) keeps the repo's MSRV lint happy.
        hits.retain(|h| matches!(h.verdict, None | Some(Groundedness::Grounded)));
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_reorders_by_relevance_not_similarity_and_keeps_belief() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // ANN order has `a` first (sim 0.9) but rerank says `b` is more relevant.
        let inputs = vec![(a, 0.9, Some(0.2_f64)), (b, 0.5, Some(0.8_f64))];
        let scores = vec![
            RerankScore { id: a, score: 0.1 },
            RerankScore { id: b, score: 0.95 },
        ];
        let out = merge_rerank_scores(&inputs, &scores);
        assert_eq!(out[0].id, b, "highest rerank score must come first");
        assert_eq!(out[1].id, a);
        // Belief carried through UNCHANGED and NOT replaced by rerank score.
        assert_eq!(out[0].belief, Some(0.8));
        assert_eq!(out[1].belief, Some(0.2));
        assert_ne!(out[0].belief, out[0].rerank_score);
    }

    #[test]
    fn merge_unscored_hits_sink_below_scored_and_keep_ann_order() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let inputs = vec![(a, 0.9, None), (b, 0.8, None), (c, 0.7, None)];
        // Only `c` gets a score; a,b are unscored and must keep ANN order a<b.
        let scores = vec![RerankScore { id: c, score: 0.5 }];
        let out = merge_rerank_scores(&inputs, &scores);
        assert_eq!(out[0].id, c);
        assert_eq!(out[1].id, a);
        assert_eq!(out[2].id, b);
    }

    #[test]
    fn parse_rerank_drops_out_of_range_index() {
        let cands = vec![RerankCandidate { id: Uuid::new_v4(), content: "x".into() }];
        let json = serde_json::json!({"results": [
            {"index": 0, "relevance_score": 0.7},
            {"index": 5, "relevance_score": 0.9}
        ]});
        let out = parse_rerank_response(&json, &cands).unwrap();
        assert_eq!(out.len(), 1, "index 5 is out of range and must be dropped");
        assert_eq!(out[0].id, cands[0].id);
    }

    #[test]
    fn parse_rerank_missing_results_is_malformed() {
        let cands: Vec<RerankCandidate> = vec![];
        let json = serde_json::json!({"oops": []});
        assert!(matches!(
            parse_rerank_response(&json, &cands),
            Err(RerankError::Malformed(_))
        ));
    }

    #[test]
    fn parse_groundedness_out_of_range_and_missing_field() {
        let json = serde_json::json!([
            {"passage_index": 0, "grounded": true},
            {"passage_index": 9, "grounded": true},
            {"passage_index": 1}
        ]);
        let out = parse_groundedness_response(&json, 2);
        // idx 9 dropped (oob); idx 1 missing `grounded` => defaults ungrounded.
        assert_eq!(out, vec![(0, Groundedness::Grounded), (1, Groundedness::Ungrounded)]);
    }

    #[test]
    fn apply_groundedness_drops_only_when_requested() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let hits = vec![
            RerankedHit { id: a, similarity: 0.9, belief: None, rerank_score: Some(0.9), verdict: None },
            RerankedHit { id: b, similarity: 0.8, belief: None, rerank_score: Some(0.8), verdict: None },
        ];
        let mut v = std::collections::HashMap::new();
        v.insert(a, Groundedness::Grounded);
        v.insert(b, Groundedness::Ungrounded);
        let annotated = apply_groundedness(hits.clone(), &v, false);
        assert_eq!(annotated.len(), 2, "drop_ungrounded=false must keep all");
        assert_eq!(annotated[1].verdict, Some(Groundedness::Ungrounded));
        let dropped = apply_groundedness(hits, &v, true);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].id, a);
    }

    #[test]
    fn http_client_without_feature_reports_disabled() {
        let r = HttpRerankClient::new(RerankProviderConfig {
            endpoint: "http://localhost".into(),
            model: "m".into(),
            api_key: "k".into(),
        });
        #[cfg(not(feature = "rerank"))]
        assert!(matches!(r, Err(RerankError::FeatureDisabled)));
        #[cfg(feature = "rerank")]
        assert!(r.is_ok());
    }
}
