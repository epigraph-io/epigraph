use std::collections::HashMap;
use uuid::Uuid;
use async_trait::async_trait;
use epigraph_interfaces::{LlmError, LlmProvider};
use epigraph_engine::rerank::{
    apply_groundedness, merge_rerank_scores, GroundednessGate, Groundedness, MockRerankClient,
    RerankCandidate, RerankClient, RerankScore,
};

/// Minimal in-test LlmProvider that returns a fixed groundedness JSON array.
struct FixedGate(serde_json::Value);
#[async_trait]
impl LlmProvider for FixedGate {
    fn name(&self) -> &str { "fixed" }
    fn model_name(&self) -> &str { "fixed" }
    fn is_active(&self) -> bool { true }
    async fn complete_json(&self, _p: &str) -> Result<serde_json::Value, LlmError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn pipeline_reranks_then_gates_dropping_ungrounded_relevant_hit() {
    let relevant_but_ungrounded = Uuid::new_v4();
    let relevant_grounded = Uuid::new_v4();
    let irrelevant = Uuid::new_v4();
    let cands = vec![
        RerankCandidate { id: irrelevant, content: "unrelated boilerplate".into() },
        RerankCandidate { id: relevant_but_ungrounded, content: "shares words only".into() },
        RerankCandidate { id: relevant_grounded, content: "directly answers the query".into() },
    ];
    // Cross-encoder ranks the two 'relevant' ones above the irrelevant one,
    // and puts the ungrounded-but-vocabulary-matching one HIGHEST (the exact
    // failure mode the gate must catch).
    let mut scores = HashMap::new();
    scores.insert(relevant_but_ungrounded, 0.95);
    scores.insert(relevant_grounded, 0.80);
    scores.insert(irrelevant, 0.10);
    let client = MockRerankClient::new(scores);
    let rscores: Vec<RerankScore> = client.rerank("the query", &cands).await.unwrap();

    let inputs: Vec<(Uuid, f64, Option<f64>)> = vec![
        (irrelevant, 0.50, Some(0.4)),
        (relevant_but_ungrounded, 0.49, Some(0.6)),
        (relevant_grounded, 0.48, Some(0.7)),
    ];
    let merged = merge_rerank_scores(&inputs, &rscores);
    // Relevance order: ungrounded(0.95) > grounded(0.80) > irrelevant(0.10).
    assert_eq!(merged[0].id, relevant_but_ungrounded);
    assert_eq!(merged[1].id, relevant_grounded);
    assert_eq!(merged[2].id, irrelevant);
    // Belief preserved per-id (NOT reordered onto the wrong row).
    assert_eq!(merged[0].belief, Some(0.6));
    assert_eq!(merged[1].belief, Some(0.7));

    // Gate (over the LLM-judge loop) says the top-ranked passage is ungrounded.
    let gate_json = serde_json::json!([
        {"passage_index": 0, "grounded": false},  // relevant_but_ungrounded (now index 0 after merge)
        {"passage_index": 1, "grounded": true},   // relevant_grounded
        {"passage_index": 2, "grounded": false}   // irrelevant
    ]);
    let llm = FixedGate(gate_json);
    let gate = GroundednessGate::new(&llm);
    let top: Vec<RerankCandidate> = merged.iter().map(|h| RerankCandidate {
        id: h.id, content: "x".into()
    }).collect();
    let verdicts = gate.judge("the query", &top).await.unwrap();
    let vmap: HashMap<Uuid, Groundedness> = top.iter().map(|c| c.id).zip(verdicts).collect();

    let kept = apply_groundedness(merged, &vmap, true);
    // The high-relevance-but-ungrounded hit is DROPPED; only the grounded one survives.
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].id, relevant_grounded);
    assert_eq!(kept[0].verdict, Some(Groundedness::Grounded));
    // Belief on the survivor is still its own, untouched.
    assert_eq!(kept[0].belief, Some(0.7));
}
