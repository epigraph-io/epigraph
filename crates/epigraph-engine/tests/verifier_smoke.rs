//! T15: smoke test for the LLM verifier wrapper.
//!
//! Tests the mapping function (pure) and the trait shape via an in-memory
//! `FakeRerank` so we don't need an LLM endpoint or DB.

use async_trait::async_trait;
use epigraph_engine::matching::verifier::{
    map_relationship, MatchVerdict, Verdict, VerifierClient,
};
use uuid::Uuid;

struct FakeRerank;

#[async_trait]
impl VerifierClient for FakeRerank {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Verdict>> {
        Ok(pairs
            .iter()
            .map(|(a, b)| Verdict {
                source_id: *a,
                target_id: *b,
                relationship: "supports".to_string(),
                strength: 0.9,
                rationale: "ok".to_string(),
            })
            .collect())
    }
}

#[test]
fn map_relationship_covers_reranker_vocabulary() {
    assert_eq!(map_relationship("supports", 0.9), MatchVerdict::Same);
    assert_eq!(map_relationship("elaborates", 0.7), MatchVerdict::Same);
    assert_eq!(map_relationship("analogous", 0.7), MatchVerdict::Paraphrase);
    assert_eq!(map_relationship("refines", 0.7), MatchVerdict::Overlapping);
    assert_eq!(
        map_relationship("contradicts", 0.7),
        MatchVerdict::Contradicts
    );
    assert_eq!(
        map_relationship("derives_from", 0.7),
        MatchVerdict::Distinct
    );
}

#[test]
fn map_relationship_unknown_defaults_to_distinct() {
    // Conservative default: an unrecognized relationship MUST NOT be promoted
    // to `Same`/`Paraphrase` — that would silently corroborate on garbage.
    assert_eq!(
        map_relationship("unknown_rel", 0.99),
        MatchVerdict::Distinct
    );
    assert_eq!(map_relationship("", 0.5), MatchVerdict::Distinct);
    assert_eq!(map_relationship("SUPPORTS", 0.9), MatchVerdict::Distinct);
}

#[tokio::test]
async fn fake_verifier_preserves_pair_order_and_count() {
    // The trait contract: result[i] corresponds to pairs[i]. Verify with three
    // distinct pair IDs so an ordering bug would be visible.
    let pairs = vec![
        (Uuid::new_v4(), Uuid::new_v4()),
        (Uuid::new_v4(), Uuid::new_v4()),
        (Uuid::new_v4(), Uuid::new_v4()),
    ];
    let verdicts = FakeRerank.verify(&pairs).await.unwrap();
    assert_eq!(verdicts.len(), pairs.len());
    for (pair, v) in pairs.iter().zip(verdicts.iter()) {
        assert_eq!(v.source_id, pair.0);
        assert_eq!(v.target_id, pair.1);
    }
}
