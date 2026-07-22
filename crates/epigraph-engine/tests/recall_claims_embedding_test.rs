//! Regression: `epigraph_engine::recall::recall`'s semantic path must query
//! `claims.embedding`, not the permanently-empty `evidence.embedding` column.
//!
//! Before the fix, `recall` ran ANN over `EvidenceRepository::search_by_embedding`
//! (i.e. `evidence.embedding`, which is 0-populated in prod), so its semantic leg
//! always returned nothing and episcience synthesis stage-1 seeding failed with
//! "seed recall returned no claims for query" — even with a real embedder.
//!
//! This test seeds a claim whose vector lives ONLY on `claims.embedding` (evidence
//! is never populated) and asserts `recall` surfaces it via the semantic path with
//! a real cosine similarity — impossible under the old evidence-column query.

use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider, EmbeddingService};
use epigraph_engine::recall::recall;
use sqlx::PgPool;
use uuid::Uuid;

fn distinct_hash(tag: u8) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = tag;
    h
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("bb".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// `recall` must find an `is_current`, above-`min_truth` claim by the similarity
/// of its `claims.embedding` vector to the query embedding.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_semantic_path_reads_claims_embedding(pool: PgPool) {
    // Deterministic mock: embedding a fixed query text always yields the same
    // 1536-d vector, so seeding a claim with that exact vector guarantees an
    // exact-match (cosine ~1.0) semantic hit.
    let mock = MockProvider::new(EmbeddingConfig::openai(1536));
    let query = "mechanosynthesis tooltip chemistry";
    let qvec = mock.generate_query(query).await.expect("mock embed");
    let pgvec = format!(
        "[{}]",
        qvec.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    let agent = seed_agent(&pool).await;
    let claim_id = Uuid::new_v4();
    // Vector on claims.embedding only; evidence.embedding is never populated, so
    // the pre-fix evidence-column search cannot return this claim. truth_value 0.9
    // clears the recall min_truth gate (0.5 below).
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, embedding, is_current) \
         VALUES ($1, $2, $3, $4, 0.9, $5::vector, true)",
    )
    .bind(claim_id)
    .bind("mechanosynthesis tooltip chemistry and molecular manufacturing")
    .bind(distinct_hash(1))
    .bind(agent)
    .bind(&pgvec)
    .execute(&pool)
    .await
    .expect("seed claim with claims.embedding vector");

    let results = recall(&pool, &mock, query, 10, 0.5)
        .await
        .expect("recall must not error");

    let hit = results
        .iter()
        .find(|r| r.claim_id == claim_id.to_string())
        .unwrap_or_else(|| {
            panic!(
                "recall must surface the seeded claim via claims.embedding; got {} \
                 result(s) — a pre-fix evidence.embedding search returns 0",
                results.len()
            )
        });

    // Guard against a lexical-fallback false positive: the semantic path yields a
    // real cosine (~1.0 for the exact-match vector); the ILIKE fallback hard-codes
    // similarity 0.0.
    assert!(
        hit.similarity > 0.5,
        "hit must come from the semantic (claims.embedding) path, not the lexical \
         fallback; similarity was {}",
        hit.similarity
    );
}
