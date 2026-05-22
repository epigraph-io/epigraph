//! kNN over `claims.embedding` via the existing HNSW index (migration 007).

use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

/// Top-K cosine neighbors per seed.
pub struct EmbeddingAnnBlocker {
    pub top_k: usize,
}

impl EmbeddingAnnBlocker {
    pub fn new(top_k: usize) -> Self {
        Self { top_k }
    }
}

#[async_trait]
impl Blocker for EmbeddingAnnBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        if seeds.is_empty() {
            return Ok(Vec::new());
        }
        let mut out: Vec<CandidatePair> = Vec::new();
        for &seed in seeds {
            // The CROSS JOIN form (c1 × c2 with WHERE c1.id = $1) prevents
            // the planner from recognizing that c1.embedding is a constant
            // — without an index on the JOIN expression, postgres seq-scans
            // c2. Use a scalar subquery so the planner sees a literal-like
            // operand against c2's embedding and uses the HNSW index
            // (idx_claims_embedding_hnsw_cosine).
            let neighbors: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM claims
                 WHERE id <> $1
                   AND embedding IS NOT NULL
                 ORDER BY embedding <=> (SELECT embedding FROM claims WHERE id = $1)
                 LIMIT $2",
            )
            .bind(seed)
            .bind(self.top_k as i64)
            .fetch_all(pool)
            .await?;
            for (nbr,) in neighbors {
                if let Some(p) = canonical(seed, nbr) {
                    out.push(p);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }
}
