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
            let neighbors: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT c2.id
                 FROM claims c1
                 CROSS JOIN claims c2
                 WHERE c1.id = $1
                   AND c2.id <> c1.id
                   AND c1.embedding IS NOT NULL
                   AND c2.embedding IS NOT NULL
                 ORDER BY c1.embedding <=> c2.embedding ASC
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
