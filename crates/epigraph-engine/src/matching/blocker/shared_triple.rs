//! Shared-triple blocker — claims with overlapping (subject_id, predicate).

use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct SharedTripleBlocker {
    pub per_triple_cap: usize,
}

impl SharedTripleBlocker {
    pub fn new(per_triple_cap: usize) -> Self {
        Self { per_triple_cap }
    }
}

#[async_trait]
impl Blocker for SharedTripleBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        let mut out = Vec::new();
        for &seed in seeds {
            let nbrs: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT DISTINCT t2.claim_id
                 FROM triples t1
                 JOIN triples t2
                      ON t2.subject_id = t1.subject_id
                     AND t2.predicate  = t1.predicate
                     AND t2.claim_id  <> t1.claim_id
                 WHERE t1.claim_id = $1
                 LIMIT $2",
            )
            .bind(seed)
            .bind(self.per_triple_cap as i64)
            .fetch_all(pool)
            .await?;
            for (n,) in nbrs {
                if let Some(p) = canonical(seed, n) {
                    out.push(p);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }
}
