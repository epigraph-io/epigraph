//! Co-cluster blocker — claims in the same `claim_clusters.cluster_id`.

use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct CompoundNbhdBlocker {
    pub per_cluster_cap: usize,
}

impl CompoundNbhdBlocker {
    pub fn new(per_cluster_cap: usize) -> Self {
        Self { per_cluster_cap }
    }
}

#[async_trait]
impl Blocker for CompoundNbhdBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        let mut out = Vec::new();
        for &seed in seeds {
            let nbrs: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT cc2.claim_id
                 FROM claim_clusters cc1
                 JOIN claim_clusters cc2
                      ON cc2.cluster_id = cc1.cluster_id
                     AND cc2.claim_id <> cc1.claim_id
                 WHERE cc1.claim_id = $1
                 LIMIT $2",
            )
            .bind(seed)
            .bind(self.per_cluster_cap as i64)
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
