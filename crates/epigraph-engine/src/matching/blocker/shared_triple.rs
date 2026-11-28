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
    /// One statement for the whole seed set (backlog d69a4d24). It used to
    /// run one self-join per seed, and `run_pipeline` builds this blocker on
    /// every matcher run, so a sweep paid one round trip per seed even with
    /// an empty triple index.
    ///
    /// The `LATERAL` subquery keeps the per-seed semantics exactly: each
    /// seed's neighbours are `DISTINCT` and capped at `per_triple_cap` on
    /// their own, so a seed with many neighbours cannot use up another seed's
    /// share. A duplicated seed is collapsed before the query; it could only
    /// repeat pairs the final `dedup` removes.
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        let mut distinct: Vec<Uuid> = seeds.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT s.seed, n.claim_id
             FROM unnest($1::uuid[]) AS s(seed)
             CROSS JOIN LATERAL (
                 SELECT DISTINCT t2.claim_id
                 FROM triples t1
                 JOIN triples t2
                      ON t2.subject_id = t1.subject_id
                     AND t2.predicate  = t1.predicate
                     AND t2.claim_id  <> t1.claim_id
                 WHERE t1.claim_id = s.seed
                 LIMIT $2
             ) n",
        )
        .bind(&distinct)
        .bind(self.per_triple_cap as i64)
        .fetch_all(pool)
        .await?;
        let mut out: Vec<CandidatePair> = rows
            .into_iter()
            .filter_map(|(seed, n)| canonical(seed, n))
            .collect();
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }
}
