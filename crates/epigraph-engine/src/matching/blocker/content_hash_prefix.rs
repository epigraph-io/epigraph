//! Content-hash equality blocker — claims with identical content_hash.

use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct ContentHashBlocker;

#[async_trait]
impl Blocker for ContentHashBlocker {
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        let mut out = Vec::new();
        for &seed in seeds {
            let nbrs: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT c2.id
                 FROM claims c1
                 JOIN claims c2 ON c2.content_hash = c1.content_hash AND c2.id <> c1.id
                 WHERE c1.id = $1",
            )
            .bind(seed)
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
