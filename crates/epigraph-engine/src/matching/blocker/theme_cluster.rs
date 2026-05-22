//! Co-theme blocker — claims that share a `claims.theme_id`.

use super::{canonical, Blocker, CandidatePair};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct ThemeClusterBlocker {
    pub per_theme_cap: usize,
}

impl ThemeClusterBlocker {
    pub fn new(per_theme_cap: usize) -> Self {
        Self { per_theme_cap }
    }
}

#[async_trait]
impl Blocker for ThemeClusterBlocker {
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
                 JOIN claims c2 ON c2.theme_id = c1.theme_id AND c2.id <> c1.id
                 WHERE c1.id = $1 AND c1.theme_id IS NOT NULL
                 LIMIT $2",
            )
            .bind(seed)
            .bind(self.per_theme_cap as i64)
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
