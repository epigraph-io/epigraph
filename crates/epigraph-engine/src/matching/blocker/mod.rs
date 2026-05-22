//! Candidate-pair generators for the matcher.
//!
//! Each strategy implements [`Blocker::candidates`] and returns pairs in
//! canonical order (`pair.0 < pair.1`, no self-pairs). The pipeline unions
//! results from multiple strategies before scoring.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub mod compound_nbhd;
pub mod content_hash_prefix;
pub mod embedding_ann;
pub mod shared_triple;
pub mod theme_cluster;

pub type CandidatePair = (Uuid, Uuid);

#[async_trait]
pub trait Blocker: Send + Sync {
    /// For the given seed claim ids, return candidate pairs in canonical
    /// order (`pair.0 < pair.1`, no self-pairs, deduplicated).
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error>;
}

/// Build a canonical-ordered pair, or `None` if `a == b`.
pub fn canonical(a: Uuid, b: Uuid) -> Option<CandidatePair> {
    if a == b {
        None
    } else if a < b {
        Some((a, b))
    } else {
        Some((b, a))
    }
}

use crate::matching::source_key::{
    derive_source_key, is_same_source, SourceFilterConfig, SourceKey,
};
use std::collections::HashMap;

/// Run all blockers on the seed set, union & dedup the results, then drop
/// pairs whose source keys are same-source (per `cfg`).
pub async fn union_block(
    pool: &PgPool,
    blockers: &[Box<dyn Blocker>],
    seeds: &[Uuid],
    cfg: SourceFilterConfig,
) -> Result<Vec<CandidatePair>, sqlx::Error> {
    let mut all: Vec<CandidatePair> = Vec::new();
    for b in blockers {
        all.extend(b.candidates(pool, seeds).await?);
    }
    all.sort_unstable();
    all.dedup();

    let mut keys: HashMap<Uuid, SourceKey> = HashMap::new();
    let mut out = Vec::with_capacity(all.len());
    for (a, b) in all {
        let ka = match keys.get(&a) {
            Some(k) => k.clone(),
            None => {
                let k = derive_source_key(pool, a).await?;
                keys.insert(a, k.clone());
                k
            }
        };
        let kb = match keys.get(&b) {
            Some(k) => k.clone(),
            None => {
                let k = derive_source_key(pool, b).await?;
                keys.insert(b, k.clone());
                k
            }
        };
        if !is_same_source(&ka, &kb, cfg) {
            out.push((a, b));
        }
    }
    Ok(out)
}
