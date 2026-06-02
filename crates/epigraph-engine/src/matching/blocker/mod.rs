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

use crate::matching::calibration::EligibilityConfig;
use crate::matching::source_key::{
    derive_source_key, is_same_source, SourceFilterConfig, SourceKey,
};
use std::collections::HashMap;

/// Run all blockers on the seed set, union & dedup the results, drop pairs that
/// touch a non-substantive (ineligible) claim per `eligibility`, then drop
/// pairs whose source keys are same-source (per `cfg`).
pub async fn union_block(
    pool: &PgPool,
    blockers: &[Box<dyn Blocker>],
    seeds: &[Uuid],
    cfg: SourceFilterConfig,
    eligibility: &EligibilityConfig,
) -> Result<Vec<CandidatePair>, sqlx::Error> {
    let mut all: Vec<CandidatePair> = Vec::new();
    for b in blockers {
        all.extend(b.candidates(pool, seeds).await?);
    }
    all.sort_unstable();
    all.dedup();

    // Candidate hygiene: drop pairs touching a non-substantive claim (e.g.
    // `workflow_step` artifacts like "Body", or host `telemetry`) before the
    // more expensive per-claim source-key derivation below. Skipped when no
    // labels are excluded (`exclude_labels = []`).
    if !eligibility.exclude_labels.is_empty() {
        all = filter_ineligible(pool, all, &eligibility.exclude_labels).await?;
    }

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

/// Keep only pairs whose BOTH endpoints are eligible to match: not carrying any
/// `exclude_labels` and without a host-provenance `properties->>'event'`
/// marker. One batched query over the distinct claim ids. `COALESCE(labels,'{}')`
/// so a claim with NULL labels is treated as eligible, not excluded.
async fn filter_ineligible(
    pool: &PgPool,
    pairs: Vec<CandidatePair>,
    exclude_labels: &[String],
) -> Result<Vec<CandidatePair>, sqlx::Error> {
    let mut ids: Vec<Uuid> = pairs.iter().flat_map(|&(a, b)| [a, b]).collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Ok(pairs);
    }
    let eligible_rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM claims
         WHERE id = ANY($1)
           AND NOT (COALESCE(labels, '{}'::text[]) && $2::text[])
           AND (properties->>'event') IS NULL",
    )
    .bind(&ids)
    .bind(exclude_labels)
    .fetch_all(pool)
    .await?;
    let eligible: std::collections::HashSet<Uuid> =
        eligible_rows.into_iter().map(|(id,)| id).collect();
    Ok(pairs
        .into_iter()
        .filter(|&(a, b)| eligible.contains(&a) && eligible.contains(&b))
        .collect())
}
