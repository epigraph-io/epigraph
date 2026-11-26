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
pub mod stance_probe;
pub mod theme_cluster;

pub type CandidatePair = (Uuid, Uuid);

#[allow(clippy::double_must_use)] // async_trait's generated #[must_use] on an already-must-use boxed future
#[async_trait]
pub trait Blocker: Send + Sync {
    /// For the given seed claim ids, return candidate pairs in canonical
    /// order (`pair.0 < pair.1`, no self-pairs, deduplicated).
    async fn candidates(
        &self,
        pool: &PgPool,
        seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error>;

    /// `true` for a probe blocker, one that searches from a rewritten query
    /// rather than from the seed's own neighbourhood (e.g.
    /// [`stance_probe::StanceProbeBlocker`]). [`union_block_with_stats`]
    /// counts a probe blocker's yield separately, so a sweep shows what the
    /// probes found that no neighbourhood blocker did.
    fn is_probe(&self) -> bool {
        false
    }
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
use std::collections::{HashMap, HashSet};

/// Recall-stage accounting for one [`union_block_with_stats`] call, so a low
/// yield can be attributed to "few pairs retrieved" versus "pairs retrieved
/// and filtered" (a04248cf). Invariant:
/// `retrieved == ineligible_dropped + same_source_dropped + kept`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockStats {
    /// Distinct canonical pairs produced by all blockers, before any filter.
    pub retrieved: usize,
    /// Dropped because an endpoint is a non-substantive claim.
    pub ineligible_dropped: usize,
    /// Dropped by the structural same-source filter (shared asserting paper,
    /// shared derivation root, or same-agent non-paper pair).
    pub same_source_dropped: usize,
    /// Distinct pairs produced by probe blockers ([`Blocker::is_probe`]),
    /// before any filter. Included in `retrieved`.
    pub probe_retrieved: usize,
    /// Of `probe_retrieved`, the pairs no non-probe blocker produced: the
    /// probes' own contribution to recall, before any filter.
    pub probe_only: usize,
    /// Of `probe_only`, the pairs that survived both filters.
    pub probe_only_kept: usize,
}

/// Everything [`union_block_detailed`] produces.
#[derive(Debug, Clone, Default)]
pub struct BlockOutcome {
    /// The surviving pairs, canonical, sorted, deduplicated.
    pub pairs: Vec<CandidatePair>,
    pub stats: BlockStats,
    /// The surviving pairs that only a probe blocker produced, so a caller can
    /// follow them through scoring.
    pub probe_only: HashSet<CandidatePair>,
}

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
    Ok(
        union_block_with_stats(pool, blockers, seeds, cfg, eligibility)
            .await?
            .0,
    )
}

/// [`union_block`], also returning how many pairs each recall-stage filter
/// dropped.
pub async fn union_block_with_stats(
    pool: &PgPool,
    blockers: &[Box<dyn Blocker>],
    seeds: &[Uuid],
    cfg: SourceFilterConfig,
    eligibility: &EligibilityConfig,
) -> Result<(Vec<CandidatePair>, BlockStats), sqlx::Error> {
    let out = union_block_detailed(pool, blockers, seeds, cfg, eligibility).await?;
    Ok((out.pairs, out.stats))
}

/// [`union_block_with_stats`], also returning which surviving pairs only a
/// probe blocker produced.
pub async fn union_block_detailed(
    pool: &PgPool,
    blockers: &[Box<dyn Blocker>],
    seeds: &[Uuid],
    cfg: SourceFilterConfig,
    eligibility: &EligibilityConfig,
) -> Result<BlockOutcome, sqlx::Error> {
    let mut all: Vec<CandidatePair> = Vec::new();
    let mut from_probe: HashSet<CandidatePair> = HashSet::new();
    let mut from_neighbourhood: HashSet<CandidatePair> = HashSet::new();
    for b in blockers {
        let found = b.candidates(pool, seeds).await?;
        if b.is_probe() {
            from_probe.extend(found.iter().copied());
        } else {
            from_neighbourhood.extend(found.iter().copied());
        }
        all.extend(found);
    }
    all.sort_unstable();
    all.dedup();
    let probe_only: HashSet<CandidatePair> = from_probe
        .difference(&from_neighbourhood)
        .copied()
        .collect();
    let mut stats = BlockStats {
        retrieved: all.len(),
        probe_retrieved: from_probe.len(),
        probe_only: probe_only.len(),
        ..BlockStats::default()
    };

    // Candidate hygiene: drop pairs touching a non-substantive claim (e.g.
    // `workflow_step` artifacts like "Body", or host `telemetry`) before the
    // more expensive per-claim source-key derivation below. Skipped when no
    // labels are excluded (`exclude_labels = []`).
    if !eligibility.exclude_labels.is_empty() {
        all = filter_ineligible(pool, all, &eligibility.exclude_labels).await?;
    }
    stats.ineligible_dropped = stats.retrieved - all.len();

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
        if is_same_source(&ka, &kb, cfg) {
            stats.same_source_dropped += 1;
        } else {
            out.push((a, b));
        }
    }
    let probe_only: HashSet<CandidatePair> = out
        .iter()
        .filter(|p| probe_only.contains(p))
        .copied()
        .collect();
    stats.probe_only_kept = probe_only.len();
    Ok(BlockOutcome {
        pairs: out,
        stats,
        probe_only,
    })
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
