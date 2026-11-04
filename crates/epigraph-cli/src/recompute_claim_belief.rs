//! The per-claim write behind the `recompute_claim_belief` binary, and the
//! wave-file record that makes a run of it reversible.
//!
//! With `--snapshot <wave file>` every claim whose cache the recompute changes
//! gets a [`WaveRecord`](crate::belief_cache::WaveRecord): the cache the run
//! found (`before`) and the cache it left (`written`). That is the file
//! `restore_belief_cache --from` reads, so the run can be rolled back by
//! compare-and-swap: a claim is put back only where it still holds exactly
//! what the run wrote (R-176: the calibration recompute is applied "sliced
//! with before/after snapshots").
//!
//! What the record covers: the seven `claims` cache columns
//! ([`CacheColumns`]), which are everything the owner-frame recompute writes
//! (`MassFunctionRepository::update_claim_belief` and
//! `update_claim_classification`; for a foreign public claim, the
//! `epigraph_foreign_belief_cache` definer writes the same columns, plus an
//! aggregate audit row a restore leaves in place). `claims.updated_at` is
//! bumped by the write and not put back. Edge-factor BBAs other claims wired
//! from a recomputed value are the follow-up re-wire's, as for every wave
//! (`restore_belief_cache`'s downstream list).

use sqlx::PgPool;
use uuid::Uuid;

use crate::belief_cache::{read_cache_columns, CacheColumns};
use crate::recompute_betp::{lock_cache, WaveLog};

/// What one claim's recompute did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimRecompute {
    /// The claim has an owner frame with input, so its cache was recomputed
    /// (the binary's `claims_recomputed`). `false`: no input, a compound, or
    /// template-only rows; the cache was left as it was.
    pub recomputed: bool,
    /// The cache columns differ from what the run found; with a wave log, the
    /// change was recorded before it committed.
    pub changed: bool,
}

/// Why one claim's recompute failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimRecomputeError {
    /// A database read, fold or write failed; nothing of this claim committed.
    Claim(String),
    /// The wave file could not be written. Nothing of this claim committed,
    /// and a later claim's record would most likely fail the same way, so a
    /// caller stops the run.
    Record(String),
}

impl std::fmt::Display for ClaimRecomputeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Claim(e) => f.write_str(e),
            Self::Record(e) => write!(f, "wave file not written, claim left unwritten: {e}"),
        }
    }
}

impl std::error::Error for ClaimRecomputeError {}

/// Recompute `claim_id`'s cached belief from its owner frame
/// (`edge_factor::recompute_claim_cached_belief`) in ONE transaction:
/// lock the claim's row, read its cache, recompute, read the cache back and,
/// when it changed and `log` is given, append and sync the
/// `{before, written}` record, then commit.
///
/// The record names the value the write produced, so it is taken after the
/// `UPDATE` and before the `COMMIT`: a write whose record cannot be written is
/// rolled back ([`ClaimRecomputeError::Record`]), so every committed write has
/// a record. The row lock keeps `before` exact: no other writer can change the
/// cache between the read and the write. A commit that fails after its record
/// was written leaves a record of a write that never landed, which a restore
/// reports `already_restored` and does not touch.
///
/// # Errors
/// See [`ClaimRecomputeError`]; the transaction is rolled back in both cases.
pub async fn recompute_claim_recorded(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    log: Option<&WaveLog>,
) -> Result<ClaimRecompute, ClaimRecomputeError> {
    use ClaimRecomputeError::{Claim, Record};
    let mut tx = pool.begin().await.map_err(|e| Claim(e.to_string()))?;
    let Some(before) = lock_cache(&mut tx, claim_id).await.map_err(Claim)? else {
        return Ok(ClaimRecompute {
            recomputed: false,
            changed: false,
        });
    };
    let recomputed =
        epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut tx, viewer, claim_id)
            .await
            .map_err(Claim)?;
    let after: CacheColumns = read_cache_columns(&mut *tx, &[claim_id])
        .await
        .map_err(|e| Claim(format!("read cache: {e}")))?
        .remove(&claim_id)
        .ok_or_else(|| {
            Claim(format!(
                "claim {claim_id} vanished inside its own transaction"
            ))
        })?;
    let changed = after != before;
    if changed {
        if let Some(log) = log {
            log.record_claim(claim_id, before, after).map_err(Record)?;
        }
    }
    tx.commit()
        .await
        .map_err(|e| Claim(format!("commit: {e}")))?;
    Ok(ClaimRecompute {
        recomputed,
        changed,
    })
}
