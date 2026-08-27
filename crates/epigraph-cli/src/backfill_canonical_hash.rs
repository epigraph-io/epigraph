//! The drain loop behind the `backfill_canonical_hash` binary (backlog
//! e09986c2).
//!
//! Lives in the library rather than in `src/bin/` so the `--max-chunks`
//! windowing can be exercised by a DB-backed test. The binary is a thin
//! argument-parsing and reporting shell over [`drain`].

use epigraph_db::{ClaimRepository, DbError};
use sqlx::PgPool;
use uuid::Uuid;

/// Outcome of one invocation of the backfill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CanonicalBackfillPass {
    /// Rows whose `canonical_hash` this pass wrote.
    pub backfilled: u64,
    /// Rows this pass read and deliberately left NULL because their
    /// `content_hash` is namespaced or client-overridden.
    pub skipped_foreign_digest: u64,
    /// Chunks committed.
    pub chunks: u64,
    /// Where the NEXT invocation must start.
    ///
    /// `None` means the scan reached the end of the table — the pass is
    /// complete and re-invoking from the beginning is free.
    ///
    /// `Some(id)` means a `--max-chunks` budget cut the pass short, and the
    /// next invocation **must** be given this id. Restarting from `None`
    /// instead re-reads the ineligible rows already scanned: they stay NULL
    /// by design, so `WHERE canonical_hash IS NULL` does not consume them and
    /// the same prefix is returned forever. Once the ineligible rows in that
    /// prefix number `max_chunks * chunk_size` or more, the entire budget is
    /// spent on re-skips and the drain can never reach an eligible row again.
    pub resume_after: Option<Uuid>,
}

impl CanonicalBackfillPass {
    /// Whether the scan reached the end of the table.
    pub fn is_complete(&self) -> bool {
        self.resume_after.is_none()
    }
}

/// Fill `claims.canonical_hash` from `after` forward, stopping at end of scan
/// or after `max_chunks` chunks (0 = run to completion).
///
/// Pass `after = None` for a fresh full run. For a budgeted drain, thread
/// [`CanonicalBackfillPass::resume_after`] from the previous invocation back in
/// here — see that field for why restarting from `None` stalls.
///
/// # Errors
/// Returns `DbError::QueryFailed` if a chunk's query fails.
pub async fn drain(
    pool: &PgPool,
    chunk_size: i64,
    max_chunks: u64,
    after: Option<Uuid>,
) -> Result<CanonicalBackfillPass, DbError> {
    let mut pass = CanonicalBackfillPass::default();
    let mut cursor = after;

    loop {
        let chunk =
            ClaimRepository::backfill_canonical_hash_chunk(pool, chunk_size, cursor).await?;

        // Terminate on END OF SCAN, never on "this chunk wrote nothing": a
        // chunk made entirely of ineligible rows (namespaced or overridden
        // `content_hash`) writes zero and must not stop the run.
        let Some(next) = chunk.next_after else {
            pass.resume_after = None;
            return Ok(pass);
        };
        cursor = Some(next);

        pass.backfilled += chunk.updated;
        pass.skipped_foreign_digest += chunk.skipped_foreign_digest;
        pass.chunks += 1;
        tracing::info!(
            chunk = pass.chunks,
            scanned = chunk.scanned,
            rows = chunk.updated,
            skipped = chunk.skipped_foreign_digest,
            total = pass.backfilled,
            "chunk committed"
        );

        if max_chunks > 0 && pass.chunks >= max_chunks {
            pass.resume_after = Some(next);
            return Ok(pass);
        }
    }
}
