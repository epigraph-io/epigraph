//! Scan settings shared by the viewer-spliced kNN reads over `claims`.
//!
//! # The two passes
//!
//! Every read here orders by a pgvector distance and applies predicates the
//! HNSW index does not encode (`is_current`, scope filters, the visibility
//! splice) AFTER the index scan. pgvector's iterative scan
//! ([`begin_iterative_hnsw`], backlog a507966d) keeps scanning past
//! `hnsw.ef_search` until `LIMIT` matching rows are found, but it still stops
//! at `hnsw.max_scan_tuples` (pgvector default 20,000) or at its memory budget
//! (`hnsw.scan_mem_multiplier` x `work_mem`). A viewer for whom more hidden
//! rows than that lie nearer the query than its own rows got a short page from
//! that first pass, or missed a near match, and the shortfall itself hinted
//! that hidden rows lie near the query (backlog 28b79b1e).
//!
//! So a read whose first pass comes back SHORT (fewer rows than the scan's
//! `LIMIT`) runs once more as an exact scan ([`begin_exact_vector_scan`]):
//! index scans are disabled for that statement, so the HNSW index cannot
//! serve it and the planner computes the distance for every row that passes
//! the predicates. A short page is the only case in which the bound can have
//! cut anything off: a full page is already the true prefix (`strict_order`
//! keeps the scan's output in exact distance order).
//!
//! A short first pass also happens for reasons that have nothing to do with
//! the bound (a scope with fewer matching rows than `LIMIT`, the end of a
//! walk), and the retry cannot tell those apart; it runs for them too. Its
//! cost is bounded: the retry carries a `statement_timeout` of at most
//! [`EXACT_RETRY_TIMEOUT_MS`] (or the caller's own timeout, if lower), and a
//! retry that times out returns the first pass's rows, i.e. exactly what the
//! read returned before this fallback existed.
//!
//! Both passes run in a transaction (a savepoint on a caller's own
//! transaction) that the caller ROLLS BACK, never commits: a released savepoint
//! would carry the `SET LOCAL` values into the caller's later reads.

use crate::errors::DbError;

/// Ceiling on the exact retry's `statement_timeout`, in milliseconds.
///
/// The exact scan reads every row that passes the read's predicates and
/// computes a distance for each, so its cost grows with the matching set. On
/// a large corpus with a broad filter it can be slow (an unindexed scan of
/// every embedded claim once ran past 30 s on a ~350k-row corpus, see
/// `ClaimRepository::semantic_search_flat`). The retry is a completeness fix,
/// not a reason for a read to hang, so it gives up after this long and keeps
/// the first pass's (possibly short) page.
pub(crate) const EXACT_RETRY_TIMEOUT_MS: i64 = 3_000;

/// Open a transaction on `conn` (a savepoint when `conn` is already in one)
/// that runs the next statement as a pgvector ITERATIVE HNSW scan: sets,
/// transaction-local, `hnsw.iterative_scan = strict_order` and
/// `hnsw.ef_search = clamp(ef_search, 40, 1000)`.
///
/// Backlog a507966d. A plain HNSW scan yields at most `ef_search` rows
/// (pgvector default 40) BEFORE the predicates the index does not encode —
/// the visibility splice among them — run, so rows a viewer cannot read
/// sitting nearer the query than its own displace the viewer's rows from the
/// result, and the size of the shortfall tells the viewer how many hidden rows
/// sit near the query. `strict_order` keeps scanning, in exact distance order,
/// until `LIMIT` matching rows are found (bounded by `hnsw.max_scan_tuples`;
/// see the module doc for the retry that covers that bound).
///
/// The caller MUST roll the returned transaction back, never commit it.
/// Harmless when the planner picks a non-HNSW plan (the 3072-d column has no
/// HNSW index).
///
/// Requires pgvector >= 0.8.0 (`hnsw.iterative_scan`).
pub(crate) async fn begin_iterative_hnsw(
    conn: &mut sqlx::PgConnection,
    ef_search: i64,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, DbError> {
    let mut tx = sqlx::Connection::begin(conn).await?;
    sqlx::query(
        "SELECT set_config('hnsw.iterative_scan', 'strict_order', true), \
                set_config('hnsw.ef_search', $1, true)",
    )
    .bind(ef_search.clamp(40, 1000).to_string())
    .execute(&mut *tx)
    .await?;
    Ok(tx)
}

/// Open a transaction on `conn` (a savepoint when `conn` is already in one)
/// that runs the next statement as an EXACT scan: transaction-local
/// `enable_indexscan = off`, so no ordering-operator index (HNSW serves only
/// those; it has no bitmap or index-only scan) can serve the `ORDER BY`
/// distance, and `enable_seqscan`, `enable_bitmapscan` and `enable_sort = on`,
/// so a session that turned those off (as the HNSW tests do) cannot leave the
/// planner with nothing but the index it was told to avoid. Bitmap scans stay
/// available, so a selective scope predicate with its own index (a label GIN,
/// a theme or date btree) still narrows the rows before any distance is
/// computed.
///
/// Also sets `statement_timeout` to the lower of the caller's own (0 = none)
/// and [`EXACT_RETRY_TIMEOUT_MS`]; see [`exact_retry_or_first_pass`].
///
/// The caller MUST roll the returned transaction back, never commit it.
pub(crate) async fn begin_exact_vector_scan(
    conn: &mut sqlx::PgConnection,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, DbError> {
    let mut tx = sqlx::Connection::begin(conn).await?;
    sqlx::query(
        "SELECT set_config('enable_indexscan', 'off', true), \
                set_config('enable_seqscan', 'on', true), \
                set_config('enable_bitmapscan', 'on', true), \
                set_config('enable_sort', 'on', true), \
                set_config('statement_timeout', \
                    (SELECT CASE WHEN s.setting::bigint = 0 THEN $1::bigint \
                                 ELSE LEAST(s.setting::bigint, $1::bigint) END \
                       FROM pg_settings s WHERE s.name = 'statement_timeout')::text, \
                    true)",
    )
    .bind(EXACT_RETRY_TIMEOUT_MS)
    .execute(&mut *tx)
    .await?;
    Ok(tx)
}

/// The result of an exact retry, given the first pass's result `first`.
///
/// A retry cancelled by `statement_timeout` (SQLSTATE 57014) yields `first`,
/// logged at WARN under `read`; any other error propagates. Call it AFTER the
/// retry's transaction has been rolled back, so the savepoint the timeout
/// aborted is gone and the connection is usable again.
pub(crate) fn exact_retry_or_first_pass<R>(
    retried: Result<R, sqlx::Error>,
    first: R,
    read: &'static str,
) -> Result<R, DbError> {
    match retried {
        Ok(rows) => Ok(rows),
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("57014") => {
            tracing::warn!(
                read,
                timeout_ms = EXACT_RETRY_TIMEOUT_MS,
                "exact kNN retry timed out; returning the iterative scan's short page"
            );
            Ok(first)
        }
        Err(e) => Err(e.into()),
    }
}
