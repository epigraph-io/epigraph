//! Backfill `claims.canonical_hash` for rows written before migration 061
//! (backlog e09986c2).
//!
//! # Why a binary rather than a migration
//!
//! `canonical_hash` is BLAKE3 over NFC-normalized, zero-width-stripped,
//! whitespace-collapsed text. Neither BLAKE3 nor NFC exists as a stock
//! PostgreSQL function, so migration 061 can only ADD the nullable column —
//! there is no `DEFAULT` and no `UPDATE ... SET canonical_hash = <expr>` that
//! could fill it. The digest must be computed by the very same
//! `ContentHasher::hash_canonical_text` the write path calls, or the
//! backfilled value would be one the write path never reproduces and the
//! lookup would silently never match.
//!
//! # What it changes and what it does not
//!
//! Writes exactly one column. `content`, `content_hash`, `updated_at`,
//! embeddings, labels, and `is_current` are untouched — this is not a
//! rewrite of claim text and it must never become one. Because
//! `canonical_hash` carries no UNIQUE constraint, filling it can never fail a
//! row: pre-existing cosmetic duplicate PAIRS simply end up sharing a value,
//! and `create_or_get` collapses future submissions onto whichever it finds.
//!
//! # What it deliberately leaves NULL
//!
//! Only rows whose `content_hash` IS the plain BLAKE3 of their `content` get a
//! canonical twin — the same rule the write path applies. Document-scoped
//! spine nodes (whose digest is namespaced by their host artifact) and rows
//! created through the `content_hash` override on `POST /api/v1/claims` are
//! SKIPPED and stay NULL forever. Filling them from their bare text would give
//! two papers' "Introduction" one lookup key, which is exactly the collision
//! the namespacing exists to prevent. Consequently `still NULL` does not trend
//! to zero: it settles at that population, which the run reports separately as
//! `skipped`.
//!
//! # Resumability
//!
//! Keyset-paged on `id`, because `WHERE canonical_hash IS NULL` is no longer
//! self-consuming — a skipped row stays NULL and would otherwise be re-read
//! forever. Termination is on END OF SCAN, never on "this chunk wrote
//! nothing", so a chunk made entirely of skipped rows cannot cut the run
//! short.
//!
//! An UNBUDGETED run (`--max-chunks 0`, the default) needs no state: it always
//! runs to end of scan, so kill it at any point and re-invoke from scratch —
//! the `IS NULL` predicate makes the re-scan of already-filled rows cheap and
//! a completed run writes nothing.
//!
//! A BUDGETED run (`--max-chunks N`) must carry its cursor forward. It stops
//! mid-table, and the ineligible rows it already scanned stay NULL, so a fresh
//! `--max-chunks N` invocation re-reads that same prefix. Once the ineligible
//! rows behind the cursor number `N * chunk_size` or more, the whole budget is
//! spent re-skipping them and no eligible row is ever reached again. The run
//! therefore prints its resume point, and the next invocation must pass it:
//!
//! ```text
//! backfill_canonical_hash --chunk-size 5000 --max-chunks 20
//! # -> resume the next window with: --after 0190f3c2-...-8a41
//! backfill_canonical_hash --chunk-size 5000 --max-chunks 20 --after 0190f3c2-...-8a41
//! ```
//!
//! Worth running on a timer while writers outside `ClaimRepository` (the raw
//! `INSERT INTO claims` in several API routes) still leave the column NULL.
//!
//! # Until it runs
//!
//! A cosmetic variant of a legacy row still misses the dedup lookup —
//! precisely the behaviour before migration 061, never worse for anyone.
//!
//! ```text
//! backfill_canonical_hash --dry-run
//! backfill_canonical_hash --chunk-size 5000
//! ```

use anyhow::Context;
use clap::Parser;
use epigraph_cli::backfill_canonical_hash::drain;
use epigraph_db::ClaimRepository;

#[derive(Parser, Debug)]
#[command(
    name = "backfill_canonical_hash",
    about = "Compute claims.canonical_hash for rows that predate migration 061"
)]
struct Cli {
    /// PostgreSQL connection URL.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Rows per UPDATE. Each chunk is one atomic statement, so this trades
    /// round-trips against lock duration on `claims`.
    #[arg(long, default_value_t = 1000)]
    chunk_size: i64,

    /// Stop after this many chunks (0 = run to completion). Useful for
    /// draining a large table across several maintenance windows. A run
    /// stopped by this budget prints an `--after` cursor that the NEXT window
    /// must be given.
    #[arg(long, default_value_t = 0)]
    max_chunks: u64,

    /// Resume the keyset scan strictly after this claim id, as printed by a
    /// previous `--max-chunks` run.
    ///
    /// Required to make windowed draining progress: rows this tool skips stay
    /// NULL by design, so a fresh scan re-reads them every time and a budget
    /// smaller than the accumulated skip prefix never reaches a new row.
    #[arg(long)]
    after: Option<uuid::Uuid>,

    /// Report how many rows WOULD be backfilled without writing anything.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();

    anyhow::ensure!(cli.chunk_size > 0, "--chunk-size must be positive");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&cli.database_url)
        .await
        .context("connect to database")?;

    let remaining = ClaimRepository::count_missing_canonical_hash(&pool)
        .await
        .context("count rows missing canonical_hash")?;

    if cli.dry_run {
        // `remaining` is an UPPER BOUND, not the work: rows with a namespaced
        // or client-overridden `content_hash` are counted by this query (SQL
        // cannot express the eligibility rule — BLAKE3 has no Postgres
        // function) but are deliberately never filled. Reporting it as the
        // figure a real run would achieve would promise a `backfilled N` line
        // that can never arrive.
        tracing::info!(rows_missing = remaining, "dry run; nothing written");
        println!("dry-run: {remaining} claims have canonical_hash IS NULL.");
        println!(
            "  That is an UPPER BOUND, not the work: rows with a namespaced or \
             client-overridden content_hash are counted here but are never \
             filled, so a real run's `backfilled N` will be lower."
        );
        return Ok(());
    }

    let pass = drain(&pool, cli.chunk_size, cli.max_chunks, cli.after)
        .await
        .context("drain canonical_hash backfill")?;

    let left = ClaimRepository::count_missing_canonical_hash(&pool)
        .await
        .context("re-count rows missing canonical_hash")?;

    let (total, skipped, chunks) = (pass.backfilled, pass.skipped_foreign_digest, pass.chunks);
    tracing::info!(
        backfilled = total,
        skipped_foreign_digest = skipped,
        chunks,
        still_null = left,
        complete = pass.is_complete(),
        "backfill pass complete"
    );

    match pass.resume_after {
        // Budget cut the scan short. The cursor is the only thing that lets
        // the next window make progress, so it goes to stdout — not just to
        // the log — and `left` is NOT attributed to skips, since most of it is
        // simply unscanned.
        Some(next) => {
            tracing::info!(
                max_chunks = cli.max_chunks,
                resume_after = %next,
                "chunk budget reached; stopping"
            );
            println!(
                "backfilled {total} claims in {chunks} chunks; \
                 skipped {skipped} with a namespaced/overridden content_hash; \
                 {left} rows still NULL. Chunk budget reached before end of \
                 table — resume the next window with: --after {next}"
            );
        }
        None => println!(
            "backfilled {total} claims in {chunks} chunks; \
             skipped {skipped} with a namespaced/overridden content_hash; \
             scan reached end of table; \
             {left} rows still NULL (skipped rows stay NULL by design)"
        ),
    }
    Ok(())
}
