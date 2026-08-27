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
//! short. No state file is needed: kill it at any point and re-invoke, and the
//! `IS NULL` predicate makes the re-scan of already-filled rows cheap. A
//! completed run writes nothing. Safe to run repeatedly, and worth running on
//! a timer while writers outside `ClaimRepository` (the raw `INSERT INTO
//! claims` in several API routes) still leave the column NULL.
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
    /// draining a large table across several maintenance windows.
    #[arg(long, default_value_t = 0)]
    max_chunks: u64,

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
        tracing::info!(rows_missing = remaining, "dry run; nothing written");
        println!("dry-run: {remaining} claims would have canonical_hash computed");
        return Ok(());
    }

    let mut total: u64 = 0;
    let mut skipped: u64 = 0;
    let mut chunks: u64 = 0;
    let mut after: Option<uuid::Uuid> = None;

    loop {
        let chunk = ClaimRepository::backfill_canonical_hash_chunk(&pool, cli.chunk_size, after)
            .await
            .context("backfill chunk")?;

        // Terminate on END OF SCAN, never on "this chunk wrote nothing": a
        // chunk made entirely of ineligible rows (namespaced or overridden
        // `content_hash`) writes zero and must not stop the run.
        let Some(next) = chunk.next_after else {
            break;
        };
        after = Some(next);

        total += chunk.updated;
        skipped += chunk.skipped_foreign_digest;
        chunks += 1;
        tracing::info!(
            chunk = chunks,
            scanned = chunk.scanned,
            rows = chunk.updated,
            skipped = chunk.skipped_foreign_digest,
            total,
            "chunk committed"
        );

        if cli.max_chunks > 0 && chunks >= cli.max_chunks {
            tracing::info!(
                max_chunks = cli.max_chunks,
                resume_after = %next,
                "chunk budget reached; stopping"
            );
            break;
        }
    }

    let left = ClaimRepository::count_missing_canonical_hash(&pool)
        .await
        .context("re-count rows missing canonical_hash")?;

    tracing::info!(
        backfilled = total,
        skipped_foreign_digest = skipped,
        chunks,
        still_null = left,
        "backfill pass complete"
    );
    println!(
        "backfilled {total} claims in {chunks} chunks; \
         skipped {skipped} with a namespaced/overridden content_hash; \
         {left} rows still NULL (skipped rows stay NULL by design)"
    );
    Ok(())
}
