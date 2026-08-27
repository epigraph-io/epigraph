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
//! # Resumability
//!
//! `WHERE canonical_hash IS NULL` is self-consuming, so the run needs no
//! cursor and no state file: kill it at any point and re-invoke, and it picks
//! up exactly where it stopped. A completed run is a no-op. Safe to run
//! repeatedly, and worth running on a timer while writers outside
//! `ClaimRepository` (the raw `INSERT INTO claims` in several API routes)
//! still leave the column NULL.
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
    let mut chunks: u64 = 0;

    loop {
        let n = ClaimRepository::backfill_canonical_hash_chunk(&pool, cli.chunk_size)
            .await
            .context("backfill chunk")?;
        if n == 0 {
            break;
        }
        total += n;
        chunks += 1;
        tracing::info!(chunk = chunks, rows = n, total, "chunk committed");

        if cli.max_chunks > 0 && chunks >= cli.max_chunks {
            tracing::info!(
                max_chunks = cli.max_chunks,
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
        chunks,
        still_missing = left,
        "backfill pass complete"
    );
    println!("backfilled {total} claims in {chunks} chunks; {left} still missing");
    Ok(())
}
