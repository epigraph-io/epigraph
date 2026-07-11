//! `dedup_execute` — the write-path companion to `dedup_sizing`: actually
//! retires Tier 1 exact-`content_hash` duplicates via
//! `ClaimRepository::mark_duplicate` (soft-retire: `is_current=false` +
//! `embedding=NULL` on the duplicate, `supersedes` pointed at the canonical,
//! canonical claim itself untouched — never a hard delete).
//!
//! Deliberately does NOT touch Tier 2 (semantic-similarity) matches —
//! `dedup_sizing` confirmed those carry real false-positive risk even above
//! 0.95 cosine similarity on this corpus's templated content, so only exact
//! `content_hash` equality (byte-identical text) is treated as safe for
//! unattended execution here.
//!
//! Defaults to a dry run (prints what WOULD be marked, writes nothing).
//! Pass `--execute` to actually call `mark_duplicate`.
//!
//! Usage: dedup_execute --limit 500 [--offset 0] [--agent-id UUID] [--execute]

use clap::Parser;
use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "dedup_execute",
    about = "Retire Tier 1 exact-content_hash duplicate claims via mark_duplicate (dry-run by default)"
)]
struct Cli {
    /// Undecomposed claims to check this run (paginate with --offset for larger sweeps).
    #[arg(long, default_value_t = 500)]
    limit: i64,
    /// Skip the first N undecomposed claims (oldest-first, matches list_undecomposed ordering).
    #[arg(long, default_value_t = 0)]
    offset: i64,
    /// Restrict to a single agent_id.
    #[arg(long)]
    agent_id: Option<Uuid>,
    /// Actually call mark_duplicate. Without this flag, only prints what
    /// would happen — no writes.
    #[arg(long, default_value_t = false)]
    execute: bool,
}

// Identical predicate to dedup_sizing / ClaimRepository::list_undecomposed,
// so this tool's window matches exactly what was sized.
const UNDECOMPOSED_PREDICATE: &str = r#"
    c.is_current = true
    AND length(c.content) > 10
    AND NOT ('telemetry' = ANY(c.labels))
    AND (c.properties ->> 'event') IS NULL
    AND ($3::uuid IS NULL OR c.agent_id = $3)
    AND NOT EXISTS (
        SELECT 1 FROM edges e
        WHERE e.source_id = c.id AND e.relationship = 'decomposes_to'
    )
    AND NOT EXISTS (
        SELECT 1 FROM edges e
        WHERE e.target_id = c.id AND e.relationship = 'decomposes_to'
    )
"#;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let pool = epigraph_cli::db_connect().await?;

    if !cli.execute {
        println!("DRY RUN (pass --execute to actually retire duplicates) — no writes will occur");
    }

    let tier1_query = format!(
        r#"
        WITH undecomposed AS (
            SELECT c.id, c.content, c.content_hash
            FROM claims c
            WHERE {UNDECOMPOSED_PREDICATE}
            ORDER BY c.created_at ASC
            LIMIT $1 OFFSET $2
        ),
        decomposed_participant AS (
            SELECT DISTINCT c.id, c.content_hash
            FROM claims c
            WHERE c.is_current = true
              AND (
                  EXISTS (SELECT 1 FROM edges e WHERE e.source_id = c.id AND e.relationship = 'decomposes_to')
                  OR EXISTS (SELECT 1 FROM edges e WHERE e.target_id = c.id AND e.relationship = 'decomposes_to')
              )
        )
        SELECT DISTINCT ON (u.id) u.id, u.content, d.id
        FROM undecomposed u
        JOIN decomposed_participant d ON d.content_hash = u.content_hash
        ORDER BY u.id, d.id
        "#
    );
    let matches: Vec<(Uuid, String, Uuid)> = sqlx::query_as(&tier1_query)
        .bind(cli.limit)
        .bind(cli.offset)
        .bind(cli.agent_id)
        .fetch_all(&pool)
        .await?;

    let total = matches.len();
    println!(
        "window: limit={} offset={} agent_id={:?} — {} Tier 1 exact-hash matches to process",
        cli.limit, cli.offset, cli.agent_id, total
    );

    let mut retired = 0usize;
    let mut skipped_already_superseded = 0usize;
    let mut failed = 0usize;

    for (i, (dup_id, content, canonical_id)) in matches.iter().enumerate() {
        if !cli.execute {
            println!(
                "[{}/{total}] WOULD RETIRE {dup_id} -> canonical {canonical_id}: {}",
                i + 1,
                truncate(content, 100)
            );
            continue;
        }

        match ClaimRepository::mark_duplicate(
            &pool,
            ClaimId::from_uuid(*dup_id),
            ClaimId::from_uuid(*canonical_id),
        )
        .await
        {
            Ok(()) => {
                retired += 1;
                if retired.is_multiple_of(100) {
                    println!("[{}/{total}] retired {retired} so far...", i + 1);
                }
            }
            Err(e) if e.to_string().contains("already superseded") => {
                skipped_already_superseded += 1;
            }
            Err(e) => {
                failed += 1;
                eprintln!("FAILED {dup_id} -> {canonical_id}: {e}");
            }
        }
    }

    println!("---");
    if cli.execute {
        println!(
            "retired: {retired}, already-superseded (skipped, idempotent re-run): \
             {skipped_already_superseded}, failed: {failed}, total considered: {total}"
        );
    } else {
        println!("dry run complete — {total} would be retired. Re-run with --execute to apply.");
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{truncated}…")
    }
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        assert_eq!(truncate("hello world", 5), "hello…");
    }
}
