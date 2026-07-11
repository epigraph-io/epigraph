//! `dedup_sizing` — dry-run measurement of Task 4.5's textbook-duplicate
//! hypothesis: how many claims in the undecomposed backlog are actually
//! content-duplicates of claims that already have decomposed atoms elsewhere
//! in the graph (confirmed pattern: claim 25907a10 duplicates atom 20421580,
//! a decomposes_to child of a different compound claim from the same agent,
//! f741ab67).
//!
//! Read-only: never calls mark_duplicate, never writes anything. Reuses the
//! exact "undecomposed" definition from `ClaimRepository::list_undecomposed`
//! (NOT EXISTS a decomposes_to edge as source or target).
//!
//! Two tiers, deliberately not conflated:
//!
//! - **Tier 1 (exact, safe):** `content_hash` equality against claims that
//!   already participate in a `decomposes_to` edge. Byte-identical text,
//!   zero embeddings involved, zero false-positive risk — the ONLY tier this
//!   tool considers safe enough for unattended `mark_duplicate` at scale.
//! - **Tier 2 (approximate, needs review):** for the remainder (no exact-hash
//!   match), nearest-neighbor cosine similarity on each claim's EXISTING
//!   embedding (no re-embedding, no OPENAI_API_KEY needed — the embedding-
//!   policy invariant in CLAUDE.md guarantees every current non-telemetry
//!   claim already has one) against claims already on a `decomposes_to` edge.
//!   CONFIRMED FALSE POSITIVES observed even at similarity 0.95-0.96 on this
//!   corpus's heavily-templated content (e.g. building-code claims that
//!   share nearly all wording but differ in the one number that matters —
//!   "TMS 403" vs "TMS 402", "1 hour" vs "2 hours" fire ratings for different
//!   construction types). Report only; do not treat Tier 2 output as
//!   actionable duplicates without a stronger discriminating signal or human
//!   review of each pair.
//!
//! Usage: dedup_sizing --limit 500 [--offset 0] [--agent-id UUID]
//!        [--min-similarity 0.85] [--neighbor-pool 20] [--skip-tier2]

use clap::Parser;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "dedup_sizing",
    about = "Dry-run: size how much of the undecomposed backlog duplicates already-decomposed claims"
)]
struct Cli {
    /// Undecomposed claims to check this run (paginate with --offset for larger sweeps).
    #[arg(long, default_value_t = 500)]
    limit: i64,
    /// Skip the first N undecomposed claims (oldest-first, matches list_undecomposed ordering).
    #[arg(long, default_value_t = 0)]
    offset: i64,
    /// Restrict to a single agent_id (e.g. the confirmed Cluster A agent f741ab67-...).
    #[arg(long)]
    agent_id: Option<Uuid>,
    /// Tier 2 minimum cosine similarity to report a match (0.0-1.0). Treat as
    /// approximate — confirmed false positives observed at 0.95-0.96 on
    /// templated building-code content.
    #[arg(long, default_value_t = 0.85)]
    min_similarity: f64,
    /// Tier 2 nearest-neighbor candidate pool size per claim, before
    /// filtering for decomposes_to participation. Larger = more thorough,
    /// slower.
    #[arg(long, default_value_t = 20)]
    neighbor_pool: i64,
    /// Skip Tier 2 (semantic similarity) entirely and report only the exact
    /// content_hash tier — much faster, useful for a quick safe-floor number.
    #[arg(long, default_value_t = false)]
    skip_tier2: bool,
}

struct ExactMatch {
    undecomposed_id: Uuid,
    undecomposed_content: String,
    match_id: Uuid,
}

struct SimilarMatch {
    undecomposed_id: Uuid,
    undecomposed_content: String,
    undecomposed_agent_id: Uuid,
    match_id: Uuid,
    match_content: String,
    similarity: f64,
}

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

// Shared "undecomposed" predicate, copied verbatim from
// ClaimRepository::list_undecomposed so this tool's window matches exactly
// what decompose_claims itself would pick up.
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

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let pool = epigraph_cli::db_connect().await?;

    let window_query = format!(
        "SELECT c.id, c.embedding IS NOT NULL AS has_embedding \
         FROM claims c WHERE {UNDECOMPOSED_PREDICATE} \
         ORDER BY c.created_at ASC LIMIT $1 OFFSET $2"
    );
    let windowed: Vec<(Uuid, bool)> = sqlx::query_as(&window_query)
        .bind(cli.limit)
        .bind(cli.offset)
        .bind(cli.agent_id)
        .fetch_all(&pool)
        .await?;

    let checked = windowed.len();
    let missing_embedding = windowed.iter().filter(|(_, has)| !has).count();

    // Tier 1: exact content_hash match against anything already on a
    // decomposes_to edge. Deterministic, no embeddings involved.
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
    let tier1: Vec<ExactMatch> = sqlx::query_as::<_, (Uuid, String, Uuid)>(&tier1_query)
        .bind(cli.limit)
        .bind(cli.offset)
        .bind(cli.agent_id)
        .fetch_all(&pool)
        .await?
        .into_iter()
        .map(
            |(undecomposed_id, undecomposed_content, match_id)| ExactMatch {
                undecomposed_id,
                undecomposed_content,
                match_id,
            },
        )
        .collect();

    for m in &tier1 {
        println!(
            "[TIER1 exact] {} DUPLICATES-OF {}",
            m.undecomposed_id, m.match_id
        );
        println!("  content: {}", truncate(&m.undecomposed_content, 160));
    }

    println!("---");
    println!(
        "window: limit={} offset={} agent_id={:?}",
        cli.limit, cli.offset, cli.agent_id
    );
    println!("undecomposed claims checked: {checked}");
    println!(
        "TIER 1 (exact content_hash match, safe): {} ({:.1}% of window)",
        tier1.len(),
        pct(tier1.len(), checked)
    );

    if cli.skip_tier2 {
        println!("(Tier 2 skipped via --skip-tier2)");
        return Ok(());
    }

    if missing_embedding > 0 {
        println!(
            "WARNING: {missing_embedding} of {checked} lack an embedding (violates embedding-policy \
             invariant) and were skipped from Tier 2 similarity search entirely"
        );
    }

    // Tier 2: for the remainder (no exact-hash match), nearest-neighbor
    // cosine similarity against claims already on a decomposes_to edge.
    let tier2_query = format!(
        r#"
        WITH undecomposed AS (
            SELECT c.id, c.content, c.agent_id, c.content_hash, c.embedding, c.created_at
            FROM claims c
            WHERE {UNDECOMPOSED_PREDICATE}
              AND c.embedding IS NOT NULL
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
        ),
        remainder AS (
            SELECT u.* FROM undecomposed u
            WHERE NOT EXISTS (
                SELECT 1 FROM decomposed_participant d WHERE d.content_hash = u.content_hash
            )
        ),
        candidates AS (
            SELECT
                u.id AS undecomposed_id,
                u.content AS undecomposed_content,
                u.agent_id AS undecomposed_agent_id,
                nn.id AS match_id,
                nn.content AS match_content,
                nn.similarity
            FROM remainder u
            CROSS JOIN LATERAL (
                SELECT c2.id, c2.content,
                       1 - (c2.embedding <=> u.embedding) AS similarity
                FROM claims c2
                WHERE c2.embedding IS NOT NULL
                  AND c2.is_current = true
                  AND c2.id <> u.id
                ORDER BY c2.embedding <=> u.embedding
                LIMIT $4
            ) nn
            WHERE nn.similarity >= $5
              AND EXISTS (
                  SELECT 1 FROM edges e
                  WHERE e.relationship = 'decomposes_to'
                    AND (e.source_id = nn.id OR e.target_id = nn.id)
              )
        )
        SELECT DISTINCT ON (undecomposed_id)
            undecomposed_id, undecomposed_content, undecomposed_agent_id,
            match_id, match_content, similarity
        FROM candidates
        ORDER BY undecomposed_id, similarity DESC
        "#
    );
    let tier2_raw: Vec<(Uuid, String, Uuid, Uuid, String, f64)> = sqlx::query_as(&tier2_query)
        .bind(cli.limit)
        .bind(cli.offset)
        .bind(cli.agent_id)
        .bind(cli.neighbor_pool)
        .bind(cli.min_similarity)
        .fetch_all(&pool)
        .await?;

    let mut tier2: Vec<SimilarMatch> = tier2_raw
        .into_iter()
        .map(
            |(
                undecomposed_id,
                undecomposed_content,
                undecomposed_agent_id,
                match_id,
                match_content,
                similarity,
            )| SimilarMatch {
                undecomposed_id,
                undecomposed_content,
                undecomposed_agent_id,
                match_id,
                match_content,
                similarity,
            },
        )
        .collect();
    tier2.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());

    for m in &tier2 {
        println!(
            "[TIER2 similar {:.4}] {} (agent {}) POSSIBLE-DUPLICATE-OF {} — NEEDS REVIEW",
            m.similarity, m.undecomposed_id, m.undecomposed_agent_id, m.match_id
        );
        println!("  undecomposed: {}", truncate(&m.undecomposed_content, 160));
        println!("  match:        {}", truncate(&m.match_content, 160));
    }

    let remainder_checked = checked - tier1.len() - missing_embedding;
    println!("---");
    println!(
        "TIER 2 (semantic similarity >= {:.2} on the {} claims with no Tier 1 match, \
         APPROXIMATE — do not act on without review): {} ({:.1}% of that remainder)",
        cli.min_similarity,
        remainder_checked,
        tier2.len(),
        pct(tier2.len(), remainder_checked)
    );
    println!(
        "note: Tier 2 only checks the top {} nearest neighbors per claim for decomposes_to \
         participation (a true match ranked outside that pool is missed), and is known to \
         include false positives on templated content (same wording, different number/value) \
         even above 0.95 similarity — treat as a lead list for human review, not a duplicate list",
        cli.neighbor_pool
    );

    Ok(())
}

fn pct(n: usize, total: usize) -> f64 {
    if total > 0 {
        100.0 * n as f64 / total as f64
    } else {
        0.0
    }
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
    use super::{pct, truncate};

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        assert_eq!(truncate("hello world", 5), "hello…");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn pct_zero_total_is_zero_not_nan() {
        assert_eq!(pct(0, 0), 0.0);
    }

    #[test]
    fn pct_computes_percentage() {
        assert_eq!(pct(1, 4), 25.0);
    }
}
