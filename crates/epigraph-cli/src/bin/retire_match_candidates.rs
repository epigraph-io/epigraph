//! Operator binary: retire a list of match_candidates and fully retract the
//! evidential edges they promoted.
//!
//! Motivation: a same-source provenance bug in `derive_source_key`
//! (`crates/epigraph-engine/src/matching/source_key.rs`, fixed in
//! `fix/cross-source-same-source-provenance`) let same-paper pairs be promoted
//! as cross-source. A 2026-07-21 audit found 71 promoted `match_candidates`
//! that are same-paper (or otherwise same-source) leaks. This binary retires
//! them.
//!
//! Retirement is NOT just an edge delete. The `edges_auto_factor` AFTER INSERT
//! trigger (migration 001; corroborates strength from score in migration 038)
//! auto-creates a `factors` row keyed by `properties->>'source_edge_id'`, and
//! there is NO delete trigger — so deleting the edge alone leaves the factor
//! (and its `bp_messages`) corroborating in the belief graph. This mirrors the
//! proven cull pattern of `migration 012_cull_low_similarity_corroborates`:
//! per matcher edge, delete `bp_messages` -> `factors` -> `edges`, all keyed by
//! `source_edge_id`, in ONE transaction. Then flip the candidates to `stale`
//! (no API exposes a promoted->stale transition) and emit the affected claim
//! ids so the caller can `recompute_claim_belief` on them.
//!
//! Scoping (see the design review): edges are matched by CLAIM PAIR + the
//! `properties->>'source' = 'cross_source_matcher'` marker, NOT by
//! `relationship = 'CORROBORATES'` (7 of the 71 are `contradicts` edges) and
//! NOT by `candidate_id` (reversed-duplicate candidates share one edge stamped
//! with only one candidate's id). Every matcher-created edge between a
//! confirmed same-source pair is a leak, so deleting by (pair, source) is both
//! correct and robust.
//!
//! Dry-run by default. `--apply` performs the writes. The set of edges that
//! would be / were deleted is always dumped to `--dump` first, as an undo
//! record.
//!
//! Usage:
//!     retire_match_candidates --ids-file leaked.txt --dump /tmp/deleted_edges.json
//!     retire_match_candidates --ids-file leaked.txt --dump /tmp/deleted_edges.json \
//!         --affected-out /tmp/affected_claims.txt --apply

use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::collections::BTreeSet;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "retire_match_candidates",
    about = "Retire promoted match_candidates and fully retract their evidential edges (edge + factors + bp_messages), flip to stale"
)]
struct Args {
    /// File with one match_candidate UUID per line. Lines starting with `#`
    /// and blank lines are ignored.
    #[arg(long)]
    ids_file: PathBuf,

    /// Where to write the JSON dump of edges that will be / were deleted
    /// (undo record). Written in BOTH dry-run and apply.
    #[arg(long)]
    dump: PathBuf,

    /// Where to write the newline-separated affected claim ids (both endpoints
    /// of every retired pair) for a follow-up `recompute_claim_belief` pass.
    #[arg(long)]
    affected_out: Option<PathBuf>,

    /// Perform the writes. Without this flag the tool is a dry-run: it reports
    /// and dumps but does not modify the database.
    #[arg(long)]
    apply: bool,

    /// Rationale recorded on the retired candidates.
    #[arg(
        long,
        default_value = "retired: same-source leak (derive_source_key relational-DOI provenance fix)"
    )]
    reason: String,
}

/// One candidate row we were asked to retire.
struct Candidate {
    id: Uuid,
    a: Uuid,
    b: Uuid,
    status: String,
}

/// An edge slated for deletion, captured for the undo dump.
#[derive(serde::Serialize)]
struct DeletedEdge {
    edge_id: Uuid,
    source_id: Uuid,
    source_type: String,
    target_id: Uuid,
    target_type: String,
    relationship: String,
    properties: serde_json::Value,
    created_at: String,
}

fn read_ids(path: &PathBuf) -> anyhow::Result<Vec<Uuid>> {
    let text = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(Uuid::parse_str(line)?);
    }
    Ok(out)
}

/// Canonical unordered pair key so reversed candidates collapse to one pair.
fn pair_key(a: Uuid, b: Uuid) -> (Uuid, Uuid) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let db_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&db_url)
        .await?;

    let ids = read_ids(&args.ids_file)?;
    if ids.is_empty() {
        anyhow::bail!("no candidate ids in {}", args.ids_file.display());
    }
    println!("Requested retirement of {} candidate id(s).", ids.len());

    // Load the candidate rows. Report any missing / already-decided.
    let rows =
        sqlx::query("SELECT id, claim_a, claim_b, status FROM match_candidates WHERE id = ANY($1)")
            .bind(&ids)
            .fetch_all(&pool)
            .await?;
    let candidates: Vec<Candidate> = rows
        .iter()
        .map(|r| Candidate {
            id: r.get("id"),
            a: r.get("claim_a"),
            b: r.get("claim_b"),
            status: r.get("status"),
        })
        .collect();

    let found: BTreeSet<Uuid> = candidates.iter().map(|c| c.id).collect();
    let missing: Vec<Uuid> = ids.iter().copied().filter(|i| !found.contains(i)).collect();
    if !missing.is_empty() {
        println!(
            "WARNING: {} requested id(s) not found in match_candidates:",
            missing.len()
        );
        for m in &missing {
            println!("  missing: {m}");
        }
    }
    let non_promoted: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| c.status != "promoted")
        .collect();
    if !non_promoted.is_empty() {
        println!(
            "NOTE: {} candidate(s) are not currently 'promoted' (status will still be set to stale):",
            non_promoted.len()
        );
        for c in &non_promoted {
            println!("  {} status={}", c.id, c.status);
        }
    }

    // Dedup to unique unordered claim pairs.
    let mut pairs: BTreeSet<(Uuid, Uuid)> = BTreeSet::new();
    let mut affected_claims: BTreeSet<Uuid> = BTreeSet::new();
    for c in &candidates {
        pairs.insert(pair_key(c.a, c.b));
        affected_claims.insert(c.a);
        affected_claims.insert(c.b);
    }
    println!(
        "{} candidate(s) -> {} unique claim pair(s), {} affected claim endpoint(s).",
        candidates.len(),
        pairs.len(),
        affected_claims.len()
    );

    // Find every matcher-created edge between each pair (either direction),
    // scoped by the cross_source_matcher provenance marker.
    let mut deleted: Vec<DeletedEdge> = Vec::new();
    let mut rel_counts: std::collections::BTreeMap<String, usize> = Default::default();
    for (a, b) in &pairs {
        let erows = sqlx::query(
            "SELECT id, source_id, source_type, target_id, target_type, relationship, \
                    properties, created_at \
             FROM edges \
             WHERE ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)) \
               AND properties->>'source' = 'cross_source_matcher'",
        )
        .bind(a)
        .bind(b)
        .fetch_all(&pool)
        .await?;
        for r in erows {
            let relationship: String = r.get("relationship");
            *rel_counts.entry(relationship.clone()).or_default() += 1;
            let created_at: chrono::DateTime<chrono::Utc> = r.get("created_at");
            deleted.push(DeletedEdge {
                edge_id: r.get("id"),
                source_id: r.get("source_id"),
                source_type: r.get("source_type"),
                target_id: r.get("target_id"),
                target_type: r.get("target_type"),
                relationship,
                properties: r.get("properties"),
                created_at: created_at.to_rfc3339(),
            });
        }
    }
    println!(
        "Found {} matcher edge(s) to delete. Relationship distribution:",
        deleted.len()
    );
    for (rel, n) in &rel_counts {
        println!("  {rel}: {n}");
    }

    // Always dump the target edges first — this is the undo record.
    std::fs::write(&args.dump, serde_json::to_string_pretty(&deleted)?)?;
    println!(
        "Dumped {} edge(s) to {}",
        deleted.len(),
        args.dump.display()
    );

    if let Some(ref out) = args.affected_out {
        let body: String = affected_claims
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(out, format!("{body}\n"))?;
        println!(
            "Wrote {} affected claim id(s) to {}",
            affected_claims.len(),
            out.display()
        );
    }

    if !args.apply {
        println!("\nDRY RUN — no writes performed. Re-run with --apply to execute.");
        return Ok(());
    }

    // APPLY: one transaction. Per edge, mirror migration 012's cull order
    // (bp_messages -> factors -> edge), all keyed by source_edge_id. Then flip
    // every requested candidate to stale.
    let mut tx = pool.begin().await?;
    let mut bp_deleted = 0u64;
    let mut factors_deleted = 0u64;
    let mut edges_deleted = 0u64;
    for e in &deleted {
        let eid_text = e.edge_id.to_string();
        let r = sqlx::query(
            "DELETE FROM bp_messages WHERE factor_id IN \
             (SELECT id FROM factors WHERE properties->>'source_edge_id' = $1)",
        )
        .bind(&eid_text)
        .execute(&mut *tx)
        .await?;
        bp_deleted += r.rows_affected();

        let r = sqlx::query("DELETE FROM factors WHERE properties->>'source_edge_id' = $1")
            .bind(&eid_text)
            .execute(&mut *tx)
            .await?;
        factors_deleted += r.rows_affected();

        let r = sqlx::query("DELETE FROM edges WHERE id = $1")
            .bind(e.edge_id)
            .execute(&mut *tx)
            .await?;
        edges_deleted += r.rows_affected();
    }

    // Flip every requested (found) candidate to stale.
    let found_ids: Vec<Uuid> = candidates.iter().map(|c| c.id).collect();
    let r = sqlx::query(
        "UPDATE match_candidates \
         SET status = 'stale', decided_at = now(), verifier_rationale = $2 \
         WHERE id = ANY($1)",
    )
    .bind(&found_ids)
    .bind(&args.reason)
    .execute(&mut *tx)
    .await?;
    let candidates_staled = r.rows_affected();

    tx.commit().await?;

    println!("\nAPPLIED:");
    println!("  bp_messages deleted: {bp_deleted}");
    println!("  factors deleted:     {factors_deleted}");
    println!("  edges deleted:       {edges_deleted}");
    println!("  candidates -> stale: {candidates_staled}");
    println!(
        "\nNext: recompute belief for the {} affected endpoints, e.g.\n  \
         recompute_claim_belief --input {}",
        affected_claims.len(),
        args.affected_out
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<affected-out file>".into())
    );
    Ok(())
}
