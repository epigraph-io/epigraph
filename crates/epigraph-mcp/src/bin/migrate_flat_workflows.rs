//! Migration CLI for issue #34. Re-ingests existing flat-JSON workflows
//! (claims labeled `'workflow'`) into the new hierarchical `workflows` table.
//! Idempotent: skips claims already labeled `'legacy_flat'`.

use std::collections::HashMap;

use clap::Parser;
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_mcp::migrate_flat::{
    build_extraction, fetch_unmigrated, mark_legacy_and_supersede, slugify, FlatContent, FlatRow,
};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Migrate flat-JSON workflows to hierarchical form (#34)"
)]
struct Args {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    #[arg(long)]
    limit: Option<i64>,
    #[arg(long, value_enum, default_value_t = CanonicalFrom::GoalSlug)]
    canonical_from: CanonicalFrom,
    #[arg(long)]
    workflow_id: Option<Uuid>,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum CanonicalFrom {
    GoalSlug,
    Tag,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let pool = PgPool::connect(&args.database_url).await?;

    let rows = fetch_unmigrated(&pool, args.limit, args.workflow_id).await?;
    println!(
        "Found {} flat-JSON workflow{} to migrate{}",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" },
        if args.dry_run { " (DRY RUN)" } else { "" }
    );

    let mut by_canonical: HashMap<String, Vec<&FlatRow>> = HashMap::new();
    let mut canonical_for_row: HashMap<Uuid, String> = HashMap::new();
    let mut row_canonical_pairs: Vec<(&FlatRow, FlatContent, String)> =
        Vec::with_capacity(rows.len());

    // First pass: parse + group by canonical name
    for row in &rows {
        let parsed: FlatContent = match serde_json::from_str(&row.content) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("SKIP claim {} — content does not parse: {e}", row.id);
                continue;
            }
        };
        let canonical = match args.canonical_from {
            CanonicalFrom::Tag => parsed
                .tags
                .first()
                .cloned()
                .unwrap_or_else(|| slugify(&parsed.goal)),
            CanonicalFrom::GoalSlug => slugify(&parsed.goal),
        };
        canonical_for_row.insert(row.id, canonical.clone());
        row_canonical_pairs.push((row, parsed, canonical.clone()));
    }
    for (row, _parsed, canonical) in &row_canonical_pairs {
        by_canonical
            .entry(canonical.clone())
            .or_default()
            .push(*row);
    }

    let mut migrated = 0_usize;
    let mut failed = 0_usize;
    for (row, parsed, canonical) in &row_canonical_pairs {
        let group = by_canonical.get(canonical).unwrap();
        let generation = group.iter().position(|r| r.id == row.id).unwrap_or(0) as u32;
        let parent_canonical = if generation > 0 {
            // Within the same canonical-name group at gen=0; lineage is the row's own group.
            None
        } else {
            row.properties
                .get("parent_id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Uuid>().ok())
                .and_then(|pid| canonical_for_row.get(&pid).cloned())
        };

        let extraction = build_extraction(parsed, canonical.clone(), generation, parent_canonical);

        if args.dry_run {
            println!(
                "DRY RUN: would migrate {} → canonical={canonical} gen={generation}",
                row.id
            );
            migrated += 1;
            continue;
        }

        match epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(&pool, &extraction)
            .await
        {
            Ok(result) => {
                let new_workflow_id: Uuid = result.workflow_id.parse().unwrap_or_else(|e| {
                    panic!(
                        "workflow_id '{}' is not a valid UUID: {e}",
                        result.workflow_id
                    )
                });
                if let Err(e) = mark_legacy_and_supersede(&pool, row.id, new_workflow_id).await {
                    eprintln!("FAIL post-migration markup for {}: {e}", row.id);
                    failed += 1;
                } else {
                    println!(
                        "migrated {} → {} (canonical={canonical}, gen={generation})",
                        row.id, result.workflow_id
                    );
                    migrated += 1;
                }
            }
            Err(e) => {
                eprintln!("FAIL ingest for {}: {e}", row.id);
                failed += 1;
            }
        }
    }
    println!("Done. migrated={migrated}, failed={failed}");
    Ok(())
}
