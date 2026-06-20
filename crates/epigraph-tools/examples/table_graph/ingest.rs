//! Per-table ingestion: one `claude -p` subprocess per narrative MD orchestrates
//! the extract-claims skill + the mcp__epigraph__ingest_document tool.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::process::Command;

/// Pipeline version string mirrored from `crates/epigraph-mcp/src/tools/ingestion.rs::PIPELINE_VERSION_BASE`.
/// The MCP-side dedup gate keys on (paper.doi, processed_by edge with this `pipeline` property).
/// Keep this in sync if the MCP constant ever changes.
const PIPELINE_VERSION: &str = "hierarchical_extraction_v2";

pub fn run(dry_run: bool, only: Option<&str>) -> Result<()> {
    let narratives_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/narratives";
    let staging_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/staging";
    let failed_path = format!("{}/failed-ingest.jsonl", staging_dir);
    fs::create_dir_all(staging_dir)?;

    let mut count_ok = 0usize;
    let mut count_fail = 0usize;

    for entry in fs::read_dir(narratives_dir).with_context(|| format!("read {}", narratives_dir))? {
        let p = entry?.path();
        if p.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }

        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let parts: Vec<&str> = stem.splitn(2, '.').collect();
        if parts.len() != 2 {
            continue;
        }
        let (repo, table) = (parts[0], parts[1]);
        if let Some(filter) = only {
            if table != filter {
                continue;
            }
        }
        let doi = format!("urn:epigraph-table:{}:{}", repo, table);
        let md_abs = std::fs::canonicalize(&p)?;
        let extraction_json = p.with_extension("extraction.json");
        // Compute the absolute path BEFORE the file exists by canonicalizing the parent
        let extraction_abs = {
            let parent = extraction_json
                .parent()
                .unwrap_or(std::path::Path::new("."));
            let parent_abs = std::fs::canonicalize(parent)?;
            parent_abs.join(extraction_json.file_name().unwrap())
        };

        eprintln!("ingest {} ({})", stem, doi);

        // Cheap pre-flight: skip if the same DOI is already processed at the
        // current pipeline version. The MCP `ingest_document` tool re-runs this
        // gate, but only AFTER the extract-claims LLM call (~$2.50 per table)
        // has already happened. Doing the check here saves that cost on re-runs.
        match already_processed(&doi)? {
            true => {
                eprintln!("  skip: already processed at pipeline {}", PIPELINE_VERSION);
                count_ok += 1;
                continue;
            }
            false => {}
        }

        if dry_run {
            eprintln!("  dry-run: would orchestrate claude -p extract+ingest");
            continue;
        }

        let prompt = format!(
            "You have one task. Do not deviate.

1. Use the `extract-claims` skill on the markdown file at:
     {md}
   Produce a `DocumentExtraction` JSON.

2. Save the JSON to:
     {json}

3. Call the MCP tool `mcp__epigraph__ingest_document` with:
     file_path = {json}
   Use synthetic DOI `{doi}` for the source.

Report only the ingest_document tool result.",
            md = md_abs.display(),
            json = extraction_abs.display(),
            doi = doi
        );

        let status = Command::new("claude")
            .args([
                "-p",
                "--output-format",
                "json",
                "--dangerously-skip-permissions",
            ])
            .arg(&prompt)
            .status()?;
        if !status.success() {
            eprintln!("  claude orchestration failed");
            log_fail(&failed_path, table, "claude-orchestration")?;
            count_fail += 1;
            continue;
        }
        count_ok += 1;
    }

    eprintln!(
        "ingestion complete: {} ok, {} failed (see {})",
        count_ok, count_fail, failed_path
    );
    Ok(())
}

fn log_fail(path: &str, table: &str, stage: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, r#"{{"table": "{}", "stage": "{}"}}"#, table, stage)?;
    Ok(())
}

pub fn verify() -> Result<()> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://epigraph:epigraph@localhost:5432/epigraph".into());

    let papers = run_psql(
        &url,
        "SELECT count(*) FROM papers WHERE doi LIKE 'urn:epigraph-table:%'",
    )?;
    eprintln!(
        "Coverage: {} papers ingested with DOI prefix urn:epigraph-table: (expected ~85)",
        papers.trim()
    );

    let total_claims = run_psql(
        &url,
        "
        SELECT count(DISTINCT e.target_id) FROM edges e
        JOIN papers p ON p.id = e.source_id
        WHERE p.doi LIKE 'urn:epigraph-table:%' AND e.relationship = 'asserts'
    ",
    )?;
    eprintln!(
        "Total claims linked from per-table papers: {}",
        total_claims.trim()
    );

    let zero = run_psql(
        &url,
        "
        SELECT p.doi FROM papers p
        WHERE p.doi LIKE 'urn:epigraph-table:%'
          AND NOT EXISTS (
              SELECT 1 FROM edges e WHERE e.source_id = p.id AND e.relationship = 'asserts'
          )
    ",
    )?;
    let zero_lines: Vec<&str> = zero.lines().filter(|l| !l.trim().is_empty()).collect();
    if !zero_lines.is_empty() {
        eprintln!(
            "WARNING: {} per-table papers have no asserts edges:",
            zero_lines.len()
        );
        for l in &zero_lines {
            eprintln!("  {}", l);
        }
    }

    eprintln!();
    eprintln!("Manual recall checks (run separately):");
    eprintln!("  recall \"what stores DST mass functions\"  → mass_functions");
    eprintln!("  recall \"belief frame definition\"         → frames");
    eprintln!("  recall \"harvester audit reports\"         → harvester_audit_reports");
    Ok(())
}

fn run_psql(url: &str, sql: &str) -> Result<String> {
    let out = std::process::Command::new("psql")
        .arg(url)
        .arg("-tAc")
        .arg(sql)
        .output()
        .with_context(|| "psql invocation failed")?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "psql failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// Pre-flight dedup check that mirrors the MCP `ingest_document` version gate.
/// Returns true iff a paper with this DOI exists AND has a `processed_by` edge
/// at the current `PIPELINE_VERSION`. Read-only, so psql is fine here.
fn already_processed(doi: &str) -> Result<bool> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://epigraph:epigraph@localhost:5432/epigraph".into());
    // Quote the DOI as a single-quoted SQL literal; doubling any embedded ' for safety.
    // DOIs in this binary are constructed from repo+table identifiers, so this is belt-and-braces.
    let doi_lit = doi.replace('\'', "''");
    let pipe_lit = PIPELINE_VERSION.replace('\'', "''");
    let sql = format!(
        "SELECT 1 FROM papers p \
         JOIN edges e ON e.source_id = p.id \
         WHERE p.doi = '{doi}' \
           AND e.source_type = 'paper' \
           AND e.relationship = 'processed_by' \
           AND e.properties ->> 'pipeline' = '{pipe}' \
         LIMIT 1",
        doi = doi_lit,
        pipe = pipe_lit,
    );
    let out = run_psql(&url, &sql)?;
    Ok(!out.trim().is_empty())
}
