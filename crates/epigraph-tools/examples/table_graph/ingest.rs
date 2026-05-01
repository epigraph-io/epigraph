//! Per-table ingestion: one `claude -p` subprocess per narrative MD orchestrates
//! the extract-claims skill + the mcp__epigraph__ingest_document tool.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::process::Command;

pub fn run(dry_run: bool) -> Result<()> {
    let narratives_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/narratives";
    let staging_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/staging";
    let failed_path = format!("{}/failed-ingest.jsonl", staging_dir);
    fs::create_dir_all(staging_dir)?;

    let mut count_ok = 0usize;
    let mut count_fail = 0usize;

    for entry in fs::read_dir(narratives_dir)
        .with_context(|| format!("read {}", narratives_dir))?
    {
        let p = entry?.path();
        if p.extension().and_then(|s| s.to_str()) != Some("md") { continue; }

        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let parts: Vec<&str> = stem.splitn(2, '.').collect();
        if parts.len() != 2 { continue; }
        let (repo, table) = (parts[0], parts[1]);
        let doi = format!("urn:epigraph-table:{}:{}", repo, table);
        let md_abs = std::fs::canonicalize(&p)?;
        let extraction_json = p.with_extension("extraction.json");
        // Compute the absolute path BEFORE the file exists by canonicalizing the parent
        let extraction_abs = {
            let parent = extraction_json.parent().unwrap_or(std::path::Path::new("."));
            let parent_abs = std::fs::canonicalize(parent)?;
            parent_abs.join(extraction_json.file_name().unwrap())
        };

        eprintln!("ingest {} ({})", stem, doi);

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
            md = md_abs.display(), json = extraction_abs.display(), doi = doi);

        let status = Command::new("claude")
            .args(["-p", "--output-format", "json"])
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

    eprintln!("ingestion complete: {} ok, {} failed (see {})", count_ok, count_fail, failed_path);
    Ok(())
}

fn log_fail(path: &str, table: &str, stage: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, r#"{{"table": "{}", "stage": "{}"}}"#, table, stage)?;
    Ok(())
}

pub fn verify() -> Result<()> {
    eprintln!("Verification — manual queries to run against EpiGraph:");
    eprintln!();
    eprintln!("1. Coverage — count purpose claims:");
    eprintln!("   recall query (filter labels = ['code-shape', 'table-purpose']):");
    eprintln!("   expected: ~85 purpose claims");
    eprintln!();
    eprintln!("2. Recall — semantic queries should surface the right table:");
    eprintln!("   recall \"what stores DST mass functions\"  → mass_functions purpose claim");
    eprintln!("   recall \"belief frame definition\"         → frames purpose claim");
    eprintln!("   recall \"harvester audit reports\"         → harvester_audit_reports");
    Ok(())
}
