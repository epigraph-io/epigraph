//! Discover tables (from migration SQL files) and crates (from Cargo workspaces).

use crate::cli::Roots;
use crate::types::{CrateRef, TableRef};
use anyhow::{Context, Result};
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

/// Scan migration directories. `repo_dirs` is `[(repo_name, dir, skip_subdirs)]`.
pub fn scan_migrations<D: AsRef<Path>>(repo_dirs: &[(&str, D, &[&str])]) -> Result<Vec<TableRef>> {
    let create_re =
        Regex::new(r"(?im)^\s*CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?(?:public\.)?(\w+)\s*\(")
            .expect("regex");
    let mut out = Vec::new();
    for (repo, dir, skips) in repo_dirs {
        let dir = dir.as_ref();
        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.path().extension().and_then(|s| s.to_str()) != Some("sql") {
                continue;
            }
            let rel = entry.path().strip_prefix(dir).unwrap_or(entry.path());
            if skips.iter().any(|s| rel.starts_with(s)) {
                continue;
            }
            let sql = std::fs::read_to_string(entry.path())
                .with_context(|| format!("read {}", entry.path().display()))?;
            for cap in create_re.captures_iter(&sql) {
                out.push(TableRef {
                    repo: (*repo).to_string(),
                    name: cap[2].to_string(),
                    migration: rel.to_string_lossy().into_owned(),
                });
            }
        }
    }
    out.sort_by(|a, b| {
        (a.repo.clone(), a.name.clone(), a.migration.clone()).cmp(&(
            b.repo.clone(),
            b.name.clone(),
            b.migration.clone(),
        ))
    });
    out.dedup_by(|a, b| a.repo == b.repo && a.name == b.name);
    Ok(out)
}

pub fn scan_crates<D: AsRef<Path>>(repo_dirs: &[(&str, D)]) -> Result<Vec<CrateRef>> {
    let mut out = Vec::new();
    for (repo, dir) in repo_dirs {
        let dir = dir.as_ref();
        let entries =
            std::fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))?;
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            if !entry.path().join("Cargo.toml").exists() {
                continue;
            }
            out.push(CrateRef {
                repo: (*repo).to_string(),
                name: entry.file_name().to_string_lossy().into_owned(),
            });
        }
    }
    out.sort_by(|a, b| (&a.repo, &a.name).cmp(&(&b.repo, &b.name)));
    Ok(out)
}

/// Every table under the two checkouts' `migrations/` and every crate under
/// their `crates/`, read from the roots given on the command line only.
pub fn collect(roots: &Roots) -> Result<(Vec<TableRef>, Vec<CrateRef>)> {
    let tables = scan_migrations(&roots.migration_dirs())?;
    let crates = scan_crates(&roots.crate_dirs())?;
    Ok((tables, crates))
}

pub fn run(roots: &Roots) -> Result<()> {
    let (tables, crates) = collect(roots)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "tables": tables, "crates": crates,
            "table_count": tables.len(), "crate_count": crates.len(),
        }))?
    );
    Ok(())
}
