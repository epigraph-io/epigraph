//! Per-table dossier: DDL, git context, call sites, FK targets.

use crate::types::*;
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub fn collect_ddl(migrations_dir: &str, table: &str) -> Result<String> {
    let mut buf = String::new();
    let mut paths: Vec<_> = WalkDir::new(migrations_dir)
        .into_iter().filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file()
            && e.path().extension().and_then(|s| s.to_str()) == Some("sql"))
        .map(|e| e.path().to_path_buf())
        .collect();
    paths.sort();
    let stmt_re = Regex::new(&format!(
        r"(?ims)\b(CREATE\s+TABLE|ALTER\s+TABLE|CREATE\s+INDEX|CREATE\s+TRIGGER)[^;]*\b{}\b[^;]*;",
        regex::escape(table)
    )).expect("regex");
    for p in paths {
        let sql = std::fs::read_to_string(&p)?;
        for m in stmt_re.find_iter(&sql) {
            buf.push_str(&format!("-- from {}\n", p.display()));
            buf.push_str(m.as_str());
            buf.push_str("\n\n");
        }
    }
    Ok(buf)
}

/// Three-slice git history:
///   1. introducing commit (--diff-filter=A --follow)
///   2. all subsequent commits touching the migration file (--follow)
///   3. commits with the table name in the message body (--grep)
/// Deduped by SHA, sorted by author date ascending.
pub fn collect_git_context(repo: &str, migration_file: &str, table: &str) -> Result<Vec<GitCommit>> {
    use std::process::Command;
    let format = "--pretty=format:%H%x09%aI%x09%s%x09%b%x1e";
    let migration_path = format!("migrations/{}", migration_file);
    let grep_arg = format!("--grep={}", regex::escape(table));
    let mut all = Vec::new();
    let slices: &[&[&str]] = &[
        &["log", "--diff-filter=A", "--follow", format, "--", &migration_path],
        &["log", "--follow", format, "--", &migration_path],
        &["log", &grep_arg, format],
    ];
    for args in slices {
        let out = Command::new("git").current_dir(repo).args(*args).output()?;
        if !out.status.success() { continue; }
        let text = String::from_utf8_lossy(&out.stdout);
        for record in text.split('\x1e') {
            let record = record.trim();
            if record.is_empty() { continue; }
            let parts: Vec<&str> = record.splitn(4, '\t').collect();
            if parts.len() < 3 { continue; }
            all.push(GitCommit {
                sha: parts[0].to_string(),
                date: parts[1].to_string(),
                subject: parts[2].to_string(),
                body: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
            });
        }
    }
    all.sort_by(|a, b| a.date.cmp(&b.date));
    all.dedup_by(|a, b| a.sha == b.sha);
    Ok(all)
}

fn back_scan_function(lines: &[&str], hit_idx: usize) -> String {
    let fn_re = Regex::new(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)").expect("regex");
    for i in (0..=hit_idx).rev() {
        if let Some(c) = fn_re.captures(lines[i]) {
            return c[1].to_string();
        }
    }
    "<top-level>".to_string()
}

fn classify(line: &str) -> Option<CallKind> {
    let l = line.to_uppercase();
    if l.contains("INSERT INTO") || l.contains("UPDATE ") || l.contains("DELETE FROM")
        || l.contains("UPSERT") || l.contains("COPY ") {
        Some(CallKind::WritesTo)
    } else if l.contains("SELECT") || l.contains("QUERY_AS") || l.contains("FROM ") {
        Some(CallKind::ReadsFrom)
    } else {
        None
    }
}

pub fn collect_call_sites(repo: &str, table: &str) -> Result<Vec<CallSite>> {
    let crates_dir = format!("{}/crates", repo);
    let word_re = Regex::new(&format!(r"\b{}\b", regex::escape(table)))?;
    let mut out = Vec::new();
    for entry in WalkDir::new(&crates_dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("rs") { continue; }
        if p.components().any(|c| c.as_os_str() == "target"
            || c.as_os_str() == ".sqlx"
            || c.as_os_str() == "migrations") { continue; }
        let rel = p.strip_prefix(&crates_dir).unwrap();
        let crate_name = rel.components().next()
            .and_then(|c| c.as_os_str().to_str())
            .unwrap_or("?").to_string();
        let text = match std::fs::read_to_string(p) { Ok(t) => t, Err(_) => continue };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("///") || trimmed.starts_with("//!") { continue; }
            if !word_re.is_match(line) { continue; }
            let kind = match classify(line) { Some(k) => k, None => continue };
            let function = back_scan_function(&lines, i);
            let end = (i + 2).min(lines.len());
            let snippet = lines[i..end].join("\n").trim().to_string();
            out.push(CallSite { crate_name: crate_name.clone(), function, snippet, kind });
        }
    }
    Ok(out)
}

pub fn extract_fk_targets(ddl: &str) -> Vec<String> {
    let re = Regex::new(r"(?i)REFERENCES\s+(?:public\.)?(\w+)\s*\(").expect("regex");
    let mut out: Vec<String> = re.captures_iter(ddl)
        .map(|c| c[1].to_lowercase())
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn build_dossier(
    repo_root: &str, migration_dir: &str, table: &TableRef,
) -> Result<Dossier> {
    let ddl = collect_ddl(migration_dir, &table.name)?;
    let commits = collect_git_context(repo_root, &table.migration, &table.name)?;
    let call_sites = collect_call_sites(repo_root, &table.name)?;
    let fk_targets = extract_fk_targets(&ddl);
    Ok(Dossier { table: table.clone(), ddl, commits, call_sites, fk_targets })
}

pub fn content_hash<T: serde::Serialize>(v: &T) -> Result<String> {
    let bytes = serde_json::to_vec(v)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

pub fn run(_only: Option<&str>) -> Result<()> {
    todo!("filled in by Task 10")
}
