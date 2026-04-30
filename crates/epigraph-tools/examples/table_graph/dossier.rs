//! Per-table dossier: DDL, git context, call sites, FK targets.

#[allow(unused_imports)]
use crate::types::*;
use anyhow::Result;
use regex::Regex;
#[allow(unused_imports)]
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

pub fn run(_only: Option<&str>) -> Result<()> {
    todo!("filled in by Task 10")
}
