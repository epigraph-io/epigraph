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

pub fn run(_only: Option<&str>) -> Result<()> {
    todo!("filled in by Task 10")
}
