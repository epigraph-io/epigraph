//! Extract subcommand: build dossier per table → LLM narrative MD → staging files.
//!
//! Lives in its own module (rather than dossier.rs) because it references
//! sibling modules `discover` and `llm`, which aren't visible when dossier.rs
//! is `#[path]`-included into the integration test crate.

use crate::dossier::{build_dossier, content_hash};
use crate::types::StagingFile;
use crate::{discover, llm};
use anyhow::Result;
use std::io::Write;

pub fn run(only: Option<&str>) -> Result<()> {
    let staging_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/staging";
    let narratives_dir = "docs/superpowers/artifacts/2026-04-30-table-graph/narratives";
    std::fs::create_dir_all(staging_dir)?;
    std::fs::create_dir_all(narratives_dir)?;

    let empty: &[&str] = &[];
    let upstream: &[&str] = &["upstream"];
    let tables = discover::scan_migrations(&[
        ("epigraph", "/home/jeremy/epigraph/migrations", empty),
        ("episcience", "/home/jeremy/episcience/migrations", upstream),
    ])?;

    for t in &tables {
        if let Some(filter) = only {
            if t.name != filter {
                continue;
            }
        }
        let staging_path = format!("{}/{}.{}.json", staging_dir, t.repo, t.name);
        let md_path = format!("{}/{}.{}.md", narratives_dir, t.repo, t.name);
        let (repo_root, migration_dir) = match t.repo.as_str() {
            "epigraph" => ("/home/jeremy/epigraph", "/home/jeremy/epigraph/migrations"),
            "episcience" => (
                "/home/jeremy/episcience",
                "/home/jeremy/episcience/migrations",
            ),
            _ => continue,
        };
        let dossier = build_dossier(repo_root, migration_dir, t)?;
        let dossier_hash = content_hash(&dossier)?;

        if let Ok(existing) = std::fs::read_to_string(&staging_path) {
            if let Ok(file) = serde_json::from_str::<StagingFile>(&existing) {
                if file.content_hash.starts_with(&dossier_hash[..16]) {
                    eprintln!("skip {} (unchanged)", t.name);
                    continue;
                }
            }
        }

        match llm::extract(&dossier) {
            Ok(narrative_md) => {
                let combined = serde_json::json!({"d": &dossier, "m": &narrative_md});
                let hash = content_hash(&combined)?;
                std::fs::write(&md_path, &narrative_md)?;
                let file = StagingFile {
                    dossier,
                    narrative_md,
                    content_hash: hash,
                };
                std::fs::write(&staging_path, serde_json::to_string_pretty(&file)?)?;
                eprintln!("wrote {} and {}", staging_path, md_path);
            }
            Err(e) => {
                eprintln!("FAIL {}: {}", t.name, e);
                let failed = format!("{}/failed.jsonl", staging_dir);
                let entry = serde_json::json!({"table": t.name, "error": e.to_string()});
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&failed)?;
                writeln!(f, "{}", entry)?;
            }
        }
    }
    Ok(())
}
