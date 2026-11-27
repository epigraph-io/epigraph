//! Shared data structures for the table_graph example binary.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRef {
    pub repo: String,      // "epigraph" | "episcience"
    pub name: String,      // table name
    pub migration: String, // relative path of the migration that created it
}

/// The synthetic DOI a table's generated paper is filed under.
///
/// Downstream filters discriminate table-graph papers by the
/// `urn:epigraph-table:` prefix, so this is the single definition of the
/// scheme — `ingest.rs` builds DOIs from bare `repo`/`table` strings parsed
/// out of a filename stem, which is why this is a free function and not a
/// `TableRef` method.
pub fn synthetic_doi(repo: &str, name: &str) -> String {
    format!("urn:epigraph-table:{repo}:{name}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateRef {
    pub repo: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    WritesTo,
    ReadsFrom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub crate_name: String,
    pub function: String,
    pub snippet: String,
    pub kind: CallKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitCommit {
    pub sha: String,
    pub date: String,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dossier {
    pub table: TableRef,
    pub ddl: String,
    pub commits: Vec<GitCommit>,
    pub call_sites: Vec<CallSite>,
    pub fk_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingFile {
    pub dossier: Dossier,
    pub narrative_md: String,
    pub content_hash: String, // sha256 of dossier + narrative
}
