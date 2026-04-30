#[path = "../examples/table_graph/dossier.rs"]
mod dossier;
#[path = "../examples/table_graph/types.rs"]
mod types;

use dossier::collect_ddl;
use dossier::collect_git_context;

#[test]
fn ddl_for_claims_includes_create_table() {
    let ddl = collect_ddl("/home/jeremy/epigraph/migrations", "claims").unwrap();
    assert!(ddl.contains("CREATE TABLE"), "missing CREATE TABLE for claims");
    assert!(ddl.contains("claims"), "DDL should mention 'claims'");
}

#[test]
fn git_context_for_claims_returns_some_commits() {
    let commits = collect_git_context(
        "/home/jeremy/epigraph",
        "001_initial_schema.sql",
        "claims",
    ).unwrap();
    assert!(!commits.is_empty(), "expected at least one commit touching claims");
    let mut shas: Vec<&str> = commits.iter().map(|c| c.sha.as_str()).collect();
    shas.sort();
    let n = shas.len();
    shas.dedup();
    assert_eq!(shas.len(), n, "duplicate SHAs in commit list");
}
