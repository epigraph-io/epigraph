#[path = "../examples/table_graph/dossier.rs"]
mod dossier;
#[path = "../examples/table_graph/types.rs"]
mod types;

use dossier::collect_ddl;
use dossier::collect_git_context;
use dossier::collect_call_sites;

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

#[test]
fn finds_claim_repo_call_sites() {
    let sites = collect_call_sites("/home/jeremy/epigraph", "claims").unwrap();
    assert!(!sites.is_empty(), "claims should have many call sites");
    assert!(
        sites.iter().any(|s| s.crate_name == "epigraph-db" || s.crate_name == "epigraph-api"),
        "expected db or api crate among call sites"
    );
    for s in &sites {
        assert!(!s.function.is_empty(), "function name must be filled");
        assert!(!s.function.contains(':'), "function should be ident, not file:line");
    }
}
