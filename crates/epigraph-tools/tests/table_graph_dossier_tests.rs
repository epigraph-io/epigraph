#[path = "../examples/table_graph/dossier.rs"]
mod dossier;
#[path = "../examples/table_graph/types.rs"]
mod types;

use dossier::collect_call_sites;
use dossier::collect_ddl;
use dossier::collect_git_context;
use dossier::extract_fk_targets;

/// Workspace root, computed at compile time.
/// `CARGO_MANIFEST_DIR` is `crates/epigraph-tools/`; root is two levels up.
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const REPO_MIGRATIONS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");

#[test]
fn ddl_for_claims_includes_create_table() {
    let ddl = collect_ddl(REPO_MIGRATIONS, "claims").unwrap();
    assert!(
        ddl.contains("CREATE TABLE"),
        "missing CREATE TABLE for claims"
    );
    assert!(ddl.contains("claims"), "DDL should mention 'claims'");
}

#[test]
fn git_context_for_claims_returns_some_commits() {
    let commits = collect_git_context(REPO_ROOT, "001_initial_schema.sql", "claims").unwrap();
    assert!(
        !commits.is_empty(),
        "expected at least one commit touching claims"
    );
    let mut shas: Vec<&str> = commits.iter().map(|c| c.sha.as_str()).collect();
    shas.sort();
    let n = shas.len();
    shas.dedup();
    assert_eq!(shas.len(), n, "duplicate SHAs in commit list");
}

#[test]
fn finds_claim_repo_call_sites() {
    let sites = collect_call_sites(REPO_ROOT, "claims").unwrap();
    assert!(!sites.is_empty(), "claims should have many call sites");
    assert!(
        sites
            .iter()
            .any(|s| s.crate_name == "epigraph-db" || s.crate_name == "epigraph-api"),
        "expected db or api crate among call sites"
    );
    for s in &sites {
        assert!(!s.function.is_empty(), "function name must be filled");
        assert!(
            !s.function.contains(':'),
            "function should be ident, not file:line"
        );
    }
}

#[test]
fn fk_targets_for_evidence_includes_claims() {
    let ddl = "CREATE TABLE evidence (id uuid, claim_id uuid REFERENCES claims(id));";
    let targets = extract_fk_targets(ddl);
    assert!(targets.contains(&"claims".to_string()));
}

#[test]
fn fk_targets_dedup() {
    let ddl = "FOO REFERENCES claims(id), BAR REFERENCES claims(id)";
    let targets = extract_fk_targets(ddl);
    assert_eq!(targets, vec!["claims".to_string()]);
}

#[path = "../examples/table_graph/llm.rs"]
mod llm;

#[test]
fn build_prompt_includes_dossier_sections() {
    use crate::types::*;
    let d = Dossier {
        table: TableRef {
            repo: "epigraph".into(),
            name: "claims".into(),
            migration: "001_initial_schema.sql".into(),
        },
        ddl: "CREATE TABLE claims (id uuid);".into(),
        commits: vec![GitCommit {
            sha: "abc12345".into(),
            date: "2025-01-01T00:00:00Z".into(),
            subject: "init".into(),
            body: "".into(),
        }],
        call_sites: vec![CallSite {
            crate_name: "epigraph-api".into(),
            function: "submit_claim_route".into(),
            snippet: "INSERT INTO claims (id".into(),
            kind: CallKind::WritesTo,
        }],
        fk_targets: vec!["agents".into()],
    };
    let p = llm::build_prompt(&d);
    assert!(p.contains("claims"));
    assert!(p.contains("CREATE TABLE claims"));
    assert!(p.contains("submit_claim_route"));
    assert!(p.contains("agents"));
    assert!(p.contains("init"));
}

#[test]
fn extract_md_from_response_strips_codefence() {
    let raw = "Sure, here you go:\n\n```markdown\n# Table `claims`\n\n## Purpose\n\ntext\n```";
    let md = llm::extract_md(raw).unwrap();
    assert!(md.starts_with("# Table"));
    assert!(!md.contains("```"));
}
