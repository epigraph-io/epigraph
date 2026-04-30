#[path = "../examples/table_graph/discover.rs"]
mod discover;
#[path = "../examples/table_graph/types.rs"]
mod types;

use discover::scan_migrations;

#[test]
fn finds_claims_table_in_epigraph_initial_schema() {
    let tables = scan_migrations(&[
        ("epigraph", "/home/jeremy/epigraph/migrations", &[]),
    ]).unwrap();
    assert!(
        tables.iter().any(|t| t.name == "claims" && t.repo == "epigraph"),
        "expected to find epigraph.claims"
    );
}

#[test]
fn finds_synthesis_tables_in_episcience() {
    let tables = scan_migrations(&[
        ("episcience", "/home/jeremy/episcience/migrations", &["upstream"]),
    ]).unwrap();
    assert!(
        tables.iter().any(|t| t.name == "syntheses" && t.repo == "episcience"),
        "expected to find episcience.syntheses (from migrations/synthesis/)"
    );
}

#[test]
fn skips_episcience_upstream_directory() {
    let tables = scan_migrations(&[
        ("episcience", "/home/jeremy/episcience/migrations", &["upstream"]),
    ]).unwrap();
    assert!(
        !tables.iter().any(|t| t.name == "claims" && t.repo == "episcience"),
        "upstream/ should be skipped — claims belongs to epigraph only"
    );
}
