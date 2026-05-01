#[path = "../examples/table_graph/discover.rs"]
mod discover;
#[path = "../examples/table_graph/types.rs"]
mod types;

use discover::scan_migrations;

/// Path to this repo's `migrations/` directory.
/// `CARGO_MANIFEST_DIR` resolves to `crates/epigraph-tools/` at compile time,
/// so the workspace root is two levels up.
const EPIGRAPH_MIGRATIONS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");

#[test]
fn finds_claims_table_in_epigraph_initial_schema() {
    let tables = scan_migrations(&[("epigraph", EPIGRAPH_MIGRATIONS, &[])]).unwrap();
    assert!(
        tables.iter().any(|t| t.name == "claims" && t.repo == "epigraph"),
        "expected to find epigraph.claims"
    );
}

/// Episcience tests require the sibling `episcience` repo checked out at
/// `/home/jeremy/episcience` — a developer-machine assumption, not present in CI.
/// Run locally with `cargo test -p epigraph-tools -- --ignored`.
#[test]
#[ignore]
fn finds_synthesis_tables_in_episcience() {
    let tables = scan_migrations(&[(
        "episcience",
        "/home/jeremy/episcience/migrations",
        &["upstream"],
    )])
    .unwrap();
    assert!(
        tables
            .iter()
            .any(|t| t.name == "syntheses" && t.repo == "episcience"),
        "expected to find episcience.syntheses (from migrations/synthesis/)"
    );
}

#[test]
#[ignore]
fn skips_episcience_upstream_directory() {
    let tables = scan_migrations(&[(
        "episcience",
        "/home/jeremy/episcience/migrations",
        &["upstream"],
    )])
    .unwrap();
    assert!(
        !tables
            .iter()
            .any(|t| t.name == "claims" && t.repo == "episcience"),
        "upstream/ should be skipped — claims belongs to epigraph only"
    );
}
