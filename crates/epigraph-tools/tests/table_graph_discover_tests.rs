// These two modules are the *example*'s source, pulled in by `#[path]` so the
// tests exercise the real code rather than a copy. Only the items this test
// binary calls are reachable from its crate root, so `dead_code` fires on the
// rest — items that are live in the `table_graph` example target. That target
// is itself linted strictly (no dead_code allow) by the `--all-targets` clippy
// gate in ci.yml / scripts/verify.sh, so genuinely dead code in these files is
// still caught there; this allow only silences the test-binary view.
#[allow(
    dead_code,
    reason = "example source #[path]-included into this test crate; the items this binary \
              does not call are still live in the `table_graph` example target, which \
              `cargo clippy --workspace --all-targets -- -D warnings` (ci.yml, verify.sh) \
              lints strictly with no dead_code allow of its own"
)]
#[path = "../examples/table_graph/discover.rs"]
mod discover;
#[allow(
    dead_code,
    reason = "example source #[path]-included into this test crate; the items this binary \
              does not call are still live in the `table_graph` example target, which \
              `cargo clippy --workspace --all-targets -- -D warnings` (ci.yml, verify.sh) \
              lints strictly with no dead_code allow of its own"
)]
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
        tables
            .iter()
            .any(|t| t.name == "claims" && t.repo == "epigraph"),
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
