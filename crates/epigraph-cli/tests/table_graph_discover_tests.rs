// These modules are the *example*'s source, pulled in by `#[path]` so the
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
#[path = "../examples/table_graph/cli.rs"]
mod cli;
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

use std::collections::BTreeSet;

use clap::{error::ErrorKind, Parser};
use cli::{Cli, Cmd, Roots};
use discover::scan_migrations;

/// Path to this repo's `migrations/` directory.
/// `CARGO_MANIFEST_DIR` resolves to `crates/epigraph-cli/` at compile time,
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

/// A sibling repository's migrations directory, committed as a fixture so the
/// two tests below run in every gate. It has the layout the scan must handle:
/// a top-level migration, a table in a nested `synthesis/` subdirectory, and a
/// vendored `upstream/` copy of epigraph's schema that is passed as a skip
/// directory. (These tests used to read a sibling checkout at a developer
/// machine's absolute path and were `#[ignore]`d, so CI never ran them.)
const SIBLING_MIGRATIONS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/table_graph/episcience/migrations"
);
/// The same fixture as a checkout root: `migrations/` above, and a `crates/`
/// whose only directory holds no `Cargo.toml`.
const SIBLING_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/table_graph/episcience"
);
/// This repository's root (`CARGO_MANIFEST_DIR` is `crates/epigraph-cli/`).
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

#[test]
fn finds_synthesis_tables_in_episcience() {
    let tables = scan_migrations(&[("episcience", SIBLING_MIGRATIONS, &["upstream"])]).unwrap();
    assert!(
        tables
            .iter()
            .any(|t| t.name == "syntheses" && t.repo == "episcience"),
        "expected to find episcience.syntheses (from migrations/synthesis/)"
    );
    assert!(
        tables
            .iter()
            .any(|t| t.name == "experiments" && t.repo == "episcience"),
        "expected to find episcience.experiments (top-level migration)"
    );
}

#[test]
fn skips_episcience_upstream_directory() {
    // Non-vacuity: without the skip, the vendored `upstream/` schema IS
    // attributed to the sibling repository, so the assertion below is about
    // the skip list and not about a fixture that lacks `claims`.
    let unskipped = scan_migrations(&[("episcience", SIBLING_MIGRATIONS, &[])]).unwrap();
    assert!(
        unskipped
            .iter()
            .any(|t| t.name == "claims" && t.repo == "episcience"),
        "fixture must define claims under upstream/"
    );

    let tables = scan_migrations(&[("episcience", SIBLING_MIGRATIONS, &["upstream"])]).unwrap();
    assert!(
        !tables
            .iter()
            .any(|t| t.name == "claims" && t.repo == "episcience"),
        "upstream/ should be skipped — claims belongs to epigraph only"
    );
}

/// Backlog d65e1279: `discover` and `extract` used to scan one developer's
/// checkouts at hard-coded absolute paths. Both roots are now required
/// arguments with no default, so a run without them is refused by the parser
/// instead of silently reading (or failing to find) somebody else's tree.
#[test]
fn discover_and_extract_require_both_checkout_roots() {
    for sub in ["discover", "extract"] {
        for argv in [
            vec!["table_graph", sub],
            vec!["table_graph", sub, "--epigraph-root", "/e"],
            vec!["table_graph", sub, "--episcience-root", "/s"],
        ] {
            let err = Cli::try_parse_from(&argv)
                .expect_err(&format!("{argv:?} names fewer than both roots"));
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument, "{argv:?}");
        }
        let cli = Cli::try_parse_from([
            "table_graph",
            sub,
            "--epigraph-root",
            "/e",
            "--episcience-root",
            "/s",
        ])
        .expect("both roots given");
        let roots = match cli.cmd {
            Cmd::Discover { roots } | Cmd::Extract { roots, .. } => roots,
            other => panic!("{sub} parsed as {other:?}"),
        };
        assert_eq!(
            roots,
            Roots {
                epigraph_root: "/e".into(),
                episcience_root: "/s".into(),
            }
        );
    }
}

/// The roots given are the only trees `discover` reads: epigraph's tables and
/// crates come from `--epigraph-root`, the sibling's from `--episcience-root`
/// (its vendored `upstream/` skipped), and nothing else is attributed to
/// either.
#[test]
fn discover_reads_the_given_roots() {
    let roots = Roots {
        epigraph_root: REPO_ROOT.into(),
        episcience_root: SIBLING_ROOT.into(),
    };
    let (tables, crates) = discover::collect(&roots).unwrap();

    assert!(
        tables
            .iter()
            .any(|t| t.repo == "epigraph" && t.name == "claims"),
        "epigraph.claims from <epigraph root>/migrations"
    );
    let sibling: BTreeSet<&str> = tables
        .iter()
        .filter(|t| t.repo == "episcience")
        .map(|t| t.name.as_str())
        .collect();
    assert_eq!(
        sibling,
        BTreeSet::from(["experiments", "syntheses"]),
        "exactly the fixture's tables, with upstream/ skipped"
    );

    assert!(
        crates
            .iter()
            .any(|c| c.repo == "epigraph" && c.name == "epigraph-cli"),
        "epigraph-cli from <epigraph root>/crates"
    );
    assert!(
        !crates.iter().any(|c| c.repo == "episcience"),
        "the fixture's crates/ holds no Cargo.toml, so no sibling crate: {crates:?}"
    );
}
