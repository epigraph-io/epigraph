//! Every `[[bin]]` of this crate is classified in its README (backlog
//! 990be2d6).
//!
//! The crate's binaries mix standing maintenance, operator ceremonies, one-shot
//! repairs, ingest clients and research experiments, and `Cargo.toml` does not
//! say which is which. `README.md`'s "Binaries" table does; this test keeps it
//! complete: a `[[bin]]` with no row, a row naming no `[[bin]]`, a binary listed
//! twice, or a class outside the five the README defines fails it.

use std::collections::{BTreeMap, BTreeSet};

const MANIFEST: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README.md");

/// The classes `README.md`'s "Classes" table defines.
const CLASSES: [&str; 5] = ["standing", "admin", "one-shot", "ingest", "experiment"];

/// The `name` of every `[[bin]]` table, wherever it sits in the manifest
/// (one is declared after `[lints]`).
fn manifest_bins(manifest: &str) -> Vec<String> {
    let mut bins = Vec::new();
    let mut in_bin = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(value) = line
            .strip_prefix("name")
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix('='))
        {
            let name = value.trim().trim_matches('"').to_string();
            bins.push(name);
            in_bin = false;
        }
    }
    bins
}

/// `(binary, class)` for every row of the table under `## <heading>`.
fn table_rows<'a>(readme: &'a str, heading: &str) -> Vec<(&'a str, &'a str)> {
    let marker = format!("## {heading}");
    let start = readme
        .lines()
        .position(|l| l.trim() == marker)
        .unwrap_or_else(|| panic!("README.md has no `{marker}` section"));
    readme
        .lines()
        .skip(start + 1)
        .take_while(|l| !l.starts_with("## "))
        .filter(|l| l.starts_with("| `"))
        .map(|row| {
            let cells: Vec<&str> = row.split('|').map(str::trim).collect();
            // ["", "`name`", "class", "what", ""]
            assert!(cells.len() >= 4, "malformed row: {row}");
            (cells[1].trim_matches('`'), cells[2].trim_matches('`'))
        })
        .collect()
}

#[test]
fn every_bin_has_exactly_one_readme_row_with_a_defined_class() {
    let bins = manifest_bins(MANIFEST);
    assert!(
        bins.len() >= 50,
        "the [[bin]] parser found only {} targets: {bins:?}",
        bins.len()
    );
    // Non-vacuity of the parser: the target declared after `[lints]`, and one
    // declared with `required-features`, are both found.
    for known in ["epigraph-privatize", "recompute_claim_belief"] {
        assert!(bins.iter().any(|b| b == known), "parser missed {known}");
    }
    let declared: BTreeSet<&str> = bins.iter().map(String::as_str).collect();
    assert_eq!(
        declared.len(),
        bins.len(),
        "a [[bin]] name is declared twice"
    );

    let defined: BTreeSet<&str> = table_rows(README, "Classes")
        .into_iter()
        .map(|(class, _)| class)
        .collect();
    assert_eq!(
        defined,
        BTreeSet::from(CLASSES),
        "README.md's Classes table and this test disagree"
    );

    let rows = table_rows(README, "Binaries");
    let mut classified: BTreeMap<&str, &str> = BTreeMap::new();
    for (bin, class) in &rows {
        assert!(
            classified.insert(bin, class).is_none(),
            "{bin} has more than one row in README.md"
        );
        assert!(
            CLASSES.contains(class),
            "{bin}'s class `{class}` is not one of {CLASSES:?}"
        );
    }
    let listed: BTreeSet<&str> = classified.keys().copied().collect();

    let unlisted: Vec<&&str> = declared.difference(&listed).collect();
    assert!(
        unlisted.is_empty(),
        "[[bin]] targets with no row in crates/epigraph-cli/README.md: {unlisted:?}. \
         Add a row with its class."
    );
    let stale: Vec<&&str> = listed.difference(&declared).collect();
    assert!(
        stale.is_empty(),
        "README.md rows naming no [[bin]] in Cargo.toml: {stale:?}. Remove or rename them."
    );
}
