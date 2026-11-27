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

/// The `name` of every `[[bin]]` target, read with a TOML parser so that any
/// valid spelling of the table header (`[[ bin ]]`, a trailing comment, the
/// inline `bin = [...]` array form) is found, wherever it sits in the manifest
/// (one is declared after `[lints]`).
fn manifest_bins(manifest: &str) -> Vec<String> {
    let manifest: toml::Table = toml::from_str(manifest).expect("Cargo.toml parses as TOML");
    let Some(bins) = manifest.get("bin") else {
        return Vec::new();
    };
    bins.as_array()
        .expect("`bin` is an array of tables")
        .iter()
        .map(|bin| {
            bin.get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("a [[bin]] has no string `name`: {bin:?}"))
                .to_string()
        })
        .collect()
}

#[test]
fn manifest_bins_finds_every_valid_spelling_of_a_bin_table() {
    let manifest = r#"
[package]
name = "x"

[[bin]]  # an operator tool
name = "commented_header"
path = "src/bin/a.rs"

[[ bin ]]
name = "spaced_header"
path = "src/bin/b.rs"

[[bin]]
path = "src/bin/c.rs"
name = "name_after_path"

[lints]
workspace = true

[[bin]]
name = "after_lints"
path = "src/bin/d.rs"
"#;
    assert_eq!(
        manifest_bins(manifest),
        [
            "commented_header",
            "spaced_header",
            "name_after_path",
            "after_lints"
        ]
    );
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

/// `(name, path)` of every `[[bin]]` target; `path` defaults to
/// `src/bin/<name>.rs`, as Cargo's does.
fn manifest_bin_paths(manifest: &str) -> Vec<(String, String)> {
    let manifest: toml::Table = toml::from_str(manifest).expect("Cargo.toml parses as TOML");
    let Some(bins) = manifest.get("bin") else {
        return Vec::new();
    };
    bins.as_array()
        .expect("`bin` is an array of tables")
        .iter()
        .map(|bin| {
            let name = bin
                .get("name")
                .and_then(toml::Value::as_str)
                .expect("a [[bin]] has a string `name`")
                .to_string();
            let path = bin
                .get("path")
                .and_then(toml::Value::as_str)
                .map_or_else(|| format!("src/bin/{name}.rs"), str::to_string);
            (name, path)
        })
        .collect()
}

/// The first `//!` line of a binary's source: the summary its header gives.
fn summary_line(source: &str) -> Option<&str> {
    source
        .lines()
        .find(|l| l.trim_start().starts_with("//!"))
        .map(str::trim)
}

/// A standing or admin binary must not introduce itself as one-time (backlog
/// 748966d0, split from 02de2b85): `epigraph-operator` called itself "the
/// one-time operator ownership backfill" while it carries the standing operator
/// verbs, which is the kind of header that gets a reusable tool retired.
#[test]
fn standing_and_admin_bins_do_not_introduce_themselves_as_one_time() {
    let classes: BTreeMap<&str, &str> = table_rows(README, "Binaries").into_iter().collect();
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    let mut offenders = Vec::new();
    for (name, path) in manifest_bin_paths(MANIFEST) {
        let Some(class) = classes.get(name.as_str()) else {
            continue; // the completeness test reports a missing row
        };
        if !matches!(*class, "standing" | "admin") {
            continue;
        }
        let source = std::fs::read_to_string(crate_dir.join(&path))
            .unwrap_or_else(|e| panic!("read {path} for [[bin]] {name}: {e}"));
        let summary = summary_line(&source)
            .unwrap_or_else(|| panic!("{path} ([[bin]] {name}) has no `//!` header"));
        checked += 1;
        let lower = summary.to_lowercase();
        if ["one-time", "one-shot", "one time", "one shot"]
            .iter()
            .any(|w| lower.contains(w))
        {
            offenders.push(format!("{name} ({class}): {summary}"));
        }
    }
    // Non-vacuity: both classes are populated well beyond a handful of bins.
    assert!(checked >= 20, "only {checked} standing/admin bins checked");
    assert!(
        offenders.is_empty(),
        "these binaries are classified standing or admin in README.md, yet their \
         header's summary line calls them one-time/one-shot; rewrite the summary \
         (keep any one-shot history further down the header):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn summary_line_is_the_first_inner_doc_line() {
    assert_eq!(
        summary_line("// licence\n//! `x` — the tool.\n//! more\n"),
        Some("//! `x` — the tool.")
    );
    assert_eq!(summary_line("fn main() {}\n"), None);
}
