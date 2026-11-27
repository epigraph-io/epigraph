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

/// The classes whose binaries may write `claims` with reviewed SQL of their
/// own (backlog 832e89a8). Every other claim writer in this crate goes through
/// `epigraph_db::ClaimRepository`, so there is one INSERT per claim shape and
/// the repository's tenancy, dedup-lock and `claim.created` contracts hold for
/// it. `admin` is the README's "operator admin or ceremony" class.
const RAW_CLAIM_INSERT_CLASSES: [&str; 2] = ["one-shot", "admin"];

/// `path -> name` of every `[[bin]]` that declares a `path`.
fn manifest_bin_paths(manifest: &str) -> BTreeMap<String, String> {
    let manifest: toml::Table = toml::from_str(manifest).expect("Cargo.toml parses as TOML");
    let Some(bins) = manifest.get("bin").and_then(toml::Value::as_array) else {
        return BTreeMap::new();
    };
    bins.iter()
        .filter_map(|bin| {
            let name = bin.get("name")?.as_str()?;
            let path = bin.get("path")?.as_str()?;
            Some((path.to_string(), name.to_string()))
        })
        .collect()
}

/// `source` with `//` comments and every `#[cfg(test)] mod … { … }` block
/// removed, so a test fixture or a doc line naming the statement is not a
/// production writer.
fn production_code(source: &str) -> String {
    let mut out = String::new();
    let mut lines = source.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() == "#[cfg(test)]" {
            let opens_module = lines
                .peek()
                .is_some_and(|next| next.trim_start().starts_with("mod "));
            if opens_module {
                let mut depth: i64 = 0;
                let mut opened = false;
                for body in lines.by_ref() {
                    depth += i64::try_from(body.matches('{').count()).unwrap();
                    depth -= i64::try_from(body.matches('}').count()).unwrap();
                    opened |= body.contains('{');
                    if opened && depth <= 0 {
                        break;
                    }
                }
                continue;
            }
        }
        let code = line.split("//").next().unwrap_or_default();
        out.push_str(code);
        out.push('\n');
    }
    out
}

#[test]
fn production_code_drops_comments_and_test_modules_only() {
    let source = "\
fn writer() { q(\"INSERT INTO claims (a)\"); }
// INSERT INTO claims in a comment
#[cfg(test)]
mod tests {
    fn fixture() { q(\"INSERT INTO claims (b)\"); }
}
fn after_the_tests() { q(\"INSERT INTO claims (c)\"); }
";
    let kept = production_code(source);
    assert_eq!(kept.matches("INSERT INTO claims").count(), 2, "{kept}");
    assert!(kept.contains("(a)") && kept.contains("(c)"), "{kept}");
}

/// No production source of this crate writes `claims` with its own `INSERT`,
/// except a `[[bin]]` the README classifies as `one-shot` or `admin` (backlog
/// 832e89a8). `hypothesis` and `method_search` (both `experiment`) used to,
/// each with an INSERT carrying the embedding, labels and properties inline;
/// they now create the row through `ClaimRepository` and store the vector
/// through its sealed-safe writer in the same transaction.
#[test]
fn only_one_shot_or_admin_bins_insert_claims_with_their_own_sql() {
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let bin_paths = manifest_bin_paths(MANIFEST);
    let classes: BTreeMap<&str, &str> = table_rows(README, "Binaries").into_iter().collect();
    let statement = regex::Regex::new(r"(?i)INSERT\s+INTO\s+(public\.)?claims\b").unwrap();

    let mut scanned = 0usize;
    let mut offenders = Vec::new();
    for entry in walkdir::WalkDir::new(crate_root.join("src")) {
        let entry = entry.expect("walk src/");
        if entry.path().extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        scanned += 1;
        let rel = entry
            .path()
            .strip_prefix(crate_root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(entry.path()).expect("read source");
        let sites = statement.find_iter(&production_code(&source)).count();
        if sites == 0 {
            continue;
        }
        let class = bin_paths
            .get(&rel)
            .and_then(|bin| classes.get(bin.as_str()).copied());
        if !class.is_some_and(|c| RAW_CLAIM_INSERT_CLASSES.contains(&c)) {
            offenders.push(format!("{rel} ({sites} site(s), class {class:?})"));
        }
    }
    assert!(scanned > 50, "scanned only {scanned} source files");
    assert!(
        offenders.is_empty(),
        "claim INSERTs outside ClaimRepository in a source that is not a one-shot or admin \
         [[bin]]: {offenders:?}. Create the claim through epigraph_db::ClaimRepository (and \
         store its vector with ClaimRepository::store_embedding_if_unsealed in the same \
         transaction), or classify the binary in README.md if it really is an operator \
         one-shot or ceremony."
    );
}
