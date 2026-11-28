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

/// The classes whose binaries may write `claims` with reviewed SQL of their
/// own (backlog 832e89a8). Every other claim writer in this crate goes through
/// `epigraph_db::ClaimRepository`, so there is one INSERT per claim shape and
/// the repository's tenancy, dedup-lock and `claim.created` contracts hold for
/// it. `admin` is the README's "operator admin or ceremony" class.
const RAW_CLAIM_INSERT_CLASSES: [&str; 2] = ["one-shot", "admin"];

/// `path -> name` of every `[[bin]]`; a missing `path` defaults to
/// `src/bin/<name>.rs`, as Cargo's does.
fn bin_names_by_path(manifest: &str) -> BTreeMap<String, String> {
    let manifest: toml::Table = toml::from_str(manifest).expect("Cargo.toml parses as TOML");
    let Some(bins) = manifest.get("bin").and_then(toml::Value::as_array) else {
        return BTreeMap::new();
    };
    bins.iter()
        .filter_map(|bin| {
            let name = bin.get("name")?.as_str()?;
            let path = bin
                .get("path")
                .and_then(toml::Value::as_str)
                .map_or_else(|| format!("src/bin/{name}.rs"), str::to_string);
            Some((path, name.to_string()))
        })
        .collect()
}

/// The net `{` minus `}` of one line, counting only braces outside `"…"`
/// strings and outside the char literals `'{'`, `'}'` and `'"'`. `in_str` carries an
/// open string over to the next line. Raw strings holding a `"` are not
/// understood; a test module that has one may end early, which only makes the
/// scan see more code, never less.
fn code_brace_delta(line: &str, in_str: &mut bool) -> i64 {
    let line = line
        .replace("'{'", "")
        .replace("'}'", "")
        .replace("'\"'", "");
    let mut delta = 0;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if *in_str => {
                chars.next();
            }
            '"' => *in_str = !*in_str,
            '{' if !*in_str => delta += 1,
            '}' if !*in_str => delta -= 1,
            _ => {}
        }
    }
    delta
}

/// `source` without its `//` comment lines (`//`, `///`, `//!`) and without
/// the body of every `#[cfg(test)] mod … { … }`, so a doc line or a test
/// fixture naming the statement is not a production writer. Errs toward
/// keeping code: a trailing `// …` comment is kept (a SQL string may hold
/// `//`), and `#[cfg(test)] mod x;` removes nothing.
fn production_code(source: &str) -> String {
    let mut out = String::new();
    let mut lines = source.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() == "#[cfg(test)]" {
            let opens_module_body = lines.peek().is_some_and(|next| {
                let next = next.trim_start();
                (next.starts_with("mod ") || next.starts_with("pub mod "))
                    && !next.trim_end().ends_with(';')
            });
            if opens_module_body {
                let mut depth: i64 = 0;
                let mut opened = false;
                let mut in_str = false;
                for body in lines.by_ref() {
                    let delta = code_brace_delta(body, &mut in_str);
                    opened |= delta > 0;
                    depth += delta;
                    if opened && depth <= 0 {
                        break;
                    }
                }
                continue;
            }
        }
        if line.trim_start().starts_with("//") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[test]
fn production_code_drops_comment_lines_and_test_module_bodies_only() {
    let source = "\
fn writer() { q(\"INSERT INTO claims (a)\"); }
// INSERT INTO claims in a comment
/// INSERT INTO claims in a doc line
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

/// The shapes the first parser got wrong, each of which hid a production
/// INSERT from the scan: a body-less `#[cfg(test)] mod x;` swallowed the next
/// item; `//` inside a SQL string cut the statement off; and a brace inside a
/// string or char literal in a test module ended or extended its body at the
/// wrong line.
#[test]
fn production_code_keeps_production_inserts_next_to_tricky_test_code() {
    let declaration_only = "\
#[cfg(test)]
mod viewer_fixture;
fn after_a_declaration() { q(\"INSERT INTO claims (d)\"); }
";
    assert!(
        production_code(declaration_only).contains("INSERT INTO claims (d)"),
        "a body-less test module hid the next item"
    );

    let url_before_insert =
        "fn w() { q(\"WITH u AS (SELECT 'https://x') INSERT INTO claims (e)\"); }\n";
    assert!(
        production_code(url_before_insert).contains("INSERT INTO claims (e)"),
        "a `//` inside a string cut the statement"
    );

    let braces_in_literals = "\
#[cfg(test)]
mod tests {
    fn f() { let open = '{'; let q = '\"'; let s = \"}\"; let t = \"{\"; }
    fn g() { q(\"INSERT INTO claims (fixture)\"); }
}
fn after_the_tests() { q(\"INSERT INTO claims (g)\"); }
";
    let kept = production_code(braces_in_literals);
    assert!(
        kept.contains("INSERT INTO claims (g)") && !kept.contains("(fixture)"),
        "a brace literal mis-ended the test module: {kept}"
    );
}

/// No production source of this crate writes `claims` with its own `INSERT`,
/// except a `[[bin]]` root file the README classifies as `one-shot` or `admin`
/// (backlog 832e89a8). Only the class is checked here; that such a binary runs
/// on the maintenance DSN is a review rule. `tests/` and `#[cfg(test)]`
/// module bodies are not scanned. `hypothesis` and `method_search` (both
/// `experiment`) used to insert claims themselves, each with an INSERT
/// carrying the embedding, labels and properties inline; they now create the
/// row through `ClaimRepository` and store the vector through its sealed-safe
/// writer in the same transaction.
#[test]
fn only_one_shot_or_admin_bins_insert_claims_with_their_own_sql() {
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let bin_paths = bin_names_by_path(MANIFEST);
    assert!(
        bin_paths.contains_key("src/bin/hypothesis.rs")
            && bin_paths.contains_key("src/bin/method_search.rs"),
        "the [[bin]] path map misses the two binaries this scan was written for"
    );
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
