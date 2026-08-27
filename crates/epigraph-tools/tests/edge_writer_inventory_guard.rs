//! Static-analysis guard for `docs/architecture/edge-writer-inventory.md`.
//!
//! The inventory enumerates every code path that writes an `edges` row and
//! records whether a signing key is in scope there. A document like that rots
//! silently: a writer moves to a new file, a path is renamed, or the first
//! signing writer lands and nobody updates the prose. These tests pin the two
//! facts that must not drift, plus the doc's own path citations.
//!
//! Hosted in `epigraph-tools` deliberately: the crate has no `sqlx`
//! dependency (so no `cargo sqlx prepare` can ever be implicated), it already
//! depends on `walkdir` and `regex`, it already has repo-walking tests using
//! the same `CARGO_MANIFEST_DIR`-relative root, and no crate in the workspace
//! depends on it. None of these tests touches a database.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use regex::Regex;
use walkdir::WalkDir;

/// Workspace root, computed at compile time.
/// `CARGO_MANIFEST_DIR` is `crates/epigraph-tools/`; root is two levels up.
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

const INVENTORY: &str = "docs/architecture/edge-writer-inventory.md";

/// The literal every direct edge writer contains. Deliberately the same string
/// the doc's own `grep` recipes use, so the test and the doc cannot disagree
/// about what "a direct edge writer" means.
const EDGE_INSERT: &str = "INSERT INTO edges";

const FILES_BEGIN: &str = "<!-- edge-writer-files:begin -->";
const FILES_END: &str = "<!-- edge-writer-files:end -->";

fn read_inventory() -> String {
    let path = Path::new(REPO_ROOT).join(INVENTORY);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Every `.rs` file under `crates/*/src/`, as a repo-relative path with `/`
/// separators. Mirrors the `crates/*/src/` glob the inventory's `grep` recipes
/// use, so the two scan exactly the same set.
fn crate_src_rust_files() -> Vec<(String, String)> {
    let crates_dir = Path::new(REPO_ROOT).join("crates");
    let mut out = Vec::new();

    let mut crate_dirs: Vec<PathBuf> = std::fs::read_dir(&crates_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", crates_dir.display()))
        .map(|e| e.expect("readdir entry").path())
        .filter(|p| p.is_dir())
        .collect();
    crate_dirs.sort();

    for crate_dir in crate_dirs {
        let crate_name = crate_dir
            .file_name()
            .expect("crate dir has a name")
            .to_string_lossy()
            .into_owned();
        let src = crate_dir.join("src");
        if !src.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&src).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel_within_src = path
                .strip_prefix(&src)
                .expect("walked path is under src")
                .to_string_lossy()
                .replace('\\', "/");
            let rel = format!("crates/{crate_name}/src/{rel_within_src}");
            let body = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            out.push((rel, body));
        }
    }

    assert!(
        !out.is_empty(),
        "found no Rust sources under {}/crates/*/src — is REPO_ROOT wrong?",
        REPO_ROOT
    );
    out
}

/// Files under `crates/*/src/` containing at least one direct edge insert.
fn actual_edge_writer_files() -> BTreeSet<String> {
    crate_src_rust_files()
        .into_iter()
        .filter(|(_, body)| body.contains(EDGE_INSERT))
        .map(|(rel, _)| rel)
        .collect()
}

/// The sentinel-delimited file list the inventory declares.
fn documented_edge_writer_files(doc: &str) -> BTreeSet<String> {
    let start = doc
        .find(FILES_BEGIN)
        .unwrap_or_else(|| panic!("{INVENTORY} is missing the `{FILES_BEGIN}` sentinel"))
        + FILES_BEGIN.len();
    let end = doc
        .find(FILES_END)
        .unwrap_or_else(|| panic!("{INVENTORY} is missing the `{FILES_END}` sentinel"));
    assert!(
        end > start,
        "{INVENTORY}: `{FILES_END}` appears before `{FILES_BEGIN}`"
    );

    let path_re = Regex::new(r"`(crates/[^`\s]+\.rs)`").expect("static regex compiles");
    path_re
        .captures_iter(&doc[start..end])
        .map(|c| c[1].to_string())
        .collect()
}

/// Strip fenced code blocks so the reproducing-commands section (which is full
/// of shell globs like `crates/*/src/`) is not mistaken for a path citation.
fn strip_fenced_code(doc: &str) -> String {
    let mut out = String::with_capacity(doc.len());
    let mut in_fence = false;
    for line in doc.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Count direct edge inserts whose column list names `signature`.
///
/// The column list is everything between `INSERT INTO edges` and the `VALUES`
/// or `SELECT` that follows it. A window of a few lines is enough: the widest
/// column list in the tree spans two.
fn signing_edge_writer_count() -> usize {
    let mut count = 0;
    for (_, body) in crate_src_rust_files() {
        let lines: Vec<&str> = body.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(col) = line.find(EDGE_INSERT) else {
                continue;
            };
            let end = lines.len().min(i + 6);
            let mut window = lines[i][col..].to_string();
            for l in &lines[i + 1..end] {
                window.push('\n');
                window.push_str(l);
            }
            let upper = window.to_uppercase();
            let stop = [upper.find("VALUES"), upper.find("SELECT")]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(window.len());
            if window[..stop].contains("signature") {
                count += 1;
            }
        }
    }
    count
}

/// Parse `<!-- signing-writer-count: N -->`.
fn documented_signing_writer_count(doc: &str) -> usize {
    let re = Regex::new(r"<!--\s*signing-writer-count:\s*(\d+)\s*-->").expect("static regex");
    let caps = re
        .captures(doc)
        .unwrap_or_else(|| panic!("{INVENTORY} is missing the `signing-writer-count` sentinel"));
    caps[1].parse().expect("sentinel digits parse as usize")
}

/// The inventory must name every file that writes an `edges` row directly, and
/// no others. Keyed on files rather than line numbers: line citations drift
/// with every unrelated edit, file membership does not.
#[test]
fn inventory_lists_every_direct_edge_insert_file() {
    let doc = read_inventory();
    let documented = documented_edge_writer_files(&doc);
    let actual = actual_edge_writer_files();

    let missing: Vec<&String> = actual.difference(&documented).collect();
    let stale: Vec<&String> = documented.difference(&actual).collect();

    assert!(
        missing.is_empty() && stale.is_empty(),
        "{INVENTORY} is out of date with the tree.\n\
         Files writing `{EDGE_INSERT}` but absent from the sentinel list: {missing:?}\n\
         Files listed in the sentinel block but no longer writing edges: {stale:?}\n\
         Fix by updating the sentinel block (and the site tables) in {INVENTORY}."
    );
}

/// Every path the inventory cites must resolve. Catches the doc rotting when a
/// file is moved or renamed.
#[test]
fn inventory_cited_paths_all_exist() {
    let doc = read_inventory();
    let prose = strip_fenced_code(&doc);

    // Backticked repo paths, optionally suffixed with `:LINE`, which we drop.
    let re = Regex::new(
        r"`((?:crates|scripts)/[A-Za-z0-9_./-]+\.(?:rs|py|sql|toml|md))(?::\d+(?:-\d+)?)?`",
    )
    .expect("static regex compiles");

    let cited: BTreeSet<String> = re.captures_iter(&prose).map(|c| c[1].to_string()).collect();

    assert!(
        !cited.is_empty(),
        "{INVENTORY} cites no repo paths at all — the extraction regex is probably broken"
    );

    let missing: Vec<&String> = cited
        .iter()
        .filter(|p| !Path::new(REPO_ROOT).join(p).is_file())
        .collect();

    assert!(
        missing.is_empty(),
        "{INVENTORY} cites paths that no longer exist: {missing:?}"
    );
}

/// Drift detector, **not** a prohibition on edge signing.
///
/// Today no direct edge insert names `signature`, so the sentinel reads 0.
/// When the first signing writer lands this test fails, which is the intended
/// behaviour: it forces the inventory to be updated rather than silently
/// becoming wrong. The fix is a one-line sentinel edit, never a reason to
/// abandon the change that tripped it.
#[test]
fn signing_writer_count_matches_documented() {
    let doc = read_inventory();
    let documented = documented_signing_writer_count(&doc);
    let actual = signing_edge_writer_count();

    assert_eq!(
        actual, documented,
        "direct `{EDGE_INSERT}` statements naming `signature`: found {actual}, \
         {INVENTORY} declares {documented}. If you just landed edge signing, \
         update the `signing-writer-count` sentinel and the inventory's tables."
    );
}
