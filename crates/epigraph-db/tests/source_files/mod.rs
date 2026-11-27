//! Path-keyed lints that survive a module split.
//!
//! Many lints in this directory key a register on a source path and a function
//! name, `("crates/epigraph-db/src/repos/claim.rs", "repair_marked_duplicate")`,
//! or read one file with `include_str!`. Splitting `claim.rs` into a directory
//! module (`repos/claim.rs` plus `repos/claim/*.rs`, or `repos/claim/mod.rs`
//! plus siblings; backlog 39955709) would change every key of a moved function:
//! the register would report the moved site as unregistered and its old entry
//! as stale, and a lint that reads only the top level of `src/repos/` would
//! stop scanning the moved code at all and pass in silence.
//!
//! This module makes a registered path name the MODULE, not the file:
//!
//! * [`module_key`] folds the path of any file inside a split module's
//!   directory onto the module's registered path, so a measured site keys the
//!   same before and after a move. Counts are summed by the callers, never
//!   overwritten, so folding two files onto one key cannot hide a site.
//! * [`module_files`] reads the registered file and every `.rs` under its
//!   directory, and [`fn_body`] finds a function across all of them, still
//!   requiring exactly one definition.
//! * [`repo_sources`] walks `src/repos/` RECURSIVELY, keyed by repos-relative
//!   path with the same folding, for the lints keyed on bare file names.
//!
//! Only the modules listed in [`SPLIT_MODULES`] fold. Two `X.rs` plus `X/`
//! pairs already exist in the workspace (`epigraph-engine`'s
//! `supersede_delta`, `epigraph-api`'s `routes/elevate`), and their child files
//! are keyed as themselves by the registers that name them; a generic rule
//! would re-key them. A module split later is added to the list in the PR that
//! splits it. The fold matches on a directory boundary (`…/claim/`), so a
//! sibling such as `claim_history.rs` or `claim_context.rs` is never folded.
//!
//! Self-tests: `source_files_self_test.rs`.

#![allow(dead_code)] // each lint uses a different subset of this module

use std::path::{Path, PathBuf};

/// Modules registered by their file path whose code may live in a directory
/// module of the same name. Workspace-relative, with `/` separators.
pub const SPLIT_MODULES: &[&str] = &["crates/epigraph-db/src/repos/claim.rs"];

/// The workspace root. `CARGO_MANIFEST_DIR` is `crates/epigraph-db`.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two ancestors")
        .to_path_buf()
}

/// The key a lint registers `path` under.
///
/// `path` may be written relative to any ancestor directory of the split
/// module (the workspace root, `crates/`, `src/repos/`): a file inside a split
/// module's directory, at any depth and `mod.rs` included, keys as the
/// module's registered file written relative to the same ancestor
/// (`claim/dedup.rs` keys as `claim.rs`, `epigraph-db/src/repos/claim/mod.rs`
/// as `epigraph-db/src/repos/claim.rs`). Any other path keys as itself.
pub fn module_key(path: &str) -> String {
    let path = path.replace('\\', "/");
    if path.ends_with(".rs") {
        for root in SPLIT_MODULES {
            let stem = root
                .strip_suffix(".rs")
                .expect("a split module is a .rs path");
            // Every suffix of `stem` that starts at a component boundary.
            let mut from = 0;
            loop {
                let form = &stem[from..];
                if path
                    .strip_prefix(form)
                    .is_some_and(|rest| rest.starts_with('/'))
                {
                    return format!("{form}.rs");
                }
                match form.find('/') {
                    Some(i) => from += i + 1,
                    None => break,
                }
            }
        }
    }
    path
}

/// Whether `path` (in any of [`module_key`]'s forms) is part of the module
/// registered as `registered` (in the same form).
pub fn belongs_to(registered: &str, path: &str) -> bool {
    module_key(path) == registered
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `(path relative to base, text)` for every `.rs` under `dir`, recursively,
/// sorted by path.
fn read_tree(base: &Path, dir: &Path) -> Vec<(String, String)> {
    let mut paths = Vec::new();
    rs_files(dir, &mut paths);
    let mut out: Vec<(String, String)> = paths
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(base)
                .expect("under the base")
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&p).expect("read source");
            (rel, text)
        })
        .collect();
    out.sort();
    out
}

/// The files of the module registered as `registered` under `root`: the file
/// itself when it exists, and every `.rs` under its directory, as
/// `(path relative to root, text)` sorted by path.
pub fn module_files_in(root: &Path, registered: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let file = root.join(registered);
    if file.is_file() {
        out.push((
            registered.to_string(),
            std::fs::read_to_string(&file).expect("read module file"),
        ));
    }
    let stem = registered.strip_suffix(".rs").expect("a .rs path");
    out.extend(read_tree(root, &root.join(stem)));
    out.sort();
    out
}

/// [`module_files_in`] at the workspace root. Panics when the module has no
/// file at all, so a misspelled or deleted path fails instead of passing on
/// an empty text.
pub fn module_files(registered: &str) -> Vec<(String, String)> {
    let out = module_files_in(&repo_root(), registered);
    assert!(
        !out.is_empty(),
        "no source for module {registered}: neither the file nor a directory module exists"
    );
    out
}

/// The paths among `files` that define `fn name` (`fn name(` or `fn name<`),
/// once per definition. Text-level, comments and strings included: a caller
/// that needs exactness uses [`fn_body`], which requires exactly one hit.
pub fn files_defining(files: &[(String, String)], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (path, text) in files {
        for open in ['(', '<'] {
            let needle = format!("fn {name}{open}");
            for (at, _) in text.match_indices(&needle) {
                let whole = at == 0 || !is_ident(text.as_bytes()[at - 1]);
                if whole {
                    out.push(path.clone());
                }
            }
        }
    }
    out
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The body (outermost braces included) of the one function whose signature
/// starts with `signature`, searched across every file in `files`.
///
/// Panics when the signature is absent from all of them or appears more than
/// once in total, so a rename (or a copy left behind by a move) cannot make a
/// structural assertion pass vacuously.
pub fn fn_body<'a>(files: &'a [(String, String)], signature: &str) -> &'a str {
    let hits: Vec<(&str, &str, usize)> = files
        .iter()
        .flat_map(|(path, text)| {
            text.match_indices(signature)
                .map(move |(i, _)| (path.as_str(), text.as_str(), i))
        })
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one `{signature}` across {:?}, found {} ({:?})",
        files.iter().map(|(p, _)| p).collect::<Vec<_>>(),
        hits.len(),
        hits.iter().map(|(p, _, i)| (p, i)).collect::<Vec<_>>()
    );
    let (_, src, start) = hits[0];
    let open = start + src[start..].find('{').expect("function has a body");
    let mut depth = 0usize;
    for (off, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..=open + off];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces after `{signature}`");
}

/// Every `.rs` under `dir`, recursively, keyed by its path relative to `dir`
/// passed through [`module_key`], sorted by key then path. A split module's
/// files all key as its registered file name (`claim/dedup.rs` as
/// `claim.rs`); a file in any other subdirectory keys as its relative path,
/// so it is scanned rather than skipped.
pub fn repo_sources_in(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String, String)> = read_tree(dir, dir)
        .into_iter()
        .map(|(rel, text)| (module_key(&rel), rel, text))
        .collect();
    out.sort();
    out.into_iter().map(|(key, _, text)| (key, text)).collect()
}

/// [`repo_sources_in`] over this crate's `src/repos/`.
pub fn repo_sources() -> Vec<(String, String)> {
    repo_sources_in(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/repos"))
}

/// For a lint's split self-test: `files` with the module registered as
/// `registered` (in the lint's own path form) split further. Its largest file
/// (ties by path) keeps its text up to the top-level `impl` line nearest its
/// middle, and the rest moves to `<stem>/split_probe.rs`, a new file inside
/// the module's directory. A top-level item boundary, so every function lands
/// whole in one file or the other.
///
/// Resolved by module, not by file, so it works on both layouts: before the
/// split (`claim.rs` is the largest file) and after it (`claim/mod.rs` or a
/// child is).
///
/// Panics when no file of `files` belongs to the module, when the probe path
/// is already taken, or when the chosen text has no top-level `impl` line.
pub fn split_module(files: &[(String, String)], registered: &str) -> Vec<(String, String)> {
    let (path, text) = files
        .iter()
        .filter(|(p, _)| belongs_to(registered, p))
        .max_by(|a, b| a.1.len().cmp(&b.1.len()).then_with(|| b.0.cmp(&a.0)))
        .unwrap_or_else(|| panic!("no file of module {registered} is among the scanned files"));
    let stem = registered.strip_suffix(".rs").expect("a .rs path");
    let probe = format!("{stem}/split_probe.rs");
    assert!(
        files.iter().all(|(p, _)| *p != probe),
        "{probe} already exists"
    );
    let middle = text.len() / 2;
    let mut at = None::<usize>;
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if line.starts_with("impl ")
            && at.is_none_or(|a| offset.abs_diff(middle) < a.abs_diff(middle))
        {
            at = Some(offset);
        }
        offset += line.len();
    }
    let at = at.unwrap_or_else(|| panic!("{path} has no top-level `impl` line to split at"));
    let mut out: Vec<(String, String)> = files.iter().filter(|(p, _)| p != path).cloned().collect();
    out.push((path.clone(), text[..at].to_string()));
    out.push((probe, text[at..].to_string()));
    out.sort();
    out
}
