//! Shared source walking for the two atom-level belief ratchets,
//! `no_role_blind_belief_reads.rs` and `bba_writer_lint.rs` (SPEC §7.3).
//!
//! Both ratchets measure the same two trees, and both are tested by adding
//! ONE scratch source to the real tree and checking the verdict, so the
//! sources are plain `(path, text)` values a test can extend in memory. No
//! scratch file is ever written to disk.

#![allow(dead_code)] // each ratchet uses a different subset of this module

use std::path::{Path, PathBuf};

/// One scanned file: its path relative to the workspace root, with `/`
/// separators, and its text.
#[derive(Clone, Debug)]
pub struct Source {
    pub path: String,
    pub text: String,
}

impl Source {
    pub fn new(path: &str, text: &str) -> Self {
        Self {
            path: path.to_string(),
            text: text.to_string(),
        }
    }
}

/// The workspace root. `CARGO_MANIFEST_DIR` is `crates/epigraph-db`.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two ancestors")
        .to_path_buf()
}

fn walk(dir: &Path, keep: &dyn Fn(&Path) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "__pycache__") {
                continue;
            }
            walk(&p, keep, out);
        } else if keep(&p) {
            out.push(p);
        }
    }
}

fn load(paths: Vec<PathBuf>) -> Vec<Source> {
    let root = repo_root();
    let mut out: Vec<Source> = paths
        .into_iter()
        .filter_map(|p| {
            // A non-UTF-8 file (an image, a compiled artifact) carries no SQL
            // a reviewer could read either.
            let text = std::fs::read_to_string(&p).ok()?;
            let rel = p
                .strip_prefix(&root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            Some(Source { path: rel, text })
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Every `.rs` file under `crates/*/src/`. Tests, benches and examples are
/// out of scope: a fixture's SQL is not a served read or a production write.
pub fn rust_sources() -> Vec<Source> {
    let mut paths = Vec::new();
    let crates = repo_root().join("crates");
    let Ok(entries) = std::fs::read_dir(&crates) else {
        return Vec::new();
    };
    for e in entries.flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            walk(
                &src,
                &|p: &Path| p.extension().is_some_and(|x| x == "rs"),
                &mut paths,
            );
        }
    }
    load(paths)
}

/// Every text file under `scripts/`, whatever its type.
pub fn script_sources() -> Vec<Source> {
    let mut paths = Vec::new();
    walk(&repo_root().join("scripts"), &|_: &Path| true, &mut paths);
    load(paths)
}

/// `base` plus one scratch source. The ratchets' synthetic tests run the
/// whole pipeline over the real tree and this one addition.
pub fn with_scratch(base: &[Source], path: &str, text: &str) -> Vec<Source> {
    let mut v = base.to_vec();
    v.push(Source::new(path, text));
    v
}
