//! Ratchet: the engine's zero-caller surface stays deleted.
//!
//! These modules and types had no production caller in this workspace or in
//! the downstream consumers, yet every reader had to work out that they were
//! dead. They were removed (backlog 122efac3); git history keeps
//! them. This test scans the crate's own `src/` so a revert or a copy-paste
//! that brings one back fails here and has to justify itself with a caller.
//!
//! Deliberately narrow: it names the deleted files and their distinctive
//! public symbols, not generic module names such as `service` or `trust`.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The deleted module files, relative to `src/`. `trust.rs` was never even
/// compiled (no `mod trust` existed); the other five were `pub mod`s.
const DELETED_FILES: &[&str] = &[
    "service.rs",
    "unified_bp.rs",
    "domain_decay.rs",
    "agent_assessment.rs",
    "belief_gate.rs",
    "trust.rs",
];

/// Distinctive public symbols of the deleted surface.
const DELETED_SYMBOLS: &[&str] = &[
    "EpistemicService",
    "run_unified_bp",
    "UnifiedBpResult",
];

#[test]
fn zero_caller_engine_modules_stay_deleted() {
    let src = src_dir();
    let present: Vec<&str> = DELETED_FILES
        .iter()
        .copied()
        .filter(|f| src.join(f).exists())
        .collect();
    assert!(
        present.is_empty(),
        "zero-caller engine module(s) reintroduced under src/: {present:?}; \
         add a production caller in the same change or leave them deleted"
    );
}

#[test]
fn zero_caller_engine_symbols_stay_deleted() {
    let mut files = Vec::new();
    rust_sources(&src_dir(), &mut files);
    assert!(!files.is_empty(), "found no .rs files under src/");

    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source file");
        for (lineno, line) in text.lines().enumerate() {
            for sym in DELETED_SYMBOLS {
                if line.contains(sym) {
                    hits.push(format!(
                        "{}:{}: {sym}",
                        file.strip_prefix(src_dir()).unwrap_or(file).display(),
                        lineno + 1
                    ));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "deleted zero-caller engine symbol(s) reappeared in src/:\n{}",
        hits.join("\n")
    );
}
