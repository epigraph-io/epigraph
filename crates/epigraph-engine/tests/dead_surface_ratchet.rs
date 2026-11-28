//! Ratchet: the engine's zero-caller surface stays deleted.
//!
//! These modules and types had no production caller in this workspace or in
//! the downstream consumers, yet every reader had to work out that they were
//! dead. They were removed (backlog 122efac3, 458fbc4c); git history keeps
//! them. This test scans the crate's own `src/` so a revert or a copy-paste
//! that brings one back fails here and has to justify itself with a caller.
//!
//! It reads code only: comments and `#[cfg(test)] mod` blocks are blanked
//! by the shared lexer (`support/rust_sources.rs`), so a doc note such as
//! "replaces the removed module" does not trip it.
//!
//! Deliberately narrow: it names the deleted files, the distinctive module
//! names and the distinctive public symbols, not generic module names such as
//! `service` or `trust` (those two are guarded by their file names only).

#[allow(dead_code)] // `production_sources`, `workspace_root`: this test walks only the engine's src.
#[path = "support/rust_sources.rs"]
mod rust_sources;

use rust_sources::production_code;
use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn engine_src_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            engine_src_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `(path relative to src/, code view)` for every engine source file.
fn engine_code() -> Vec<(String, String)> {
    let src = src_dir();
    let mut files = Vec::new();
    engine_src_files(&src, &mut files);
    assert!(!files.is_empty(), "found no .rs files under src/");
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&src)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&p).expect("read source file");
            (rel, production_code(&text))
        })
        .collect()
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

/// Deleted module names distinctive enough to forbid as a `mod` declaration
/// anywhere in `src/` (inline, `name.rs` or `name/mod.rs` alike).
const DELETED_MODULES: &[&str] = &[
    "unified_bp",
    "domain_decay",
    "agent_assessment",
    "belief_gate",
];

/// Distinctive public symbols of the deleted surface. The orchestrator
/// wrapper's name is spelled in two halves so that a repo-wide `git grep`
/// for it stays empty once it is gone; this test still matches the whole name.
const DELETED_SYMBOLS: &[&str] = &[
    "EpistemicService",
    "run_unified_bp",
    "UnifiedBpResult",
    "DomainDecay",
    "AgentAssessment",
    "should_include_evidence",
    concat!("Concurrent", "Orchestrator"),
];

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// True when `line` declares `mod <name>` (any visibility, inline or not).
fn declares_mod(line: &str, name: &str) -> bool {
    let toks: Vec<&str> = line
        .split(|c: char| !is_ident(c))
        .filter(|t| !t.is_empty())
        .collect();
    toks.windows(2).any(|w| w[0] == "mod" && w[1] == name)
}

#[test]
fn zero_caller_engine_modules_stay_deleted() {
    let src = src_dir();
    let mut present: Vec<String> = DELETED_FILES
        .iter()
        .filter(|f| src.join(f).exists())
        .map(|f| (*f).to_string())
        .collect();
    for name in DELETED_MODULES {
        let dir_mod = format!("{name}/mod.rs");
        if src.join(&dir_mod).exists() {
            present.push(dir_mod);
        }
    }
    for (rel, code) in engine_code() {
        for (lineno, line) in code.lines().enumerate() {
            for name in DELETED_MODULES {
                if declares_mod(line, name) {
                    present.push(format!("{rel}:{}: mod {name}", lineno + 1));
                }
            }
        }
    }
    assert!(
        present.is_empty(),
        "zero-caller engine module(s) reintroduced under src/: {present:?}; \
         add a production caller in the same change or leave them deleted"
    );
}

#[test]
fn zero_caller_engine_symbols_stay_deleted() {
    let mut hits = Vec::new();
    for (rel, code) in engine_code() {
        for (lineno, line) in code.lines().enumerate() {
            for sym in DELETED_SYMBOLS {
                if line.contains(sym) {
                    hits.push(format!("{rel}:{}: {sym}", lineno + 1));
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

#[test]
fn mod_declaration_matcher_reads_code_not_prose() {
    assert!(declares_mod("pub mod belief_gate;", "belief_gate"));
    assert!(declares_mod("mod belief_gate {", "belief_gate"));
    assert!(declares_mod("pub(crate) mod domain_decay;", "domain_decay"));
    assert!(!declares_mod("pub mod belief_gates;", "belief_gate"));
    assert!(!declares_mod("use crate::belief_gate;", "belief_gate"));
    // Comments are blanked before matching, so a history note is fine.
    let code = production_code("//! replaces the removed `pub mod belief_gate`\n");
    assert!(!code.lines().any(|l| declares_mod(l, "belief_gate")));
    let code = production_code("/// was `EpistemicService` before\nfn x() {}\n");
    assert!(!code.contains("EpistemicService"));
}
