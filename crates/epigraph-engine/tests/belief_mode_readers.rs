//! Ratchet: the belief-mode flags have ONE reader,
//! `crates/epigraph-engine/src/belief_modes.rs`.
//!
//! - Backlog 820c15f1: four types parsed the same variables with their own
//!   `OnceLock` readers: `atom_items::{AtomFoldMode, CompoundSourceEdges}`,
//!   `belief_view::CompoundBeliefMode` and the API's `state::BpApply`. They
//!   could disagree with what `/health` reported.
//!   [`no_belief_flag_is_read_outside_belief_modes`] fails on any production
//!   source outside the module that names a flag's variable as a string
//!   literal, or reads the environment through a flag's `ENV` constant.
//!
//! The scan is plain text over every `crates/*/src` file, with comments and
//! `#[cfg(test)] mod` blocks excluded (`support/rust_sources.rs`).

#[path = "support/rust_sources.rs"]
mod rust_sources;

use epigraph_engine::belief_modes::BeliefModes;
use rust_sources::{production_code, production_sources, workspace_root};

/// The one module that parses the flags.
const READER: &str = "crates/epigraph-engine/src/belief_modes.rs";

/// The type names whose `ENV` constant names a flag's variable, past and
/// present spellings.
const FLAG_TYPES: &[&str] = &[
    "AtomFold",
    "AtomFoldMode",
    "CompoundBelief",
    "CompoundBeliefMode",
    "CompoundWriteGuard",
    "CompoundSourceEdges",
    "AtomCacheMode",
    "Inference",
    "BpApply",
];

/// `src` with every whitespace character removed, so a call that rustfmt
/// split over lines still matches one needle.
fn squeezed(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The places in one file's production code that parse a flag themselves.
fn flag_parses(src: &str) -> Vec<String> {
    let code = production_code(src);
    let mut hits = Vec::new();
    for field in BeliefModes::default().fields() {
        let literal = format!("\"{}\"", field.env);
        for (n, line) in code.lines().enumerate() {
            if line.contains(&literal) {
                hits.push(format!("line {}: {}", n + 1, line.trim()));
            }
        }
    }
    let flat = squeezed(&code);
    for read in ["env::var(", "env::var_os("] {
        for (i, _) in flat.match_indices(read) {
            let arg: String = flat[i + read.len()..]
                .chars()
                .take_while(|c| *c != ')')
                .collect();
            let through_a_flag = FLAG_TYPES
                .iter()
                .any(|ty| arg == format!("{ty}::ENV") || arg.ends_with(&format!("::{ty}::ENV")));
            if through_a_flag || arg.ends_with("BP_APPLY_ENV") {
                hits.push(format!("reads the environment through {arg}"));
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

#[test]
fn no_belief_flag_is_read_outside_belief_modes() {
    let root = workspace_root();
    let offenders: Vec<String> = production_sources(&root)
        .into_iter()
        .filter(|(file, _)| file != READER)
        .flat_map(|(file, src)| {
            flag_parses(&src)
                .into_iter()
                .map(move |hit| format!("{file}: {hit}"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "a belief-mode flag is read outside {READER}; read it from \
         `belief_modes::current()` instead, so every reader and `/health` see the same \
         value:\n{}",
        offenders.join("\n")
    );
}

/// The scanner itself, on known text: a parse is a hit; the same text in a
/// comment or a `#[cfg(test)] mod` is not.
#[test]
fn the_scanner_sees_parses_and_skips_comments_and_tests() {
    let parse = r#"
pub const ENV: &str = "EPIGRAPH_ATOM_FOLD";
fn on() -> bool { std::env::var(BpApply::ENV).is_ok() }
fn on2() -> bool { std::env::var(crate::belief_modes::Inference::ENV).is_ok() }
"#;
    let hits = flag_parses(parse);
    assert_eq!(hits.len(), 3, "{hits:?}");

    let quiet = r#"
// "EPIGRAPH_ATOM_FOLD" in a comment, std::env::var(BpApply::ENV) too.
#[cfg(test)]
mod tests {
    const X: &str = "EPIGRAPH_BP_APPLY";
    fn f() { let _ = crate::belief_modes::current().bp_apply; }
}
"#;
    assert!(flag_parses(quiet).is_empty());
}
