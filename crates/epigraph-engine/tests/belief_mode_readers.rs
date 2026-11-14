//! Ratchets: the belief-mode flags have ONE reader,
//! `crates/epigraph-engine/src/belief_modes.rs`, and its module doc's "acted
//! on in this build" table says which flags this build acts on.
//!
//! - Backlog 820c15f1: four types parsed the same variables with their own
//!   `OnceLock` readers: `atom_items::{AtomFoldMode, CompoundSourceEdges}`,
//!   `belief_view::CompoundBeliefMode` and the API's `state::BpApply`. They
//!   could disagree with what `/health` reported.
//!   [`no_belief_flag_is_read_outside_belief_modes`] fails on any production
//!   source outside the module that names a flag's variable as a string
//!   literal, or reads the environment through a flag's `ENV` constant.
//! - Backlog fcc33cb1: the table said `bp_apply`, `compound_belief` and
//!   `compound_source_edges` were not acted on, when the code did act on them.
//!   Code acts on a flag by reading its field of the modes the process read:
//!   `belief_modes::current().<key>`, or the atom-cache writer's
//!   `atom_items::modes().<key>`.
//!   [`the_acted_on_table_says_yes_for_every_flag_the_code_reads`] fails when
//!   such a read exists while the flag's table row says "no".
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

/// Whether one file's production code acts on the flag reported as `key`.
fn reads_flag(src: &str, key: &str) -> bool {
    let flat = squeezed(&production_code(src));
    ["current().", "modes()."].iter().any(|via| {
        let needle = format!("{via}{key}");
        flat.match_indices(&needle).any(|(i, _)| {
            // `current().atom_fold` must not also match `current().atom_fold_x`.
            !flat[i + needle.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    })
}

/// The table rows of `belief_modes.rs`'s module doc: variable -> the "acted
/// on in this build" cell.
fn acted_on_table(src: &str) -> Vec<(String, String)> {
    src.lines()
        .filter_map(|l| l.strip_prefix("//! | `EPIGRAPH_"))
        .map(|row| {
            let cells: Vec<&str> = row.split(" | ").collect();
            let env = format!("EPIGRAPH_{}", cells[0].trim_end_matches('`'));
            let acted = cells
                .last()
                .expect("a table row has cells")
                .trim_end_matches('|')
                .trim()
                .to_string();
            (env, acted)
        })
        .collect()
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

#[test]
fn the_acted_on_table_says_yes_for_every_flag_the_code_reads() {
    let root = workspace_root();
    let doc = std::fs::read_to_string(root.join(READER)).expect("read belief_modes.rs");
    let table = acted_on_table(&doc);
    let sources: Vec<(String, String)> = production_sources(&root)
        .into_iter()
        .filter(|(file, _)| file != READER)
        .collect();

    let mut stale = Vec::new();
    for field in BeliefModes::default().fields() {
        let Some((_, acted)) = table.iter().find(|(env, _)| env == field.env) else {
            stale.push(format!("{}: no row in the table", field.env));
            continue;
        };
        let readers: Vec<&str> = sources
            .iter()
            .filter(|(_, src)| reads_flag(src, field.key))
            .map(|(file, _)| file.as_str())
            .collect();
        if !readers.is_empty() && (acted == "no" || acted.starts_with("no:")) {
            stale.push(format!(
                "{}: the table says {acted:?}, but {} read it",
                field.env,
                readers.join(", ")
            ));
        }
    }
    assert_eq!(
        table.len(),
        BeliefModes::default().fields().len(),
        "one table row per flag: {table:?}"
    );
    assert!(
        stale.is_empty(),
        "the \"acted on in this build\" table in {READER} is stale:\n{}",
        stale.join("\n")
    );
}

/// The scanners themselves, on known text: a parse and a read are hits; the
/// same text in a comment or a `#[cfg(test)] mod` is not.
#[test]
fn the_scanners_see_parses_and_reads_and_skip_comments_and_tests() {
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
    assert!(!reads_flag(quiet, "bp_apply"));

    let read = "fn f() -> bool {\n    crate::belief_modes::current()\n        .bp_apply\n        == On\n}\n";
    assert!(reads_flag(read, "bp_apply"));
    assert!(!reads_flag(read, "atom_fold"));
    assert!(reads_flag(
        "let m = atom_items::modes().atom_fold;",
        "atom_fold"
    ));
    assert!(!reads_flag("let m = current().atom_fold_x;", "atom_fold"));

    let table = acted_on_table(
        "//! | `EPIGRAPH_BP_APPLY` | `off`, `on` | `off` | no: still writes |\n\
         //! | `EPIGRAPH_INFERENCE` | `off` | `off` | yes |",
    );
    assert_eq!(
        table,
        vec![
            (
                "EPIGRAPH_BP_APPLY".to_string(),
                "no: still writes".to_string()
            ),
            ("EPIGRAPH_INFERENCE".to_string(), "yes".to_string()),
        ]
    );
}
