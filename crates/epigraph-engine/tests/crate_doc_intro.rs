//! The opening of the crate doc in `src/lib.rs` describes the engine that
//! runs (backlog f814e581).
//!
//! It once introduced the crate as Bayesian truth updates, evidence
//! weighting, DAG validation and reputation, and named none of the modules
//! the served paths run: the DS fold, the belief profile and modes, edge
//! factors, the retraction cascades. The rules pinned here, for the intro
//! only (the crate doc up to its first `# ` heading; the sections after it
//! have their own owners):
//!
//! 1. the intro links every module of the production pipeline below, so a
//!    rewrite cannot drop one silently;
//! 2. the first path segment of every intra-doc link in the intro is a
//!    `pub mod` declared in `lib.rs`, so the intro cannot name a module that
//!    no longer exists.
//!
//! `cargo check` and clippy do not run rustdoc, and CI does not build the
//! docs, so neither drift would otherwise be caught.

use std::path::Path;

/// The modules the served belief pipeline runs, which the intro must name.
const PIPELINE_MODULES: &[&str] = &[
    // The DS fold.
    "bba",
    "source_dependence",
    "classifier",
    "scoped_belief",
    // Belief profile and modes.
    "belief_profile",
    "belief_modes",
    // Edge factors (also home of the cache refresh).
    "edge_factor",
    // Cascades.
    "retraction_cascade",
    "admin_cascade",
    "bba_retract",
    // Cross-source matching.
    "matching",
];

fn lib_rs() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    std::fs::read_to_string(path).expect("read src/lib.rs")
}

/// The crate doc's text up to (not including) its first heading.
fn intro(src: &str) -> String {
    src.lines()
        .map_while(|l| l.strip_prefix("//!"))
        .map(|l| l.strip_prefix(' ').unwrap_or(l))
        .take_while(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The targets of the intra-doc links in `doc`: every "[`path`]" (a
/// "[text](`path`)" link with a module target is not used in this doc).
fn link_targets(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = doc;
    while let Some(at) = rest.find("[`") {
        let after = &rest[at + 2..];
        let Some(end) = after.find("`]") else { break };
        let target = &after[..end];
        // `[`x`](...)` is an explicit link: its text is not the target.
        if !after[end + 2..].starts_with('(') {
            out.push(target.to_string());
        }
        rest = &after[end + 2..];
    }
    out
}

/// The names of the `pub mod` items declared in `src`.
fn pub_mods(src: &str) -> Vec<String> {
    src.lines()
        .filter_map(|l| l.trim().strip_prefix("pub mod "))
        .map(|rest| {
            rest.trim_end_matches(|c: char| c == ';' || c == '{' || c.is_whitespace())
                .to_string()
        })
        .collect()
}

#[test]
fn intro_links_every_pipeline_module() {
    let src = lib_rs();
    let links = link_targets(&intro(&src));
    let missing: Vec<&str> = PIPELINE_MODULES
        .iter()
        .copied()
        .filter(|m| !links.iter().any(|l| l.split("::").next() == Some(*m)))
        .collect();
    assert!(
        missing.is_empty(),
        "the crate doc intro does not link pipeline module(s) {missing:?}; \
         describe what runs before the first `# ` heading of src/lib.rs"
    );
}

#[test]
fn intro_links_name_declared_modules() {
    let src = lib_rs();
    let mods = pub_mods(&src);
    let dangling: Vec<String> = link_targets(&intro(&src))
        .into_iter()
        .filter(|l| {
            let first = l.split("::").next().unwrap_or_default();
            !mods.iter().any(|m| m == first)
        })
        .collect();
    assert!(
        dangling.is_empty(),
        "the crate doc intro links {dangling:?}, whose first segment is not a \
         `pub mod` declared in src/lib.rs"
    );
}

#[test]
fn helpers_read_the_doc_as_written() {
    let src = "//! Title\n//!\n//! Uses [`bba`] and [`edge_factor::recompute`].\n\
               //! [text](`not_a_target`) and [`x`](crate::y).\n\
               //! # Heading\n//! [`after_heading`]\npub mod bba;\npub mod edge_factor {\n}\n";
    let doc = intro(src);
    assert!(!doc.contains("after_heading"), "intro stops at the heading");
    assert_eq!(link_targets(&doc), vec!["bba", "edge_factor::recompute"]);
    assert_eq!(pub_mods(src), vec!["bba", "edge_factor"]);
}
