//! The crate doc in `src/lib.rs` describes the crate that actually ships
//! (backlog 35be3cd3).
//!
//! The doc once opened with "Label Property Graph Primitives" and listed
//! `Node`, `Edge`, `NodeId`/`EdgeId` and `PropertyMap` as the core types: an
//! in-memory graph model that no crate in the workspace, and no crate that
//! pins `epigraph-core` by git rev, ever used. Meanwhile it said nothing about
//! the modules the kernel does depend on (tenancy, challenges, atomicity, the
//! relationship vocabulary). The rules pinned here:
//!
//! 1. every `pub mod` declared in `lib.rs` is named by an intra-doc link in
//!    the crate doc, so a new module cannot ship undescribed;
//! 2. every intra-doc link in the crate doc resolves to something `lib.rs`
//!    declares: a lower-case first path segment must be a declared module,
//!    and a bare upper-case name must be re-exported at the root by a
//!    `pub use`. A type that is deleted cannot stay advertised.
//!
//! `cargo check` and clippy do not run rustdoc, so a stale intra-doc link
//! would otherwise go unnoticed.
//!
//! The last test pins the one path downstream crates import from the `edge`
//! module, `epigraph_core::edge::relationships`. It is a guard, not a proof:
//! it compiles on both sides of the deletion.
//!
//! The source is read as text, so this test adds no dependency.

use std::collections::BTreeSet;

const LIB_RS: &str = include_str!("../src/lib.rs");

/// Module names from `pub mod <name>;` lines.
fn declared_modules() -> BTreeSet<String> {
    LIB_RS
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub mod "))
        .filter_map(|rest| rest.strip_suffix(';'))
        .map(str::to_string)
        .collect()
}

/// The `//!` crate doc, joined into one string.
fn crate_doc() -> String {
    LIB_RS
        .lines()
        .filter_map(|l| l.strip_prefix("//!"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every `` [`target`] `` intra-doc link target in `doc`.
fn doc_links(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = doc;
    while let Some(start) = rest.find("[`") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("`]") else { break };
        out.push(after[..end].to_string());
        rest = &after[end + 2..];
    }
    out
}

/// Everything the root `pub use` statements re-export, as raw text (the
/// statements span several lines, so they are collected up to their `;`).
fn root_reexport_text() -> String {
    let mut text = String::new();
    let mut in_use = false;
    for line in LIB_RS.lines() {
        let t = line.trim();
        if t.starts_with("pub use ") {
            in_use = true;
        }
        if in_use {
            text.push_str(t);
            text.push(' ');
            if t.ends_with(';') {
                in_use = false;
            }
        }
    }
    text
}

fn reexports(name: &str) -> bool {
    root_reexport_text()
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|tok| tok == name)
}

#[test]
fn crate_doc_names_every_declared_module() {
    let links = doc_links(&crate_doc());
    let missing: Vec<String> = declared_modules()
        .into_iter()
        .filter(|m| {
            !links
                .iter()
                .any(|l| l == m || l.starts_with(&format!("{m}::")))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "lib.rs declares these modules but the crate doc never links them: {missing:?}"
    );
}

#[test]
fn crate_doc_links_only_what_lib_rs_declares() {
    let modules = declared_modules();
    let mut dangling = Vec::new();
    for link in doc_links(&crate_doc()) {
        let first = link.split("::").next().unwrap_or_default();
        let ok = if first.starts_with(|c: char| c.is_ascii_lowercase()) {
            modules.contains(first)
        } else {
            !link.contains("::") && reexports(first)
        };
        if !ok {
            dangling.push(link);
        }
    }
    assert!(
        dangling.is_empty(),
        "the crate doc links names lib.rs neither declares as a module nor re-exports: {dangling:?}"
    );
}

#[test]
fn edge_relationships_path_stays_importable() {
    use epigraph_core::edge::relationships::{
        canonical_relationship, is_lineage_relationship, is_symmetric_claim_relationship,
        relationship_spellings, CASE_FOLDED_RELATIONSHIPS, SUPERSEDES_ACT_ONLY, SUPPORTS,
    };
    assert_eq!(SUPPORTS, "supports");
    assert_eq!(canonical_relationship("SUPPORTS"), SUPPORTS);
    assert_eq!(
        relationship_spellings("REFINES"),
        vec!["REFINES".to_string()]
    );
    assert!(is_lineage_relationship("SUPERSEDES"));
    assert!(is_symmetric_claim_relationship("CONTRADICTS"));
    assert!(CASE_FOLDED_RELATIONSHIPS.contains(&"refutes"));
    assert!(SUPERSEDES_ACT_ONLY.contains("supersedes"));
}
