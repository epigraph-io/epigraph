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
//! 2. every intra-doc link in the crate doc resolves, segment by segment, to
//!    a public item of the crate: each leading segment must be a `pub mod`
//!    declared in its parent (as a file or inline), and the last segment must
//!    be a `pub` item or module declared in, or `pub use`d by, the module the
//!    path ends in. A deleted type cannot stay advertised, whether the doc
//!    names it bare (`Node`) or by module path (`edge::Edge`).
//!
//! `cargo check` and clippy do not run rustdoc, so a stale intra-doc link
//! would otherwise go unnoticed.
//!
//! Rule 1 is a doc-coverage ratchet, not the proof that the graph types are
//! gone: that proof is the workspace build after their deletion.
//!
//! Known limits of the text-level resolver (it reads the source, it does not
//! parse it): a `pub` item inside a `#[cfg(...)]`-gated block or a
//! macro-generated item still counts; a `pub use` counts if its text names
//! the last segment anywhere; an inline module's body is cut by brace
//! counting, which a brace inside a string literal or comment would skew.
//!
//! The last test pins the one path downstream crates import from the `edge`
//! module, `epigraph_core::edge::relationships`. It is a guard, not a proof:
//! it compiles on both sides of the deletion.
//!
//! The source is read as text, so this test adds no dependency.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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

/// The text of every `pub use` statement in `src`, joined (the statements
/// span several lines, so each is collected up to its `;`).
fn pub_use_text(src: &str) -> String {
    let mut text = String::new();
    let mut in_use = false;
    for line in src.lines() {
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

fn idents(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
}

/// Whether `src` declares a `pub` item (or module) named `name` on a line of
/// its own, e.g. `pub fn name(`, `pub const fn name(`, `pub struct name<`,
/// `pub mod name;` / `pub mod name {`. `pub(crate)` items do not count.
fn declares_pub_item(src: &str, name: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "async", "const", "enum", "fn", "mod", "static", "struct", "trait", "type", "unsafe",
    ];
    src.lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .any(|rest| {
            let mut toks = idents(rest);
            let mut saw_keyword = false;
            for tok in toks.by_ref() {
                if KEYWORDS.contains(&tok) {
                    saw_keyword = true;
                } else {
                    return saw_keyword && tok == name;
                }
            }
            false
        })
}

/// Whether `src` makes `name` public: declares it, or names it in a
/// `pub use`.
fn exposes(src: &str, name: &str) -> bool {
    declares_pub_item(src, name) || idents(&pub_use_text(src)).any(|t| t == name)
}

/// The body of `pub mod <name> { ... }` inside `src`, cut by brace counting.
fn inline_module_body(src: &str, name: &str) -> Option<String> {
    let open = format!("pub mod {name} {{");
    let at = src.find(&open)? + open.len();
    let mut depth = 1usize;
    for (i, c) in src[at..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(src[at..at + i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Where a file-backed module's children live: `src/a.rs` keeps them in
/// `src/a/`, `src/a/mod.rs` keeps them beside it.
fn child_dir(file: &Path) -> PathBuf {
    let parent = file.parent().expect("a module file has a parent dir");
    match file.file_stem().and_then(|s| s.to_str()) {
        Some("mod" | "lib") => parent.to_path_buf(),
        Some(stem) => parent.join(stem),
        None => parent.to_path_buf(),
    }
}

/// Whether the intra-doc link `link` (a path relative to the crate root)
/// names a public item of this crate. Each leading segment must be a
/// `pub mod` of its parent; the last must be exposed by the module the path
/// ends in.
fn resolves(link: &str) -> bool {
    let segs: Vec<&str> = link.split("::").collect();
    let Some((last, modules)) = segs.split_last() else {
        return false;
    };
    let lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    // The current module's source text and, if it is file-backed, its file.
    let mut src = LIB_RS.to_string();
    let mut file: Option<PathBuf> = Some(lib);
    for m in modules {
        if src.contains(&format!("pub mod {m};")) {
            let Some(dir) = file.as_deref().map(child_dir) else {
                return false;
            };
            let flat = dir.join(format!("{m}.rs"));
            let nested = dir.join(m).join("mod.rs");
            let path = if flat.is_file() { flat } else { nested };
            let Ok(text) = std::fs::read_to_string(&path) else {
                return false;
            };
            src = text;
            file = Some(path);
        } else if let Some(body) = inline_module_body(&src, m) {
            src = body;
            // An inline module's file-backed children would sit in a dir
            // named after it; none exist in this crate, so stop resolving
            // files below an inline module.
            file = None;
        } else {
            return false;
        }
    }
    exposes(&src, last)
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
    let dangling: Vec<String> = doc_links(&crate_doc())
        .into_iter()
        .filter(|l| !resolves(l))
        .collect();
    assert!(
        dangling.is_empty(),
        "the crate doc links paths that do not resolve to a public item of the crate: {dangling:?}"
    );
}

/// The resolver itself: a deleted or unknown item behind a real module path
/// must not resolve. Review of backlog 35be3cd3 found that a first-segment
/// check alone let `edge::Edge` (the struct this change deleted) stay
/// advertised.
#[test]
fn the_link_resolver_follows_the_whole_path() {
    for good in [
        "tenancy",
        "AgentId",
        "domain::ids",
        "domain::ids::AgentId",
        "domain::Claim",
        "tenancy::consolidate_tenancy",
        "edge::relationships",
        "edge::relationships::SUPPORTS",
        "edge::relationships::canonical_relationship",
    ] {
        assert!(resolves(good), "{good} should resolve");
    }
    for bad in [
        "Node",
        "graph::InMemoryGraph",
        "edge::Edge",
        "tenancy::NoSuchThing",
        "domain::nope::Claim",
        "edge::relationships::Edge",
        "CoreError::NodeNotFound",
    ] {
        assert!(!resolves(bad), "{bad} should not resolve");
    }
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
