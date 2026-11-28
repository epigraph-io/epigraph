//! Ratchet: the engine's internal-only helpers stay off its public surface.
//!
//! `reconciliation::{cluster_obstructions, extract_cospan}` are steps of
//! `reconciliation::reconcile` (which the API calls) and have no other
//! caller, so they are `pub(crate)`. `sheaf::compute_cohomology` (the scalar,
//! non-CDST H¹) is called only by its own unit tests, so it lives in
//! `sheaf.rs`'s `#[cfg(test)]` module. None of the three is re-exported from
//! `lib.rs` (backlog f0d266af). A `pub` on any of them again makes every
//! reader work out whether it has a caller; this test makes that change
//! justify itself.
//!
//! It reads code only: comments and `#[cfg(test)] mod` blocks are blanked by
//! the shared lexer (`support/rust_sources.rs`).

#[allow(dead_code)] // `production_sources`, `workspace_root`: this test reads three engine files.
#[path = "support/rust_sources.rs"]
mod rust_sources;

use rust_sources::production_code;
use std::path::Path;

fn code_of(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
    production_code(&text)
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The identifier tokens of `line`, in order.
fn tokens(line: &str) -> Vec<&str> {
    line.split(|c: char| !is_ident(c))
        .filter(|t| !t.is_empty())
        .collect()
}

/// For each line of `code` that declares `fn <name>`, the text before the
/// `fn` keyword, trimmed (its visibility and qualifiers, e.g. `pub(crate)`).
fn fn_decl_prefixes(code: &str, name: &str) -> Vec<String> {
    code.lines()
        .filter(|l| tokens(l).windows(2).any(|w| w[0] == "fn" && w[1] == name))
        .map(|l| {
            let at = l.find("fn ").expect("a fn declaration has `fn `");
            l[..at].trim().to_string()
        })
        .collect()
}

/// True when `code` names `ident` as a whole identifier anywhere.
fn names(code: &str, ident: &str) -> bool {
    code.lines().any(|l| tokens(l).contains(&ident))
}

const CRATE_PRIVATE_IN_RECONCILIATION: &[&str] = &["cluster_obstructions", "extract_cospan"];
const TEST_ONLY_IN_SHEAF: &[&str] = &["compute_cohomology"];

#[test]
fn reconciliation_helpers_are_crate_private() {
    let code = code_of("reconciliation.rs");
    for name in CRATE_PRIVATE_IN_RECONCILIATION {
        let prefixes = fn_decl_prefixes(&code, name);
        assert_eq!(
            prefixes,
            vec!["pub(crate)".to_string()],
            "reconciliation::{name} must be declared exactly once, as `pub(crate) fn`: \
             its only caller is `reconcile`"
        );
    }
}

#[test]
fn compute_cohomology_is_test_only() {
    let code = code_of("sheaf.rs");
    for name in TEST_ONLY_IN_SHEAF {
        assert!(
            fn_decl_prefixes(&code, name).is_empty(),
            "sheaf::{name} is declared outside `#[cfg(test)] mod tests`; \
             it has no production caller"
        );
    }
}

#[test]
fn lib_does_not_reexport_internal_helpers() {
    let code = code_of("lib.rs");
    let leaked: Vec<&str> = CRATE_PRIVATE_IN_RECONCILIATION
        .iter()
        .chain(TEST_ONLY_IN_SHEAF)
        .copied()
        .filter(|name| names(&code, name))
        .collect();
    assert!(
        leaked.is_empty(),
        "lib.rs re-exports internal-only helper(s): {leaked:?}"
    );
}

#[test]
fn matchers_read_declarations_not_prose() {
    assert_eq!(
        fn_decl_prefixes("pub fn extract_cospan(", "extract_cospan"),
        vec!["pub"]
    );
    assert_eq!(
        fn_decl_prefixes("pub(crate) fn extract_cospan(", "extract_cospan"),
        vec!["pub(crate)"]
    );
    assert!(fn_decl_prefixes("let c = extract_cospan(x);", "extract_cospan").is_empty());
    assert!(fn_decl_prefixes("pub fn extract_cospans(", "extract_cospan").is_empty());
    assert!(names(
        "pub use reconciliation::{\n    cluster_obstructions, reconcile,\n};",
        "cluster_obstructions"
    ));
    assert!(!names(
        "pub use sheaf::compute_cohomology_x;",
        "compute_cohomology"
    ));
    // A `#[cfg(test)] mod` is blanked, so a test-only definition is invisible.
    let code = production_code(
        "pub fn live() {}\n#[cfg(test)]\nmod tests {\n    fn compute_cohomology() {}\n}\n",
    );
    assert!(fn_decl_prefixes(&code, "compute_cohomology").is_empty());
    // Comments are blanked too, so a history note does not trip the scan.
    let code = production_code("//! `compute_cohomology` moved to tests\n");
    assert!(!names(&code, "compute_cohomology"));
}
