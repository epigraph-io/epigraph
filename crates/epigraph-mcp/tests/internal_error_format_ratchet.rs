//! Source ratchet: no new `internal_error(format!("ctx: {e}"))` in this crate
//! (backlog e0f0cb68 (2)).
//!
//! `crate::errors::internal_error` redacts what it is handed: the caller gets
//! the fixed `INTERNAL_ERROR_MESSAGE`, and the text goes to the server log. A
//! `format!` built for it therefore throws away its own context. The caller
//! never learns which step failed ("could not commit", "could not record
//! authorship"), and a coded refusal formatted into the `String` loses the type
//! `designed_refusal` recognises it by. The form that keeps both halves is
//! `internal_error_logged("ctx", e)`: the designed context goes to the caller
//! and the error goes to the log.
//!
//! The scan drops `//` comments, is not fooled by a line break between
//! `internal_error(` and `format!`, and skips rmcp's two-argument constructor
//! (`McpError::internal_error(format!(..), None)`), which sends its message as
//! written.

use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Files allowed to keep the pattern, how many sites each, and why.
///
/// `errors.rs` defines the helper, and its own redaction test calls it with a
/// `format!` on purpose; its count is exact. `tools/recall.rs` belongs to
/// another session's work and is grandfathered at its count on 2026-10-26 as
/// a CEILING: work in that file may remove sites without editing this test,
/// but may not add one. Lower the number as its sites are converted.
const ALLOWED: &[(&str, usize, Bound, &str)] = &[
    (
        "errors.rs",
        1,
        Bound::Exact,
        "the helper's own test of its redaction (internal_error_withholds_the_error_text_and_logs_it)",
    ),
    (
        "tools/recall.rs",
        12,
        Bound::AtMost,
        "grandfathered: owned by another session's open work; convert, then lower this",
    ),
];

/// How an allowlisted file's count is held.
#[derive(Clone, Copy, Debug)]
enum Bound {
    /// Exactly this many: a change in either direction fails.
    Exact,
    /// No more than this many.
    AtMost,
}

fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The 1-based lines where `internal_error(` (the crate helper, not
/// `McpError::internal_error` / `ErrorData::internal_error`) takes a
/// `format!` as its first argument.
fn sites(text: &str) -> Vec<usize> {
    const CALL: &str = "internal_error(";
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(off) = text[from..].find(CALL) {
        let at = from + off;
        from = at + CALL.len();
        let before = &text[..at];
        // A longer identifier ending in `internal_error` (e.g.
        // `log_internal_error(`) is not the helper.
        if before
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        if before.ends_with("McpError::") || before.ends_with("ErrorData::") {
            continue;
        }
        if text[from..].trim_start().starts_with("format!") {
            out.push(before.matches('\n').count() + 1);
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_internal_error_is_handed_a_formatted_string() {
    let root = src();
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    assert!(
        files.len() > 50,
        "the scan found only {} files",
        files.len()
    );

    let mut offenders = Vec::new();
    let mut allowed_seen = std::collections::BTreeMap::new();
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = strip_line_comments(&std::fs::read_to_string(path).expect("read source"));
        let found = sites(&text);
        if let Some((_, allowed, _, _)) = ALLOWED.iter().find(|(f, _, _, _)| *f == rel) {
            allowed_seen.insert(rel.clone(), (found.len(), *allowed));
            continue;
        }
        for line in found {
            offenders.push(format!("{rel}:{line}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "internal_error(format!(..)) discards its own context (the caller gets only \
         INTERNAL_ERROR_MESSAGE). Use internal_error_logged(\"<context>\", e), or \
         .map_err(internal_error) to keep a designed refusal. Sites:\n  {}",
        offenders.join("\n  ")
    );
    for (file, allowed, bound, why) in ALLOWED {
        let (found, _) = allowed_seen
            .get(*file)
            .copied()
            .unwrap_or_else(|| panic!("allowlisted file {file} was not scanned"));
        let holds = match bound {
            Bound::Exact => found == *allowed,
            Bound::AtMost => found <= *allowed,
        };
        assert!(
            holds,
            "{file} has {found} internal_error(format!(..)) sites; the ratchet allows {bound:?} \
             {allowed} ({why}). Convert the new site with internal_error_logged, or lower the \
             number."
        );
    }
}

/// The scanner itself: the shapes it must catch and the ones it must skip.
#[test]
fn the_scanner_tells_the_helper_from_the_rmcp_constructor() {
    let caught = "a.map_err(|e| internal_error(format!(\"x: {e}\")))?;\n\
                  b.map_err(|e| {\n    crate::errors::internal_error(\n        format!(\"y: {e}\"),\n    )\n})?;";
    assert_eq!(sites(caught), vec![1, 3]);
    let skipped = "McpError::internal_error(format!(\"t\"), None);\n\
                   McpError::internal_error(\n    format!(\"t\"),\n    None,\n);\n\
                   internal_error_logged(\"ctx\", e);\n\
                   .map_err(internal_error)?;\n\
                   log_internal_error(format!(\"z\"));";
    assert!(sites(skipped).is_empty(), "{:?}", sites(skipped));
}
