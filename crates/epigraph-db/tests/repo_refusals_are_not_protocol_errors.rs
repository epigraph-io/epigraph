//! Source ratchet: the repo layer builds no `sqlx::Error::Protocol(..)` of its
//! own (backlog e0f0cb68 (1)).
//!
//! A refusal the repo layer authors ("mark_duplicate: canonical .. is not
//! current", "FA07: ..", "not a plain role identifier: ..") is
//! `DbError::Refused { kind, message }`. It used to be built as
//! `DbError::QueryFailed { source: sqlx::Error::Protocol(msg) }`, the shape
//! `From<sqlx::Error>` also gives sqlx's own protocol errors, so the MCP layer
//! could not tell the two apart and now redacts `QueryFailed { Protocol }`
//! (`epigraph-mcp/src/errors.rs::designed_refusal`). A site reverted to the old
//! shape would still read the same in `err.to_string()`, which is all most of
//! the sites' behaviour tests check, while the MCP caller silently lost that
//! refusal's text. This scan is what fails.
//!
//! It reads the code view of `lint_text::spend_views`: comments removed and
//! string contents blanked, so a doc comment or a log line that names
//! `Protocol(` is not a site.

mod lint_text;

use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Files allowed to keep `Protocol(`, how many sites each, and why. Counts are
/// exact: a change in either direction fails.
const ALLOWED: &[(&str, usize, &str)] = &[(
    "repos/match_candidate.rs",
    3,
    "require_privileged and mark_retired_on's two refusals return sqlx::Result; their only \
     production consumer (engine admin_cascade, via repair_with_audit!) stringifies the error, \
     so they never reach MCP designed_refusal. Converting them changes public signatures.",
)];

/// How many times the identifier `Protocol` is called in `code` (`Protocol(`,
/// `Protocol (`). A count, not line numbers: the code view blanks string
/// contents (their newlines included), so its line numbers drift from the
/// file's; [`raw_lines`] locates the sites for the failure message.
fn sites(code: &str) -> usize {
    const NAME: &str = "Protocol";
    let mut out = 0;
    let mut from = 0;
    while let Some(off) = code[from..].find(NAME) {
        let at = from + off;
        from = at + NAME.len();
        let before = &code[..at];
        if before
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        let after = &code[from..];
        if after
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        if after.trim_start().starts_with('(') {
            out += 1;
        }
    }
    out
}

/// The 1-based lines of the RAW source that mention `Protocol(`, to point a
/// failure at the site (comments and strings included, so it can over-list).
fn raw_lines(raw: &str) -> Vec<usize> {
    raw.lines()
        .enumerate()
        .filter(|(_, l)| l.contains("Protocol("))
        .map(|(i, _)| i + 1)
        .collect()
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
fn the_repo_layer_builds_no_protocol_error_of_its_own() {
    let root = src();
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    assert!(
        files.len() > 30,
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
        let raw = std::fs::read_to_string(path).expect("read source");
        let found = sites(&lint_text::spend_views(&raw).0);
        if ALLOWED.iter().any(|(f, _, _)| *f == rel) {
            allowed_seen.insert(rel, found);
            continue;
        }
        if found > 0 {
            offenders.push(format!(
                "{rel}: {found} site(s), near lines {:?}",
                raw_lines(&raw)
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "a repo-authored refusal built as sqlx::Error::Protocol(..) is indistinguishable from \
         sqlx's own protocol errors, so the MCP layer redacts it. Build \
         DbError::Refused {{ kind, message }} instead. Sites:\n  {}",
        offenders.join("\n  ")
    );
    for (file, allowed, why) in ALLOWED {
        let found = allowed_seen
            .get(*file)
            .copied()
            .unwrap_or_else(|| panic!("allowlisted file {file} was not scanned"));
        assert_eq!(
            found, *allowed,
            "{file} has {found} Protocol( sites; the ratchet allows exactly {allowed} ({why}). \
             Build DbError::Refused for a new refusal, or lower the number."
        );
    }
}

/// The scanner itself: the shapes it must catch and the ones it must skip,
/// read through the same code view the ratchet reads.
#[test]
fn the_scanner_finds_protocol_calls_only_in_code() {
    let caught = "return Err(DbError::QueryFailed {\n\
                  \x20   source: sqlx::Error::Protocol(format!(\"x\")),\n\
                  });\n\
                  let e = Protocol (\"y\".into());";
    assert_eq!(sites(&lint_text::spend_views(caught).0), 2);
    let skipped = "/// used to be `sqlx::Error::Protocol(msg)`\n\
                   // sqlx::Error::Protocol(old)\n\
                   tracing::warn!(\"was Protocol(x)\");\n\
                   let p = ProtocolError(1);\n\
                   let q = my_Protocol(2);";
    assert_eq!(sites(&lint_text::spend_views(skipped).0), 0);
}
