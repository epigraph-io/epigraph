//! No production SQL may resolve a `claims` row by `content_hash` ALONE.
//!
//! # What this closes
//!
//! `ClaimRepository::create` and `create_with_tx` deduplicated with
//! `SELECT … FROM claims WHERE content_hash = $1 LIMIT 1` and returned the
//! first matching row, whoever had written it and in whatever tenant. That is
//! the cross-agent collapse the noun-claims design names (the canonical key is
//! `(content_hash, agent_id)`, enforced by `uq_claims_content_hash_agent`), and
//! after the tenancy series it was a cross-TENANT one: the MCP document ingest
//! labelled and wrote provenance onto another tenant's private claim through
//! it, and `routes/conventions.rs` 400'd whenever the text already existed.
//! Both methods are deleted, their callers moved to `create_or_get` /
//! `create_strict` / `create_with_id_if_absent`, and
//! `epigraph-cli/src/bin/method_search.rs`'s own copy of the shape now names
//! the agent. Deferred-commitment screen key `legacy-claim-create-callers`
//! (s3a-followup #7 and #8).
//!
//! # The rule
//!
//! Every Rust string literal under `crates/*/src/` that filters `claims` with a
//! `content_hash = $N` or `content_hash = ANY(` predicate must name `agent_id`
//! in the same `WHERE` region (projecting it is not enough; the retired
//! statement did). More than one spelling is matched on purpose:
//! `method_search.rs` used `SELECT 1 FROM claims WHERE content_hash = $1` with
//! no `LIMIT`, which a needle keyed on the legacy statement's exact text would
//! have missed.
//!
//! # What it cannot see, stated rather than implied
//!
//! * SQL assembled from several literals (`concat!`, `format!` pieces) is
//!   judged one literal at a time.
//! * A predicate spelled another way (`content_hash IN (…)`, a join on
//!   `content_hash`) is not matched.
//! * Comments are excluded, so prose that QUOTES the retired statement — this
//!   file's own sibling docs do — is not an offender.

use std::path::{Path, PathBuf};

/// One string literal: the file it came from, its 1-based line, its contents.
struct Literal {
    file: PathBuf,
    line: usize,
    text: String,
}

/// Collect the contents of every string literal in `src`, skipping comments.
///
/// Handles `"…"` with escapes, raw strings `r"…"` / `r#"…"#` (any number of
/// hashes), byte strings, line and block comments, and the char-literal /
/// lifetime ambiguity of `'`, which is the one that would otherwise let a
/// `'"'` open a phantom string and invert the rest of the file.
fn string_literals(file: &Path, src: &str) -> Vec<Literal> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1;
    let bump = |c: u8, line: &mut usize| {
        if c == b'\n' {
            *line += 1;
        }
    };
    while i < b.len() {
        let c = b[i];
        // Line comment.
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment (Rust nests them).
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    bump(b[i], &mut line);
                    i += 1;
                }
            }
            continue;
        }
        // Raw string: r"…", r#"…"#, br#"…"#. Only when the prefix starts a
        // token, so the `r` ending an identifier (`bar"`) is not one.
        let prev_is_ident = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if !prev_is_ident && (c == b'r' || (c == b'b' && b.get(i + 1) == Some(&b'r'))) {
            let mut j = if c == b'b' { i + 2 } else { i + 1 };
            let mut hashes = 0;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&b'"') {
                let start_line = line;
                let body_start = j + 1;
                let mut k = body_start;
                loop {
                    if k >= b.len() {
                        break;
                    }
                    if b[k] == b'"' && (0..hashes).all(|h| b.get(k + 1 + h) == Some(&b'#')) {
                        break;
                    }
                    bump(b[k], &mut line);
                    k += 1;
                }
                out.push(Literal {
                    file: file.to_path_buf(),
                    line: start_line,
                    text: src[body_start..k.min(b.len())].to_string(),
                });
                i = k + 1 + hashes;
                continue;
            }
        }
        // Ordinary (or byte) string.
        if c == b'"' {
            let start_line = line;
            let body_start = i + 1;
            let mut k = body_start;
            while k < b.len() && b[k] != b'"' {
                if b[k] == b'\\' {
                    bump(b.get(k + 1).copied().unwrap_or(0), &mut line);
                    k += 2;
                    continue;
                }
                bump(b[k], &mut line);
                k += 1;
            }
            out.push(Literal {
                file: file.to_path_buf(),
                line: start_line,
                text: src[body_start..k.min(b.len())].to_string(),
            });
            i = k + 1;
            continue;
        }
        // Char literal vs lifetime.
        if c == b'\'' {
            if b.get(i + 1) == Some(&b'\\') {
                // Skip the backslash AND the escaped char before looking for
                // the close, or `'\''` closes on its own escaped quote.
                let mut k = i + 3;
                while k < b.len() && b[k] != b'\'' {
                    k += 1;
                }
                i = k + 1;
                continue;
            }
            if b.get(i + 2) == Some(&b'\'') {
                i += 3;
                continue;
            }
            // A multi-byte char literal such as '→'.
            if let Some(ch) = src[i + 1..].chars().next() {
                let w = ch.len_utf8();
                if w > 1 && b.get(i + 1 + w) == Some(&b'\'') {
                    i += 2 + w;
                    continue;
                }
            }
            i += 1; // lifetime
            continue;
        }
        bump(c, &mut line);
        i += 1;
    }
    out
}

/// Collapse all whitespace runs to one space and lowercase, so spelling and
/// layout do not decide the verdict.
fn normalise(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// The `WHERE` region of a statement over `claims`, normalised, or `None`
/// when the literal does not filter `claims`.
///
/// The PREDICATE region, not the whole literal: the retired statement
/// PROJECTS `agent_id` (`SELECT id, content, truth_value, agent_id, …`), so a
/// rule that asked only whether `agent_id` appeared anywhere would have passed
/// the very statement this file exists to keep out.
fn claims_predicate(sql: &str) -> Option<String> {
    let s = normalise(sql);
    let from = s.find("from claims").or_else(|| s.find("update claims"))?;
    let tail = &s[from..];
    let at = tail.find(" where ")?;
    Some(tail[at..].to_string())
}

/// `content_hash = $N` or `content_hash = ANY(`, with or without an alias.
fn has_content_hash_predicate(pred: &str) -> bool {
    pred.match_indices("content_hash").any(|(at, needle)| {
        let rest = pred[at + needle.len()..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            return false;
        };
        let rest = rest.trim_start();
        rest.starts_with('$') || rest.starts_with("any(") || rest.starts_with("any (")
    })
}

/// Does this literal filter `claims` on `content_hash` without the agent in the
/// same predicate?
fn is_content_hash_only_claim_lookup(sql: &str) -> bool {
    claims_predicate(sql)
        .is_some_and(|pred| has_content_hash_predicate(&pred) && !pred.contains("agent_id"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn rust_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            rust_files_under(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Every string literal in every `crates/*/src/**/*.rs`.
fn production_literals() -> (usize, Vec<Literal>) {
    let root = workspace_root();
    let mut files = Vec::new();
    for krate in std::fs::read_dir(root.join("crates")).expect("crates/") {
        let src = krate.expect("crate entry").path().join("src");
        if src.is_dir() {
            rust_files_under(&src, &mut files);
        }
    }
    let mut lits = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).expect("read source");
        let rel = f.strip_prefix(&root).unwrap_or(f).to_path_buf();
        lits.extend(string_literals(&rel, &text));
    }
    (files.len(), lits)
}

#[test]
fn no_production_sql_resolves_a_claim_by_content_hash_alone() {
    let (files, lits) = production_literals();
    let offenders: Vec<String> = lits
        .iter()
        .filter(|l| is_content_hash_only_claim_lookup(&l.text))
        .map(|l| format!("  {}:{}: {}", l.file.display(), l.line, normalise(&l.text)))
        .collect();

    // Non-vacuity: the scan must have reached real code, and must SEE the
    // compliant lookups that exist today, or a broken extractor would pass.
    assert!(files > 100, "scanned only {files} files under crates/*/src");
    let compliant = lits
        .iter()
        .filter(|l| {
            claims_predicate(&l.text)
                .is_some_and(|p| has_content_hash_predicate(&p) && p.contains("agent_id"))
        })
        .count();
    assert!(
        compliant >= 2,
        "CALIBRATION: expected to see at least the two agent-keyed lookups \
         (`ClaimRepository::find_by_content_hash_and_agent`, `consolidate`'s \
         idempotency probe); saw {compliant}. The extractor is not reading the \
         SQL it is meant to judge."
    );

    assert!(
        offenders.is_empty(),
        "\n\nContent-hash-only claim lookup(s) in production code:\n{}\n\n\
         A `claims` row resolved by `content_hash` ALONE is whichever agent's \
         (and whichever tenant's) row happens to carry that text. The canonical \
         key is `(content_hash, agent_id)`: use \
         `ClaimRepository::find_by_content_hash_and_agent` / `create_or_get` \
         (viewer-scoped), or key on the id with `create_with_id_if_absent`.\n",
        offenders.join("\n")
    );
}

#[test]
fn the_matcher_flags_every_retired_spelling_and_nothing_agent_keyed() {
    // The legacy `create` / `create_with_tx` dedup read, verbatim. It PROJECTS
    // `agent_id`, which is why the rule reads the predicate region only.
    assert!(is_content_hash_only_claim_lookup(
        "-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate.\n \
         SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at\n \
         FROM claims WHERE content_hash = $1 LIMIT 1"
    ));
    // `method_search.rs`'s former spelling: no LIMIT, different projection.
    assert!(is_content_hash_only_claim_lookup(
        "SELECT 1 FROM claims WHERE content_hash = $1"
    ));
    // Set form and aliasing.
    assert!(is_content_hash_only_claim_lookup(
        "SELECT c.id FROM claims c WHERE c.content_hash = ANY($1)"
    ));
    assert!(is_content_hash_only_claim_lookup(
        "select id from claims where content_hash=$2"
    ));

    // Agent-keyed: allowed.
    assert!(!is_content_hash_only_claim_lookup(
        "SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2"
    ));
    assert!(!is_content_hash_only_claim_lookup(
        "SELECT EXISTS (SELECT 1 FROM claims WHERE content_hash = $1 AND agent_id = $2)"
    ));
    // Not a claims lookup, or not a predicate.
    assert!(!is_content_hash_only_claim_lookup(
        "SELECT id FROM evidence WHERE content_hash = $1"
    ));
    assert!(!is_content_hash_only_claim_lookup(
        "UPDATE claims SET content_hash = COALESCE($1, content_hash) WHERE id = $3"
    ));
}

#[test]
fn the_extractor_reads_literals_and_skips_comments() {
    let src = r####"
        // SELECT id FROM claims WHERE content_hash = $1   (a comment)
        /* SELECT id FROM claims WHERE content_hash = $1 */
        /// SELECT id FROM claims WHERE content_hash = $1
        fn f<'a>(x: &'a str) -> char {
            let q = "SELECT 1 FROM claims WHERE content_hash = $1";
            let r = r#"SELECT id FROM claims
                       WHERE content_hash = $1 LIMIT 1"#;
            let quote = '"';
            let s = "tail";
            '\''
        }
    "####;
    let lits = string_literals(Path::new("t.rs"), src);
    let texts: Vec<&str> = lits.iter().map(|l| l.text.as_str()).collect();
    assert_eq!(
        texts.len(),
        3,
        "exactly the three string literals, no comment, and the `'\"'` char \
         literal must not open a phantom string; got {texts:?}"
    );
    assert_eq!(
        lits.iter()
            .filter(|l| is_content_hash_only_claim_lookup(&l.text))
            .count(),
        2
    );
    assert_eq!(texts[2], "tail");
    assert_eq!(
        lits[0].line, 6,
        "line numbers are 1-based and count comments"
    );
}
