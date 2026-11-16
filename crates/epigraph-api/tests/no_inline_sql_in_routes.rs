//! Source lint: inline SQL in the HTTP route handlers is a ratchet, not a
//! free-for-all.
//!
//! # The rule and where it comes from
//!
//! CLAUDE.md, "Schema, migrations, claim mechanics": *"All SQL stays in
//! `crates/epigraph-db/src/repos/`. HTTP routes
//! (`crates/epigraph-api/src/routes/`) and MCP tools
//! (`crates/epigraph-mcp/src/tools/`) both call the repo layer; do not
//! duplicate SQL between them."* For MCP tools the rule is pinned by
//! `crates/epigraph-mcp/tests/no_inline_sql_in_tools.rs`. The HTTP routes had
//! no equivalent until this file. An architecture review counted roughly 126
//! production `sqlx::query*` call sites in 28 files under
//! `crates/epigraph-api/src/routes/` (backlog
//! 04ab6607-628a-4138-a42f-6e3b934edefe).
//!
//! # The count is NOT zero
//!
//! Like its MCP sibling this file does not pass at zero, and says so rather
//! than asserting a rule the tree does not meet. It is an **exact-set
//! ratchet** in the style of `epigraph-mcp/tests/no_inline_sql_in_tools.rs`
//! and `epigraph-db/tests/no_unscoped_pool.rs`: [`REGISTER`] is the measured
//! per-file production count, so the test passes today and the number can
//! only fall. [`HIGH_WATER`] is the measured total. The largest offenders
//! when it was written:
//!
//! | file               | production statements |
//! |--------------------|-----------------------|
//! | `graph.rs`         | 11 |
//! | `hypothesis.rs`    | 11 |
//! | `belief.rs`        | 10 |
//! | `computation.rs`   | 9 |
//! | `policies.rs`      | 9 |
//! | `clusters.rs`      | 8 (tied with `papers.rs`) |
//!
//! 121 statements in 24 files in all when this file was written (120 after
//! #869). The large in-crate DB test modules of
//! `workflows.rs` and `edges.rs` are not counted: they are `#[cfg(test)]` code,
//! and their production halves hold 4 and 6. [`REGISTER`] is authoritative if
//! this table ever drifts from it.
//!
//! # What counts, and what does not
//!
//! A *statement* is one occurrence of the token `sqlx::query` in code. That
//! covers `sqlx::query`, `sqlx::query_as`, `sqlx::query_scalar`, their `!`
//! macro forms and `query_file*`, which all start with it; it is the same
//! needle as the MCP ratchet. Two on one line are two. The scanner first
//! masks line comments, block comments, string literals (including raw
//! strings) and char literals, so prose that mentions `sqlx::query` and SQL
//! text that contains it are not counted. It then drops every item annotated
//! `#[cfg(test)]` or `#[cfg(all(test, ...))]` (the form this crate uses for
//! its in-crate DB tests), by brace matching, wherever the item sits in the
//! file. The MCP ratchet cuts at the first `#[cfg(test)]` instead; that is
//! unsound here, because several route files carry more than one cfg-test
//! item.
//!
//! The known blind spots of a text scan. This is a ratchet over a proxy for
//! "SQL outside the repo layer", not a proof of it:
//!
//! * **Other spellings of a query are invisible.** `sqlx::QueryBuilder`,
//!   `sqlx::raw_sql`, a `use sqlx::query;` followed by a bare `query(..)`, an
//!   alias (`use sqlx as db`), and any helper that wraps `sqlx::query` in
//!   another module are not counted. Moving a statement into a local helper
//!   function inside the route file keeps the count but hides nothing; moving
//!   it into a non-routes module of this crate (for example `state.rs`)
//!   lowers the count without moving it to the repo layer. Review the diff,
//!   not just the number.
//! * **A `use sqlx::query...` line is counted** as a statement, as is a mention
//!   in code that is not a call.
//! * **A call site is not a statement.** One `sqlx::query` token inside a loop,
//!   a helper or a `macro_rules!` body is one site however often it runs.
//! * **Only `#[cfg(test)]` and `#[cfg(all(test, ..))]` are recognised** as
//!   test-only. `#[cfg(any(test, ..))]`, `#[cfg_attr(..)]`, `#![cfg(test)]` and
//!   out-of-line test modules in other files are scanned as production code.
//! * **The scan root is `crates/epigraph-api/src/routes/` only.** Other
//!   `epigraph-api` sources (`state.rs`, `migrate.rs`, ...) hold queries too
//!   and are out of scope here.
//! * Statements are counted in `sqlx::query` form, so a repo-layer call that
//!   itself runs a query is, correctly, not counted.
//!
//! # How to change the register
//!
//! **Only downward.** To remove a statement, move it into
//! `crates/epigraph-db/src/repos/` and call it from the handler, then lower
//! that file's number in [`REGISTER`] and [`HIGH_WATER`] in the same commit.
//! A file driven to zero has its row REMOVED, not set to `0`: the scanner only
//! emits non-zero files, so a `0` row can never be satisfied. Do not raise a
//! number or add a row to make a new query pass; put the query in the repo
//! layer instead.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Production inline-SQL statements per file, as
/// `(path relative to crates/epigraph-api/src/routes, count)`, sorted by path.
const REGISTER: &[(&str, usize)] = &[
    ("assess.rs", 2),
    ("belief.rs", 7),
    ("claims.rs", 3),
    ("clusters.rs", 8),
    ("computation.rs", 9),
    ("conventions.rs", 3),
    ("cross_source.rs", 1),
    ("crud.rs", 3),
    ("edges.rs", 6),
    ("experiment_loop.rs", 2),
    ("graph.rs", 8),
    ("graph_neighborhood.rs", 1),
    ("graph_query_utils.rs", 1),
    ("hypothesis.rs", 11),
    ("papers.rs", 8),
    ("policies.rs", 4),
    ("revoke_signature.rs", 6),
    ("search.rs", 3),
    ("submit.rs", 5),
];

/// Total of [`REGISTER`]. Never raise this.
///
/// Measured on 2026-11-14 at commit c802844b0 (origin/main, merge of PR #817):
/// 121 production statements in 24 files. Lowered to 120 when #869 moved
/// `patch_claim`'s ownership read into the repo layer, and to 115 when the
/// policies reads and challenge-create statements moved into `PolicyRepository`.
/// Lowered to 112 when backlog 9bef22f3 deleted the PUT claim and evidence
/// embedding routes (`rag.rs` 2 -> 0) and `assess` stored its claim vector
/// through the shared unsealed writer (`assess.rs` 3 -> 2).
/// Lowered to 105 when backlog batch B08 moved `frame_conflict`'s aggregate
/// into `MassFunctionRepository::frame_conflict_summary` (`belief.rs` 10 -> 9)
/// and the compound neighbourhood's graph reads into `GraphViewRepository`
/// (`graph_neighborhood.rs` 7 -> 1).
/// Lowered to 103 on staging batch 3a (#922), where the B08 / B22 stack met
/// the rest of that batch: `belief.rs` measures 7 on the combined tree.
/// Lowered to 101 on staging batch 4 when the hierarchical outcome report's
/// counter write (its `SELECT metadata .. FOR UPDATE` and
/// `UPDATE workflows SET metadata`) moved into `WorkflowRepository`, shared
/// with the MCP tool (`workflows.rs` 4 -> 2, backlog batch B31).
/// Lowered to 94 on staging batch 4 by backlog batch B37 (#895): its route
/// reads moved into the repo layer (`search.rs` 4 -> 3; `conflicts.rs`,
/// `embeddings.rs`, `political.rs` and `workflows.rs` reached zero).
const HIGH_WATER: usize = 91;

/// The token that marks an inline query. `sqlx::query`, `sqlx::query_as`,
/// `sqlx::query_scalar` and their `!` macro forms all start with it. Same
/// needle as `epigraph-mcp/tests/no_inline_sql_in_tools.rs::QUERY_TOKEN`
/// (copied, not shared: that constant is private to another crate's test).
const QUERY_TOKEN: &str = "sqlx::query";

fn routes_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes")
}

/// Every `.rs` file under `root`, recursively, sorted. Same shape as
/// `epigraph-db/tests/no_unscoped_pool.rs::collect`.
fn collect(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Replace comments, string literals and char literals with spaces, keeping
/// newlines and byte offsets, so later passes see code only.
fn mask(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = src[i..].find('\n').map_or(b.len(), |n| i + n);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                // Block comments nest in Rust.
                let (mut depth, mut j) = (1usize, i + 2);
                while j < b.len() && depth > 0 {
                    if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                        depth += 1;
                        j += 2;
                    } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                        depth -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                blank(&mut out, i, j);
                i = j;
            }
            b'r' | b'b'
                if {
                    // Raw string: r"..", r#".."#, br#".."#. Not preceded by an
                    // identifier character (so `for"` style is not misread).
                    let prev_ident =
                        i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
                    let mut j = i;
                    if b[j] == b'b' {
                        j += 1;
                    }
                    let raw = b.get(j) == Some(&b'r');
                    if raw {
                        j += 1;
                    }
                    while b.get(j) == Some(&b'#') {
                        j += 1;
                    }
                    !prev_ident && raw && b.get(j) == Some(&b'"')
                } =>
            {
                let mut j = i;
                if b[j] == b'b' {
                    j += 1;
                }
                j += 1; // 'r'
                let hashes = b[j..].iter().take_while(|&&c| c == b'#').count();
                j += hashes + 1; // hashes and opening quote
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                let end = b[j..]
                    .windows(close.len())
                    .position(|w| w == close.as_slice())
                    .map_or(b.len(), |n| j + n + close.len());
                blank(&mut out, i, end);
                i = end;
            }
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                let end = (j + 1).min(b.len());
                blank(&mut out, i, end);
                i = end;
            }
            b'\'' => {
                // A char literal ('x', '\n', '\u{..}') versus a lifetime ('a).
                let rest = &src[i + 1..];
                let mut chars = rest.chars();
                let len = match chars.next() {
                    Some('\\') => rest.find('\'').map(|n| n + 1),
                    Some(c) if chars.next() == Some('\'') => Some(c.len_utf8() + 1),
                    _ => None,
                };
                if let Some(n) = len {
                    blank(&mut out, i, i + 1 + n);
                    i += 1 + n;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).expect("masking only writes ASCII spaces over whole literals")
}

/// Is this attribute (whitespace removed) a test-only `cfg`?
fn is_test_only_cfg(attr: &str) -> bool {
    let compact: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
    compact == "#[cfg(test)]" || compact.starts_with("#[cfg(all(test,")
}

/// Blank out every item annotated with a test-only `cfg`, by brace matching.
/// Operates on [`mask`]ed text, so braces in strings and comments are gone.
fn drop_test_items(masked: &str) -> String {
    let b = masked.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while let Some(at) = masked[i..].find("#[") {
        let start = i + at;
        // The attribute ends at its matching `]`.
        let (mut depth, mut j) = (0usize, start + 1);
        while j < b.len() {
            match b[j] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        j += 1;
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        if !is_test_only_cfg(&masked[start..j]) {
            i = j;
            continue;
        }
        // Skip to the end of the annotated item: the close of its first
        // top-level `{..}` block, or a top-level `;`, whichever comes first.
        let (mut brace, mut nest, mut k) = (0usize, 0usize, j);
        let mut end = b.len();
        while k < b.len() {
            match b[k] {
                b'(' | b'[' => nest += 1,
                b')' | b']' => nest = nest.saturating_sub(1),
                b'{' => brace += 1,
                b'}' => {
                    brace = brace.saturating_sub(1);
                    if brace == 0 {
                        end = k + 1;
                        break;
                    }
                }
                b';' if brace == 0 && nest == 0 => {
                    end = k + 1;
                    break;
                }
                _ => {}
            }
            k += 1;
        }
        for c in &mut out[start..end] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
        i = end;
    }
    String::from_utf8(out).expect("blanking only writes ASCII spaces")
}

/// Production inline-SQL statements in one source file.
fn count_sites(src: &str) -> usize {
    drop_test_items(&mask(src)).matches(QUERY_TOKEN).count()
}

/// Every scanned file with at least one production statement, keyed relative
/// to the routes directory. Only non-zero entries, which is why a `0` row in
/// [`REGISTER`] can never be satisfied.
fn measure() -> BTreeMap<String, usize> {
    let root = routes_dir();
    let mut files = Vec::new();
    collect(&root, &mut files);
    files.sort();
    let mut out = BTreeMap::new();
    for path in &files {
        let n = count_sites(&std::fs::read_to_string(path).expect("read source"));
        if n > 0 {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, n);
        }
    }
    out
}

/// The scan must read the tree it claims to. A silently empty scan is how a
/// ratchet certifies a codebase it never opened.
#[test]
fn the_scan_root_resolves_and_contains_rs_files() {
    let root = routes_dir();
    assert!(
        root.is_dir(),
        "scan root crates/epigraph-api/src/routes does not exist at {}",
        root.display()
    );
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(
        files.len() > 40,
        "expected >40 .rs files under crates/epigraph-api/src/routes; found {}",
        files.len()
    );
}

/// The ratchet proper: every file's production count is exactly what was
/// recorded, and no unregistered file has any.
#[test]
fn inline_sql_in_routes_is_exactly_the_registered_residue() {
    let measured = measure();
    let expected: BTreeMap<&str, usize> = REGISTER.iter().copied().collect();
    let mut findings = Vec::new();

    for (file, n) in &measured {
        match expected.get(file.as_str()) {
            None => findings.push(format!(
                "  {file}: {n} inline sqlx::query* statement(s) and the file is NOT in REGISTER.\n    \
                 Don't add one: put the query in crates/epigraph-db/src/repos/ and call it \
                 from the handler (CLAUDE.md)."
            )),
            Some(e) if e < n => findings.push(format!(
                "  {file}: registered {e}, measured {n}.\n    \
                 MORE than registered: a new inline query was added to a route file. Move it \
                 to crates/epigraph-db/src/repos/ rather than raising the number."
            )),
            Some(e) if e > n => findings.push(format!(
                "  {file}: registered {e}, measured {n}.\n    \
                 FEWER than registered: a statement was moved out. Lower this number (and \
                 HIGH_WATER) in the same commit so the ratchet tightens."
            )),
            Some(_) => {}
        }
    }
    for (file, e) in &expected {
        if !measured.contains_key(*file) {
            findings.push(format!(
                "  {file}: registered {e}, measured NONE.\n    \
                 The file is clean: REMOVE its row (do not set it to 0; the scanner only \
                 emits non-zero files) and lower HIGH_WATER by {e}."
            ));
        }
    }
    assert!(
        findings.is_empty(),
        "\n\nInline SQL under crates/epigraph-api/src/routes/ changed. {} finding(s):\n{}\n",
        findings.len(),
        findings.join("\n")
    );
}

/// The total equals [`HIGH_WATER`], the register is well formed, and the
/// ceiling is not above what was measured when the ratchet was written.
#[test]
fn the_total_can_only_fall() {
    assert!(
        REGISTER.windows(2).all(|w| w[0].0 < w[1].0),
        "REGISTER must be sorted by path with no duplicates"
    );
    assert!(
        REGISTER.iter().all(|(_, n)| *n > 0),
        "a REGISTER row at 0 can never be satisfied; remove the row"
    );
    let registered: usize = REGISTER.iter().map(|(_, n)| n).sum();
    assert_eq!(
        registered, HIGH_WATER,
        "REGISTER sums to {registered} but HIGH_WATER is {HIGH_WATER}; keep them equal"
    );
    let measured: usize = measure().values().sum();
    assert_eq!(
        measured, HIGH_WATER,
        "measured {measured} production inline statements, HIGH_WATER is {HIGH_WATER}. \
         HIGH_WATER is never raised; if it is above the measurement, lower it."
    );
    // The ceiling at the time of writing. Lowering HIGH_WATER is the only edit
    // this test allows.
    const MEASURED_AT_WRITING: usize = 121;
    const {
        assert!(HIGH_WATER <= MEASURED_AT_WRITING, "HIGH_WATER exceeds the total measured when the ratchet was written; it may only go down")
    };
}

/// The scanner's own blind spots, pinned against synthetic input, so a counter
/// that silently stopped counting cannot certify the tree.
#[test]
fn the_scanner_is_not_vacuous() {
    let sample = "\
fn a() { sqlx::query(\"SELECT 1\"); }
fn b() { let _ = sqlx::query_as::<_, i64>(\"x\"); sqlx::query_scalar(\"y\"); }
";
    assert_eq!(
        count_sites(sample),
        3,
        "two forms on one line and one on another are three statements"
    );
    assert_eq!(count_sites("let q = sqlx::query!(\"SELECT 1\");"), 1);

    // The same statement in a cfg(test) module, in a cfg(all(test, ..)) module
    // and on a single cfg(test) fn mid-file does not count, and production code
    // after a cfg-test item still does.
    let gated = "\
fn prod() { sqlx::query(\"SELECT 1\"); }
#[cfg(test)]
fn only_in_tests() { sqlx::query(\"SELECT 2\"); }
#[cfg(all(test, feature = \"db\"))]
mod db_tests {
    fn t() { sqlx::query(\"SELECT {} 3\"); }
}
#[cfg(test)]
mod tests {
    fn t() { sqlx::query(\"SELECT 4\"); }
}
fn prod_after() { sqlx::query(\"SELECT 5\"); }
";
    assert_eq!(
        count_sites(gated),
        2,
        "only the two production statements count"
    );
    // `cfg(any(test, ..))` is not test-only, so it is scanned.
    assert_eq!(
        count_sites("#[cfg(any(test, feature = \"db\"))]\nfn f() { sqlx::query(\"x\"); }"),
        1
    );

    // Comments and string contents are ignored.
    let prose = "\
// sqlx::query in a line comment
/// sqlx::query! in a doc comment
/* sqlx::query in a block comment */
fn f() { let _ = \"sqlx::query in a string\"; let _ = r#\"sqlx::query raw\"#; }
";
    assert_eq!(
        count_sites(prose),
        0,
        "prose and literals are not statements"
    );
}
