//! Shared source-text preparation for this crate's **source-scanning lints**.
//!
//! # This is a deliberate second copy, and the alternative was worse
//!
//! The implementation is `crates/epigraph-api/tests/lint_text/mod.rs`. Rust
//! integration tests cannot share modules across crates, so reaching the
//! original needs a shared test-support crate, an `include!` across a crate
//! boundary, or a copy. This workspace has no test-support crate and no
//! cross-crate `include!` today, so the first two both mean inventing a
//! mechanism. (The workspace's one `include!`,
//! `epigraph-harvester/src/proto/mod.rs` pulling in its own generated protobuf,
//! is within a single crate and establishes no precedent for the pattern being
//! declined here. An earlier revision of this paragraph said there was no
//! `include!` at all, which a one-line grep refutes.)
//!
//! **`F-PR28-viewer-fixture-duplication` is that same decision and is assigned
//! to a different batch.** Inventing an answer here would either be undone or
//! contradicted by it. So this batch takes the minimum that keeps its own lints
//! honest — one file, one public function, zero dependencies, byte-identical
//! logic — and leaves the shape of cross-crate test reuse to the batch that owns
//! it. When that decision lands, this file and its `epigraph-api` twin collapse
//! into it with no callers to rewrite.
//!
//! `epigraph-db/tests` already carries its own `strip_line_comments` copies and
//! belongs to the same future decision; this batch does not touch them, and
//! deliberately does not scan `crates/epigraph-db/src/repos/` with this function
//! — see the note on [`strip_comments`].

/// Remove `//` line comments and `/* */` block comments, respecting string
/// literals so a `"//"` inside a SQL fragment does not truncate the line.
///
/// Deliberately simple and deliberately over-eager on one case: a `//` inside a
/// raw string would be treated as a comment.
///
/// # The safety argument is NOT the same for every caller
///
/// The original argument for that over-eagerness — it can only make the lint see
/// LESS code and under-report, never fail a clean tree — holds for a sentinel
/// scan and **inverts for a ratchet asserted as an exact set**, which fails in
/// both directions. A stripper that ate real code would silently lower a control
/// and keep it lowered. So a caller adopting this must show its own registers do
/// not move; this crate's caller did, before adopting it: the tool count, the
/// three-way acquisition partition and the tool-module mention set are all
/// byte-identical over stripped and unstripped source on the tree as it stands.
///
/// The same measurement is why `crates/epigraph-db/src/repos/` is not a scan
/// root for this function: there, stripping DOES move a register, because the
/// `VISIBILITY-EXEMPT:` convention is carried in comments by design —
/// `VISIBILITY-EXEMPT` measures 40 → 32 under the stripper as shipped, 8 of the
/// markers being Rust line comments rather than in-SQL `/* */` ones.
///
/// It is NOT because a lifetime toggles this function's string state. An earlier
/// revision of this paragraph said so; that was true of the PRE-FIX stripper and
/// is exactly what the `'` arm below removes. Re-measured with the shipped
/// version over `src/repos/`: `E: sqlx::PgExecutor` 191 → 191 and
/// `conn: &mut PgConnection` 52 → 52 — no declaration is lost.
pub fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let (mut in_str, mut in_line, mut in_block) = (false, false, false);
    let mut quote = b'"';
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if in_line {
            if c == b'\n' {
                in_line = false;
                out.push('\n');
            }
        } else if in_block {
            if c == b'*' && next == Some(b'/') {
                in_block = false;
                i += 1;
            }
        } else if in_str {
            if c == b'\\' {
                i += 1; // skip the escaped byte
            } else if c == quote {
                in_str = false;
            }
            out.push(c as char);
        } else if c == b'/' && next == Some(b'/') {
            in_line = true;
            i += 1;
        } else if c == b'/' && next == Some(b'*') {
            in_block = true;
            i += 1;
        } else if c == b'\'' {
            // A `'` is a LIFETIME far more often than a char literal in this
            // tree, and an earlier revision treated both as string delimiters.
            // That left the scanner in string state from the tick until the
            // next one anywhere in the file, and the string arm copies bytes
            // verbatim — so every comment in between survived unstripped. It
            // was measured, not theorised. Counting rule, stated because an
            // earlier revision gave three magnitudes that no single rule
            // produces: a line whose FIRST non-whitespace is `//` and which the
            // shipped stripper blanks while the pre-fix one left intact. On that
            // rule, 122 such lines under `crates/epigraph-api/src/routes/`, 52
            // under `crates/epigraph-mcp/src/tools/`, and 29 in `webhooks.rs` —
            // the file whose doc comment produced the original report — came
            // through the pre-fix stripper unstripped.
            //
            // The in-tree precedent for the correct rule is `balanced` /
            // `balanced_block` in the two lint files that call this: recognise
            // the char-literal SHAPE and treat nothing else as a string. So
            // copy a char literal whole (its contents cannot open a comment)
            // and otherwise emit the tick and stay in code.
            let close = if b.get(i + 1) == Some(&b'\\') {
                // Escaped: '\n', '\'', '\u{1F600}'. Bounded, because a Rust
                // char escape is at most twelve bytes and an unbounded search
                // would resurrect the defect above.
                (i + 2..(i + 14).min(b.len())).find(|&k| b[k] == b'\'')
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 2)
            } else {
                None
            };
            match close {
                Some(end) => {
                    for &x in &b[i..=end] {
                        out.push(x as char);
                    }
                    i = end;
                }
                None => out.push('\''),
            }
        } else {
            if c == b'"' {
                in_str = true;
                quote = c;
            }
            out.push(c as char);
        }
        i += 1;
    }
    out
}
