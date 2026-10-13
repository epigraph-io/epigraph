//! Shared source-text preparation for this crate's **source-scanning lints**.
//!
//! A third copy of `crates/epigraph-api/tests/lint_text/mod.rs` (the second is
//! `crates/epigraph-mcp/tests/lint_text/mod.rs`). The body of
//! [`strip_comments`] is byte-identical to both; only this header and the doc
//! comment differ. The reason it is a copy and not a shared crate is the one the
//! `epigraph-mcp` twin gives: integration tests cannot share modules across
//! crates, and how cross-crate test reuse should work is a separate decision.
//! When that decision lands, all three collapse into it.
//!
//! The older `strip_line_comments` copies in this directory are left alone;
//! they handle line comments only and serve sentinel scans whose argument does
//! not depend on block comments.
//!
//! # What the callers here read stripped, and what they deliberately do not
//!
//! `visibility_lint.rs` and `write_gate_lint.rs` use this for ONE thing: the
//! *spend* markers (`.splice(`, `.splice_write(`, `visibility = 'public'`) are
//! matched against comment-stripped function bodies, so a marker written in a
//! comment does not count as the function using its viewer. Everything else
//! stays on the raw body, for measured reasons:
//!
//! * **`VISIBILITY-EXEMPT:` is read RAW.** The exemption convention is carried
//!   in comments by design. Most markers sit inside SQL string literals as
//!   `-- VISIBILITY-EXEMPT:` (which survive this function, since it keeps
//!   strings), but some are Rust line comments, and stripping them would turn
//!   reviewed exemptions into offenders and shrink the exemption register.
//! * **String literals are kept.** `visibility = 'public'` only ever appears
//!   inside SQL text, so a stripper that also blanked strings would report
//!   every `sqlx::query!` macro site as unspent.
//! * **Scoped-write offsets, the "runs SQL" gate and the function selectors
//!   are unchanged.** They are a different measurement; moving them in the same
//!   change as the spend predicate would make a moved register ambiguous
//!   between "the tree changed" and "the scanner's view changed".
//!
//! Every exact-set register in both files is unchanged by adopting this — the
//! files' own register tests are the measurement.

/// Remove `//` line comments and `/* */` block comments, respecting string
/// literals so a `"//"` inside a SQL fragment does not truncate the line, and
/// recognising char literals so a lifetime tick does not open a string.
///
/// Deliberately simple and deliberately over-eager on one case: a `//` inside a
/// raw string would be treated as a comment. For a caller that reads stripped
/// text only to decide whether a SPEND marker is present, that over-eagerness
/// can only hide a marker and report a function as unspent — a loud failure,
/// never a silent clearance.
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
