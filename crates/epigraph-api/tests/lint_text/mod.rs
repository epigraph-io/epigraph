//! Shared source-text preparation for this crate's **source-scanning lints**.
//!
//! # Why this module exists rather than a fourth hand-written stripper
//!
//! [`strip_comments`] was written for `no_redaction_sentinel.rs` and lived
//! inside it. `viewer_route_table_lint.rs` needs the same function, and Rust
//! integration tests are separate binaries that cannot `use` each other's
//! items, so the choice was: copy it, or lift it to a module both binaries
//! declare. This is the lift, and the diff that added the second consumer added
//! no second implementation.
//!
//! **This is not the only comment stripper in `epigraph-api/tests/`.**
//! `no_bypass_in_handlers.rs::strip_line_comments` is a separate, narrower one
//! (line comments only), and it is the helper
//! `F-PR10-fail-open-lint-counts-comments`'s own `suggested_fix` names. Adopting
//! this module there would have been a free same-crate consolidation; it was
//! left deliberately, because it is outside the four findings this batch owns,
//! moves no register, and belongs with the rest of the stripper inventory below.
//! Stating "one copy" without it would have been the kind of accounting error
//! this batch exists to remove.
//!
//! It is deliberately dependency-free — no `sqlx`, no `epigraph_*`, no feature
//! gate. `tests/common/mod.rs` cannot host it: that module builds an axum app
//! and needs the `db` feature, and these lints read files off disk and touch no
//! database.
//!
//! # Interaction with the cross-crate duplication question
//!
//! `epigraph-mcp` needs the same function and has no stripper at all, so it
//! carries one deliberate copy in `crates/epigraph-mcp/tests/lint_text/mod.rs`.
//! Two crates, two module files, one implementation each — not a shared
//! test-support crate, and not an `include!`. Consolidating test helpers ACROSS
//! crates is a single decision that `F-PR28-viewer-fixture-duplication` owns and
//! that a different batch is scheduled to make; this module is shaped so that
//! decision can absorb it (one file, one public function, no dependencies)
//! rather than having to unpick it.
//!
//! The full inventory that decision inherits is **five** strippers: the two
//! `strip_comments` module copies (this one and `epigraph-mcp`'s), and three
//! `strip_line_comments` — `epigraph-api/tests/no_bypass_in_handlers.rs` plus
//! `epigraph-db/tests/{locked_decisions.rs, no_anonymous_viewer.rs}`. None is
//! touched here beyond the lift.

/// Remove `//` line comments and `/* */` block comments, respecting string
/// literals so a `"//"` inside a SQL fragment does not truncate the line.
///
/// Deliberately simple and deliberately over-eager on one case: a `//` inside a
/// raw string would be treated as a comment.
///
/// # The safety argument is NOT the same for every caller, and must be made at
/// the use site
///
/// The original argument for that over-eagerness was: it can only cause the lint
/// to see LESS code and so to under-report, never to fail a clean tree. **That
/// holds for a sentinel scan and inverts for a ratchet.** `no_redaction_sentinel`
/// searches for a forbidden string, so seeing less code can only lose a
/// detection — bad, but loud when the string is reintroduced elsewhere. A
/// register asserted as an exact set fails in BOTH directions, so a stripper
/// that quietly ate real code would silently lower a security ratchet and keep
/// it lowered. Over-suppression is the failure mode that does not announce
/// itself.
///
/// So a caller adopting this must show its own registers do not move. Both
/// current callers did, before adopting it: every quantity their tests compare
/// is byte-identical over stripped and unstripped source on the tree as it
/// stands, which means this change closes a hazard without moving a number.
///
/// The same measurement is why `crates/epigraph-db/src/repos/` is NOT a scan
/// root for this function: there, stripping *does* move a register, because the
/// `VISIBILITY-EXEMPT:` convention is carried in comments BY DESIGN. Measured
/// over `src/repos/` with the stripper as shipped: `VISIBILITY-EXEMPT` goes
/// 40 → 32, because 8 of the 40 markers are Rust line comments rather than
/// in-SQL `/* */` ones. Those scanners read their markers from raw source on
/// purpose.
///
/// The DECLARATION registers are not what would move, and an earlier revision of
/// this paragraph said they were: it claimed a lifetime
/// (`<'e, E: sqlx::PgExecutor<'e>>`) toggles this function's string state and so
/// would drop functions out of the executor register. That was true of the
/// PRE-FIX stripper and is what the `'` arm below exists to stop. Re-measured
/// with the shipped version: `E: sqlx::PgExecutor` 191 → 191 and
/// `conn: &mut PgConnection` 52 → 52 — zero declarations lost. (The bare token
/// `PgExecutor` does go 196 → 191, and all five losses are prose mentions in
/// comments, which is correct stripping.)
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
