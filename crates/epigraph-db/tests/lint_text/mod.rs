//! Shared source-text preparation for this crate's **source-scanning lints**.
//!
//! One function, [`spend_views`], used by `visibility_lint.rs` and
//! `write_gate_lint.rs` for ONE thing: deciding whether a function body
//! *spends* its viewer (or, for writes, gates them). Each spend marker is
//! matched only where it can take effect:
//!
//! * the method-call markers (`.splice(`, `.splice_write(`) in CODE — not in a
//!   comment, not inside a string literal;
//! * the SQL-text marker (`visibility = 'public'`) in LIVE SQL — inside a
//!   string literal, but not inside that SQL's own `--` / `/* */` comments, and
//!   not in a Rust comment.
//!
//! Everything else in those files stays on the raw body, for measured reasons:
//!
//! * **`VISIBILITY-EXEMPT:` is read RAW.** The exemption convention is carried
//!   in comments by design — mostly in-SQL `-- VISIBILITY-EXEMPT:`, some as
//!   Rust line comments — so stripping it would turn reviewed exemptions into
//!   offenders and shrink the exemption register.
//! * **Scoped-write offsets, the "runs SQL" gate and the function selectors
//!   are unchanged.** They are a different measurement; moving them in the same
//!   change as the spend predicate would make a moved register ambiguous
//!   between "the tree changed" and "the scanner's view changed".
//!
//! Every exact-set register in both files is unchanged by adopting this — the
//! files' own register tests are the measurement.
//!
//! `epigraph-mcp/tests/tool_viewer_is_spent.rs` carries a copy with a
//! byte-identical body, for the same reason `epigraph-mcp` carries its own
//! `lint_text`: integration tests cannot share modules across crates, and how
//! cross-crate test reuse should work is a separate, pending decision.

/// The two texts a SPEND check reads, returned as `(code, live_sql)`:
///
/// * **`code`** — Rust comments removed and string-literal CONTENTS blanked,
///   the quotes kept. A method-call marker (`.splice(`, `.splice_write(`)
///   counts only here: written inside a string — a log line, an error
///   message — it calls nothing.
/// * **`live_sql`** — Rust comments removed, string-literal contents kept minus
///   the comments of the SQL they carry: `--` up to the end of its line (a real
///   newline or a `\n` escape) and `/* */` spans. A SQL-text marker
///   (`visibility = 'public'`) counts only here: a predicate commented out of
///   the statement is not one the database evaluates.
///
/// One pass over the RAW source, with the comment and char-literal rules of
/// `epigraph-api/tests/lint_text/mod.rs::strip_comments`. It does not run on
/// that function's output, because that output drops the byte after each `\`
/// escape — the byte that tells `\n` (an SQL newline) from any other escape.
///
/// Limits, stated so a green run is not read as more than it is:
///
/// * A `--` inside a SQL quoted literal (`'--'`) is read as a comment. That
///   over-strips: it can only hide a marker and report a function as unspent,
///   a loud failure.
/// * An SQL comment is ended at the close of its Rust string. Where one
///   statement is assembled from several literals with no newline between
///   them, a comment that runs on into the next literal is not followed.
/// * Raw strings are read with ordinary-string rules, as `strip_comments`
///   reads them. The `"` pairs of sqlx `AS "col!"` overrides inside an
///   `r#"…"#` statement keep the state in sync at the literal's end; the
///   override name between them is read as code, in both views alike.
///
/// The `VISIBILITY-EXEMPT:` marker reads neither view: it is a comment
/// convention by design and is read from the raw body.
pub fn spend_views(src: &str) -> (String, String) {
    let b = src.as_bytes();
    let mut code = String::with_capacity(b.len());
    let mut sql = String::with_capacity(b.len());
    let mut i = 0;
    let (mut in_line, mut in_block, mut in_str) = (false, false, false);
    let (mut sql_line, mut sql_block) = (false, false);
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if in_line {
            if c == b'\n' {
                in_line = false;
                code.push('\n');
                sql.push('\n');
            }
        } else if in_block {
            if c == b'*' && next == Some(b'/') {
                in_block = false;
                i += 1;
            }
        } else if in_str {
            if c == b'\\' {
                // An escape is never a delimiter. `\n` is an SQL newline, so it
                // ends an SQL line comment; `\` + a real newline is a Rust line
                // continuation, which removes the newline, so it does not.
                if sql_line && next == Some(b'n') {
                    sql_line = false;
                }
                if !sql_line && !sql_block {
                    sql.push('\\');
                    if let Some(n) = next {
                        sql.push(n as char);
                    }
                }
                i += 2;
                continue;
            }
            if c == b'"' {
                (in_str, sql_line, sql_block) = (false, false, false);
                code.push('"');
                sql.push('"');
            } else if sql_line {
                if c == b'\n' {
                    sql_line = false;
                    sql.push('\n');
                }
            } else if sql_block {
                if c == b'*' && next == Some(b'/') {
                    sql_block = false;
                    i += 1;
                }
            } else if c == b'-' && next == Some(b'-') {
                sql_line = true;
                i += 1;
            } else if c == b'/' && next == Some(b'*') {
                sql_block = true;
                i += 1;
            } else {
                sql.push(c as char);
            }
        } else if c == b'/' && next == Some(b'/') {
            in_line = true;
            i += 1;
        } else if c == b'/' && next == Some(b'*') {
            in_block = true;
            i += 1;
        } else if c == b'\'' {
            // The char-literal SHAPE rule of `strip_comments`, for the same
            // reason: a lifetime tick must not open a string, and the contents
            // of `'"'` must not either.
            let close = if next == Some(b'\\') {
                (i + 2..(i + 14).min(b.len())).find(|&k| b[k] == b'\'')
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 2)
            } else {
                None
            };
            let end = close.unwrap_or(i);
            for &x in &b[i..=end] {
                code.push(x as char);
                sql.push(x as char);
            }
            i = end;
        } else {
            if c == b'"' {
                in_str = true;
            }
            code.push(c as char);
            sql.push(c as char);
        }
        i += 1;
    }
    (code, sql)
}
