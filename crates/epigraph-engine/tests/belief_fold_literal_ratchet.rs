//! Ratchet: no numeric literal in the belief fold modules outside the belief
//! profile's defaults table.
//!
//! Every number that shapes a belief value (a weight, a factor, a threshold,
//! a ceiling) lives in `belief_profile.rs` between the defaults-table markers,
//! so it is configurable through the profile tiers and covered by the profile
//! hash. This test scans the fold modules' code (comments, string literals and
//! the `#[cfg(test)] mod` block excluded) and fails on any other numeric
//! literal.
//!
//! Allowed without a marker: `0`, `1`, `0.0` and `1.0` (indices, identities,
//! the `[0, 1]` probability bounds), and tuple-field access such as `.0`.
//! Anything else needs the line, or the line directly above it, to carry
//! `belief-profile: allow-literal (<reason>)`, so every exception is visible
//! in review with its reason.
//!
//! A float `0.0` / `1.0` is NOT allowed where it stands for a parameter's
//! value: the whole of an `else` or then arm, an `unwrap_or` /
//! `unwrap_or_else` default, a match arm, a `return`, or a factor of `*` /
//! `/` (that is how a parameter whose default is 0 or 1, such as the cross
//! locality factor or a class weight, would be hardcoded back). Known limit:
//! a 0/1 in any other position (a function argument, a struct field, a
//! `let`) is still read as an identity or a bound, and integer `0` / `1` are
//! never flagged.
//!
//! The defaults table is exempt only in `belief_profile.rs`, and only as ONE
//! balanced `defaults-table-begin` / `defaults-table-end` pair. A marker in
//! any other module, an unclosed or second pair, or a stray end exempts
//! nothing and is itself reported.
//!
//! The scanner is plain text processing over the source files (no proc-macro,
//! no syn), so it runs everywhere the test suite runs.

use std::path::PathBuf;

/// Fold modules under the ratchet, relative to this crate's `src/`. The MCP
/// DS write folds (`auto_wire_ds_for_claim`, `auto_wire_ds_update`) are the
/// second production fold that writes the served cache, so they are scanned
/// here too, by their path in the sibling crate. `atom_items.rs` is the atom
/// evidence fold (the fold the atom-cache writer runs).
const FOLD_MODULES: &[&str] = &[
    "belief_query.rs",
    "edge_factor.rs",
    "source_dependence.rs",
    "atom_items.rs",
    "belief_profile.rs",
    "../../epigraph-mcp/src/tools/ds_auto.rs",
];

const ALLOW_MARKER: &str = "belief-profile: allow-literal";
const TABLE_BEGIN: &str = "belief-profile: defaults-table-begin";
const TABLE_END: &str = "belief-profile: defaults-table-end";

#[derive(Debug, PartialEq)]
struct Finding {
    line: usize,
    literal: String,
}

/// Blank out comments, string/char literals and `#[cfg(test)] mod … { … }`
/// blocks, keeping newlines so line numbers survive. Returns the code-only
/// text.
fn code_only(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(b.len());
    let mut i = 0;
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        // Line comment.
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        // Block comment (nested).
        if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                out.push(blank(b[i]));
                i += 1;
            }
            continue;
        }
        // Raw string r"…", r#"…"#, br#"…"#.
        let prev_ident = i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_');
        if !prev_ident && (c == 'r' || (c == 'b' && next == Some('r'))) {
            let mut j = if c == 'b' { i + 2 } else { i + 1 };
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&'"') {
                // Skip to closing quote followed by `hashes` #s.
                let start = i;
                j += 1;
                loop {
                    if j >= b.len() {
                        break;
                    }
                    if b[j] == '"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&'#')) {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                for &ch in &b[start..j.min(b.len())] {
                    out.push(blank(ch));
                }
                i = j;
                continue;
            }
        }
        // String "…" (also b"…").
        if c == '"' {
            out.push(' ');
            i += 1;
            while i < b.len() {
                if b[i] == '\\' {
                    out.push(' ');
                    if i + 1 < b.len() {
                        out.push(blank(b[i + 1]));
                    }
                    i += 2;
                    continue;
                }
                if b[i] == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(blank(b[i]));
                i += 1;
            }
            continue;
        }
        // Char literal 'x' / '\n' (a lifetime has no closing quote).
        if c == '\'' {
            let close = if next == Some('\\') {
                (i + 3..(i + 12).min(b.len())).find(|&k| b[k] == '\'')
            } else if b.get(i + 2) == Some(&'\'') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(end) = close {
                out.extend(std::iter::repeat_n(' ', end + 1 - i));
                i = end + 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    let text: String = out.into_iter().collect();
    strip_test_modules(&text)
}

/// Blank every `#[cfg(test)]` item that is a `mod … { … }` block.
fn strip_test_modules(code: &str) -> String {
    let mut chars: Vec<char> = code.chars().collect();
    let pat: Vec<char> = "#[cfg(test)]".chars().collect();
    let mut i = 0;
    while i + pat.len() <= chars.len() {
        if chars[i..i + pat.len()] == pat[..] {
            // Next non-whitespace tokens must be `mod <ident> {`.
            let mut j = i + pat.len();
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            let rest: String = chars[j..chars.len().min(j + 4)].iter().collect();
            if rest == "mod " {
                if let Some(open) = (j..chars.len()).find(|&k| chars[k] == '{' || chars[k] == ';') {
                    if chars[open] == '{' {
                        let mut depth = 0;
                        let mut end = open;
                        for (k, ch) in chars.iter().enumerate().skip(open) {
                            if *ch == '{' {
                                depth += 1;
                            } else if *ch == '}' {
                                depth -= 1;
                                if depth == 0 {
                                    end = k;
                                    break;
                                }
                            }
                        }
                        for ch in chars.iter_mut().take(end + 1).skip(i) {
                            if *ch != '\n' {
                                *ch = ' ';
                            }
                        }
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    chars.into_iter().collect()
}

fn allowed_value(lit: &str) -> bool {
    let mut core = lit.replace('_', "");
    for suffix in [
        "usize", "isize", "u128", "i128", "u64", "i64", "u32", "i32", "u16", "i16", "u8", "i8",
        "f64", "f32",
    ] {
        if let Some(stripped) = core.strip_suffix(suffix) {
            core = stripped.to_string();
            break;
        }
    }
    matches!(core.as_str(), "0" | "1" | "0.0" | "1.0")
}

/// Scan a fold module that may NOT carry the defaults table: every table
/// marker is itself a finding and exempts nothing.
fn scan(src: &str) -> Vec<Finding> {
    scan_with(src, false)
}

/// The defaults table's line range (inclusive, 0-based), when `src` carries
/// exactly one `begin` marker followed by exactly one `end` marker.
fn table_range(raw_lines: &[&str]) -> Option<(usize, usize)> {
    let begins: Vec<usize> = (0..raw_lines.len())
        .filter(|&i| raw_lines[i].contains(TABLE_BEGIN))
        .collect();
    let ends: Vec<usize> = (0..raw_lines.len())
        .filter(|&i| raw_lines[i].contains(TABLE_END))
        .collect();
    match (begins.as_slice(), ends.as_slice()) {
        ([b], [e]) if b < e => Some((*b, *e)),
        _ => None,
    }
}

/// Scan one module's source. Lines carrying (or directly under) the allow
/// marker are exempt. When `table_allowed` (the profile module only) and the
/// source carries exactly one balanced table, the table's lines are exempt;
/// otherwise every table marker is reported and nothing is exempt.
fn scan_with(src: &str, table_allowed: bool) -> Vec<Finding> {
    let raw_lines: Vec<&str> = src.lines().collect();
    let code = code_only(src);
    let table = if table_allowed {
        table_range(&raw_lines)
    } else {
        None
    };
    let mut findings = Vec::new();
    for (idx, line) in code.lines().enumerate() {
        let raw = raw_lines.get(idx).copied().unwrap_or("");
        if table.is_some_and(|(b, e)| (b..=e).contains(&idx)) {
            continue;
        }
        if raw.contains(TABLE_BEGIN) || raw.contains(TABLE_END) {
            findings.push(Finding {
                line: idx + 1,
                literal: MISPLACED_MARKER.into(),
            });
        }
        let marked = is_marked(&raw_lines, idx);
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let prev = if i > 0 { Some(chars[i - 1]) } else { None };
            let starts_number = c.is_ascii_digit()
                && !prev.is_some_and(|p| p.is_alphanumeric() || p == '_' || p == '.');
            if !starts_number {
                // Tuple index after `.`: consume the digits so they are not rescanned.
                if c.is_ascii_digit() {
                    while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                        i += 1;
                    }
                    continue;
                }
                i += 1;
                continue;
            }
            let start = i;
            while i < chars.len() {
                let ch = chars[i];
                let fractional_dot = ch == '.'
                    && chars.get(i + 1).is_some_and(|n| n.is_ascii_digit())
                    && !chars[start..i].contains(&'.');
                let exponent_sign = (ch == '+' || ch == '-')
                    && i > start
                    && matches!(chars[i - 1], 'e' | 'E')
                    && !chars[start..i].contains(&'x');
                if ch.is_ascii_alphanumeric() || ch == '_' || fractional_dot || exponent_sign {
                    i += 1;
                } else {
                    break;
                }
            }
            let lit: String = chars[start..i].iter().collect();
            if !marked && !allowed_value(&lit) {
                findings.push(Finding {
                    line: idx + 1,
                    literal: lit,
                });
            }
        }
    }
    let exempt = |idx: usize| {
        table.is_some_and(|(b, e)| (b..=e).contains(&idx)) || is_marked(&raw_lines, idx)
    };
    findings.extend(positional_findings(&code, exempt));
    findings.sort_by_key(|f| f.line);
    findings
}

/// The line (0-based) carries the allow marker, or the line directly above
/// it does.
fn is_marked(raw_lines: &[&str], idx: usize) -> bool {
    raw_lines.get(idx).is_some_and(|l| l.contains(ALLOW_MARKER))
        || (idx > 0 && raw_lines[idx - 1].contains(ALLOW_MARKER))
}

/// A float-typed 0 or 1 (`0.0`, `1.0`, `0_f64`, `1.0f32`, ...). Integer `0` /
/// `1` are indices and counts, never a belief parameter's value, so they are
/// not considered.
fn is_float_zero_or_one(lit: &str) -> bool {
    let core = lit.replace('_', "");
    let (core, suffixed) = match core
        .strip_suffix("f64")
        .or_else(|| core.strip_suffix("f32"))
    {
        Some(c) => (c.to_string(), true),
        None => (core.clone(), false),
    };
    matches!(core.as_str(), "0.0" | "1.0") || (suffixed && matches!(core.as_str(), "0" | "1"))
}

/// `text` ends with the keyword `kw` as a whole word.
fn ends_with_word(text: &str, kw: &str) -> bool {
    text.strip_suffix(kw)
        .is_some_and(|rest| !rest.ends_with(|c: char| c.is_alphanumeric() || c == '_'))
}

/// `text` starts with the keyword `kw` as a whole word.
fn starts_with_word(text: &str, kw: &str) -> bool {
    text.strip_prefix(kw)
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
}

/// A float 0 or 1 in a position where it stands for a parameter's VALUE
/// rather than an identity or a bound: the whole of an `else` or then arm,
/// an `unwrap_or` / `unwrap_or_else` default, a match arm, a `return`, or a
/// factor of `*` / `/`. Scanned over the whole code text, so rustfmt's
/// multi-line arms are seen. `exempt(line_idx)` skips marked and table lines.
fn positional_findings(code: &str, exempt: impl Fn(usize) -> bool) -> Vec<Finding> {
    let closure_default =
        regex::Regex::new(r"unwrap_or_else\s*\(\s*(move\s*)?\|[^|]*\|$").expect("regex");
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let prev = if i > 0 { Some(chars[i - 1]) } else { None };
        let starts_number = c.is_ascii_digit()
            && !prev.is_some_and(|p| p.is_alphanumeric() || p == '_' || p == '.');
        if !starts_number {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() {
            let ch = chars[i];
            let fractional_dot = ch == '.'
                && chars.get(i + 1).is_some_and(|n| n.is_ascii_digit())
                && !chars[start..i].contains(&'.');
            if ch.is_ascii_alphanumeric() || ch == '_' || fractional_dot {
                i += 1;
            } else {
                break;
            }
        }
        let lit: String = chars[start..i].iter().collect();
        if !is_float_zero_or_one(&lit) {
            continue;
        }
        let line_idx = chars[..start].iter().filter(|&&ch| ch == '\n').count();
        if exempt(line_idx) {
            continue;
        }
        let window = start.saturating_sub(160);
        let before: String = chars[window..start].iter().collect();
        let before = before.trim_end();
        let after_end = (i + 160).min(chars.len());
        let after: String = chars[i..after_end].iter().collect();
        let after = after.trim_start();
        let arm_open = before.strip_suffix('{').map(str::trim_end);
        let is_param = (after.starts_with(')')
            && before
                .strip_suffix('(')
                .is_some_and(|b| ends_with_word(b.trim_end(), "unwrap_or")))
            || (after.starts_with(')') && closure_default.is_match(before))
            || (after.starts_with('}') && arm_open.is_some_and(|b| ends_with_word(b, "else")))
            || (after.starts_with('}')
                && arm_open.is_some()
                && starts_with_word(after[1..].trim_start(), "else"))
            || before.ends_with("=>")
            || ends_with_word(before, "return")
            || before.ends_with('*')
            || before.ends_with('/')
            || after.starts_with('*')
            || after.starts_with('/');
        if is_param {
            out.push(Finding {
                line: line_idx + 1,
                literal: lit,
            });
        }
    }
    out
}

/// The module that owns the defaults table.
const PROFILE_MODULE: &str = "belief_profile.rs";

/// What a defaults-table marker that does not delimit THE table is reported as.
const MISPLACED_MARKER: &str = "<defaults-table marker>";

/// Scan one named fold module: only [`PROFILE_MODULE`] may carry the table.
fn scan_module(module: &str, src: &str) -> Vec<Finding> {
    scan_with(src, module == PROFILE_MODULE)
}

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

#[test]
fn fold_modules_carry_no_numeric_literal_outside_the_profile_defaults_table() {
    let mut report = Vec::new();
    for module in FOLD_MODULES {
        let path = src_dir().join(module);
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                report.push(format!("{module}: cannot read ({e})"));
                continue;
            }
        };
        if *module == PROFILE_MODULE {
            assert!(
                src.contains(TABLE_BEGIN) && src.contains(TABLE_END),
                "belief_profile.rs must delimit its defaults table"
            );
        }
        for f in scan_module(module, &src) {
            report.push(format!("{module}:{}: literal `{}`", f.line, f.literal));
        }
    }
    assert!(
        report.is_empty(),
        "numeric literals in belief fold modules outside the profile defaults table \
         (move them into BeliefProfile, or mark a non-belief number with `{ALLOW_MARKER} (<reason>)`):\n{}",
        report.join("\n")
    );
}

#[test]
fn the_scanner_flags_a_synthetic_literal_and_only_that() {
    let src = r##"
fn fold(x: f64) -> f64 {
    let a = x * 0.42;
    a.clamp(0.0, 1.0)
}
"##;
    assert_eq!(
        scan(src),
        vec![Finding {
            line: 3,
            literal: "0.42".into()
        }]
    );
}

#[test]
fn the_scanner_flags_integers_exponents_and_suffixed_literals() {
    let src = "const CAP: usize = 8;\nlet t = 2.5e-3;\nlet w = 7_f64;\nlet h = 0x10;\n";
    let lits: Vec<String> = scan(src).into_iter().map(|f| f.literal).collect();
    assert_eq!(lits, vec!["8", "2.5e-3", "7_f64", "0x10"]);
}

#[test]
fn the_scanner_ignores_comments_strings_tests_markers_tuple_fields_and_the_table() {
    let src = r##"
// a comment 0.42
/* block 0.42 /* nested 3 */ still 0.42 */
/// doc 0.42
fn f(p: (f64, f64)) -> f64 {
    let s = "string 0.42 {0}";
    let r = r#"SELECT 2 FROM t WHERE x > 0.5"#;
    let c = '9';
    let marked = 0.77; // belief-profile: allow-literal (fixture)
    // belief-profile: allow-literal (next line)
    let marked_next = [0u8; 4];
    let idx = p.0 + p.1;
    let ok = 0.0_f64 + 1.0 + 0 as f64 + 1_usize as f64;
    idx + ok + marked + marked_next.len() as f64 + s.len() as f64 + r.len() as f64 + c as u8 as f64
}
// belief-profile: defaults-table-begin
const TABLE_VALUE: f64 = 0.33;
// belief-profile: defaults-table-end
#[cfg(test)]
mod tests {
    #[test]
    fn t() { assert_eq!(0.42, 0.42); }
}
"##;
    assert_eq!(scan_module(PROFILE_MODULE, src), vec![]);
}

fn misplaced(line: usize) -> Finding {
    Finding {
        line,
        literal: MISPLACED_MARKER.into(),
    }
}

fn lit(line: usize, literal: &str) -> Finding {
    Finding {
        line,
        literal: literal.into(),
    }
}

#[test]
fn a_defaults_table_outside_the_profile_module_exempts_nothing_and_is_flagged() {
    // Only belief_profile.rs owns THE table; a fold module cannot open its own.
    let src = "// belief-profile: defaults-table-begin\nconst X: f64 = 0.33;\n\
               // belief-profile: defaults-table-end\nfn f() -> f64 { 0.42 }\n";
    assert_eq!(
        scan_module("edge_factor.rs", src),
        vec![misplaced(1), lit(2, "0.33"), misplaced(3), lit(4, "0.42")]
    );
}

#[test]
fn an_unclosed_table_in_the_profile_module_exempts_nothing_and_is_flagged() {
    let src = "// belief-profile: defaults-table-begin\nconst X: f64 = 0.33;\n\
               fn f() -> f64 { 0.42 }\n";
    assert_eq!(
        scan_module(PROFILE_MODULE, src),
        vec![misplaced(1), lit(2, "0.33"), lit(3, "0.42")]
    );
}

#[test]
fn a_second_table_in_the_profile_module_exempts_nothing_and_is_flagged() {
    // Exactly one balanced pair: a second pair (or a stray end) voids the
    // exemption, so the table cannot be split to hide a literal between.
    let src = "// belief-profile: defaults-table-begin\nconst A: f64 = 0.33;\n\
               // belief-profile: defaults-table-end\nfn f() -> f64 { 0.42 }\n\
               // belief-profile: defaults-table-begin\nconst B: f64 = 0.55;\n\
               // belief-profile: defaults-table-end\n";
    assert_eq!(
        scan_module(PROFILE_MODULE, src),
        vec![
            misplaced(1),
            lit(2, "0.33"),
            misplaced(3),
            lit(4, "0.42"),
            misplaced(5),
            lit(6, "0.55"),
            misplaced(7)
        ]
    );
}

#[test]
fn a_literal_after_the_test_module_is_still_scanned() {
    let src = "#[cfg(test)]\nmod tests {\n    const X: f64 = 0.9;\n}\nfn late() -> f64 { 0.9 }\n";
    assert_eq!(
        scan(src),
        vec![Finding {
            line: 5,
            literal: "0.9".into()
        }]
    );
}

#[test]
fn a_zero_or_one_in_a_parameter_position_is_flagged() {
    // 0.0 and 1.0 are allowed as identities and bounds, but NOT where they
    // stand for a parameter's value: an `else` / then arm, an `unwrap_or`
    // default, a match arm, a `return`, or a factor of a product. These are
    // exactly how a profile parameter whose default is 0 or 1 (the cross
    // locality factor, a class weight) gets hardcoded back into a fold.
    // rustfmt's multi-line shape, as the fold modules are written.
    let src = r##"
fn fold(r: &R, intra: bool, w: Option<f64>) -> f64 {
    let locality = if intra {
        r.intra
    } else {
        1.0
    };
    let primary = if intra {
        1.0
    } else {
        r.cross
    };
    let base = w.unwrap_or(1.0);
    let k = w.unwrap_or_else(|| 0.0_f64);
    let m = match intra {
        true => r.intra,
        false => 1.0,
    };
    if base > r.cap {
        return 1.0;
    }
    let scaled = base * 1.0;
    let halved = 1.0 / base;
    locality * primary * k * m * scaled * halved
}
"##;
    assert_eq!(
        scan(src),
        vec![
            lit(6, "1.0"),
            lit(9, "1.0"),
            lit(13, "1.0"),
            lit(14, "0.0_f64"),
            lit(17, "1.0"),
            lit(20, "1.0"),
            lit(22, "1.0"),
            lit(23, "1.0"),
        ]
    );
}

#[test]
fn a_zero_or_one_as_a_bound_identity_or_index_is_not_flagged() {
    let src = r##"
fn f(x: f64, v: &[f64], i: Option<usize>) -> f64 {
    let a = x.clamp(0.0, 1.0);
    let b = 1.0 - x;
    let c = if x > 0.0 { x } else { a };
    let d = (0.0..=1.0).contains(&x);
    let e = i.unwrap_or(0);
    let g = vec![0.0; v.len()];
    let h = [0.0, 1.0];
    let s = Some(1.0);
    let t = x == 1.0 || x.max(0.0) < 1.0;
    a + b + c + f64::from(u8::from(d)) + e as f64 + g[0] + h[0] + s.unwrap() + f64::from(u8::from(t))
}
"##;
    assert_eq!(scan(src), vec![]);
}

#[test]
fn a_marked_zero_or_one_in_a_parameter_position_is_not_flagged() {
    let src = "fn f(w: Option<f64>) -> f64 {\n    \
               // belief-profile: allow-literal (a probability's upper bound)\n    \
               w.unwrap_or(1.0)\n}\n";
    assert_eq!(scan(src), vec![]);
}
