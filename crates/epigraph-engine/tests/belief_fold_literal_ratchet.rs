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
//! The scanner is plain text processing over the source files (no proc-macro,
//! no syn), so it runs everywhere the test suite runs.

use std::path::PathBuf;

/// Fold modules under the ratchet, relative to this crate's `src/`.
const FOLD_MODULES: &[&str] = &[
    "belief_query.rs",
    "edge_factor.rs",
    "source_dependence.rs",
    "belief_profile.rs",
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

/// Scan one module's source; lines inside the defaults table and lines
/// carrying (or directly under) the allow marker are exempt.
fn scan(src: &str) -> Vec<Finding> {
    let raw_lines: Vec<&str> = src.lines().collect();
    let code = code_only(src);
    let mut in_table = false;
    let mut findings = Vec::new();
    for (idx, line) in code.lines().enumerate() {
        let raw = raw_lines.get(idx).copied().unwrap_or("");
        if raw.contains(TABLE_BEGIN) {
            in_table = true;
            continue;
        }
        if raw.contains(TABLE_END) {
            in_table = false;
            continue;
        }
        if in_table {
            continue;
        }
        let marked =
            raw.contains(ALLOW_MARKER) || (idx > 0 && raw_lines[idx - 1].contains(ALLOW_MARKER));
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
    findings
}

/// The module that owns the defaults table.
const PROFILE_MODULE: &str = "belief_profile.rs";

/// What a defaults-table marker that does not delimit THE table is reported as.
const MISPLACED_MARKER: &str = "<defaults-table marker>";

/// Scan one named fold module.
fn scan_module(_module: &str, src: &str) -> Vec<Finding> {
    scan(src)
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
