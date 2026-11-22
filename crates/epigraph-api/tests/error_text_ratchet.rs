//! Error text reaches a caller only through the redacted 500 body (backlog
//! f9acb220). Two surfaces bypass that redaction because they are not an
//! `ApiError` 500, and this source scan pins both.
//!
//! 1. **The 502 and 503 variants.** `ApiError::BadGateway { reason }` and
//!    `ApiError::ServiceUnavailable { service }` are rendered verbatim. Every
//!    construction site under `crates/epigraph-api/src` (outside `errors.rs`
//!    and test modules) is classified as one of these:
//!    - a string literal;
//!    - a SCREAMING_CASE const;
//!    - an entry in [`DYNAMIC_502_503`], which states why its text is safe and
//!      carries a sentinel that fails if that reason stops holding.
//!
//!    So `format!("...: {e}")` in a 502/503 fails the scan.
//! 2. **Per-item results in a 2xx body.** A batch route answers 200 with one
//!    result per item, and a failed item's `error` string bypasses the 500
//!    redaction. The serializable types that carry such a field form an exact
//!    register, [`PER_ITEM_TYPES`]. A function that builds one of them must not
//!    render an error with `to_string()` or `{e}` outside a `tracing::` call.
//!    It takes an `ApiError`'s text from `ApiError::caller_message()`.
//!
//! The scan is TEXTUAL, so what it does not see is stated here. It recognizes
//! an error value by the receiver names `e`, `err`, `error`, `source` and
//! `db_err`. A per-item `error` built in a helper the constructing function
//! calls is out of reach, unless that helper also builds the type, as
//! `belief.rs::pair_conflict` does. The JSON `"error"` rule covers 5xx bodies
//! only: its one allowed file, `routes/submit.rs`, is allowed whole, so a 4xx
//! body there is not checked.
//!
//! Comments are stripped by this file's own [`strip_comments`], not the shared
//! `lint_text` one, which drops the byte that follows a backslash inside a
//! string literal. A literal holding one escaped backslash then reads as an
//! escaped quote, and a delimiter matcher over that output loses track of
//! where the string ends.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// 502/503 sites whose text is not a literal or a const:
/// `(path under src/, enclosing fn, the exact expression, whitespace
/// normalized, sentinel)`. A reviewed function whose expression changes is
/// unreviewed again, and each entry must still be found.
const DYNAMIC_502_503: &[(&str, &str, &str, &str)] = &[(
    "routes/analyze.rs",
    "llm_unavailable",
    // Interpolates only `stage`, a `&'static str` chosen by the caller site;
    // the provider error is logged, never formatted into the text.
    "format!(\"LLM {stage} failed; the detail is in the server log\")",
    "fn llm_unavailable(stage: &'static str",
)];

/// The serializable types under `src/` with a per-item `error: Option<String>`
/// field: `(path under src/, type)`.
const PER_ITEM_TYPES: &[(&str, &str)] = &[
    ("routes/batch.rs", "BatchClaimResult"),
    ("routes/belief.rs", "ConflictBatchResult"),
];

/// A JSON `"error": e.to_string()` is allowed only where the body is a 5xx that
/// a choke point redacts: `(path under src/, sentinel in that file)`.
const JSON_ERROR_FIELD_REDACTED_AT: &[(&str, &str)] = &[(
    "routes/submit.rs",
    // `error_response` sends a 4xx as built and redacts every 5xx.
    "if !status.is_server_error() {\n        return (status, Json(error)).into_response();",
)];

const ERROR_RECEIVERS: &[&str] = &["e", "err", "error", "source", "db_err"];

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// `(path under src/ with '/' separators, comment-stripped non-test source,
/// raw source)` for every file.
fn sources() -> Vec<(String, String, String)> {
    let root = src_root();
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let raw = std::fs::read_to_string(&p).expect("read source");
            let rel = p
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, strip_test_modules(&strip_comments(&raw)), raw)
        })
        .collect()
}

/// Remove `//` and `/* */` comments, keeping string and char literals byte
/// for byte (escapes included).
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let (mut in_str, mut in_line, mut in_block) = (false, false, false);
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if in_line {
            if c == b'\n' {
                in_line = false;
                out.push(c);
            }
        } else if in_block {
            if c == b'*' && next == Some(b'/') {
                in_block = false;
                i += 1;
            }
        } else if in_str {
            out.push(c);
            if c == b'\\' {
                if let Some(n) = next {
                    out.push(n);
                }
                i += 1;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'/' && next == Some(b'/') {
            in_line = true;
            i += 1;
        } else if c == b'/' && next == Some(b'*') {
            in_block = true;
            i += 1;
        } else if c == b'\'' {
            // A char literal is copied whole; any other tick is a lifetime.
            let close = if next == Some(b'\\') {
                (i + 2..(i + 14).min(b.len())).find(|&k| b[k] == b'\'')
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 2)
            } else {
                None
            };
            match close {
                Some(end) => {
                    out.extend_from_slice(&b[i..=end]);
                    i = end;
                }
                None => out.push(c),
            }
        } else {
            if c == b'"' {
                in_str = true;
            }
            out.push(c);
        }
        i += 1;
    }
    String::from_utf8(out).expect("stripping only removes whole comments")
}

/// Index of the delimiter closing the one opened at `open` (`{` or `(`),
/// skipping string and char literals.
fn closing(s: &str, open: usize) -> usize {
    let b = s.as_bytes();
    let (o, c) = (b[open], if b[open] == b'{' { b'}' } else { b')' });
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'"' => {
                // A raw string `r"..."` / `r#"..."#` has no escapes.
                let raw_hashes = raw_prefix_hashes(b, i);
                i += 1;
                if let Some(h) = raw_hashes {
                    let end: String = std::iter::once('"')
                        .chain(std::iter::repeat_n('#', h))
                        .collect();
                    i += s[i..].find(&end).expect("raw string closes") + end.len() - 1;
                } else {
                    while b.get(i).is_some_and(|&x| x != b'"') {
                        if b[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    assert!(
                        i < b.len(),
                        "unterminated string from delimiter at byte {open}: {:?}",
                        s[open..].chars().take(80).collect::<String>()
                    );
                }
            }
            // A char literal: `'\''`, `'\n'`, `'\u{..}'` (escape first), or
            // `'x'`. Anything else is a lifetime and is not skipped.
            b'\'' if b.get(i + 1) == Some(&b'\\') => {
                i += 3;
                while b[i] != b'\'' {
                    i += 1;
                }
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 2,
            x if x == o => depth += 1,
            x if x == c => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unbalanced delimiter at byte {open}");
}

/// `Some(n)` when the `"` at `i` opens a raw string with `n` hashes.
fn raw_prefix_hashes(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    let mut hashes = 0;
    while j > 0 && b[j - 1] == b'#' {
        hashes += 1;
        j -= 1;
    }
    let is_raw = j > 0
        && b[j - 1] == b'r'
        && (j < 2 || !(b[j - 2].is_ascii_alphanumeric() || b[j - 2] == b'_'));
    is_raw.then_some(hashes)
}

/// Remove every `#[cfg(test)] mod NAME { ... }`.
fn strip_test_modules(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(at) = find_test_module(&out) {
        let open = at + out[at..].find('{').unwrap();
        let close = closing(&out, open);
        out.replace_range(at..=close, "");
    }
    out
}

fn find_test_module(s: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = s[from..].find("#[cfg(test)]") {
        let at = from + rel;
        let rest = s[at + "#[cfg(test)]".len()..].trim_start();
        if rest.starts_with("mod ") || rest.starts_with("pub mod ") {
            let header_end = rest.find(['{', ';']).unwrap_or(rest.len());
            if rest.as_bytes().get(header_end) == Some(&b'{') {
                return Some(at);
            }
        }
        from = at + 1;
    }
    None
}

/// The name of the last `fn` declared before `pos`.
fn enclosing_fn(s: &str, pos: usize) -> String {
    let before = &s[..pos];
    let mut search = before.len();
    while let Some(at) = before[..search].rfind("fn ") {
        let ok_prefix = at == 0 || !before.as_bytes()[at - 1].is_ascii_alphanumeric();
        if ok_prefix {
            return before[at + 3..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
        }
        search = at;
    }
    String::from("<top level>")
}

/// The `{ ... }` body of the `fn name` declared in `s`.
fn fn_body<'a>(s: &'a str, name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let needle = format!("fn {name}");
    let mut from = 0;
    while let Some(rel) = s[from..].find(&needle) {
        let at = from + rel;
        from = at + needle.len();
        let next = s.as_bytes().get(from).copied().unwrap_or(b' ');
        if next.is_ascii_alphanumeric() || next == b'_' {
            continue;
        }
        // Skip the signature: the body is the first `{` at paren depth 0.
        let mut i = from;
        let mut parens = 0i32;
        let b = s.as_bytes();
        while i < b.len() {
            match b[i] {
                b'(' | b'<' | b'[' => parens += 1,
                b')' | b'>' | b']' => parens -= 1,
                b'{' if parens <= 0 => break,
                b';' if parens <= 0 => break,
                _ => {}
            }
            i += 1;
        }
        if b.get(i) == Some(&b'{') {
            out.push(&s[i..=closing(s, i)]);
        }
    }
    out
}

/// `s` with every `tracing::LEVEL!( ... )` call removed: rendering an error
/// into the server log is what a redacted site is meant to do.
fn without_tracing(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(at) = out.find("tracing::") {
        let Some(bang) = out[at..].find("!(").map(|r| at + r) else {
            break;
        };
        let close = closing(&out, bang + 1);
        out.replace_range(at..=close, "");
    }
    out
}

/// Every way `s` renders one of [`ERROR_RECEIVERS`] into text.
fn error_renderings(s: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for r in ERROR_RECEIVERS {
        for pat in [
            format!("{{{r}}}"),
            format!("{{{r}:?}}"),
            format!("{{{r}:#?}}"),
            // `format!("...{}", e)`: the format string's closing quote, then e.
            format!("\", {r})"),
        ] {
            if s.contains(&pat) {
                hits.push(pat);
            }
        }
        for method in ["to_string()", "to_owned()"] {
            let pat = format!("{r}.{method}");
            let mut from = 0;
            while let Some(rel) = s[from..].find(&pat) {
                let at = from + rel;
                // `e.to_string()`, not `node.to_string()` or `x.e.to_string()`.
                let prev = at.checked_sub(1).map(|p| s.as_bytes()[p]);
                if !prev.is_some_and(|p| p.is_ascii_alphanumeric() || p == b'_' || p == b'.') {
                    hits.push(pat.clone());
                }
                from = at + 1;
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

#[derive(Debug, PartialEq)]
enum Text {
    Literal,
    Const,
    Dynamic(String),
}

/// Classify a 502/503 field value such as `"x".to_string()`,
/// `CONST.into()`, `format!(..)` or a bare shorthand field.
fn classify(value: &str) -> Text {
    let mut v = value.trim().trim_end_matches(',').trim();
    for suffix in [".to_string()", ".into()", ".to_owned()"] {
        if let Some(stripped) = v.strip_suffix(suffix) {
            v = stripped.trim();
            break;
        }
    }
    if v.starts_with('"') && v.ends_with('"') && closing_quote(v) == v.len() - 1 {
        return Text::Literal;
    }
    let last = v.rsplit("::").next().unwrap_or(v);
    if !last.is_empty()
        && last
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Text::Const;
    }
    Text::Dynamic(v.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Index of the `"` closing the literal that opens `v`.
fn closing_quote(v: &str) -> usize {
    let b = v.as_bytes();
    let mut i = 1;
    while b[i] != b'"' {
        if b[i] == b'\\' {
            i += 1;
        }
        i += 1;
    }
    i
}

/// `(file, enclosing fn, classification)` for every 502/503 construction.
fn sites_502_503() -> Vec<(String, String, Text)> {
    let mut out = Vec::new();
    for (rel, src, _) in sources() {
        if rel == "errors.rs" {
            continue;
        }
        for variant in ["BadGateway", "ServiceUnavailable"] {
            let mut from = 0;
            while let Some(rel_at) = src[from..].find(variant) {
                let at = from + rel_at;
                from = at + variant.len();
                let rest = &src[from..];
                let trimmed = rest.trim_start();
                if !trimmed.starts_with('{') {
                    continue;
                }
                let open = from + (rest.len() - trimmed.len());
                let close = closing(&src, open);
                let inner = src[open + 1..close].trim();
                let after = src[close + 1..].trim_start();
                // A pattern, not a construction.
                if inner == ".."
                    || after.starts_with("=>")
                    || (after.starts_with('=') && !after.starts_with("=="))
                {
                    continue;
                }
                let value = match inner.split_once(':') {
                    Some((_field, value)) => classify(value),
                    None => Text::Dynamic(format!("shorthand `{inner}`")),
                };
                out.push((rel.clone(), enclosing_fn(&src, at), value));
            }
        }
    }
    out
}

#[test]
fn every_502_503_text_is_a_literal_a_const_or_a_reviewed_dynamic_site() {
    let sites = sites_502_503();
    let (mut literal, mut constant) = (0, 0);
    let mut dynamic: BTreeSet<(String, String)> = BTreeSet::new();
    let mut unreviewed = Vec::new();
    for (file, func, text) in &sites {
        match text {
            Text::Literal => literal += 1,
            Text::Const => constant += 1,
            Text::Dynamic(expr) => {
                if DYNAMIC_502_503
                    .iter()
                    .any(|(f, n, x, _)| f == file && n == func && x == expr)
                {
                    dynamic.insert((file.clone(), func.clone()));
                } else {
                    unreviewed.push(format!("{file}::{func}: `{expr}`"));
                }
            }
        }
    }
    eprintln!(
        "502/503 construction sites: {} ({literal} literal, {constant} const, {} reviewed dynamic)",
        sites.len(),
        dynamic.len()
    );
    // Calibration: the scan sees the population it claims to classify (about
    // a hundred sites at the time of writing). A broken scanner finds none
    // and would pass everything.
    assert!(
        literal >= 80 && constant >= 2,
        "the scan found only {literal} literal and {constant} const sites; it is not seeing the tree"
    );
    assert!(
        unreviewed.is_empty(),
        "a 502/503 is rendered verbatim to the caller, so its text must be a literal or a \
         const (log the detail server-side), or a reviewed entry in DYNAMIC_502_503:\n{}",
        unreviewed.join("\n")
    );
    for (file, func, _, sentinel) in DYNAMIC_502_503 {
        assert!(
            dynamic.contains(&(file.to_string(), func.to_string())),
            "stale DYNAMIC_502_503 entry {file}::{func}: no such site any more"
        );
        let raw = sources()
            .into_iter()
            .find(|(rel, _, _)| rel == file)
            .map(|(_, _, raw)| raw)
            .unwrap_or_default();
        assert!(
            raw.contains(sentinel),
            "{file}::{func}: the reason its dynamic text is safe no longer holds \
             (missing `{sentinel}`)"
        );
    }
}

#[test]
fn the_per_item_error_types_are_an_exact_register() {
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    for (rel, src, _) in sources() {
        let mut from = 0;
        while let Some(rel_at) = src[from..].find("struct ") {
            let at = from + rel_at;
            from = at + "struct ".len();
            if at > 0 && src.as_bytes()[at - 1].is_ascii_alphanumeric() {
                continue;
            }
            let name: String = src[from..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let header = &src[from..];
            let Some(brace) = header.find(['{', ';', '(']) else {
                continue;
            };
            if header.as_bytes()[brace] != b'{' {
                continue;
            }
            let open = from + brace;
            let body = &src[open..=closing(&src, open)];
            // The attributes are the text between the previous item and `struct`.
            let prev_end = src[..at].rfind(['}', ';']).map_or(0, |p| p + 1);
            let attrs = &src[prev_end..at];
            let tokens: Vec<&str> = body.split_whitespace().collect();
            let carries_error = tokens
                .windows(2)
                .any(|w| w[0] == "error:" && w[1].trim_end_matches(',') == "Option<String>");
            if attrs.contains("Serialize") && carries_error {
                found.insert((rel.clone(), name));
            }
        }
    }
    let expected: BTreeSet<(String, String)> = PER_ITEM_TYPES
        .iter()
        .map(|(f, t)| (f.to_string(), t.to_string()))
        .collect();
    assert_eq!(
        found, expected,
        "the serializable types carrying a per-item `error: Option<String>` changed; a new one \
         goes in PER_ITEM_TYPES so the rendering rule below covers it"
    );
}

#[test]
fn no_function_that_builds_a_per_item_result_renders_an_error_into_it() {
    let all = sources();
    let mut offenders = Vec::new();
    let mut constructors = 0;
    for (file, ty) in PER_ITEM_TYPES {
        let src = &all
            .iter()
            .find(|(rel, _, _)| rel == file)
            .unwrap_or_else(|| panic!("{file} is gone"))
            .1;
        let mut fns: BTreeSet<String> = BTreeSet::new();
        let mut from = 0;
        while let Some(rel_at) = src[from..].find(ty) {
            let at = from + rel_at;
            from = at + ty.len();
            let declared = src[..at].trim_end().ends_with("struct");
            if !declared && src[from..].trim_start().starts_with('{') {
                fns.insert(enclosing_fn(src, at));
            }
        }
        for func in fns {
            for body in fn_body(src, &func) {
                constructors += 1;
                let hits = error_renderings(&without_tracing(body));
                if !hits.is_empty() {
                    offenders.push(format!("{file}::{func} (builds {ty}): {hits:?}"));
                }
            }
        }
    }
    // Calibration: both register entries are built somewhere (batch.rs twice,
    // once per feature arm; belief.rs once).
    assert!(
        constructors >= PER_ITEM_TYPES.len(),
        "found {constructors} constructing functions; the scan is not seeing the tree"
    );
    assert!(
        offenders.is_empty(),
        "a per-item result is in a 2xx body, which the 500 redaction never sees: take an \
         ApiError's text from `caller_message()` and log any other error, never render it \
         into the result:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn a_json_error_field_carries_error_text_only_in_a_redacted_5xx() {
    let mut offenders = Vec::new();
    for (rel, src, raw) in sources() {
        let squashed: String = src.split_whitespace().collect();
        let renders = ERROR_RECEIVERS.iter().any(|r| {
            squashed.contains(&format!("\"error\":{r}.to_string()"))
                || squashed.contains(&format!("\"error\":format!(\"{{{r}}}\")"))
        });
        if !renders {
            continue;
        }
        match JSON_ERROR_FIELD_REDACTED_AT.iter().find(|(f, _)| *f == rel) {
            Some((_, sentinel)) => assert!(
                raw.contains(sentinel),
                "{rel}: its 5xx choke point no longer redacts (missing `{sentinel}`)"
            ),
            None => offenders.push(rel),
        }
    }
    assert!(
        offenders.is_empty(),
        "a JSON `\"error\"` field renders an error's text outside a redacted 5xx: {offenders:?}"
    );
}
