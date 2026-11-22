//! Source ratchet: the text an MCP internal error SENDS carries no error
//! (backlog b89d475e).
//!
//! `crate::errors::internal_error` redacts what it is handed, and
//! `internal_error_logged(message, cause)` sends `message` and logs `cause`.
//! Three constructors send their message to the caller as written:
//!
//! * `internal_error_text(message)`,
//! * the FIRST argument of `internal_error_logged(message, cause)`,
//! * rmcp's `McpError::internal_error(message, data)` /
//!   `ErrorData::internal_error(..)`.
//!
//! PR #686 moved the error sites on the viewer-resolution, maintenance,
//! claim-helper and workflow-authority paths (`tools/viewer.rs`,
//! `maintenance.rs`, `claim_helper.rs`, `tools/workflow_authority.rs`) onto
//! those helpers, with the error on the logged side. Every authenticated tool
//! call goes through them, and nothing but this scan fails if a later edit
//! writes `internal_error_text(format!("...: {e}"))` there: the driver's or
//! provider's text (SQL, an internal host, another tenant's row) would reach
//! every MCP client. `internal_error_format_ratchet.rs` does not cover it: it
//! scans `internal_error(` only, and deliberately skips rmcp's constructor.
//!
//! The scan runs over the whole crate, not only those four files, and asserts
//! that each of the four still holds caller-text constructor sites, so a
//! rename cannot drop them from it silently.
//!
//! In those four files it also scans the caller-error constructors that send
//! their message as written: `invalid_request(` (rmcp's
//! `McpError::invalid_request`), `invalid_params(` (the crate helper and
//! rmcp's), and `Cow::from(` (the message of an `McpError { .. }` struct
//! literal). Only there: crate-wide those spellings are ~270 sites, many of
//! them a caller-input parse error (`invalid UUID: {e}`) whose text is the
//! caller's own input, not driver text, and they are designed.
//!
//! # What it flags, inside a constructor's message argument
//!
//! * a format capture of an error binding, Display or Debug (`{e}`,
//!   `{err:?}`, `{source}`);
//! * a positional `format!` argument that is an error binding (`e`,
//!   `e.to_string()`, `&err`);
//! * `<error binding>.to_string()` anywhere in it.
//!
//! An error binding is `e`, `err`, `error`, `source`, `cause`, or a name
//! ending `_err` / `_error`.
//!
//! # Known limits
//!
//! It recognises an error by its binding NAME: a closure that names its error
//! `x` and interpolates `{x}` is not caught, nor is a message built into a
//! `let` first and passed by name. Text taken out of an error through a method
//! call is not caught either: `db.message().to_string()` or
//! `format!("x: {}", d.message())` (a `.to_string()` whose receiver ends in
//! `)` or follows a field is skipped, and `d` is not an error binding). Nor is
//! a struct-literal message built with `.into()` (`message: format!(..).into()`)
//! rather than `Cow::from`, and the caller-error constructors
//! (`invalid_request(`, `invalid_params(`, `Cow::from(`) are scanned in the
//! four converted files only. Comments are stripped
//! (`lint_text::strip_comments`), string literals are kept, so a `tracing`
//! line that logs `{e}` beside a constructor is not a site. The stripper drops
//! the byte after a `\` escape, so a line continuation inside a string shifts
//! a reported line number up by one per continuation above it in the file; the
//! site count is unaffected.

mod lint_text;

use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The files PR #686 converted: each must still be scanned and hold at least
/// one caller-text constructor (backlog b89d475e).
const CONVERTED: &[&str] = &[
    "tools/viewer.rs",
    "maintenance.rs",
    "claim_helper.rs",
    "tools/workflow_authority.rs",
];

/// Caller-error constructors that also send their message as written,
/// scanned in the [`CONVERTED`] files only (see the module doc for why not
/// crate-wide). The bare spellings match `McpError::invalid_request(` and
/// `crate::errors::invalid_params(` too, once each.
const CONVERTED_CONSTRUCTORS: &[&str] = &["invalid_request(", "invalid_params(", "Cow::from("];

/// Sites allowed to interpolate an error, per file, with why. Counts are
/// exact: a change in either direction fails.
const ALLOWED: &[(&str, usize, &str)] = &[(
    "errors.rs",
    1,
    "executor_caller_error's SystemAgentUnregistered arm: migration 148's armed-and-unregistered \
     refusal, whose Display is the operator's remedy (no driver text), sent as designed text",
)];

/// The caller-text constructors. The two bare helpers must not be the tail of
/// a longer identifier; the rmcp spellings are matched qualified.
const CONSTRUCTORS: &[&str] = &[
    "internal_error_text(",
    "internal_error_logged(",
    "McpError::internal_error(",
    "ErrorData::internal_error(",
];

fn is_error_binding(name: &str) -> bool {
    matches!(name, "e" | "err" | "error" | "source" | "cause")
        || name.ends_with("_err")
        || name.ends_with("_error")
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The text between the `(` that ends at `open` and its matching `)`. String
/// literals and char literals are skipped, so a `)` inside one does not close
/// the call.
fn call_args(text: &str, open: usize) -> &str {
    let b = text.as_bytes();
    let mut depth = 1usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 2,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &text[open..i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    &text[open..]
}

/// `args` split at its top-level commas (not inside a string, a char literal
/// or brackets), each part trimmed.
fn top_level(args: &str) -> Vec<&str> {
    let b = args.as_bytes();
    let (mut depth, mut start, mut i) = (0usize, 0usize, 0usize);
    let mut out = Vec::new();
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 2,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                out.push(args[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(args[start..].trim());
    out
}

/// The contents of every `"..."` literal in `expr`.
fn literals(expr: &str) -> Vec<&str> {
    let b = expr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let start = i + 1;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            out.push(&expr[start..i.min(b.len())]);
        }
        i += 1;
    }
    out
}

/// Why `message` (a constructor's message expression) carries an error, or
/// an empty list.
fn leaks(message: &str) -> Vec<String> {
    let mut why = Vec::new();
    // Format captures inside the string literals: `{e}`, `{err:?}`. `{{` is
    // an escaped brace, not a capture. A Debug capture of a non-error
    // (`{viewer:?}`, an `Option<Uuid>`) is not flagged.
    for lit in literals(message) {
        let mut rest = lit;
        while let Some(at) = rest.find('{') {
            let after = &rest[at + 1..];
            if let Some(escaped) = after.strip_prefix('{') {
                rest = escaped;
                continue;
            }
            let Some(close) = after.find('}') else { break };
            let capture = &after[..close];
            let name = capture.split_once(':').map_or(capture, |(n, _)| n);
            if is_error_binding(name.trim()) {
                why.push(format!("{{{capture}}}"));
            }
            rest = &after[close + 1..];
        }
    }
    // Positional `format!` arguments.
    let trimmed = message.trim_start();
    let trimmed = trimmed.strip_prefix('&').map_or(trimmed, str::trim_start);
    if let Some(inner) = trimmed.strip_prefix("format!") {
        let inner = inner.trim_start();
        if let Some(inner) = inner.strip_prefix('(') {
            for arg in top_level(call_args(inner, 0)).into_iter().skip(1) {
                let value = arg.split_once('=').map_or(arg, |(_, v)| v).trim();
                let value = value.strip_prefix('&').unwrap_or(value).trim();
                let value = value.strip_suffix(".to_string()").unwrap_or(value);
                if is_error_binding(value) {
                    why.push(format!("argument `{arg}`"));
                }
            }
        }
    }
    // `<error binding>.to_string()` anywhere in the expression, outside the
    // string literals.
    let code: String = {
        let mut out = String::new();
        let mut in_str = false;
        let mut escaped = false;
        for c in message.chars() {
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                }
                out.push(' ');
            } else {
                if c == '"' {
                    in_str = true;
                }
                out.push(if c == '"' { ' ' } else { c });
            }
        }
        out
    };
    let mut from = 0;
    while let Some(off) = code[from..].find(".to_string()") {
        let at = from + off;
        from = at + 1;
        let before = &code[..at];
        let start = before
            .char_indices()
            .rev()
            .take_while(|(_, c)| is_ident(*c))
            .last()
            .map_or(at, |(i, _)| i);
        let name = &code[start..at];
        let preceded_by_field = code[..start].ends_with('.');
        if !preceded_by_field && is_error_binding(name) {
            why.push(format!("`{name}.to_string()`"));
        }
    }
    why
}

/// Every caller-text constructor site in `text` (comment-stripped): its
/// 1-based line and the reasons its message carries an error (empty when it
/// does not).
fn sites(text: &str, spellings: &[&str]) -> Vec<(usize, Vec<String>)> {
    let mut out = Vec::new();
    for spelling in spellings {
        let mut from = 0;
        while let Some(off) = text[from..].find(spelling) {
            let at = from + off;
            from = at + spelling.len();
            // The bare helpers: not a longer identifier ending in the name,
            // and not the definition (`fn internal_error_text(`).
            if !spelling.contains("::") {
                let before = text[..at].trim_end();
                if text[..at].chars().next_back().is_some_and(is_ident) || before.ends_with("fn") {
                    continue;
                }
            }
            let args = call_args(text, from);
            let message = top_level(args).into_iter().next().unwrap_or("");
            out.push((text[..at].matches('\n').count() + 1, leaks(message)));
        }
    }
    out.sort();
    out
}

fn strip(text: &str) -> String {
    lint_text::strip_comments(text)
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
fn no_caller_facing_internal_error_carries_an_error() {
    let root = src();
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    assert!(
        files.len() > 50,
        "the scan found only {} files",
        files.len()
    );

    let mut offenders = Vec::new();
    let mut allowed_seen = std::collections::BTreeMap::new();
    let mut converted_seen = std::collections::BTreeMap::new();
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = strip(&std::fs::read_to_string(path).expect("read source"));
        let found = if CONVERTED.contains(&rel.as_str()) {
            let internal = sites(&text, CONSTRUCTORS);
            converted_seen.insert(rel.clone(), internal.len());
            let mut all = internal;
            all.extend(sites(&text, CONVERTED_CONSTRUCTORS));
            all
        } else {
            sites(&text, CONSTRUCTORS)
        };
        let leaking: Vec<_> = found
            .into_iter()
            .filter(|(_, why)| !why.is_empty())
            .collect();
        if ALLOWED.iter().any(|(f, _, _)| *f == rel) {
            allowed_seen.insert(rel.clone(), leaking.len());
            continue;
        }
        for (line, why) in leaking {
            offenders.push(format!("{rel}:{line} ({})", why.join(", ")));
        }
    }
    assert!(
        offenders.is_empty(),
        "an internal error's caller-facing message interpolates an error: the driver's or \
         provider's text would reach the MCP caller. Put the designed text in the message and the \
         error on the logged side (internal_error_logged(\"<context>\", e)), or hand the typed \
         error to internal_error. Sites:\n  {}",
        offenders.join("\n  ")
    );
    for file in CONVERTED {
        let n = converted_seen
            .get(*file)
            .copied()
            .unwrap_or_else(|| panic!("{file} was not scanned (moved or renamed?)"));
        assert!(
            n > 0,
            "{file} holds no caller-text internal-error constructor any more; the scan no \
             longer covers it. Update CONVERTED to where its error sites went."
        );
    }
    for (file, allowed, why) in ALLOWED {
        let found = allowed_seen
            .get(*file)
            .copied()
            .unwrap_or_else(|| panic!("allowlisted file {file} was not scanned"));
        assert_eq!(
            found, *allowed,
            "{file} has {found} caller-text sites interpolating an error; the ratchet allows \
             exactly {allowed} ({why})"
        );
    }
}

/// The scanner itself: the shapes it must catch and the ones it must skip.
#[test]
fn the_scanner_catches_error_text_in_every_constructor() {
    let leaky = |src: &str| -> Vec<usize> {
        sites(&strip(src), CONSTRUCTORS)
            .into_iter()
            .filter(|(_, why)| !why.is_empty())
            .map(|(line, _)| line)
            .collect()
    };
    let caught = "a.map_err(|e| internal_error_text(format!(\"viewer: {e}\")))?;\n\
                  b.map_err(|err| crate::errors::internal_error_logged(\n    format!(\"x: {err:?}\"),\n    err,\n))?;\n\
                  c.map_err(|e| McpError::internal_error(format!(\"y: {}\", e), None))?;\n\
                  d.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;\n\
                  f.map_err(|db_err| internal_error_text(format!(\"z: {}\", db_err.to_string())))?;\n\
                  g.map_err(|e| internal_error_text(format!(\"{tool}: {source}\", tool = t)))?;";
    assert_eq!(leaky(caught), vec![1, 2, 6, 7, 8, 9]);

    let clean = "a.map_err(|e| internal_error_logged(format!(\"{tool}: could not read\"), e))?;\n\
                 b.ok_or_else(|| internal_error_text(format!(\"{tool}: no ScopedPool\")))?;\n\
                 McpError::internal_error(\"no maintenance pool\".to_string(), None);\n\
                 internal_error_text(format!(\"agent {principal} is operated by {}\", link.operator_id));\n\
                 internal_error_text(format!(\"literal {{e}} braces\"));\n\
                 pub fn internal_error_text(message: impl Into<String>) -> McpError {}\n\
                 log_internal_error_text(format!(\"{e}\"));\n\
                 tracing::error!(\"failed: {e}\"); internal_error_text(\"failed\");\n\
                 McpError::internal_error(format!(\"the viewer names {viewer:?}\"), None);";
    assert!(
        leaky(clean).is_empty(),
        "{:?}",
        sites(&strip(clean), CONSTRUCTORS)
    );
    assert_eq!(
        sites(&strip(clean), CONSTRUCTORS).len(),
        7,
        "every constructor in the clean sample is still SEEN: {:?}",
        sites(&strip(clean), CONSTRUCTORS)
    );

    let commented = "// internal_error_text(format!(\"x: {e}\"));\n\
                     /* McpError::internal_error(format!(\"{e}\"), None) */";
    assert!(leaky(commented).is_empty());
}

/// The caller-error constructors scanned in the converted files: an error
/// interpolated into `invalid_request`, `invalid_params` or a struct literal's
/// `Cow::from` message is caught, designed text is not, and each spelling is
/// seen once per site (the bare spelling matches the qualified call too).
#[test]
fn the_scanner_catches_error_text_in_the_caller_error_constructors() {
    let scan = |src: &str| sites(&strip(src), CONVERTED_CONSTRUCTORS);
    let leaky = |src: &str| -> Vec<usize> {
        scan(src)
            .into_iter()
            .filter(|(_, why)| !why.is_empty())
            .map(|(line, _)| line)
            .collect()
    };
    let caught = "a.map_err(|e| McpError::invalid_request(format!(\"viewer: {e}\"), None))?;\n\
                  b.map_err(|err| crate::errors::invalid_params(err.to_string()))?;\n\
                  McpError { code: ErrorCode::INVALID_REQUEST, message: std::borrow::Cow::from(format!(\"x: {}\", e)), data: None };\n\
                  c.map_err(|source| ErrorData::invalid_params(format!(\"{source:?}\"), None))?;";
    assert_eq!(leaky(caught), vec![1, 2, 3, 4]);

    let clean = "McpError::invalid_request(format!(\"no principal for {tool}\"), None);\n\
                 crate::errors::invalid_params(format!(\"{entity} {id} not found\"));\n\
                 McpError { message: std::borrow::Cow::from(message), code, data: None };\n\
                 pub fn invalid_params(msg: impl Into<String>) -> McpError {}";
    assert!(leaky(clean).is_empty(), "{:?}", scan(clean));
    assert_eq!(
        scan(clean).len(),
        3,
        "every constructor in the clean sample is SEEN once: {:?}",
        scan(clean)
    );
}
