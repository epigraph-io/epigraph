//! Every `JobHandler` this crate defines is one the drain registers (backlog
//! 47bb548f).
//!
//! `epigraph-api/src/jobs_drain.rs::build_job_runner` is the ONE place
//! production handlers are registered. A handler defined here and registered
//! nowhere is code no job can reach: it is maintained, reviewed and listed in
//! tenancy registers without ever running, and it reads as a capability the
//! system does not have. The four that accumulated (truth propagation,
//! reputation, webhook, data cleanup) were deleted for that reason; this keeps
//! a fifth from appearing. A new handler lands together with its registration.
//!
//! Both sides are read from source. The handler side is every
//! `impl ... JobHandler for <Type>` under `epigraph-jobs/src` outside a
//! `#[cfg(test)]` module; the registration side is every
//! `register_handler(Arc::new(<Type>` inside `build_job_runner`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// The source with comments removed and the contents of string and char
/// literals blanked, every newline kept.
///
/// Both later passes count braces and match text, so neither may see a `{`
/// inside `'{'` or `"{"` (it would unbalance the test-module strip and swallow
/// the production code after it), nor an `impl JobHandler for X` written in a
/// doc comment or a message string (it would count a handler that is not
/// there). A `'` opens a char literal only when it is one: `'x'`, `'\…'`; a
/// lifetime such as `'static` or `'_` is code.
fn code_only(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let n = c.len();
    let mut out = String::with_capacity(src.len());
    let blank = |ch: char| if ch == '\n' { '\n' } else { ' ' };
    // `r"…"`, `r#"…"#`, `br"…"`: the hash count, when a raw string opens at `i`.
    let raw_at = |i: usize| -> Option<usize> {
        let ident = |j: usize| c[j].is_alphanumeric() || c[j] == '_';
        let prefix_ok = i == 0 || !ident(i - 1) || (c[i - 1] == 'b' && (i == 1 || !ident(i - 2)));
        if c[i] != 'r' || !prefix_ok {
            return None;
        }
        let hashes = c[i + 1..].iter().take_while(|&&x| x == '#').count();
        (c.get(i + 1 + hashes) == Some(&'"')).then_some(hashes)
    };
    let mut i = 0;
    while i < n {
        if c[i] == '/' && c.get(i + 1) == Some(&'/') {
            while i < n && c[i] != '\n' {
                i += 1;
            }
        } else if c[i] == '/' && c.get(i + 1) == Some(&'*') {
            let mut depth = 0usize;
            while i < n {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(c[i]));
                    i += 1;
                }
            }
        } else if let Some(hashes) = raw_at(i) {
            // Ends at a quote followed by as many hashes as opened it.
            out.push('"');
            i += 2 + hashes;
            while i < n {
                let run = c[i + 1..].iter().take_while(|&&x| x == '#').count();
                if c[i] == '"' && run >= hashes {
                    i += 1 + hashes;
                    break;
                }
                out.push(blank(c[i]));
                i += 1;
            }
            out.push('"');
        } else if c[i] == '"' {
            out.push('"');
            i += 1;
            while i < n && c[i] != '"' {
                if c[i] == '\\' {
                    out.push(' ');
                    i += 1;
                }
                if i < n {
                    out.push(blank(c[i]));
                    i += 1;
                }
            }
            out.push('"');
            i += 1;
        } else if c[i] == '\'' && (c.get(i + 1) == Some(&'\\') || c.get(i + 2) == Some(&'\'')) {
            // A char literal. In '\…' the escaped char (maybe a quote, as in
            // '\'') is skipped before looking for the closing quote.
            i += if c[i + 1] == '\\' { 3 } else { 2 };
            while i < n && c[i] != '\'' {
                i += 1;
            }
            out.push_str("' '");
            i += 1;
        } else {
            out.push(c[i]);
            i += 1;
        }
    }
    out
}

/// The (already [`code_only`]) source with every `#[cfg(test)] mod … { … }`
/// removed, brace-matched, so a test double implementing `JobHandler` is not
/// counted. A bodiless `#[cfg(test)] mod name;` declares a file module and
/// strips nothing here (that file is scanned on its own).
fn without_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "#[cfg(test)]".len()..];
        let open = after.find('{');
        let has_body = after.trim_start().starts_with("mod ")
            && open.is_some_and(|o| after.find(';').is_none_or(|semi| o < semi));
        let Some(open) = open.filter(|_| has_body) else {
            out.push_str("#[cfg(test)]");
            rest = after;
            continue;
        };
        let mut depth = 0usize;
        let mut end = after.len();
        for (i, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn ident_at(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Every type one source file implements `JobHandler` for, outside tests.
///
/// Matched on the whitespace-flattened code, so a header rustfmt wrapped over
/// several lines (`impl<…>\n    JobHandler for X<…>\nwhere …`) is still seen.
/// A match counts only when the text since the previous `{`, `}` or `;` holds
/// an `impl` keyword, i.e. when it is an impl header.
fn handlers_in(raw: &str) -> BTreeSet<String> {
    let flat = without_test_modules(&code_only(raw))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let needle = "JobHandler for ";
    let mut found = BTreeSet::new();
    for (at, _) in flat.match_indices(needle) {
        let item_start = flat[..at].rfind(['{', '}', ';']).map_or(0, |p| p + 1);
        let header = &flat[item_start..at];
        let is_impl = header
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|word| word == "impl");
        if !is_impl {
            continue;
        }
        let name = ident_at(&flat[at + needle.len()..]);
        assert!(!name.is_empty(), "unparsed impl header: {header}{needle}…");
        found.insert(name);
    }
    found
}

/// Every type `epigraph-jobs/src` implements `JobHandler` for, outside tests.
fn defined_handlers(src_dir: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    rust_files(src_dir, &mut files);
    files
        .iter()
        .flat_map(|f| handlers_in(&std::fs::read_to_string(f).expect("read source")))
        .collect()
}

/// Every type `build_job_runner` registers.
fn registered_handlers(jobs_drain: &str) -> BTreeSet<String> {
    let start = jobs_drain
        .find("pub fn build_job_runner(")
        .expect("jobs_drain.rs must still define build_job_runner");
    let body = &jobs_drain[start..];
    let end = body.find("\n}\n").expect("end of build_job_runner");
    let flat: String = body[..end].split_whitespace().collect();
    let needle = "register_handler(Arc::new(";
    flat.match_indices(needle)
        .map(|(at, _)| ident_at(&flat[at + needle.len()..]))
        .collect()
}

#[test]
fn every_handler_the_crate_defines_is_registered_by_the_drain() {
    let jobs_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let drain = Path::new(env!("CARGO_MANIFEST_DIR")).join("../epigraph-api/src/jobs_drain.rs");
    let defined = defined_handlers(&jobs_src);
    let registered = registered_handlers(&std::fs::read_to_string(drain).expect("read jobs_drain"));

    // Non-vacuity: both scans must see the handlers that are known to exist,
    // or a broken parser would pass by finding nothing on either side.
    for known in [
        "ClusterGraphHandler",
        "PrivatizationApplyHandler",
        "PrivatizationRevertHandler",
        "PrivatizationResealHandler",
        "ConfigurableEmbeddingHandler",
    ] {
        assert!(defined.contains(known), "scan missed {known}: {defined:?}");
        assert!(
            registered.contains(known),
            "build_job_runner scan missed {known}: {registered:?}"
        );
    }

    let unregistered: Vec<_> = defined.difference(&registered).collect();
    assert!(
        unregistered.is_empty(),
        "epigraph-jobs defines job handlers that drain_jobs never registers, so no job can \
         reach them. Register each in epigraph-api's jobs_drain::build_job_runner, or delete \
         it (and retire its EpiGraphJob kind, see EpiGraphJob::is_retired). \
         Unregistered: {unregistered:?}"
    );
}

#[test]
fn the_test_module_strip_keeps_production_impls() {
    let src = "impl JobHandler for Before {}\n\
               #[cfg(test)]\nmod tests { struct Fake; impl JobHandler for Fake { fn f() { if x {} } } }\n\
               impl<S: X + 'static> JobHandler for After<S> {}\n";
    let stripped = without_test_modules(&code_only(src));
    assert!(stripped.contains("Before") && stripped.contains("After<S>"));
    assert!(!stripped.contains("Fake"));
    assert_eq!(handlers_in(src), set(&["After", "Before"]));
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

/// A bodiless `#[cfg(test)] mod name;` has no block to strip. Looking for the
/// next `{` regardless would strip the next production item instead.
#[test]
fn a_bodiless_test_module_strips_nothing() {
    let src = "#[cfg(test)]\nmod helpers;\n\nimpl JobHandler for AfterBodilessMod {}\n";
    assert_eq!(handlers_in(src), set(&["AfterBodilessMod"]));
}

/// A brace inside a char or string literal, or a comment, in a test module
/// must not unbalance the strip and swallow the production code after it.
#[test]
fn braces_in_literals_and_comments_do_not_unbalance_the_strip() {
    let src = r##"
#[cfg(test)]
mod tests {
    const OPEN: char = '{';
    const ESCAPED: char = '\u{7b}';
    const BYTE: u8 = b'{';
    const QUOTE: char = '\'';
    const S: &str = "{{ \" {";
    const R: &str = r#"{"#;
    const BR: &[u8] = br"{";
    // an unbalanced { in a comment
    /* and { another */
    fn lifetimes<'a>(x: &'a str) -> &'static str { let _: &'_ str = x; "" }
    struct Fake;
    impl JobHandler for Fake {}
}

impl<S: Store + 'static> crate::JobHandler for AfterTestModule<S> {}
"##;
    assert_eq!(handlers_in(src), set(&["AfterTestModule"]));
}

/// rustfmt wraps a long impl header; the handler is still seen.
#[test]
fn a_wrapped_impl_header_is_seen() {
    let src =
        "impl<S>\n    JobHandler\n    for WrappedHeader<S>\nwhere\n    S: Send + 'static,\n{\n}\n";
    assert_eq!(handlers_in(src), set(&["WrappedHeader"]));
}

/// Prose and strings naming a handler are not a handler.
#[test]
fn comments_and_strings_naming_a_handler_do_not_count() {
    let src = r#"
/// Docs mention `impl JobHandler for InADocComment`.
// impl JobHandler for InALineComment {}
/* impl JobHandler for InABlockComment {} */
const MSG: &str = "impl JobHandler for InAString";
fn f() { let _ = "JobHandler for NotAnImpl"; }
impl JobHandler for Real {}
"#;
    assert_eq!(handlers_in(src), set(&["Real"]));
}
