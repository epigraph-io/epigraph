//! A database refusal code is recognised in ONE place: the registry in
//! `crates/epigraph-db/src/refusal_codes.rs` (backlog d9ff9949, split 2/2 of
//! ad2c7b0e).
//!
//! Before it, each repo or route that called a coded definer recognised the
//! family's codes itself: `msg.starts_with("VIS01")` in `claim_visibility.rs`,
//! `starts_with("PVS0..")` in `agent.rs`, `"CSG0.."` in `countersign.rs`, a
//! `"BUG0.."` match in `bug_report.rs`, `Some("TGP0..")` in
//! `person_team_group.rs`, `Some("ELV0..")` in the elevation routes,
//! `contains("AK02:")` and `contains("ADM02:")` in the agent-key routes, a
//! comparison with a local `AID06` constant in the prompt-history route, the
//! RT07 prefix and the custom-SQLSTATE arms in `errors.rs`. Every one was a
//! place a code could be answered differently from the registry, or be missed
//! by a test that every raised code is mapped.
//!
//! This scan fails on any such one-off match in non-test source outside the
//! registry:
//!
//! * `starts_with("XX0`..: a message-prefix match on a code literal;
//! * `contains("XX01:")`, `strip_prefix("XX01")`, `ends_with(..)`: a match on
//!   a literal that is a code, or a code and its colon;
//! * `Some("XX01")`, `== "XX01"`, `!= "XX01"`, `"XX01" |`, `"XX01" =>`: a
//!   SQLSTATE or code match on a code literal;
//! * the same shapes on a constant declared outside the registry whose value
//!   is a code (`const X: &str = "XX01"; .. == X`). A constant of the registry
//!   is what a route compares [`route_code`] with, so it is not one;
//! * in `errors.rs`, a `starts_with(` or a `code().as_deref() == Some(..)`
//!   other than the standard `CHECK_VIOLATION`: the central conversion reads a
//!   coded refusal only through the registry.
//!
//! Test items are not scanned: the item that follows `#[cfg(test)]` or
//! `#[cfg(all(test, ..))]` (a `mod tests { .. }` anywhere in the file, a
//! test-only constant or function), found by rustfmt's layout (the closing
//! line at the attribute's indent). Comment lines are not scanned either. A
//! test asserting a code is expected, not a match.
//!
//! [`route_code`]: epigraph_db::refusal_codes::route_code

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two parents")
        .to_path_buf()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `crates/*/src/**.rs` file, relative to the repo root.
fn source_files() -> Vec<(String, String)> {
    let root = repo_root();
    let mut files = Vec::new();
    for krate in std::fs::read_dir(root.join("crates"))
        .expect("crates/")
        .flatten()
    {
        collect(&krate.path().join("src"), &mut files);
    }
    let mut out: Vec<(String, String)> = files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p).expect("readable source");
            (rel, src)
        })
        .collect();
    out.sort();
    out
}

/// `line` gates the next item to tests only. `cfg(any(.., test))` gates
/// production code too, so it is not one.
fn is_test_gate(line: &str) -> bool {
    let t = line.trim();
    t == "#[cfg(test)]" || t.starts_with("#[cfg(all(test,") || t.starts_with("#[cfg(all(test )")
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The item's first line holds the whole item: `mod tests;`, a one-line
/// constant, `fn f() {}`.
fn one_line_item(line: &str) -> bool {
    let t = line.trim_end();
    t.ends_with(';') || (t.contains('{') && t.matches('{').count() == t.matches('}').count())
}

/// The line that closes a multi-line item opened at `at` indent: rustfmt puts
/// it at the item's own indent, opening with `}` (a block) or being `];` /
/// `);` (a multi-line initialiser).
fn closes_item(line: &str, at: usize) -> bool {
    let t = line.trim();
    indent(line) == at && (t.starts_with('}') || t == "];" || t == ");")
}

/// The non-test, non-comment lines of `src`, numbered from 1. `file` names the
/// source in a panic when a test item never closes (a layout this scan does
/// not understand must be loud, not silently skip production code).
fn code_lines<'a>(file: &str, src: &'a str) -> Vec<(usize, &'a str)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if is_test_gate(line) {
            let at = indent(line);
            i += 1;
            while i < lines.len() && lines[i].trim_start().starts_with("#[") {
                i += 1;
            }
            if i < lines.len() && !one_line_item(lines[i]) {
                let open = i + 1;
                i += 1;
                while i < lines.len() && !closes_item(lines[i], at) {
                    i += 1;
                }
                assert!(
                    i < lines.len(),
                    "{file}:{open}: the test item opened here never closes at indent {at}"
                );
            }
            i += 1;
            continue;
        }
        if !line.trim_start().starts_with("//") {
            out.push((i + 1, line));
        }
        i += 1;
    }
    out
}

/// `s` opens with a code: two to four ASCII capitals, then a digit.
fn opens_with_code(s: &str) -> bool {
    let caps = s.bytes().take_while(u8::is_ascii_uppercase).count();
    (2..=4).contains(&caps) && s.as_bytes().get(caps).is_some_and(u8::is_ascii_digit)
}

/// `s` is exactly a code: two to four ASCII capitals, then two digits.
fn is_code(s: &str) -> bool {
    let caps = s.bytes().take_while(u8::is_ascii_uppercase).count();
    (2..=4).contains(&caps)
        && s.len() == caps + 2
        && s.as_bytes()[caps..].iter().all(u8::is_ascii_digit)
}

/// The text matches a code with `before` standing before it and `after`
/// after it: a comparison, a pattern alternative or arm, or a string search.
fn in_matcher_position(before: &str, after: &str) -> bool {
    const BEFORE: &[&str] = &[
        "Some(",
        "==",
        "!=",
        "|",
        "starts_with(",
        "strip_prefix(",
        "contains(",
        "ends_with(",
    ];
    BEFORE.iter().any(|b| before.ends_with(b))
        || after.starts_with("==")
        || after.starts_with("!=")
        || after.starts_with('|')
        || after.starts_with("=>")
}

/// The one-off code-literal matches on `line`, as short descriptions.
fn one_off_matches(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for needle in ["starts_with(\"", "starts_with(b\""] {
        let mut rest = line;
        while let Some(at) = rest.find(needle) {
            let after = &rest[at + needle.len()..];
            if opens_with_code(after) {
                found.push(format!("starts_with({}..)", &after[..after.len().min(5)]));
            }
            rest = after;
        }
    }
    // Every complete string literal on the line that is exactly a code (or,
    // searched for, a code and its colon), with what stands before and after.
    let bytes = line.as_bytes();
    let mut i = 0;
    while let Some(open) = line[i..].find('"').map(|o| i + o) {
        let Some(close) = line[open + 1..].find('"').map(|c| open + 1 + c) else {
            break;
        };
        let lit = &line[open + 1..close];
        let before = line[..open]
            .strip_suffix('b')
            .filter(|s| s.ends_with('('))
            .unwrap_or(&line[..open])
            .trim_end();
        let after = line[close + 1..].trim_start();
        let searched = ["contains(", "strip_prefix(", "ends_with(", "starts_with("]
            .iter()
            .any(|b| before.ends_with(b));
        let code = is_code(lit) || (searched && lit.strip_suffix(':').is_some_and(is_code));
        if code && in_matcher_position(before, after) && !before.ends_with("starts_with(") {
            found.push(format!("code literal \"{lit}\""));
        }
        i = close + 1;
        if i >= bytes.len() {
            break;
        }
    }
    found
}

/// `const NAME: &str = "XX01";` (or `&'static str`) on `line`: the name and the
/// code.
fn code_constant(line: &str) -> Option<(&str, &str)> {
    let t = line.trim_start();
    let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
    let t = t.strip_prefix("pub ").unwrap_or(t);
    let t = t.strip_prefix("const ")?;
    let (name, rest) = t.split_once(':')?;
    let rest = rest.trim_start();
    let rest = rest
        .strip_prefix("&'static str")
        .or_else(|| rest.strip_prefix("&str"))?;
    let lit = rest
        .trim_start()
        .strip_prefix("= \"")?
        .strip_suffix("\";")?;
    is_code(lit).then_some((name.trim(), lit))
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The matches on `line` against one of `constants` (each a name and its
/// code), as short descriptions. A path to the name (`x::NAME`) is the name.
fn constant_matches(line: &str, constants: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (name, code) in constants {
        let mut from = 0;
        while let Some(at) = line[from..].find(name.as_str()).map(|a| from + a) {
            let end = at + name.len();
            from = end;
            let whole = (at == 0 || !is_ident_byte(line.as_bytes()[at - 1]))
                && line.as_bytes().get(end).is_none_or(|b| !is_ident_byte(*b));
            if !whole {
                continue;
            }
            let mut before = line[..at].trim_end();
            while let Some(path) = before.strip_suffix("::") {
                before = path.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
            }
            let before = before.trim_end();
            if in_matcher_position(before, line[end..].trim_start()) {
                found.push(format!("constant {name} (\"{code}\")"));
            }
        }
    }
    found
}

const REGISTRY: &str = "crates/epigraph-db/src/refusal_codes.rs";
const ERRORS: &str = "crates/epigraph-db/src/errors.rs";

/// The one-off matches kept outside the registry on purpose, each a file and
/// the code it recognises, with the reason.
///
/// * `CX03` in `epigraph-auth`'s `claim_act.rs`: the cascade-deferral refusal
///   both transports' supersede mappers recognise through
///   `is_cascade_deferral_refusal`, which takes a SQLSTATE and a message so
///   that `epigraph-auth` stays free of the database layer (it does not depend
///   on `epigraph-db`). The registry lists `CX03` too, so a coverage test over
///   the registry sees it; [`the_exemptions_are_live_and_registered`] ties the
///   two.
const EXEMPT: &[(&str, &str)] = &[("crates/epigraph-auth/src/claim_act.rs", "CX03")];

fn exempt(file: &str, finding: &str) -> bool {
    EXEMPT
        .iter()
        .any(|(f, code)| *f == file && finding.contains(&format!("\"{code}\"")))
}

/// Every code constant declared outside the registry, in non-test source.
fn foreign_constants(files: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = BTreeSet::new();
    for (file, src) in files {
        if file == REGISTRY {
            continue;
        }
        for (_, line) in code_lines(file, src) {
            if let Some((name, code)) = code_constant(line) {
                out.insert((name.to_string(), code.to_string()));
            }
        }
    }
    out.into_iter().collect()
}

/// Every one-off match in `files` outside the registry, as
/// `(file, "file:line: what: text")`.
fn scan(files: &[(String, String)]) -> Vec<(String, String)> {
    let constants = foreign_constants(files);
    let mut out = Vec::new();
    for (file, src) in files {
        if file == REGISTRY {
            continue;
        }
        for (n, line) in code_lines(file, src) {
            for m in one_off_matches(line)
                .into_iter()
                .chain(constant_matches(line, &constants))
            {
                out.push((file.clone(), format!("{file}:{n}: {m}: {}", line.trim())));
            }
        }
    }
    out
}

#[test]
fn no_one_off_refusal_code_match_outside_the_registry() {
    let files = source_files();
    assert!(
        files.len() > 100 && files.iter().any(|(f, _)| f == REGISTRY),
        "the scan must see the workspace's sources and the registry: {}",
        files.len()
    );
    let offenders: Vec<String> = scan(&files)
        .into_iter()
        .filter(|(file, m)| !exempt(file, m))
        .map(|(_, m)| m)
        .collect();
    assert!(
        offenders.is_empty(),
        "recognise a refusal code through epigraph_db::refusal_codes, not a one-off \
         match:\n{}",
        offenders.join("\n")
    );
}

/// Each exemption still matches its code (so it cannot go stale and hide a
/// new match in its file), and the registry lists the code.
#[test]
fn the_exemptions_are_live_and_registered() {
    let files = source_files();
    let found = scan(&files);
    let (_, registry) = files
        .iter()
        .find(|(f, _)| f == REGISTRY)
        .expect("the registry is scanned");
    for (file, code) in EXEMPT {
        assert!(
            found.iter().any(|(f, m)| f == file && exempt(f, m)),
            "{file} no longer matches {code}: drop its exemption"
        );
        assert!(
            registry.contains(&format!("(\"{code}\", Answer::")),
            "the registry must list the exempted {code}"
        );
    }
}

#[test]
fn the_central_conversion_reads_coded_refusals_only_through_the_registry() {
    let files = source_files();
    let (_, src) = files
        .iter()
        .find(|(f, _)| f == ERRORS)
        .expect("errors.rs is scanned");
    let mut offenders = Vec::new();
    for (n, line) in code_lines(ERRORS, src) {
        let sqlstate_arm =
            line.contains("code().as_deref() == Some(") && !line.contains("Some(CHECK_VIOLATION)");
        if sqlstate_arm || line.contains(".starts_with(") {
            offenders.push(format!("{ERRORS}:{n}: {}", line.trim()));
        }
    }
    assert!(
        offenders.is_empty(),
        "From<sqlx::Error> for DbError must look a coded refusal up in the registry:\n{}",
        offenders.join("\n")
    );
}

/// The scanner sees each shape it exists to refuse, and passes text that only
/// names a code.
#[test]
fn the_scanner_is_not_vacuous() {
    for line in [
        r#"if msg.starts_with("VIS01") || msg.starts_with("VIS02") {"#,
        r#"if b.starts_with(b"BUG0") {"#,
        r#"Err(e) if sqlstate(&e).as_deref() == Some("ELV06") => x(),"#,
        r#"Some("TGP01" | "TGP02") => Some(RefusalKind::Authority),"#,
        r#""BUG04" | "BUG05" => RefusalKind::Input,"#,
        r#"Some((code, _)) if code == "ELV07" => {"#,
        r#"if code != "ELV07" {"#,
        r#""BUG03" => RefusalKind::State,"#,
        r#"if message.contains("AK02:") {"#,
        r#"&& e.to_string().contains("ADM02:") {"#,
        r#"message.strip_prefix("CX03").is_some_and(|r| r.starts_with(':'))"#,
        r#"if msg.ends_with("VIS01") {"#,
    ] {
        assert!(!one_off_matches(line).is_empty(), "missed: {line}");
    }
    for line in [
        r#"message: "OPL01: agent a is not bound".to_string(),"#,
        r#"let refuse = |m: String| Err(invalid_params(format!("BUG04: {m}")));"#,
        r#"pub const OPERATOR_LINK_REQUIRED: &str = "OPL01";"#,
        r#"Some(c) if c == ELV07 => {"#,
        r#"Some("23505" | "23P01") => true,"#,
        r#"assert!(!message.starts_with(SIGNING_DOMAIN_V1));"#,
        r#"err.message.contains("RFC3339"),"#,
        r#"if s.contains("VIS01 and VIS02") {"#,
    ] {
        assert!(one_off_matches(line).is_empty(), "false hit: {line}");
    }

    let constants = [(String::from("FOO_REFUSED"), String::from("FOO01"))];
    assert_eq!(
        code_constant(r#"pub const FOO_REFUSED: &str = "FOO01";"#),
        Some(("FOO_REFUSED", "FOO01"))
    );
    assert_eq!(
        code_constant(r#"const PREFIX: &'static str = "FOO01";"#),
        Some(("PREFIX", "FOO01"))
    );
    assert_eq!(code_constant(r#"const X: &str = "not a code";"#), None);
    for line in [
        r#"if db.code().as_deref() == Some(FOO_REFUSED) {"#,
        r#".is_some_and(|c| c == agent_identity::FOO_REFUSED),"#,
        r#"FOO_REFUSED => RefusalKind::Input,"#,
        r#"message.strip_prefix(FOO_REFUSED)"#,
        r#"if e.to_string().contains(FOO_REFUSED) {"#,
    ] {
        assert!(
            !constant_matches(line, &constants).is_empty(),
            "missed: {line}"
        );
    }
    for line in [
        r#"format!("{FOO_REFUSED}: the claim {id} is not yours")"#,
        r#"/// [`FOO_REFUSED`] when the caller may not"#,
        r#"if x == FOO_REFUSED_TOO {"#,
        r#"pub const FOO_REFUSED: &str = "FOO01";"#,
    ] {
        assert!(
            constant_matches(line, &constants).is_empty(),
            "false hit: {line}"
        );
    }
}

/// A test item is skipped, and only it: production code after a test-only
/// constant, or after a test module in the middle of a file, is scanned.
#[test]
fn only_test_items_are_skipped() {
    let src = "\
#[cfg(test)]
const SAMPLE: &str = \"VIS01: x\";

fn after_a_test_constant(m: &str) -> bool {
    m.starts_with(\"VIS07\")
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        assert!(super::after_a_test_constant(\"VIS07: x\"));
        if \"x\".starts_with(\"VIS08\") {}
    }
}

fn after_a_test_module(code: Option<&str>) -> bool {
    code == Some(\"TGP10\")
}

#[cfg(all(test, feature = \"db\"))]
fn test_only(
    m: &str,
) -> bool {
    m.starts_with(\"VIS09\")
}

    #[cfg(test)]
    fn one_line() {}

fn last(m: &str) -> bool {
    m.contains(\"AK04:\")
}
";
    let lines = code_lines("sample.rs", src);
    let found: Vec<(usize, String)> = lines
        .iter()
        .flat_map(|(n, l)| one_off_matches(l).into_iter().map(move |m| (*n, m)))
        .collect();
    let at: Vec<usize> = found.iter().map(|(n, _)| *n).collect();
    assert_eq!(at, vec![5, 18, 32], "{found:?}");
    assert!(
        !lines.iter().any(|(_, l)| l.contains("SAMPLE")),
        "the test-only constant is skipped"
    );
}

/// A test item whose closing line this scan cannot find is loud.
#[test]
#[should_panic(expected = "never closes")]
fn an_unclosed_test_item_is_loud() {
    let src = "#[cfg(test)]\nmod tests {\n    fn t() {}\n";
    let _ = code_lines("broken.rs", src);
}
