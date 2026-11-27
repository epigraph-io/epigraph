//! A database refusal code is recognised in ONE place: the registry in
//! `crates/epigraph-db/src/refusal_codes.rs` (backlog d9ff9949, split 2/2 of
//! ad2c7b0e).
//!
//! Before it, each repo or route that called a coded definer recognised the
//! family's codes itself: `msg.starts_with("VIS01")` in `claim_visibility.rs`,
//! `starts_with("PVS0..")` in `agent.rs`, `"CSG0.."` in `countersign.rs`, a
//! `"BUG0.."` match in `bug_report.rs`, `Some("TGP0..")` in
//! `person_team_group.rs`, `Some("ELV0..")` in the elevation routes, the RT07
//! prefix and the custom-SQLSTATE arms in `errors.rs`. Every one was a place a
//! code could be answered differently from the registry, or be missed by a
//! test that every raised code is mapped.
//!
//! This scan fails on any such one-off match in non-test source outside the
//! registry:
//!
//! * `starts_with("XX0`..: a message-prefix match on a code literal;
//! * `Some("XX01")`, `== "XX01"`, `"XX01" |`, `"XX01" =>`: a SQLSTATE or code
//!   match on a code literal;
//! * in `errors.rs`, a `starts_with(` or a `code().as_deref() == Some(..)`
//!   other than the standard `CHECK_VIOLATION`: the central conversion reads a
//!   coded refusal only through the registry.
//!
//! Lines inside a `#[cfg(test)]` module (everything after the first such line
//! of a file) and comment lines are not scanned: a test asserting a code is
//! expected, not a match.

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

/// The non-test, non-comment lines of `src`, numbered from 1.
fn code_lines(src: &str) -> impl Iterator<Item = (usize, &str)> {
    src.lines()
        .enumerate()
        .take_while(|(_, l)| l.trim_start() != "#[cfg(test)]")
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .map(|(i, l)| (i + 1, l))
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

/// The one-off code matches on `line`, as short descriptions.
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
    // Every complete string literal on the line that is exactly a code,
    // with what stands before and after it.
    let bytes = line.as_bytes();
    let mut i = 0;
    while let Some(open) = line[i..].find('"').map(|o| i + o) {
        let Some(close) = line[open + 1..].find('"').map(|c| open + 1 + c) else {
            break;
        };
        let lit = &line[open + 1..close];
        if is_code(lit) {
            let before = line[..open].trim_end();
            let after = line[close + 1..].trim_start();
            let matcher = before.ends_with("Some(")
                || before.ends_with("==")
                || before.ends_with('|')
                || after.starts_with('|')
                || after.starts_with("=>");
            if matcher {
                found.push(format!("code literal \"{lit}\""));
            }
        }
        i = close + 1;
        if i >= bytes.len() {
            break;
        }
    }
    found
}

const REGISTRY: &str = "crates/epigraph-db/src/refusal_codes.rs";
const ERRORS: &str = "crates/epigraph-db/src/errors.rs";

#[test]
fn no_one_off_refusal_code_match_outside_the_registry() {
    let files = source_files();
    assert!(
        files.len() > 100 && files.iter().any(|(f, _)| f == REGISTRY),
        "the scan must see the workspace's sources and the registry: {}",
        files.len()
    );
    let mut offenders = Vec::new();
    for (file, src) in &files {
        if file == REGISTRY {
            continue;
        }
        for (n, line) in code_lines(src) {
            for m in one_off_matches(line) {
                offenders.push(format!("{file}:{n}: {m}: {}", line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "recognise a refusal code through epigraph_db::refusal_codes, not a one-off \
         match:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_central_conversion_reads_coded_refusals_only_through_the_registry() {
    let files = source_files();
    let (_, src) = files
        .iter()
        .find(|(f, _)| f == ERRORS)
        .expect("errors.rs is scanned");
    let mut offenders = Vec::new();
    for (n, line) in code_lines(src) {
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
        r#""BUG03" => RefusalKind::State,"#,
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
    ] {
        assert!(one_off_matches(line).is_empty(), "false hit: {line}");
    }
}
