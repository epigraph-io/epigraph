//! Source lint: **the redacted-claim response shape does not exist.**
//!
//! PR-14's acceptance line is *"a redacted-claim response shape no longer exists"*.
//! That is a property of the whole tree, not of any one handler, and nothing
//! else in the suite can state it: every behavioural test asserts what ONE
//! endpoint does for ONE fixture, so re-introducing blanking on a different
//! endpoint would be green everywhere.
//!
//! # Why a sentinel scan rather than a behavioural test
//!
//! Deleting redaction is only durable if it is *monotone*. The deleted code was
//! not one function — it was a helper (`redact_claim_content`), a second helper
//! on the MCP side (`redact_content`), a shared constant (`REDACTED`), and
//! **four hand-rolled `"[REDACTED]"` string literals** in `routes/edges.rs` and
//! `routes/graph_query.rs` that went through neither helper and that neither the
//! plan's *Files* line nor either scope document named. The literals are the
//! reason this file exists: a lint that watched only the helpers would have
//! reported success while the copy-pasted spelling survived, which is exactly
//! how the surface grew in the first place.
//!
//! So the invariant is spelled at the level the defect actually recurs at: the
//! **string**. A future author who reaches for `"[REDACTED]"` gets a build
//! failure naming the file and line, and has to argue with this comment instead
//! of quietly re-opening the oracle.
//!
//! # What "the oracle" means, briefly, so the rule is not cargo-culted
//!
//! Returning a placeholder body for a row the caller may not read discloses
//! that the row EXISTS. A `404` and a `200 {"content": "[REDACTED]"}` are
//! trivially distinguishable, so an endpoint that blanks is an existence oracle
//! even though it never reveals content. §8.5 states the rule: *any operation on
//! a resource the `Viewer` cannot read returns byte-identical status and body to
//! a nonexistent resource.* A placeholder cannot satisfy that. Absence can, and
//! is what the read paths now produce — see
//! `read_path_authz_test.rs::get_claim_private_and_nonexistent_are_indistinguishable_to_a_stranger`.
//!
//! # Scope, and what is deliberately NOT scanned
//!
//! Production sources only: `crates/*/src/`, for **every** crate in the
//! workspace, discovered by walking `crates/` rather than from a list — see
//! [`scanned_crates`] for why an allowlist cannot state a whole-tree property.
//! Comments are stripped first, so
//! *explaining* the deleted mechanism stays legal — several files do, including
//! this one, and a lint that forbade the word would have made its own rationale
//! unwritable. Tests are not scanned: they assert on the string as a NEGATIVE
//! (`!body.contains("[REDACTED]")`), which is the opposite of the defect and
//! must stay expressible.
//!
//! This lint does not and cannot prove that no OTHER placeholder spelling is
//! introduced (`"<private>"`, `""`, `"***"`). Nothing mechanical can. It pins
//! the one spelling this codebase actually used, for eight years of git history,
//! at ~20 sites.

use std::path::{Path, PathBuf};

/// The literal that must not reappear in production code.
///
/// Written in two halves so that THIS constant is not itself a match — the lint
/// scans `crates/*/src/`, and `epigraph-api/tests/` is outside that root, but
/// the split keeps the file honest if the scan root is ever widened.
const SENTINEL: &str = concat!("[RED", "ACTED]");

/// Every crate in the workspace that has a `src/` tree, discovered by walking
/// `crates/` rather than listed.
///
/// The mechanism lived in three crates — `epigraph-api` owned
/// `redact_claim_content` and the four inline literals, `epigraph-mcp` owned
/// `redact_content` and the `REDACTED` constant, `epigraph-db` owned
/// `ContentAccess` and `check_content_access` — and an earlier revision of this
/// lint named exactly those three. That is the wrong shape for the property it
/// claims to state. "The redacted-claim response shape no longer exists" is a
/// statement about the TREE, and a hardcoded allowlist cannot make it: it omits
/// `epigraph-engine`, `epigraph-cli` and the rest, and it omits any crate added
/// after today. Enumeration means a new crate is covered on the day it is
/// created. It is free: the sentinel appears in no `src/` file anywhere in the
/// workspace as of PR-14 except one comment in `epigraph-mcp`.
///
/// # If this fires on a crate that has nothing to do with claims
///
/// The property is scoped to CLAIM CONTENT — a row the caller's `Viewer` cannot
/// read must be absent, not returned with a placeholder body. A crate with a
/// legitimate unrelated use (masking a secret in a log line, say) is not what
/// this lint is about: give the placeholder a different spelling, or narrow the
/// walk and say in the PR body which crate left the scan and why.
fn scanned_crates(crates_dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(crates_dir)
        .expect("crates/ must be readable")
        .flatten()
    {
        let src = e.path().join("src");
        if src.is_dir() {
            let name = e.file_name().to_string_lossy().into_owned();
            out.push((name, src));
        }
    }
    out.sort();
    out
}

fn workspace_crates_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<workspace>/crates/epigraph-api`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ is the parent of this crate")
        .to_path_buf()
}

/// Remove `//` line comments and `/* */` block comments, respecting string
/// literals so a `"//"` inside a SQL fragment does not truncate the line.
///
/// Deliberately simple and deliberately over-eager on one case: a `//` inside a
/// raw string would be treated as a comment. That direction is safe — it can
/// only cause the lint to see LESS code and so to under-report, never to fail a
/// clean tree, and no scanned crate puts the sentinel in a raw string.
fn strip_comments(src: &str) -> String {
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
        } else {
            if c == b'"' || c == b'\'' {
                in_str = true;
                quote = c;
            }
            out.push(c as char);
        }
        i += 1;
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_production_source_reintroduces_the_redaction_placeholder() {
    let crates = workspace_crates_dir();
    let mut offenders = Vec::new();
    let mut scanned = 0usize;

    let roots = scanned_crates(&crates);
    // A workspace this size has many crates; a walk that found one or two means
    // the discovery is broken, not that the workspace shrank.
    assert!(
        roots.len() >= 10,
        "expected to discover the whole workspace under {}, found only {:?}",
        crates.display(),
        roots.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );

    for (_krate, src) in &roots {
        let mut files = Vec::new();
        rust_files(src, &mut files);
        for f in files {
            scanned += 1;
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            if !text.contains(SENTINEL) {
                continue; // fast path: most files never mention it
            }
            let code = strip_comments(&text);
            for (n, line) in code.lines().enumerate() {
                if line.contains(SENTINEL) {
                    offenders.push(format!("  {}:{}: {}", f.display(), n + 1, line.trim()));
                }
            }
        }
    }

    // A scan that finds no files is not a passing lint, it is a broken one.
    assert!(
        scanned > 100,
        "expected to scan hundreds of files across {} crates, scanned only \
         {scanned} — the scan root is wrong and this lint is asserting nothing",
        roots.len()
    );

    assert!(
        offenders.is_empty(),
        "\n\nA production source file reintroduced the redaction placeholder:\n{}\n\n\
         PR-14 deleted redaction. A row the caller's `Viewer` cannot read must be \
         ABSENT — 404 / not-found / omitted from the list — never returned with its \
         content replaced by a placeholder.\n\n\
         Blanking is not a weaker form of hiding, it is a different disclosure: a \
         placeholder body confirms the row EXISTS, so the endpoint stays an existence \
         oracle even though it reveals no content. Plan §8.5: any operation on a \
         resource the Viewer cannot read returns byte-identical status and body to a \
         nonexistent resource — which a placeholder cannot do.\n\n\
         Fix: filter at the READ instead. Move the statement into \
         crates/epigraph-db/src/repos/, carry a /* {{VISIBILITY:...}} */ marker, and \
         splice the Viewer — then the row does not come back and there is nothing to \
         blank. `EvidenceRepository::detail_by_id` is the worked example; it replaced \
         one of the four literals this lint exists to keep deleted.\n",
        offenders.join("\n")
    );
}

/// The lint must be able to FAIL. A scanner whose matcher is broken reports a
/// clean tree forever, which is indistinguishable from success.
#[test]
fn the_scanner_detects_the_sentinel_it_is_looking_for() {
    let positive = format!("let x = \"{SENTINEL}\";");
    assert!(
        strip_comments(&positive).contains(SENTINEL),
        "the scanner cannot see the sentinel in ordinary code"
    );

    // And it must NOT fire on prose, or the rationale above becomes unwritable.
    let commented = format!("// we used to return \"{SENTINEL}\" here\nlet y = 1;");
    assert!(
        !strip_comments(&commented).contains(SENTINEL),
        "the scanner fires on a comment; explaining the deleted mechanism must stay legal"
    );

    let block = format!("/* {SENTINEL} */ let z = 2;");
    assert!(
        !strip_comments(&block).contains(SENTINEL),
        "the scanner fires inside a block comment"
    );

    // A `//` inside a string must not truncate the rest of the line.
    let url = format!("let u = \"https://x\"; let v = \"{SENTINEL}\";");
    assert!(
        strip_comments(&url).contains(SENTINEL),
        "a `//` inside a string literal made the scanner drop real code"
    );
}
