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

mod lint_text;

use lint_text::strip_comments;
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

    // A LIFETIME MUST NOT PUT THE SCANNER IN STRING STATE. This is the
    // regression fixture for the defect that made `strip_comments` a partial
    // no-op: a `'` treated as a string delimiter has no partner, so everything
    // after it — comments included — was copied through verbatim. Measured at
    // 122 surviving comment lines in `epigraph-api/src/routes/` alone — counting
    // lines whose first non-whitespace is `//` and which the shipped stripper
    // blanks — which silently un-did the stripping this helper's callers depend
    // on.
    //
    // `&'a` and `'static` are written with an ODD number of ticks on purpose:
    // an even count happens to re-balance and would let the bug pass.
    let after_lifetime = format!("fn f(x: &'a str) {{}}\n// {SENTINEL}\nlet y = 1;");
    assert!(
        !strip_comments(&after_lifetime).contains(SENTINEL),
        "a lifetime tick left the scanner in string state and a comment survived"
    );
    let after_static = format!("const S: &'static str = \"s\";\n// {SENTINEL}\nlet z = 2;");
    assert!(
        !strip_comments(&after_static).contains(SENTINEL),
        "a `'static` tick left the scanner in string state and a comment survived"
    );

    // …and a real char literal must still be treated as one, including the
    // `'/'` case, whose contents would otherwise open a line comment and eat
    // the rest of the line.
    let char_lit = format!("let c = '/'; let d = '\\\\'; let e = \"{SENTINEL}\";");
    assert!(
        strip_comments(&char_lit).contains(SENTINEL),
        "a char literal was mis-lexed and swallowed the code after it"
    );

    // THE ONE DOCUMENTED OVER-EAGERNESS, PINNED IN BOTH DIRECTIONS. This is the
    // silent direction — over-suppression cannot announce itself, so it has to
    // be measured rather than reasoned about.
    //
    // `strip_comments` does not lex raw strings. An odd number of inner `"`
    // closes its string state early, and a `//` after that opens comment state
    // inside what is really still string content. The fixture below is built so
    // each half is decidable: the sentinel on the SAME line as the stray `//` is
    // eaten, and the one on the NEXT line survives.
    //
    // The point is the bound. The damage stops at the newline, so the loss is
    // one line rather than the rest of the file — which is exactly the
    // difference between this and the lifetime defect above. If a future edit
    // makes the first assertion pass, the over-eagerness is gone and this
    // fixture should be simplified; if it makes the SECOND one fail, the
    // stripper has started eating whole files again.
    let raw = format!("let q = r#\"a \" // b\"#; let s = \"{SENTINEL}\";\nlet t = \"{SENTINEL}\";");
    let stripped = strip_comments(&raw);
    assert_eq!(
        stripped.matches(SENTINEL).count(),
        1,
        "the raw-string over-eagerness is no longer bounded to one line; \
         `strip_comments` ate more (or less) than the documented case"
    );
    assert!(
        stripped
            .lines()
            .next()
            .is_some_and(|l| !l.contains(SENTINEL)),
        "documented behaviour: the rest of the line after a stray `//` inside a \
         raw string is suppressed"
    );
    assert!(
        stripped
            .lines()
            .nth(1)
            .is_some_and(|l| l.contains(SENTINEL)),
        "the stray `//` inside a raw string ran past its own newline and ate the \
         FOLLOWING line of real code — that is unbounded over-suppression, and a \
         sentinel that sees less code silently loses detections"
    );
}
