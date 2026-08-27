//! Source lint: no request handler may mint an unrestricted `Viewer`.
//!
//! Plan §4.13. `Viewer::system` needs a `MaintenanceLease`, which only
//! `epigraph-db` can construct, so a handler *cannot* build a `Bypass` viewer
//! today — the type system already forbids it. This test exists for the shape
//! of the mistake that comes next: someone adds a lease accessor for a
//! background job (PR-04 does exactly that), and six months later a handler
//! reaches for it to "just make this one query work".
//!
//! It passes trivially right now, at zero hits. That is the correct state for a
//! ratchet at the moment it is installed; its value is entirely in PR-07 and
//! PR-09, when handlers and MCP tools start taking viewers for real.
//!
//! Scope: HTTP route handlers (`epigraph-api/src/routes/`) and MCP tool
//! implementations (`epigraph-mcp/src/tools/`). Both are request-serving code
//! reached by an authenticated (or, before PR-03, unauthenticated) caller.
//! Background jobs, CLI bins and the repo layer are deliberately NOT scanned —
//! a maintenance job holding a lease is the entire point of the mechanism.

#![cfg(feature = "db")]

use std::path::{Path, PathBuf};

/// `(needle, why)`.
const BANNED: &[(&str, &str)] = &[
    (
        "Viewer::system(",
        "An unrestricted Viewer emits no visibility predicate, so this handler \
         would return every tenant's rows to whoever called it. A handler's \
         read authority must come from ViewerExtractor — i.e. from the \
         caller's own credential — never from a constant.",
    ),
    (
        "MaintenanceLease",
        "MaintenanceLease is proof that the caller holds a maintenance-role \
         connection. A request handler runs on the application pool; a lease \
         reaching one means either the proof is being forged or an \
         application request is running with maintenance privileges.",
    ),
];

fn scan_roots() -> Vec<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR is crates/epigraph-api.
    let crates = manifest.parent().expect("crates/ is the parent");
    vec![
        manifest.join("src/routes"),
        crates.join("epigraph-mcp/src/tools"),
    ]
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Drop `//`-style comments so that a doc comment *explaining* why bypass is
/// forbidden does not itself count as a violation. Block comments and string
/// literals are not handled: a `Viewer::system(` inside either is unusual
/// enough that flagging it and making the author restructure is the right
/// outcome.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_handler_or_tool_mints_a_bypass_viewer() {
    let mut files = Vec::new();
    for root in scan_roots() {
        assert!(
            root.is_dir(),
            "scan root {} does not exist — this lint is silently covering \
             nothing. Fix the path.",
            root.display()
        );
        rust_files(&root, &mut files);
    }
    assert!(
        files.len() > 20,
        "only {} files found to scan; the walker is probably broken and this \
         lint is passing vacuously",
        files.len()
    );

    let mut violations = Vec::new();
    for file in &files {
        let src = strip_line_comments(&std::fs::read_to_string(file).expect("readable"));
        for (lineno, line) in src.lines().enumerate() {
            for (needle, why) in BANNED {
                if line.contains(needle) {
                    violations.push(format!(
                        "{}:{}\n    {}\n    `{needle}` — {why}",
                        file.display(),
                        lineno + 1,
                        line.trim(),
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n\nRequest-serving code must not construct an unrestricted Viewer:\n\n{}\n",
        violations.join("\n\n")
    );
}
