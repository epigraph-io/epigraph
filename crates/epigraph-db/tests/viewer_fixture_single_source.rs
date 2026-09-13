//! The viewer fixture has exactly ONE body, and every other crate re-exports it.
//!
//! # Why this exists
//!
//! `viewer_fixture.rs` was hand-copied into five crates' test trees in two
//! content groups. The duplication was not detected by any gate: each copy is a
//! valid file, each crate's tests pass against its own copy, and a copy that
//! falls behind a migration fails only in the crate that still exercises the
//! stale shape. PR-28 added the same 69 lines to two of the copies by hand,
//! which is how the class was finally noticed.
//!
//! De-duplicating without a ratchet just resets the clock: the next test binary
//! that needs a helper in a crate whose shim does not obviously contain one is
//! one `cp` away from re-forking it. So this asserts the invariant directly.
//!
//! Deliberately NOT a byte-equality check between copies — that is the control
//! for a world where copies are allowed. The invariant here is stronger: there
//! is one body, and the other paths are shims that cannot diverge from it
//! because they contain no fixture code at all.

use std::path::{Path, PathBuf};

/// The one file that may contain fixture bodies.
const CANONICAL: &str = "crates/epigraph-db/tests/viewer_fixture.rs";

/// What a shim must contain to be a shim.
///
/// The `#[path]` needle is the TAIL of the canonical path, not the whole
/// attribute: the `../..` prefix is correct for `crates/<x>/tests/` and would be
/// wrong for a member outside `crates/`, and this lint now walks the whole tree.
/// Matching the tail keeps the invariant ("this file points at the canonical
/// one") without also pinning where the shim may live.
const SHIM_INCLUDE: &str = "epigraph-db/tests/viewer_fixture.rs\"]";
const SHIM_REEXPORT: &str = "pub use canonical::*;";

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/epigraph-db.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root is two levels above crates/epigraph-db")
        .to_path_buf()
}

/// Directory names never worth walking into.
///
/// `target` and the shared `CARGO_TARGET_DIR` hold build output, and `.git`
/// holds object files; none can contain a source copy anyone edits.
///
/// `.claude` is skipped for a different and less obvious reason: it is TRACKED
/// in this repository and is not in `.gitignore`, and the agent harness creates
/// in-repo git worktrees under `.claude/worktrees/<name>/` — each a full second
/// checkout of this workspace, whose own `crates/epigraph-db/tests/`
/// `viewer_fixture.rs` this walk would otherwise report as an offender. That
/// would be a red gate for a legitimate local layout, and the failure message
/// below ("replace the file with a `#[path]` to …") would be wrong advice: a
/// nested checkout's canonical copy is not a re-fork of anything. A ratchet that
/// goes red on a working convention gets weakened, which is how ratchets die.
const SKIP_DIRS: &[&str] = &[".git", ".claude", "target", ".cargo-target", "node_modules"];

/// Every `viewer_fixture.rs` anywhere in the working tree, workspace-relative
/// and sorted.
///
/// Walks the WHOLE tree rather than `crates/*/tests/`. The narrow form was the
/// obvious one and it is wrong for this workspace: `tests/engine-integration`
/// is a workspace member that does not live under `crates/`, so a copy landing
/// there — or under any future member outside `crates/` — would be invisible to
/// the very assertion that claims nothing can diverge. A scanner whose blind
/// spot is exactly where the next copy is most likely to appear is worse than
/// no scanner, because it is believed.
fn fixture_paths() -> Vec<String> {
    let root = workspace_root();
    let mut found = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            // An unreadable directory is not a silent pass: the non-vacuity arm
            // below still has to find the canonical file.
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if !SKIP_DIRS.contains(&name.as_ref()) {
                    stack.push(path);
                }
            } else if name == "viewer_fixture.rs" {
                let rel = path
                    .strip_prefix(&root)
                    .expect("candidate is under the workspace root");
                found.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn the_scanner_finds_the_canonical_file_at_all() {
    // Without this, a wrong root or a renamed file turns every assertion below
    // into a vacuous pass over an empty set — the failure mode this whole batch
    // exists to remove.
    let paths = fixture_paths();
    assert!(
        paths.iter().any(|p| p == CANONICAL),
        "scanner found {paths:?} and not {CANONICAL}; it is looking in the \
         wrong place and every other assertion in this file is vacuous"
    );
}

#[test]
fn only_the_canonical_viewer_fixture_carries_a_body() {
    let root = workspace_root();
    let mut offenders = Vec::new();

    for rel in fixture_paths() {
        if rel == CANONICAL {
            continue;
        }
        let body = std::fs::read_to_string(root.join(&rel)).expect("read a fixture path");
        let is_shim = body.contains(SHIM_INCLUDE) && body.contains(SHIM_REEXPORT);
        // A shim has no fixture code of its own. `pub async fn` is the shape
        // every helper in the canonical file has, so one appearing outside it
        // is a re-fork whatever else the file says.
        let has_own_helpers = body.contains("pub async fn");
        if !is_shim || has_own_helpers {
            offenders.push(rel);
        }
    }

    assert!(
        offenders.is_empty(),
        "\n\nThese viewer_fixture.rs files are not re-export shims:\n  {}\n\n\
         The fixture body lives at {CANONICAL} and nowhere else. A second copy \
         is invisible to every gate in this workspace: it compiles, its own \
         crate's tests pass against it, and it only fails once a migration \
         changes a shape that copy still encodes — in whichever crate happens \
         to exercise it.\n\n\
         Fix: replace the file with a `#[path]` to {CANONICAL} (relative to the \
         offending file), `mod canonical;`, and `{SHIM_REEXPORT}` — copy any \
         existing shim, e.g. crates/epigraph-mcp/tests/viewer_fixture.rs — and \
         move any genuinely new helper into {CANONICAL}, where every crate gets \
         it.\n",
        offenders.join("\n  ")
    );
}
