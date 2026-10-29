//! Every crate under `crates/` is a workspace member (backlog 3caeb71f).
//!
//! A crate in the workspace `exclude` list is never built by
//! `cargo check --workspace`, never linted and never tested by CI, so it
//! rots unverified while still looking like part of the tree. That is how
//! `epigraph-harvester` became ~1,600 lines of Rust nothing compiled. The
//! rule pinned here: a directory under `crates/` that carries a `Cargo.toml`
//! is listed in `[workspace] members`, and the workspace excludes nothing. A
//! crate that should not be built is deleted (git history keeps it), not
//! excluded.
//!
//! The manifest is read as text, not through a TOML parser, so this test adds
//! no dependency and does not move the lockfile.

use std::collections::BTreeSet;
use std::path::Path;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// The quoted entries of the `key = [ ... ]` array inside `[workspace]`.
/// `None` when the key is absent.
fn workspace_array(manifest: &str, key: &str) -> Option<Vec<String>> {
    let ws = manifest
        .split("\n[")
        .find(|section| section.starts_with("[workspace]") || section.starts_with("workspace]"))
        .expect("root Cargo.toml has a [workspace] table");
    let start = ws
        .lines()
        .position(|l| l.trim_start().starts_with(&format!("{key} =")))?;
    let mut entries = Vec::new();
    for line in ws.lines().skip(start) {
        let code = line.split('#').next().unwrap_or("");
        let mut rest = code;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else { break };
            entries.push(after[..close].to_string());
            rest = &after[close + 1..];
        }
        if code.contains(']') {
            break;
        }
    }
    Some(entries)
}

/// Every `crates/<name>` directory that holds a `Cargo.toml`.
fn crate_dirs() -> BTreeSet<String> {
    let crates = Path::new(ROOT).join("crates");
    std::fs::read_dir(&crates)
        .unwrap_or_else(|e| panic!("read {}: {e}", crates.display()))
        .flatten()
        .filter(|e| e.path().join("Cargo.toml").is_file())
        .map(|e| format!("crates/{}", e.file_name().to_string_lossy()))
        .collect()
}

#[test]
fn every_crate_directory_is_a_workspace_member_and_nothing_is_excluded() {
    let manifest = std::fs::read_to_string(Path::new(ROOT).join("Cargo.toml"))
        .expect("read the root Cargo.toml");
    let members: BTreeSet<String> = workspace_array(&manifest, "members")
        .expect("[workspace] declares members")
        .into_iter()
        .collect();

    // Calibration: the parser found the real list, so an empty difference
    // below means "every crate is a member", not "nothing was read".
    for known in [
        "crates/epigraph-core",
        "crates/epigraph-db",
        "crates/epigraph-api",
    ] {
        assert!(
            members.contains(known),
            "the members parser missed {known}; read {members:?}"
        );
    }

    let dirs = crate_dirs();
    assert!(
        dirs.len() > 10,
        "expected the workspace's crates, found {dirs:?}"
    );
    let outside: Vec<&String> = dirs.difference(&members).collect();
    assert!(
        outside.is_empty(),
        "crates under crates/ that are not workspace members, so no `cargo check --workspace` \
         or CI run ever builds them: {outside:?}. Add them to [workspace] members or delete them."
    );

    let excluded = workspace_array(&manifest, "exclude").unwrap_or_default();
    assert!(
        excluded.is_empty(),
        "[workspace] exclude lists {excluded:?}: an excluded crate is never built or tested. \
         Delete it instead (git history keeps it)."
    );
}
