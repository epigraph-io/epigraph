//! The tenancy entry points moved into the service crate (backlog 30133ca8)
//! are DEFINED there and nowhere else: every front end reaches them through
//! `epigraph_service::ctx`, re-exported where a front end kept its old path.
//!
//! A second definition in a front end is how the two copies would drift: the
//! refusal triple in `author_write_authority` is the whole safety argument of
//! an author-stamped write, and a copy that skipped one refusal would stamp a
//! session with an empty writable set. This scan fails on any `fn` of these
//! names under any workspace crate's `src/` other than the service crate's
//! `src/ctx.rs`.

use std::path::{Path, PathBuf};

/// The functions only `crates/epigraph-service/src/ctx.rs` may define.
const SERVICE_ONLY: &[&str] = &[
    "begin_author_stamped_tx",
    "begin_author_stamped_tx_for",
    "author_write_authority",
    "resolve_claim_visibility",
];

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Each `fn <name>` definition of a [`SERVICE_ONLY`] name in `text`, by name.
fn definitions(text: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    for name in SERVICE_ONLY {
        let needle = format!("fn {name}");
        for (at, _) in text.match_indices(&needle) {
            let next = text[at + needle.len()..].chars().next();
            // `fn begin_author_stamped_tx` must not also count
            // `fn begin_author_stamped_tx_for`.
            if next.is_some_and(|c| c == '(' || c == '<' || c.is_whitespace()) {
                found.push(*name);
            }
        }
    }
    found
}

#[test]
fn the_service_crate_holds_the_only_definitions() {
    let root = crates_root();
    let mut files = Vec::new();
    for krate in std::fs::read_dir(&root).expect("read crates/") {
        rust_files(&krate.expect("crate dir").path().join("src"), &mut files);
    }
    assert!(files.len() > 200, "the scan saw only {} files", files.len());

    let home = root.join("epigraph-service/src/ctx.rs");
    let mut at_home = Vec::new();
    let mut elsewhere = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source");
        for name in definitions(&text) {
            if *file == home {
                at_home.push(name);
            } else {
                elsewhere.push(format!("{}: fn {name}", file.display()));
            }
        }
    }
    at_home.sort_unstable();
    let mut expected = SERVICE_ONLY.to_vec();
    expected.sort_unstable();
    assert_eq!(
        at_home, expected,
        "epigraph-service/src/ctx.rs defines each of these exactly once"
    );
    assert!(
        elsewhere.is_empty(),
        "a second definition outside the service crate (re-export the service crate's \
         instead):\n{}",
        elsewhere.join("\n")
    );
}

#[test]
fn the_definition_scan_tells_the_two_helpers_apart() {
    assert_eq!(
        definitions("pub async fn begin_author_stamped_tx<'p>(\n"),
        vec!["begin_author_stamped_tx"]
    );
    assert_eq!(
        definitions("pub async fn begin_author_stamped_tx_for<'p>(\n"),
        vec!["begin_author_stamped_tx_for"]
    );
    assert!(definitions("begin_author_stamped_tx(server, a, \"t\")").is_empty());
}

/// `Ctx::seed_agent_id_for_tests` sets the process's own agent, which every
/// stdio write authors as, so its `test-support` feature must never reach a
/// normal build: a crate may enable it only under `[dev-dependencies]`.
/// (`epigraph-db` keeps its viewer fixture `#[cfg(test)]` for the same reason:
/// a feature switched on in a dependent's build graph reaches production.)
///
/// Verified by planting `epigraph-service = { workspace = true, features =
/// ["test-support"] }` in a `[dependencies]` table: it fails.
#[test]
fn the_test_support_feature_is_enabled_by_dev_dependencies_only() {
    let workspace = crates_root().join("..");
    let mut manifests = vec![workspace.join("Cargo.toml")];
    for group in ["crates", "tests"] {
        let Ok(entries) = std::fs::read_dir(workspace.join(group)) else {
            continue;
        };
        for entry in entries {
            let manifest = entry.expect("entry").path().join("Cargo.toml");
            if manifest.is_file() {
                manifests.push(manifest);
            }
        }
    }
    assert!(manifests.len() > 15, "saw {} manifests", manifests.len());
    let mut offenders = Vec::new();
    for manifest in &manifests {
        let text = std::fs::read_to_string(manifest).expect("read manifest");
        let mut section = String::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                section = trimmed.to_string();
                continue;
            }
            let code = trimmed.split('#').next().unwrap_or("");
            // An inline dependency entry or a `[features]` entry that names
            // both the crate and the feature. (A `[dependencies.epigraph-service]`
            // table with `features` on its own line is not read; none exists.)
            if code.contains("epigraph-service")
                && code.contains("test-support")
                && !section.ends_with("dev-dependencies]")
            {
                offenders.push(format!("{} {section}: {trimmed}", manifest.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "epigraph-service's test-support is enabled outside [dev-dependencies]:\n{}",
        offenders.join("\n")
    );
}
