//! Every `#[ignore]`d test in the workspace runs in a CI lane (backlog 4ae8f96c).
//!
//! No plain `cargo test` runs an ignored test, so an `#[ignore]` that no CI
//! step passes `--ignored` for is a test nothing ever executes: it rots while
//! still reading as coverage. Before this ratchet the workspace held thirteen
//! such tests (perspectival suites waiting on a seed directory, operator
//! harnesses, production-scale tests, and two scans of a sibling repository at
//! a developer machine's path); 4290a51c showed what that costs, an ignored
//! suite that had silently stopped matching the code.
//!
//! The rule pinned here: an `#[ignore]` attribute on a test under a workspace
//! member's `src/` or `tests/` is allowed only when [`REGISTER`] names it
//! together with the workflow step that runs it with `--ignored`, and that step
//! still exists. Everything else is one of:
//!
//! - a `#[sqlx::test]` (fresh migrated database) or a plain test over a
//!   committed fixture, so it runs in every gate;
//! - an operator tool that asserts nothing, moved to the crate's `examples/`
//!   (still compiled by `cargo test` and `clippy --all-targets`);
//! - registered below, with its lane.
//!
//! The scan is textual: every attribute (a trimmed line starting with `#[`,
//! joined with the lines after it until its brackets balance, since rustfmt
//! wraps a long `#[cfg_attr(..., ignore = "...")]` so its first line is a bare
//! `#[cfg_attr(`) that is `#[ignore...]` or a `cfg_attr` naming `ignore`, then
//! the next `fn` name. Comment lines start with `//`, so a doc comment that
//! mentions `#[ignore]` is not an attribute.
//!
//! CI selection: test-shard.py runs this target on a change to any member's
//! `src/` (WALKERS), not on every test-only change; a new `#[ignore]` in a test
//! file is caught by the next full run (main, staging, `ci:full`).

use std::path::{Path, PathBuf};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// Where an ignored test runs.
struct Lane {
    /// Workflow file, relative to the repository root.
    workflow: &'static str,
    /// Substrings that ONE step of that workflow (its `- name:` block,
    /// environment and `run:` included) must all contain.
    step_contains: &'static [&'static str],
}

/// One registered ignored test: (file relative to the root, test fn, lane).
struct Entry {
    file: &'static str,
    test: &'static str,
    lane: Lane,
}

const SCALE_LANE: Lane = Lane {
    workflow: ".github/workflows/scale-advisory.yml",
    step_contains: &[
        "EPIGRAPH_BACKFILL_SCALE:",
        "-p epigraph-cli",
        "--test operator_backfill_ingest_markers_scale",
        "--ignored",
    ],
};

/// Every `#[ignore]`d test in the workspace and the lane that runs it.
const REGISTER: &[Entry] = &[
    // Production-scale (~1.25M edges, tens of minutes): too slow for every run.
    Entry {
        file: "crates/epigraph-cli/tests/operator_backfill_ingest_markers_scale.rs",
        test: "every_census_statement_finishes_at_production_scale",
        lane: SCALE_LANE,
    },
    Entry {
        file: "crates/epigraph-cli/tests/operator_backfill_ingest_markers_scale.rs",
        test: "the_backfill_and_its_reversal_finish_at_production_scale",
        lane: SCALE_LANE,
    },
];

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

/// The subdirectories of a workspace member that hold tests. (A constant, not
/// `join("tests")`: test-shard.py reads a bare `join("<top-level dir>")` in a
/// walker as a read of that whole top-level directory.)
const MEMBER_SUBDIRS: [&str; 2] = ["src", "tests"];

/// The `src/` and `tests/` of every workspace member: each `crates/<name>`
/// (workspace_layout.rs pins that every one is a member) and
/// `tests/engine-integration`.
fn scanned_files(root: &Path) -> Vec<PathBuf> {
    let mut members: Vec<PathBuf> = std::fs::read_dir(root.join("crates"))
        .expect("read crates/")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    members.push(root.join("tests/engine-integration"));
    let mut files = Vec::new();
    for m in members {
        for sub in MEMBER_SUBDIRS {
            rust_files(&m.join(sub), &mut files);
        }
    }
    files.sort();
    files
}

/// Net bracket depth of `line` (`[`/`(` open, `]`/`)` close), not counting
/// brackets inside string literals.
fn bracket_delta(line: &str) -> i32 {
    let mut depth = 0;
    let mut in_str = false;
    let mut escaped = false;
    for c in line.chars() {
        if in_str {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// Every attribute on `lines`: (index of its last line, its text with the
/// lines it spans joined by spaces). An attribute starts on a trimmed line
/// beginning `#[` and runs until its brackets balance.
fn attributes(lines: &[&str]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[") {
            let mut text = String::new();
            let mut depth = 0;
            loop {
                let l = lines[i].trim();
                depth += bracket_delta(l);
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(l);
                if depth <= 0 || i + 1 == lines.len() {
                    break;
                }
                i += 1;
            }
            out.push((i, text));
        }
        i += 1;
    }
    out
}

/// Whether a (joined) attribute marks its item ignored.
fn is_ignore_attribute(attr: &str) -> bool {
    attr.starts_with("#[ignore") || (attr.starts_with("#[cfg_attr(") && attr.contains("ignore"))
}

/// The name of the test under each ignore attribute on `lines`.
fn ignored_fns(lines: &[&str]) -> Vec<String> {
    attributes(lines)
        .into_iter()
        .filter(|(_, attr)| is_ignore_attribute(attr))
        .map(|(end, _)| {
            next_fn_name(lines[end + 1..].iter().copied())
                .unwrap_or_else(|| format!("<no fn after line {}>", end + 1))
        })
        .collect()
}

/// The name of the first `fn` declared on `lines` (attributes and blank lines
/// before it are skipped).
fn next_fn_name<'a>(lines: impl Iterator<Item = &'a str>) -> Option<String> {
    for line in lines {
        let t = line.trim_start();
        let t = t.strip_prefix("pub ").unwrap_or(t);
        let t = t.strip_prefix("async ").unwrap_or(t);
        if let Some(rest) = t.strip_prefix("fn ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            return Some(name);
        }
    }
    None
}

/// (file relative to the root, test fn) for every ignore attribute.
fn ignored_tests(root: &Path, files: &[PathBuf]) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for f in files {
        let text =
            std::fs::read_to_string(f).unwrap_or_else(|e| panic!("read {}: {e}", f.display()));
        let rel = f
            .strip_prefix(root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        let lines: Vec<&str> = text.lines().collect();
        for name in ignored_fns(&lines) {
            found.push((rel.clone(), name));
        }
    }
    found
}

/// The `- name:` blocks of a workflow, each with everything up to the next.
fn steps(workflow: &str) -> Vec<&str> {
    workflow.split("- name:").skip(1).collect()
}

#[test]
fn every_ignored_test_is_registered_with_a_lane() {
    let root = PathBuf::from(ROOT);
    let files = scanned_files(&root);
    // Non-vacuity: the walk reached the workspace's sources.
    assert!(
        files.len() > 500,
        "scanned only {} .rs files under {}: the walk is broken",
        files.len(),
        root.display()
    );
    let found = ignored_tests(&root, &files);

    let unregistered: Vec<String> = found
        .iter()
        .filter(|(file, test)| !REGISTER.iter().any(|e| e.file == file && e.test == test))
        .map(|(file, test)| format!("  {file}::{test}"))
        .collect();
    assert!(
        unregistered.is_empty(),
        "#[ignore]d tests that no CI lane runs (no plain `cargo test` executes them):\n{}\n\
         Convert each to a `#[sqlx::test]` or a test over a committed fixture so it runs in \
         every gate; or, if it asserts nothing, move it to the crate's examples/; or add it to \
         REGISTER in {} with the workflow step that passes --ignored for it.",
        unregistered.join("\n"),
        file!()
    );

    let stale: Vec<String> = REGISTER
        .iter()
        .filter(|e| !found.iter().any(|(f, t)| f == e.file && t == e.test))
        .map(|e| format!("  {}::{}", e.file, e.test))
        .collect();
    assert!(
        stale.is_empty(),
        "REGISTER names tests that are no longer #[ignore]d (or no longer exist); remove them:\n{}",
        stale.join("\n")
    );
}

#[test]
fn every_registered_lane_still_runs_its_tests() {
    let root = PathBuf::from(ROOT);
    for e in REGISTER {
        let path = root.join(e.lane.workflow);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("{}::{}: read {}: {err}", e.file, e.test, path.display()));
        assert!(
            steps(&text)
                .iter()
                .any(|step| e.lane.step_contains.iter().all(|s| step.contains(s))),
            "{}::{}: no step of {} contains all of {:?}; the lane that ran this ignored test is gone",
            e.file,
            e.test,
            e.lane.workflow,
            e.lane.step_contains
        );
    }
}

#[test]
fn the_scan_sees_attributes_and_not_comments() {
    // One source line per element: written as `\`-continued string lines,
    // the attribute lines would start with `#[ignore` in THIS file and trip the
    // workspace scan above.
    let lines = [
        "/// A doc line mentioning #[ignore] is not an attribute.",
        "// #[ignore = \"commented out\"]",
        "#[tokio::test]",
        "#[ignore = \"reason\"]",
        "async fn ignored_one() {}",
        "#[test]",
        "fn plain() {}",
        "#[cfg_attr(not(feature = \"x\"), ignore)]",
        "#[test]",
        "pub fn conditionally_ignored() {}",
        // rustfmt's wrapping of a long conditional ignore: the first line is a
        // bare `#[cfg_attr(`, and the reason holds brackets of its own.
        "#[cfg_attr(",
        "    not(feature = \"some_quite_long_feature_name_here\"),",
        "    ignore = \"needs a service [CI has none) that is long enough to wrap\"",
        ")]",
        "#[tokio::test]",
        "async fn wrapped_conditional_ignore() {}",
        // A wrapped attribute that is not an ignore.
        "#[cfg_attr(",
        "    feature = \"some_quite_long_feature_name_here\",",
        "    allow(clippy::too_many_lines)",
        ")]",
        "#[test]",
        "fn wrapped_but_not_ignored() {}",
    ];
    assert_eq!(
        ignored_fns(&lines),
        [
            "ignored_one",
            "conditionally_ignored",
            "wrapped_conditional_ignore"
        ]
    );
}
