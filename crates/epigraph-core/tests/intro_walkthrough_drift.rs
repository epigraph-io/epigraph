//! `docs/intro/03-walkthroughs.md` teaches the commit-ingestion pipeline by
//! quoting its flags, its reconciler config keys and the labels it writes. A
//! quoted name that the code no longer has sends the reader into an
//! `Unknown argument` error or a query that finds nothing, so every such name
//! must exist where the page says it does:
//!
//! - each `--flag` in an `ingest_git` command inside a fenced block, and each
//!   inline-code span in the prose that starts with a `--flag` or with
//!   `ingest_git`, is a `"--flag"` match arm in
//!   `crates/epigraph-cli/src/bin/ingest_git.rs`;
//! - each `key =` line in a fenced `toml` block is a key that
//!   `scripts/git_ingest_reconciler.py::load_config_str` reads
//!   (`data.get("key"`);
//! - each inline-code label of the form `source:git-history` or `node:<kind>`
//!   is a string literal in `ingest_git.rs`.
//!
//! Floors on each count keep a broken scanner from passing on nothing.
//! The scan is std-only, like `doc_links.rs`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Fenced blocks of `text` as `(info string, body lines)`.
fn fenced_blocks(text: &str) -> Vec<(String, Vec<String>)> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(info) = trimmed.strip_prefix("```") {
            match current.take() {
                Some(block) => blocks.push(block),
                None => current = Some((info.trim().to_string(), Vec::new())),
            }
        } else if let Some((_, body)) = current.as_mut() {
            body.push(line.to_string());
        }
    }
    blocks
}

/// `--flags` passed to `ingest_git` in a shell block: from a line whose first
/// word ends in `ingest_git` through its `\` continuation lines.
fn ingest_git_flags(lines: &[String]) -> Vec<String> {
    let mut flags = Vec::new();
    let mut in_command = false;
    for line in lines {
        let first = line.split_whitespace().next().unwrap_or_default();
        if first.ends_with("ingest_git") {
            in_command = true;
        }
        if in_command {
            for word in line.split_whitespace() {
                if let Some(name) = word.strip_prefix("--") {
                    if name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                        flags.push(format!("--{name}"));
                    }
                }
            }
            in_command = line.trim_end().ends_with('\\');
        }
    }
    flags
}

/// The text of `text` outside fenced blocks.
fn prose(text: &str) -> String {
    let mut out = String::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        } else if !fenced {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Inline-code spans of `text` (the odd pieces between backticks).
fn inline_spans(text: &str) -> impl Iterator<Item = &str> {
    text.split('`').skip(1).step_by(2)
}

/// `--flags` named in prose: a span that starts with a flag names that flag,
/// and a span that starts with `ingest_git` names every flag in it.
fn prose_flags(prose: &str) -> Vec<String> {
    let mut flags = Vec::new();
    for span in inline_spans(prose) {
        let mut words = span.split_whitespace();
        let first = words.next().unwrap_or_default();
        if first.starts_with("--") {
            flags.push(first.to_string());
        } else if first.ends_with("ingest_git") {
            flags.extend(words.filter(|w| w.starts_with("--")).map(str::to_string));
        }
    }
    flags
}

/// `key` from each `key = value` line of a TOML block (comments skipped).
fn toml_keys(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.trim().to_string()))
        .filter(|k| !k.is_empty() && !k.contains(' '))
        .collect()
}

/// Inline-code spans that name an ingester label.
fn ingester_labels(text: &str) -> Vec<String> {
    inline_spans(text)
        .filter(|span| *span == "source:git-history" || span.starts_with("node:"))
        .map(str::to_string)
        .collect()
}

#[test]
fn the_walkthrough_quotes_only_flags_keys_and_labels_the_code_has() {
    let page = read("docs/intro/03-walkthroughs.md");
    let ingest_git = read("crates/epigraph-cli/src/bin/ingest_git.rs");
    let reconciler = read("scripts/git_ingest_reconciler.py");

    let blocks = fenced_blocks(&page);
    let mut flags: Vec<String> = blocks
        .iter()
        .filter(|(info, _)| info == "bash")
        .flat_map(|(_, body)| ingest_git_flags(body))
        .collect();
    let block_flags = flags.len();
    flags.extend(prose_flags(&prose(&page)));
    let keys: Vec<String> = blocks
        .iter()
        .filter(|(info, _)| info == "toml")
        .flat_map(|(_, body)| toml_keys(body))
        .collect();
    let labels = ingester_labels(&page);

    let mut missing = Vec::new();
    for f in &flags {
        if !ingest_git.contains(&format!("\"{f}\"")) {
            missing.push(format!("flag {f} is not an ingest_git argument"));
        }
    }
    for k in &keys {
        if !reconciler.contains(&format!("data.get(\"{k}\"")) {
            missing.push(format!("config key {k} is not read by load_config_str"));
        }
    }
    for l in &labels {
        if !ingest_git.contains(&format!("\"{l}\"")) {
            missing.push(format!("label {l} is not written by ingest_git"));
        }
    }

    assert!(
        block_flags >= 10 && flags.len() >= block_flags + 10,
        "expected at least 10 ingest_git flags in the walkthrough's bash blocks \
         and 10 more in its prose, found {flags:?} ({block_flags} in blocks); \
         the scanner is broken"
    );
    assert!(
        keys.len() >= 4,
        "expected at least 4 reconciler config keys in the walkthrough's toml \
         blocks, found {keys:?}; the scanner is broken"
    );
    assert!(
        labels.len() >= 4,
        "expected at least 4 ingester labels in the walkthrough, found \
         {labels:?}; the scanner is broken"
    );
    assert!(
        missing.is_empty(),
        "docs/intro/03-walkthroughs.md quotes names the code does not have:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn the_scanners_pick_out_flags_keys_and_labels() {
    let lines: Vec<String> = [
        "cargo build --release --bin ingest_git",
        "./target/release/ingest_git --pr-ingest \\",
        "  --repo-slug o/r --pr-number 7 \\",
        "  --dry-run",
        "echo --not-a-flag",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(
        ingest_git_flags(&lines),
        vec!["--pr-ingest", "--repo-slug", "--pr-number", "--dry-run"]
    );

    let toml: Vec<String> = ["# comment = no", "repos = [\"o/r\"]", "window_minutes = 60"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(toml_keys(&toml), vec!["repos", "window_minutes"]);

    assert_eq!(
        prose_flags(
            "pass `--token \"$T\"`, run `ingest_git --repo . --limit 1`, \
             not `cargo build --bin x` or `EPIGRAPH_X`"
        ),
        vec!["--token", "--repo", "--limit"]
    );
    assert_eq!(prose("a\n```bash\n`--x`\n```\nb\n"), "a\nb\n");

    assert_eq!(
        ingester_labels("a `node:pr` b `repo:o/r` c `source:git-history` d"),
        vec!["node:pr", "source:git-history"]
    );
}
