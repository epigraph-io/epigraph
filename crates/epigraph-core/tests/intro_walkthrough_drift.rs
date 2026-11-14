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
//! The page also quotes values the code decides, which go stale without a
//! renamed name to flag them, so they are pinned too:
//!
//! - each captured dry-run packet's methodology, initial truth and confidence
//!   is what `CommitType::methodology`, `CommitType::initial_truth` and the
//!   parser's confidence table give its commit type;
//! - each inline-code `EPIGRAPH_*` variable is read (`"NAME"`) by
//!   `ingest_git.rs` or the API server's `bin/server.rs`;
//! - the `#N` reference limit ("up to N current claims") is the `limit` that
//!   `find_claims_citing_pr` sends, and the edges' `if_not_exists` is set.
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

/// The text of `src` from `start` up to the first `end` after it.
fn section<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
    let from = src
        .find(start)
        .unwrap_or_else(|| panic!("ingest_git.rs has no `{start}`"));
    let rest = &src[from..];
    let to = rest
        .find(end)
        .unwrap_or_else(|| panic!("no `{end}` after `{start}`"));
    &rest[..to]
}

/// One captured dry-run packet: its commit type, whether it has Verification
/// items, and the methodology, confidence (percent) and initial truth printed.
#[derive(Debug, PartialEq)]
struct Captured {
    commit_type: String,
    has_verification: bool,
    methodology: String,
    confidence_pct: String,
    initial_truth: String,
}

/// The packets in the page's fenced dry-run output.
fn captured_packets(lines: &[String]) -> Vec<Captured> {
    let mut out = Vec::new();
    let mut commit_type = None;
    let mut has_verification = None;
    for line in lines {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Packet ") {
            commit_type = rest
                .split_once("\"[")
                .and_then(|(_, r)| r.split_once(']'))
                .map(|(t, _)| t.to_string());
        } else if let Some((_, v)) = line.split_once("Verification: ") {
            has_verification = v.split_whitespace().next().map(|n| n != "0");
        } else if let Some(rest) = line.strip_prefix("Methodology: ") {
            let fields: Vec<&str> = rest.split(", ").collect();
            let value = |prefix: &str| {
                fields
                    .iter()
                    .find_map(|f| f.strip_prefix(prefix))
                    .map(str::to_string)
            };
            if let (Some(t), Some(v), Some(m), Some(c), Some(i)) = (
                commit_type.take(),
                has_verification.take(),
                fields.first().map(|m| m.to_string()),
                value("confidence: ").map(|c| c.trim_end_matches('%').to_string()),
                value("initial_truth: "),
            ) {
                out.push(Captured {
                    commit_type: t,
                    has_verification: v,
                    methodology: m,
                    confidence_pct: c,
                    initial_truth: i,
                });
            }
        }
    }
    out
}

/// The text of the match arm for `Self::<variant>` in `body`: from its line
/// up to the next line that starts another arm.
fn arm<'a>(body: &'a str, variant: &str) -> Option<&'a str> {
    let pat = format!("Self::{variant}");
    let lines: Vec<&str> = body.lines().collect();
    let start = lines.iter().position(|l| {
        l.match_indices(&pat).any(|(i, _)| {
            !l[i + pat.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
        })
    })?;
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.trim_start().starts_with("Self::"))
        .map_or(lines.len(), |n| start + 1 + n);
    let from = body.find(lines[start])?;
    let to = if end < lines.len() {
        body.find(lines[end]).unwrap_or(body.len())
    } else {
        body.len()
    };
    Some(&body[from..to])
}

/// Float literals (`0.6`) in `text`, in order.
fn floats(text: &str) -> Vec<f64> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter(|w| w.contains('.') && !w.starts_with('.') && !w.ends_with('.'))
        .filter_map(|w| w.parse().ok())
        .collect()
}

fn variant_of(commit_type: &str) -> String {
    let mut c = commit_type.chars();
    c.next()
        .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
        .unwrap_or_default()
}

#[test]
fn the_walkthrough_quotes_only_values_and_limits_the_code_has() {
    let page = read("docs/intro/03-walkthroughs.md");
    let ingest_git = read("crates/epigraph-cli/src/bin/ingest_git.rs");
    let server = read("crates/epigraph-api/src/bin/server.rs");
    let mut wrong = Vec::new();

    // Captured packets: methodology, initial truth, confidence.
    let methodology = section(&ingest_git, "fn methodology(", "fn initial_truth(");
    let initial_truth = section(&ingest_git, "fn initial_truth(", "\n}\n");
    let confidence = section(&ingest_git, "let parser_confidence = match", "};");
    let packets: Vec<Captured> = fenced_blocks(&page)
        .iter()
        .flat_map(|(_, body)| captured_packets(body))
        .collect();
    for p in &packets {
        let variant = variant_of(&p.commit_type);
        match arm(methodology, &variant) {
            Some(a) if a.contains(&format!("\"{}\"", p.methodology)) => {}
            _ => wrong.push(format!(
                "{} packet: methodology {} is not CommitType::{variant}'s",
                p.commit_type, p.methodology
            )),
        }
        let truth: f64 = p.initial_truth.parse().unwrap_or(f64::NAN);
        // An arm with an if/else lists the with-Verification value first.
        let expected = arm(initial_truth, &variant).map(floats).and_then(|f| {
            match (f.as_slice(), p.has_verification) {
                ([v], _) | ([v, _], true) | ([_, v], false) => Some(*v),
                _ => None,
            }
        });
        if !matches!(expected, Some(e) if (e - truth).abs() <= 1e-9) {
            wrong.push(format!(
                "{} packet: initial_truth {} is not CommitType::{variant}'s ({expected:?})",
                p.commit_type, p.initial_truth
            ));
        }
        let pct: f64 = p.confidence_pct.parse().unwrap_or(f64::NAN);
        let row = format!("(false, false, {}) =>", p.has_verification);
        let table = confidence
            .lines()
            .find(|l| l.contains(&row))
            .map(floats)
            .and_then(|f| f.first().copied());
        if !matches!(table, Some(c) if (c * 100.0 - pct).abs() <= 1e-9) {
            wrong.push(format!(
                "{} packet: confidence {}% is not the parser's {row} {table:?}",
                p.commit_type, p.confidence_pct
            ));
        }
    }

    // Environment variables.
    let page_prose = prose(&page);
    let env_vars: Vec<&str> = inline_spans(&page_prose)
        .filter(|s| {
            s.starts_with("EPIGRAPH_") && s.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        })
        .collect();
    for v in &env_vars {
        let lit = format!("\"{v}\"");
        if !ingest_git.contains(&lit) && !server.contains(&lit) {
            wrong.push(format!(
                "{v} is read by neither ingest_git nor the API server"
            ));
        }
    }

    // The `#N` reference limit and the edges' `if_not_exists`.
    let citing = section(&ingest_git, "async fn find_claims_citing_pr(", "\n}\n");
    let limits: Vec<&str> = page
        .match_indices("up to ")
        .filter_map(|(i, m)| {
            let rest = &page[i + m.len()..];
            let n = rest.split(' ').next()?;
            (!n.is_empty()
                && n.chars().all(|c| c.is_ascii_digit())
                && rest[n.len()..].starts_with(" current claims"))
            .then_some(n)
        })
        .collect();
    for n in &limits {
        if !citing.contains(&format!("(\"limit\", \"{n}\")")) {
            wrong.push(format!("the #N limit {n} is not find_claims_citing_pr's"));
        }
    }
    if page.contains("`if_not_exists`") && !ingest_git.contains("\"if_not_exists\": true") {
        wrong.push("ingest_git no longer posts edges with if_not_exists".to_string());
    }

    assert!(
        packets.len() >= 3,
        "expected at least 3 captured packets in the walkthrough, found \
         {packets:?}; the scanner is broken"
    );
    assert!(
        env_vars.len() >= 2,
        "expected at least 2 EPIGRAPH_* variables in the walkthrough, found \
         {env_vars:?}; the scanner is broken"
    );
    assert_eq!(
        limits.len(),
        1,
        "expected one \"up to N current claims\" in the walkthrough; the \
         scanner is broken"
    );
    assert!(
        wrong.is_empty(),
        "docs/intro/03-walkthroughs.md quotes values the code does not give:\n  {}",
        wrong.join("\n  ")
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

    let out: Vec<String> = [
        "Packet 1: \"[feat][api] x\"",
        "  Evidence: 2 item(s), Verification: 0 item(s)",
        "  Methodology: extraction, confidence: 70%, initial_truth: 0.4",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(
        captured_packets(&out),
        vec![Captured {
            commit_type: "feat".into(),
            has_verification: false,
            methodology: "extraction".into(),
            confidence_pct: "70".into(),
            initial_truth: "0.4".into(),
        }]
    );

    let body = "match self {\n    Self::Feat => {\n        if v { 0.6 } else { 0.4 }\n    }\n    Self::Fix | Self::FixUp => 0.7,\n}";
    assert_eq!(arm(body, "Feat").map(floats), Some(vec![0.6, 0.4]));
    assert_eq!(arm(body, "Fix").map(floats), Some(vec![0.7]));
    assert_eq!(arm(body, "Fi"), None);
}
