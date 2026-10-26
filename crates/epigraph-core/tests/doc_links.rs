//! Every relative link in the onboarding path must resolve to a file in the
//! repository.
//!
//! The onboarding path is `README.md` plus the numbered `docs/intro/` tree a
//! new reader follows in order. A relative link there that points at a file
//! nobody wrote renders as a 404 on GitHub at exactly the step the reader was
//! sent to — `README.md` once listed `docs/intro/03-walkthroughs.md`, which
//! never existed, between `02-concepts` and `04-glossary`.
//!
//! Scope is deliberately narrow: `docs/superpowers/` holds plans and specs
//! that name files *to be created* and absolute paths on a developer's
//! machine, so they are not reader-facing links and are not scanned.
//!
//! The scan is std-only (no regex dev-dependency): it finds every inline
//! `](target)` link, skips external (`http:`, `https:`, `mailto:`) and pure
//! in-page (`#anchor`) targets, strips a `#fragment` and an optional
//! `"title"`, and resolves the rest against the directory of the file that
//! contains the link.
//!
//! Known limits, acceptable while the scope is README + `docs/intro/` (widen
//! the scanner before widening the scope): reference-style definitions
//! (`[x]: path`) are not checked; `](` inside fenced blocks or inline code is
//! scanned as a link; a target containing `)` is cut at the first `)`; a
//! root-absolute target (`/docs/...`) is not resolved against the repo root;
//! and on a case-insensitive filesystem a wrong-case target passes locally.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The reader-facing onboarding files: `README.md` and `docs/intro/*.md`.
fn onboarding_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = vec![root.join("README.md")];
    let intro = root.join("docs/intro");
    let mut intro_files: Vec<PathBuf> = std::fs::read_dir(&intro)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", intro.display()))
        .map(|entry| entry.expect("docs/intro entry").path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "md"))
        .collect();
    intro_files.sort();
    files.extend(intro_files);
    files
}

/// Relative link targets in `text`, with any `#fragment` and `"title"`
/// removed. External and pure-anchor targets are not returned.
fn relative_link_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("](") {
        let after = &rest[start + 2..];
        let Some(end) = after.find(')') else { break };
        let raw = after[..end].trim();
        rest = &after[end + 1..];

        // `[x](<path with spaces>)` and `[x](path "title")`.
        let target = if let Some(inner) = raw.strip_prefix('<') {
            inner.split('>').next().unwrap_or_default()
        } else {
            raw.split_whitespace().next().unwrap_or_default()
        };
        if target.is_empty()
            || target.starts_with('#')
            || target.starts_with("http:")
            || target.starts_with("https:")
            || target.starts_with("mailto:")
        {
            continue;
        }
        let path = target.split('#').next().unwrap_or_default();
        if !path.is_empty() {
            targets.push(path.to_string());
        }
    }
    targets
}

#[test]
fn every_relative_link_in_the_onboarding_path_resolves() {
    let root = repo_root();
    let mut broken = Vec::new();
    let mut checked = 0usize;
    let mut readme_intro_links = 0usize;

    for file in onboarding_files() {
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let base = file.parent().expect("file has a parent directory");
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string();
        for target in relative_link_targets(&text) {
            checked += 1;
            if shown == "README.md" && target.starts_with("docs/intro/") {
                readme_intro_links += 1;
            }
            if !base.join(&target).exists() {
                broken.push(format!("{shown} -> {target}"));
            }
        }
    }

    // Guard against a scanner that silently finds nothing: README.md lists
    // the intro tree, and the intro files cross-link heavily.
    assert!(
        readme_intro_links >= 4,
        "expected README.md to link at least 4 docs/intro/ files, the scan found \
         {readme_intro_links}; the link scanner is broken"
    );
    assert!(
        checked >= 40,
        "expected at least 40 relative links across the onboarding path, the \
         scan found {checked}; the link scanner is broken"
    );
    assert!(
        broken.is_empty(),
        "relative links in the onboarding path point at files that do not exist:\n  {}",
        broken.join("\n  ")
    );
}

#[test]
fn the_link_scanner_extracts_and_filters_targets() {
    let text = "see [a](docs/a.md), [b](../b.md#section \"Title\"), \
                [c](https://example.com/c.md), [d](#anchor), \
                [e](mailto:x@example.com), [f](<dir with space/f.md>)";
    assert_eq!(
        relative_link_targets(text),
        vec!["docs/a.md", "../b.md", "dir with space/f.md"]
    );
}
