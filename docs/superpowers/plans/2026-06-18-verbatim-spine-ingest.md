# Verbatim Spine Ingest — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the hierarchical-ingest spine store verbatim source text (not LLM paraphrase) at section/paragraph nodes, recovering structure deterministically for markdown/plaintext and fencing the LLM to atoms only.

**Architecture:** A new pure-Rust **structurer** (`epigraph-ingest::document::structure`) parses clean markdown/plaintext into a tree of byte-exact verbatim spans and enforces a verbatim guard. The `DocumentExtraction` schema swaps `Paragraph.compound`→`text` (verbatim), drops `Section.summary`/`Paragraph.supporting_text`, and gains optional `source_text` + per-node byte spans so the writer re-verifies. A new `structure_source` MCP tool returns a `DocumentExtraction` with atoms empty; the agent fills atoms and resubmits via `ingest_document_inline`. HTML/CNXML stay on the existing Python emitters (Tier 2: faithful full text, no spans). See spec `docs/superpowers/specs/2026-06-18-deterministic-spine-ingest-design.md`.

**Tech Stack:** Rust (epigraph-ingest, epigraph-mcp, epigraph-embeddings), `pulldown-cmark` (new dep), `blake3`, `uuid` v5, `sqlx`/Postgres test harness, Python 3 (structured-source emitters).

**Two-PR split:**
- **PR1 (Tasks 1–6):** the structurer — pure, additive, no schema change, independently mergeable and green.
- **PR2 (Tasks 7–13):** the schema cascade + writer + tool + Python + skill. The schema migration (Task 7) is one green-to-green commit.

**Conventions for every commit:** follow the Epistemic Commit Protocol (`<type>(<scope>): <claim>` + Evidence/Reasoning/Verification). Run `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` before each Rust commit. End messages with the `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer.

---

# PART 1 — PR1: The structurer (pure, additive)

## Task 1: Add the `pulldown-cmark` dependency

**Files:**
- Modify: `Cargo.toml` (workspace root, `[workspace.dependencies]`)
- Modify: `crates/epigraph-ingest/Cargo.toml` (`[dependencies]`)

- [ ] **Step 1: Add to workspace dependencies**

In the root `Cargo.toml`, under `[workspace.dependencies]`, add (keep alphabetical near other `p*` deps):

```toml
pulldown-cmark = { version = "0.12", default-features = false }
```

- [ ] **Step 2: Reference it from the crate**

In `crates/epigraph-ingest/Cargo.toml`, under `[dependencies]`, add (use the workspace style — NOT blake3's inline outlier):

```toml
pulldown-cmark = { workspace = true }
```

- [ ] **Step 3: Verify it resolves**

Run: `cargo build -p epigraph-ingest`
Expected: compiles (no new code yet); `Cargo.lock` gains `pulldown-cmark`.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/epigraph-ingest/Cargo.toml Cargo.lock
git commit  # chore(ingest): add pulldown-cmark for markdown source-offset parsing
```

---

## Task 2: Structurer types + module registration

**Files:**
- Create: `crates/epigraph-ingest/src/document/structure.rs`
- Modify: `crates/epigraph-ingest/src/document/mod.rs`

- [ ] **Step 1: Create the module with core types**

Create `crates/epigraph-ingest/src/document/structure.rs`:

```rust
//! Deterministic source→tree structurer for the verbatim ingest spine.
//!
//! Parses clean markdown/plaintext into a tree of BYTE-EXACT verbatim spans
//! (Tier 1 of the §2 invariant). The LLM never paraphrases; for messy input it
//! supplies boundary strings (`Segmentation`) that we LOCATE verbatim and slice.
//! Every public function is pure (no I/O) and enforces [`verify_verbatim`].

use std::ops::Range;
use thiserror::Error;

/// A verbatim slice of the source: UTF-8 byte offsets + the exact text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredParagraph {
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredSection {
    /// `None` for a synthesized implicit section (headingless / pre-first-heading body).
    pub heading: Option<Span>,
    pub paragraphs: Vec<StructuredParagraph>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredDoc {
    pub source_text: String,
    pub sections: Vec<StructuredSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    Markdown,
    PlainText,
}

/// Messy-input boundary contract (§5/D2). Offsets are advisory; the authoritative
/// locator is the verbatim boundary string, so an LLM that cannot emit byte-exact
/// offsets still succeeds. Strings are located in order, each searched from the
/// cursor left by the previous match (handles duplicate text + enforces order).
#[derive(Debug, Clone)]
pub struct Segmentation {
    pub sections: Vec<SegSection>,
}

#[derive(Debug, Clone)]
pub struct SegSection {
    /// Verbatim heading text, or `None` for an implicit section.
    pub heading: Option<String>,
    /// Verbatim paragraph block strings, in document order.
    pub paragraphs: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StructureError {
    #[error("span {start}..{end} is not a valid byte slice of the source (off a UTF-8 boundary or out of range)")]
    BadSpan { start: usize, end: usize },
    #[error("span {start}..{end} text mismatch: expected {expected:?}, got {got:?}")]
    TextMismatch { start: usize, end: usize, expected: String, got: String },
    #[error("spans out of order or overlapping at {prev_end} -> {next_start}")]
    OrderOverlap { prev_end: usize, next_start: usize },
    #[error("uncaptured prose in inter-span gap {start}..{end}: {gap:?}")]
    UncapturedProse { start: usize, end: usize, gap: String },
    #[error("empty or whitespace-only paragraph at {start}..{end}")]
    EmptyParagraph { start: usize, end: usize },
    #[error("segmentation boundary not found at/after byte {cursor}: {needle:?}")]
    BoundaryNotFound { cursor: usize, needle: String },
}
```

- [ ] **Step 2: Register the module**

In `crates/epigraph-ingest/src/document/mod.rs`, add `pub mod structure;` (keep the existing `pub use` lines):

```rust
pub mod builder;
pub mod schema;
pub mod structure;
pub use builder::build_ingest_plan;
pub use schema::*;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p epigraph-ingest`
Expected: compiles (unused-code warnings are fine for now).

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-ingest/src/document/structure.rs crates/epigraph-ingest/src/document/mod.rs
git commit  # feat(ingest): add structurer types for the verbatim spine
```

---

## Task 3: The verbatim guard (`verify_verbatim`)

**Files:**
- Modify: `crates/epigraph-ingest/src/document/structure.rs`
- Test: same file (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Append to `structure.rs`:

```rust
#[cfg(test)]
mod guard_tests {
    use super::*;

    fn doc(src: &str, paras: &[(usize, usize)]) -> StructuredDoc {
        StructuredDoc {
            source_text: src.to_string(),
            sections: vec![StructuredSection {
                heading: None,
                paragraphs: paras
                    .iter()
                    .map(|&(s, e)| StructuredParagraph {
                        span: Span { start: s, end: e, text: src[s..e].to_string() },
                    })
                    .collect(),
            }],
        }
    }

    #[test]
    fn accepts_byte_exact_ordered_covered() {
        let src = "alpha\n\nbeta";
        let d = doc(src, &[(0, 5), (7, 11)]); // "alpha", "beta"; gap "\n\n" is whitespace
        assert_eq!(verify_verbatim(src, &d), Ok(()));
    }

    #[test]
    fn rejects_text_mismatch() {
        let src = "alpha\n\nbeta";
        let mut d = doc(src, &[(0, 5)]);
        d.sections[0].paragraphs[0].span.text = "ALPHA".to_string();
        assert!(matches!(verify_verbatim(src, &d), Err(StructureError::TextMismatch { .. })));
    }

    #[test]
    fn rejects_overlap() {
        let src = "alphabeta";
        let d = doc(src, &[(0, 5), (4, 9)]);
        assert!(matches!(verify_verbatim(src, &d), Err(StructureError::OrderOverlap { .. })));
    }

    #[test]
    fn rejects_uncaptured_prose_in_gap() {
        let src = "alpha DROPPEDWORD beta";
        // capture "alpha" and "beta" but leave "DROPPEDWORD" in the gap
        let d = doc(src, &[(0, 5), (18, 22)]);
        assert!(matches!(verify_verbatim(src, &d), Err(StructureError::UncapturedProse { .. })));
    }

    #[test]
    fn allows_markup_punctuation_in_gap() {
        let src = "# Title\n\nbody";
        // heading content "Title" (2..7) then body (9..13); gap "# " before and "\n\n" between
        let d = StructuredDoc {
            source_text: src.to_string(),
            sections: vec![StructuredSection {
                heading: Some(Span { start: 2, end: 7, text: "Title".to_string() }),
                paragraphs: vec![StructuredParagraph {
                    span: Span { start: 9, end: 13, text: "body".to_string() },
                }],
            }],
        };
        assert_eq!(verify_verbatim(src, &d), Ok(()));
    }

    #[test]
    fn rejects_empty_paragraph() {
        let src = "a\n\n   \n\nb";
        let d = doc(src, &[(2, 5)]); // "   " whitespace-only
        assert!(matches!(verify_verbatim(src, &d), Err(StructureError::EmptyParagraph { .. })));
    }

    #[test]
    fn mid_codepoint_span_errors_not_panics() {
        let src = "β-barrel"; // 'β' is 2 bytes (0..2)
        let d = doc(src, &[(1, 8)]); // start 1 is mid-codepoint
        assert!(matches!(verify_verbatim(src, &d), Err(StructureError::BadSpan { .. })));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p epigraph-ingest guard_tests`
Expected: FAIL — `verify_verbatim` not found.

- [ ] **Step 3: Implement `verify_verbatim`**

Add to `structure.rs` (above the test modules):

```rust
/// Max run of consecutive alphanumeric chars allowed in an inter-span gap.
/// Markup punctuation (`#`, `|`, `>`, `-`, list digits) never forms a 3-run;
/// dropped prose ("the cat sat") does — so this catches uncaptured prose
/// without rejecting legitimate markup. (§7.3)
const MAX_GAP_ALNUM_RUN: usize = 3;

/// Enforce the §7 verbatim invariant for one [`StructuredDoc`]. Pure; fail-closed.
pub fn verify_verbatim(source: &str, doc: &StructuredDoc) -> Result<(), StructureError> {
    // Flatten all spans (heading + paragraphs) in document order.
    let mut spans: Vec<&Span> = Vec::new();
    for sec in &doc.sections {
        if let Some(h) = &sec.heading {
            spans.push(h);
        }
        for p in &sec.paragraphs {
            // (4) non-empty
            if p.span.text.trim().is_empty() {
                return Err(StructureError::EmptyParagraph {
                    start: p.span.start,
                    end: p.span.end,
                });
            }
            spans.push(&p.span);
        }
    }

    let mut prev_end = 0usize;
    for span in &spans {
        // (1) byte-exact, fail-closed on bad/mid-codepoint offsets
        let slice = source
            .get(span.start..span.end)
            .ok_or(StructureError::BadSpan { start: span.start, end: span.end })?;
        if slice != span.text {
            return Err(StructureError::TextMismatch {
                start: span.start,
                end: span.end,
                expected: span.text.clone(),
                got: slice.to_string(),
            });
        }
        // (2) ordered + non-overlapping
        if span.start < prev_end {
            return Err(StructureError::OrderOverlap { prev_end, next_start: span.start });
        }
        // (3) coverage — no uncaptured prose between prev span and this one
        if span.start > prev_end {
            let gap = source
                .get(prev_end..span.start)
                .ok_or(StructureError::BadSpan { start: prev_end, end: span.start })?;
            if max_alnum_run(gap) >= MAX_GAP_ALNUM_RUN {
                return Err(StructureError::UncapturedProse {
                    start: prev_end,
                    end: span.start,
                    gap: gap.to_string(),
                });
            }
        }
        prev_end = span.end;
    }
    Ok(())
}

/// Longest run of consecutive `char::is_alphanumeric` chars in `s`.
fn max_alnum_run(s: &str) -> usize {
    let mut max = 0usize;
    let mut cur = 0usize;
    for c in s.chars() {
        if c.is_alphanumeric() {
            cur += 1;
            max = max.max(cur);
        } else {
            cur = 0;
        }
    }
    max
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p epigraph-ingest guard_tests`
Expected: PASS (7 tests). Note: pre-first-span and post-last-span regions are intentionally NOT coverage-checked (title/frontmatter/back-matter are out-of-spine, §7.3).

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-ingest/src/document/structure.rs
git commit  # feat(ingest): add the verbatim guard (byte-exact/order/coverage/non-empty)
```

---

## Task 4: Markdown parser (`parse_structure` for Markdown)

**Files:**
- Modify: `crates/epigraph-ingest/src/document/structure.rs`
- Test: same file

- [ ] **Step 1: Write the failing tests**

Append a `#[cfg(test)] mod markdown_tests`:

```rust
#[cfg(test)]
mod markdown_tests {
    use super::*;

    #[test]
    fn headings_open_sections_blocks_become_paragraphs() {
        let src = "# Intro\n\nFirst para.\n\nSecond para.\n\n## Methods\n\nWe did things.";
        let d = parse_structure(src, SourceFormat::Markdown).unwrap();
        assert_eq!(d.sections.len(), 2);
        assert_eq!(d.sections[0].heading.as_ref().unwrap().text, "Intro");
        assert_eq!(d.sections[0].paragraphs.len(), 2);
        assert_eq!(d.sections[0].paragraphs[0].span.text, "First para.");
        assert_eq!(d.sections[1].heading.as_ref().unwrap().text, "Methods");
        assert_eq!(d.sections[1].paragraphs[0].span.text, "We did things.");
        // the parse must satisfy its own guard
        assert_eq!(verify_verbatim(src, &d), Ok(()));
    }

    #[test]
    fn list_and_code_and_table_are_single_spans_not_rejected() {
        let src = "# H\n\n- a\n- b\n\n```\ncode line\n```\n\n| x | y |\n|---|---|\n| 1 | 2 |";
        let d = parse_structure(src, SourceFormat::Markdown).unwrap();
        assert_eq!(d.sections.len(), 1);
        // list, code block, table => 3 paragraph-spans, each whole-block verbatim
        assert_eq!(d.sections[0].paragraphs.len(), 3);
        assert!(d.sections[0].paragraphs[0].span.text.contains("- a\n- b"));
        assert!(d.sections[0].paragraphs[1].span.text.contains("code line"));
        assert!(d.sections[0].paragraphs[2].span.text.contains("| 1 | 2 |"));
        assert_eq!(verify_verbatim(src, &d), Ok(())); // MUST NOT reject clean markdown
    }

    #[test]
    fn headingless_doc_gets_one_implicit_section() {
        let src = "Just a body paragraph.\n\nAnd another.";
        let d = parse_structure(src, SourceFormat::Markdown).unwrap();
        assert_eq!(d.sections.len(), 1);
        assert!(d.sections[0].heading.is_none());
        assert_eq!(d.sections[0].paragraphs.len(), 2);
        assert_eq!(verify_verbatim(src, &d), Ok(()));
    }

    #[test]
    fn pre_heading_body_kept_in_leading_implicit_section() {
        let src = "Preamble line.\n\n# Real Heading\n\nBody.";
        let d = parse_structure(src, SourceFormat::Markdown).unwrap();
        assert_eq!(d.sections.len(), 2);
        assert!(d.sections[0].heading.is_none());
        assert_eq!(d.sections[0].paragraphs[0].span.text, "Preamble line.");
        assert_eq!(d.sections[1].heading.as_ref().unwrap().text, "Real Heading");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p epigraph-ingest markdown_tests`
Expected: FAIL — `parse_structure` not found.

- [ ] **Step 3: Implement the markdown parser**

Add to `structure.rs`:

```rust
use pulldown_cmark::{Event, Options, Parser, Tag};

/// Parse clean markup into a verbatim [`StructuredDoc`]. Tier 1 (§2).
pub fn parse_structure(source: &str, fmt: SourceFormat) -> Result<StructuredDoc, StructureError> {
    let doc = match fmt {
        SourceFormat::Markdown => parse_markdown(source),
        SourceFormat::PlainText => parse_plaintext(source),
    };
    verify_verbatim(source, &doc)?;
    Ok(doc)
}

fn parse_markdown(source: &str) -> StructuredDoc {
    let mut sections: Vec<StructuredSection> = Vec::new();
    let mut leading: Vec<StructuredParagraph> = Vec::new(); // pre-first-heading blocks
    let mut depth: i32 = 0;

    for (event, range) in Parser::new_ext(source, Options::all()).into_offset_iter() {
        match event {
            Event::Start(tag) if depth == 0 => {
                if let Tag::Heading { level, .. } = tag {
                    let (s, e) = heading_content_span(source, range.start, range.end, level as usize);
                    sections.push(StructuredSection {
                        heading: Some(Span { start: s, end: e, text: source[s..e].to_string() }),
                        paragraphs: Vec::new(),
                    });
                } else {
                    let (s, e) = trim_block(source, range.start, range.end);
                    let para = StructuredParagraph {
                        span: Span { start: s, end: e, text: source[s..e].to_string() },
                    };
                    match sections.last_mut() {
                        Some(sec) => sec.paragraphs.push(para),
                        None => leading.push(para),
                    }
                }
                depth += 1; // consume this block's inner events
            }
            Event::Start(_) => depth += 1,
            Event::End(_) if depth > 0 => depth -= 1,
            _ => {}
        }
    }

    // Headingless or pre-heading body → synthesize a leading implicit section.
    if !leading.is_empty() {
        sections.insert(0, StructuredSection { heading: None, paragraphs: leading });
    }
    if sections.is_empty() {
        sections.push(StructuredSection { heading: None, paragraphs: Vec::new() });
    }
    StructuredDoc { source_text: source.to_string(), sections }
}

/// Heading content range = block range minus leading `#`*level + spaces and
/// trailing whitespace/newline/closing-`#`. Byte-exact; markers fall in the gap.
fn heading_content_span(src: &str, start: usize, end: usize, _level: usize) -> (usize, usize) {
    let b = src.as_bytes();
    let mut s = start;
    while s < end && b[s] == b'#' {
        s += 1;
    }
    while s < end && (b[s] == b' ' || b[s] == b'\t') {
        s += 1;
    }
    let mut e = end;
    while e > s && matches!(b[e - 1], b'\n' | b'\r' | b' ' | b'\t' | b'#') {
        e -= 1;
    }
    (s, e)
}

/// Trim only trailing whitespace/newlines from a block range (leading bytes of a
/// list/code block are significant). Byte offsets stay valid (ASCII trims).
fn trim_block(src: &str, start: usize, end: usize) -> (usize, usize) {
    let b = src.as_bytes();
    let mut e = end;
    while e > start && matches!(b[e - 1], b'\n' | b'\r' | b' ' | b'\t') {
        e -= 1;
    }
    (start, e)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p epigraph-ingest markdown_tests`
Expected: PASS (4 tests). If the list/table test fails on span boundaries, inspect with `cargo test ... -- --nocapture` and adjust `trim_block` (do NOT loosen the guard).

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-ingest/src/document/structure.rs
git commit  # feat(ingest): markdown structurer — headings->sections, blocks->verbatim spans
```

---

## Task 5: Plaintext parser

**Files:**
- Modify: `crates/epigraph-ingest/src/document/structure.rs`
- Test: same file

- [ ] **Step 1: Write the failing test**

Append `#[cfg(test)] mod plaintext_tests`:

```rust
#[cfg(test)]
mod plaintext_tests {
    use super::*;

    #[test]
    fn splits_on_blank_lines_one_implicit_section() {
        let src = "Para one line one.\nstill para one.\n\nPara two.";
        let d = parse_structure(src, SourceFormat::PlainText).unwrap();
        assert_eq!(d.sections.len(), 1);
        assert!(d.sections[0].heading.is_none());
        assert_eq!(d.sections[0].paragraphs.len(), 2);
        assert_eq!(d.sections[0].paragraphs[0].span.text, "Para one line one.\nstill para one.");
        assert_eq!(d.sections[0].paragraphs[1].span.text, "Para two.");
        assert_eq!(verify_verbatim(src, &d), Ok(()));
    }

    #[test]
    fn collapses_blank_runs_and_trims() {
        let src = "a\n\n\n\nb\n\n";
        let d = parse_structure(src, SourceFormat::PlainText).unwrap();
        assert_eq!(d.sections[0].paragraphs.len(), 2);
        assert_eq!(d.sections[0].paragraphs[0].span.text, "a");
        assert_eq!(d.sections[0].paragraphs[1].span.text, "b");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p epigraph-ingest plaintext_tests`
Expected: FAIL — `parse_plaintext` not found.

- [ ] **Step 3: Implement the plaintext parser**

Add to `structure.rs`:

```rust
/// Split plaintext on blank-line boundaries into verbatim paragraph spans under
/// one implicit section. Block = maximal run of non-blank lines; byte offsets are
/// tracked exactly and trailing whitespace trimmed.
fn parse_plaintext(source: &str) -> StructuredDoc {
    let mut paragraphs: Vec<StructuredParagraph> = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();
    while i < n {
        // skip blank/whitespace lines to the start of a block
        while i < n && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= n {
            break;
        }
        let block_start = i;
        // advance to a blank-line boundary ("\n\n", tolerating spaces) or EOF
        let mut last_nonws = i;
        while i < n {
            if bytes[i] == b'\n' {
                // look ahead: is the next line blank?
                let mut j = i + 1;
                while j < n && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\r') {
                    j += 1;
                }
                if j >= n || bytes[j] == b'\n' {
                    break; // blank line ⇒ end of block
                }
            }
            if !bytes[i].is_ascii_whitespace() {
                last_nonws = i;
            }
            i += 1;
        }
        let end = last_nonws + 1; // inclusive of last non-ws byte
        paragraphs.push(StructuredParagraph {
            span: Span { start: block_start, end, text: source[block_start..end].to_string() },
        });
    }
    StructuredDoc {
        source_text: source.to_string(),
        sections: vec![StructuredSection { heading: None, paragraphs }],
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p epigraph-ingest plaintext_tests`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-ingest/src/document/structure.rs
git commit  # feat(ingest): plaintext structurer — blank-line blocks as verbatim spans
```

---

## Task 6: `slice_segmentation` (messy fallback)

**Files:**
- Modify: `crates/epigraph-ingest/src/document/structure.rs`
- Test: same file

- [ ] **Step 1: Write the failing tests**

Append `#[cfg(test)] mod segmentation_tests`:

```rust
#[cfg(test)]
mod segmentation_tests {
    use super::*;

    #[test]
    fn locates_boundary_strings_verbatim_in_order() {
        let src = "Intro heading line\nAlpha block text.\nBeta block text.";
        let seg = Segmentation {
            sections: vec![SegSection {
                heading: Some("Intro heading line".to_string()),
                paragraphs: vec!["Alpha block text.".to_string(), "Beta block text.".to_string()],
            }],
        };
        let d = slice_segmentation(src, &seg).unwrap();
        assert_eq!(d.sections[0].heading.as_ref().unwrap().text, "Intro heading line");
        assert_eq!(d.sections[0].paragraphs[1].span.text, "Beta block text.");
        // spans are real byte slices ⇒ guard passes
        assert_eq!(verify_verbatim(src, &d), Ok(()));
    }

    #[test]
    fn errors_when_boundary_absent() {
        let src = "only this text";
        let seg = Segmentation {
            sections: vec![SegSection { heading: None, paragraphs: vec!["MISSING".to_string()] }],
        };
        assert!(matches!(
            slice_segmentation(src, &seg),
            Err(StructureError::BoundaryNotFound { .. })
        ));
    }

    #[test]
    fn duplicate_text_resolved_by_forward_cursor() {
        let src = "dup\nmiddle\ndup";
        let seg = Segmentation {
            sections: vec![SegSection {
                heading: None,
                paragraphs: vec!["dup".to_string(), "dup".to_string()],
            }],
        };
        let d = slice_segmentation(src, &seg).unwrap();
        assert_eq!(d.sections[0].paragraphs[0].span.start, 0);
        assert_eq!(d.sections[0].paragraphs[1].span.start, 11); // the SECOND "dup"
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p epigraph-ingest segmentation_tests`
Expected: FAIL — `slice_segmentation` not found.

- [ ] **Step 3: Implement `slice_segmentation`**

Add to `structure.rs`:

```rust
/// Slice an agent [`Segmentation`] into a verbatim [`StructuredDoc`]. Locates each
/// boundary string by the FIRST exact match at/after a forward cursor (handles
/// duplicates + enforces order); never trusts agent-supplied text otherwise.
pub fn slice_segmentation(source: &str, seg: &Segmentation) -> Result<StructuredDoc, StructureError> {
    let mut cursor = 0usize;
    let mut locate = |needle: &str| -> Result<Span, StructureError> {
        let rel = source[cursor..]
            .find(needle)
            .ok_or_else(|| StructureError::BoundaryNotFound { cursor, needle: needle.to_string() })?;
        let start = cursor + rel;
        let end = start + needle.len();
        cursor = end;
        Ok(Span { start, end, text: needle.to_string() })
    };

    let mut sections = Vec::with_capacity(seg.sections.len());
    for s in &seg.sections {
        let heading = match &s.heading {
            Some(h) => Some(locate(h)?),
            None => None,
        };
        let mut paragraphs = Vec::with_capacity(s.paragraphs.len());
        for p in &s.paragraphs {
            paragraphs.push(StructuredParagraph { span: locate(p)? });
        }
        sections.push(StructuredSection { heading, paragraphs });
    }
    let doc = StructuredDoc { source_text: source.to_string(), sections };
    verify_verbatim(source, &doc)?;
    Ok(doc)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p epigraph-ingest segmentation_tests`
Expected: PASS (3 tests).

- [ ] **Step 5: Full-crate gate + commit**

Run: `cargo fmt --all && cargo clippy -p epigraph-ingest --all-targets -- -D warnings && cargo test -p epigraph-ingest`
Expected: clean; all structurer tests pass.

```bash
git add crates/epigraph-ingest/src/document/structure.rs
git commit  # feat(ingest): slice_segmentation — verbatim messy-input fallback by boundary match
```

**→ PR1 is complete and green. Open it as a standalone PR; it is additive and changes no existing behavior.**

---

# PART 2 — PR2: Schema cascade + writer + tool + Python + skill

## Task 7: Schema migration (one atomic green-to-green commit)

This task changes the `DocumentExtraction` schema and every in-repo consumer/fixture together, because a Rust field rename/removal breaks the crate and the `epigraph-mcp` smoke fixtures atomically. Do NOT commit partway.

**Files:**
- Modify: `crates/epigraph-ingest/src/document/schema.rs`
- Modify: `crates/epigraph-ingest/src/document/builder.rs`
- Modify: `crates/epigraph-ingest/tests/structured_source_glue.rs`
- Modify fixtures/inline JSON: `crates/epigraph-ingest/src/lib.rs`, `crates/epigraph-ingest/tests/integration.rs`, `crates/epigraph-ingest/tests/fixtures/sample_hierarchical.json`, `crates/epigraph-mcp/tests/ingest_document_smoke.rs`

- [ ] **Step 1: Update the glue test FIRST to assert verbatim node content (will not compile yet)**

In `crates/epigraph-ingest/tests/structured_source_glue.rs`, replace the `.compound`/`.supporting_text` references (lines ~65, 77, 129, 134) with `.text`. Concretely:
- `:65` `assert!(!p.compound.is_empty(), "compound is required + non-empty");` → `assert!(!p.text.is_empty(), "verbatim text is required + non-empty");`
- `:77` `.map(|p| p.supporting_text.clone())` → `.map(|p| p.text.clone())`
- `:129` `.any(|p| p.supporting_text.contains("[equation]"))` → `.any(|p| p.text.contains("[equation]"))`
- `:134` `.supporting_text` → `.text`

- [ ] **Step 2: Change the schema**

In `crates/epigraph-ingest/src/document/schema.rs`:

(a) Add a `ByteSpan` type:

```rust
/// A byte-offset span into `DocumentExtraction.source_text` (D9). Optional on
/// each node; when present, the writer re-verifies the node text against it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}
```

(b) Add `source_text` to `DocumentExtraction` (after `relationships`):

```rust
    #[serde(default)]
    pub relationships: Vec<ClaimRelationship>,
    /// Original source bytes the spans index into (D9). Present ⇒ the writer
    /// re-runs the verbatim guard. Tier 2 (HTML/CNXML) omits it.
    #[serde(default)]
    pub source_text: Option<String>,
}
```

(c) `Section`: remove `summary`, add `heading_span`:

```rust
pub struct Section {
    pub title: String,
    #[serde(default)]
    pub heading_span: Option<ByteSpan>,
    #[serde(default)]
    pub paragraphs: Vec<Paragraph>,
}
```

(d) `Paragraph`: rename `compound`→`text`, remove `supporting_text`, add `span`:

```rust
pub struct Paragraph {
    /// Verbatim source text (Tier 1) or faithful full extraction (Tier 2).
    pub text: String,
    #[serde(default)]
    pub span: Option<ByteSpan>,
    #[serde(default)]
    pub atoms: Vec<String>,
    #[serde(default)]
    pub generality: Vec<i32>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default)]
    pub methodology: Option<String>,
    #[serde(default)]
    pub evidence_type: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub instruments_used: Vec<String>,
    #[serde(default)]
    pub reagents_involved: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<String>,
}
```

- [ ] **Step 3: Update `builder.rs`**

In `crates/epigraph-ingest/src/document/builder.rs`:

(a) Thesis ID seed (line ~49) — path-qualify:
```rust
let id = compound_claim_id(&hash, &format!("{doc_title}\u{1f}thesis"));
```

(b) Section (lines ~77–95): use `title`, path-qualified seed, drop `summary`; add `spine_text_kind`:
```rust
let section_hash = content_hash(&section.title);
let section_id = compound_claim_id(&section_hash, &format!("{doc_title}\u{1f}{section_path}"));
// ...
claims.push(PlannedClaim {
    id: section_id,
    content: section.title.clone(),
    level: 1,
    properties: serde_json::json!({
        "level": 1,
        "source_type": source_type,
        "section": section.title,
        "spine_text_kind": spine_text_kind(extraction),
    }),
    content_hash: section_hash,
    confidence: 1.0,
    methodology: None,
    evidence_type: None,
    supporting_text: None,
    enrichment: serde_json::json!({}),
});
```

(c) Paragraph (lines ~106–137): use `text`, path-qualified seed, drop `supporting_text` from properties, set `supporting_text: Some(paragraph.text.clone())` and `spine_text_kind`:
```rust
let para_hash = content_hash(&paragraph.text);
let para_id = compound_claim_id(&para_hash, &format!("{doc_title}\u{1f}{para_path}"));
// ...
claims.push(PlannedClaim {
    id: para_id,
    content: paragraph.text.clone(),
    level: 2,
    properties: serde_json::json!({
        "level": 2,
        "source_type": source_type,
        "section": section.title,
        "spine_text_kind": spine_text_kind(extraction),
    }),
    content_hash: para_hash,
    confidence: paragraph.confidence,
    methodology: paragraph.methodology.clone(),
    evidence_type: para_evidence_type.clone(),
    supporting_text: Some(paragraph.text.clone()),
    enrichment: enrichment.clone(),
});
```

(d) Atom (line ~167): `supporting_text: Some(paragraph.text.clone()),`

(e) Add the tier helper near the top of `builder.rs`:
```rust
/// Tier stamp (§2). Tier 1 (verbatim_v2) when the extraction carries source_text
/// AND this is span-backed; else Tier 2 (extracted_v2, e.g. Python HTML/CNXML).
fn spine_text_kind(extraction: &DocumentExtraction) -> &'static str {
    if extraction.source_text.is_some() {
        "verbatim_v2"
    } else {
        "extracted_v2"
    }
}
```
(Import `DocumentExtraction` is already in scope via `crate::document::schema`.)

- [ ] **Step 4: Update Bucket-B fixtures + inline JSON**

In each of these, change `"compound":` → `"text":` and DELETE every `"supporting_text": …` and `"summary": …` key:
- `crates/epigraph-ingest/src/lib.rs` — inline test JSON (around lines 28–30, 124–129, 257–259).
- `crates/epigraph-ingest/tests/integration.rs` — inline JSON (line ~14) + assertions referencing thesis/levels stay valid.
- `crates/epigraph-ingest/tests/fixtures/sample_hierarchical.json` — `summary` (lines 19, 39), `compound` (22, 42, 54), `supporting_text` (23, 43, 55). Hand-edit: rename compound→text with the FULL text value, delete summary + supporting_text.
- `crates/epigraph-mcp/tests/ingest_document_smoke.rs` — `FIXTURE` (lines 27/29/30), `FIXTURE_OVERLAP`, `make_chapter` (199–202), and the two `serde_json::json!` fixtures (413–420, 467–477).

Because `text` is now serde-required (no default), any JSON still using `"compound"` fails to parse — so this step is mandatory for tests to pass.

- [ ] **Step 5: Build + test the cascade green**

Run: `cargo build -p epigraph-ingest -p epigraph-mcp`
Expected: compiles.
Run: `cargo test -p epigraph-ingest && cargo test -p epigraph-mcp --test ingest_document_smoke`
Expected: PASS. If a smoke assertion counted claims by old field names, it still counts nodes — adjust only literal `compound`/`summary` strings, not counts.

- [ ] **Step 6: fmt + clippy + commit (atomic)**

Run: `cargo fmt --all && cargo clippy -p epigraph-ingest -p epigraph-mcp --all-targets -- -D warnings`

```bash
git add crates/epigraph-ingest/src/document/schema.rs crates/epigraph-ingest/src/document/builder.rs \
        crates/epigraph-ingest/tests/structured_source_glue.rs crates/epigraph-ingest/src/lib.rs \
        crates/epigraph-ingest/tests/integration.rs crates/epigraph-ingest/tests/fixtures/sample_hierarchical.json \
        crates/epigraph-mcp/tests/ingest_document_smoke.rs
git commit  # feat(ingest): verbatim paragraph/section nodes; path-seeded IDs; source_text+spans
```
Commit message Evidence must note: paragraph node content was `compound` (LLM paraphrase); now `text` (verbatim). Reasoning: path-folded seed prevents duplicate-heading UUID collisions; `relationships[]` resolution unaffected because `path_index` keys are unchanged.

---

## Task 8: Writer — version bump, re-verify guard, embed truncation

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/ingestion.rs`
- Modify: `crates/epigraph-ingest/src/document/structure.rs` (add `verify_extraction_verbatim`)
- Modify: `crates/epigraph-mcp/src/embed.rs`
- Test: `crates/epigraph-mcp/tests/ingest_document_smoke.rs`

- [ ] **Step 1: Add the extraction-level guard to `structure.rs`**

```rust
use crate::document::schema::DocumentExtraction;

/// Writer-side re-verification (D9). When `extraction.source_text` is present,
/// rebuild a `StructuredDoc` from the carried spans and run [`verify_verbatim`].
/// When absent (Tier 2), this is a no-op — the writer does its own non-empty check.
pub fn verify_extraction_verbatim(extraction: &DocumentExtraction) -> Result<(), StructureError> {
    let Some(source) = extraction.source_text.as_deref() else {
        return Ok(());
    };
    let sections = extraction
        .sections
        .iter()
        .map(|sec| StructuredSection {
            heading: sec.heading_span.as_ref().and_then(|sp| {
                source.get(sp.start..sp.end).map(|t| Span { start: sp.start, end: sp.end, text: t.to_string() })
            }),
            paragraphs: sec
                .paragraphs
                .iter()
                .filter_map(|p| {
                    p.span.as_ref().map(|sp| StructuredParagraph {
                        span: Span { start: sp.start, end: sp.end, text: p.text.clone() },
                    })
                })
                .collect(),
        })
        .collect();
    verify_verbatim(source, &StructuredDoc { source_text: source.to_string(), sections })
}
```

- [ ] **Step 2: Write the failing writer test**

In `ingest_document_smoke.rs`, add a test that submits an extraction whose paragraph `span` text does NOT match `source_text`, and asserts the ingest is rejected:

```rust
#[sqlx::test(migrations = "../../migrations")]
async fn writer_rejects_span_text_drift(pool: PgPool) {
    let server = make_server(pool);
    let extraction: DocumentExtraction = serde_json::from_value(serde_json::json!({
        "source": { "title": "Drift Doc", "doi": "10.1/drift" },
        "thesis": "t",
        "sections": [{
            "title": "S",
            "paragraphs": [{ "text": "TAMPERED", "span": { "start": 0, "end": 5 }, "atoms": ["a"] }]
        }],
        "source_text": "alpha beta"
    })).unwrap();
    let err = do_ingest_document(&server, &extraction).await;
    assert!(err.is_err(), "drift between span and source_text must be rejected");
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p epigraph-mcp --test ingest_document_smoke writer_rejects_span_text_drift`
Expected: FAIL — ingest currently succeeds (no guard).

- [ ] **Step 4: Bump version + call the guard in `do_ingest_document`**

In `ingestion.rs`:
- Change `const PIPELINE_VERSION_BASE: &str = "hierarchical_extraction_v1";` → `"hierarchical_extraction_v2";`
- At the top of `do_ingest_document` (right after the signature, before `build_ingest_plan`), add:
```rust
epigraph_ingest::document::structure::verify_extraction_verbatim(extraction)
    .map_err(|e| invalid_params(format!("verbatim guard failed: {e}")))?;
```
(Use the existing `invalid_params` helper already imported in this file.)

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p epigraph-mcp --test ingest_document_smoke writer_rejects_span_text_drift`
Expected: PASS. Also run the whole smoke file: `cargo test -p epigraph-mcp --test ingest_document_smoke` → PASS (existing fixtures have no `source_text`, so the guard is a no-op for them).

- [ ] **Step 6: Wire embed-input truncation in `embed.rs`**

In `crates/epigraph-mcp/src/embed.rs`, in `generate` (lines ~70–79), truncate the input to the model limit before the API call, using the existing tokenizer:
```rust
pub async fn generate(&self, text: &str) -> Result<Vec<f32>, String> {
    let api_key = self.api_key.as_deref()
        .filter(|k| !k.is_empty() && *k != "mock")
        .ok_or_else(|| "embeddings disabled (no API key)".to_string())?;
    // Truncate the EMBEDDING INPUT only; the stored claim content stays full verbatim.
    let truncated = epigraph_embeddings::tokenizer::truncate_to_tokens(
        text,
        epigraph_embeddings::config::DEFAULT_MAX_TOKENS,
    );
    generate_openai_embedding_with_model(&self.http, api_key, &truncated, "text-embedding-3-small").await
}
```
Verify the exact function/const names in `crates/epigraph-embeddings/src/tokenizer.rs` and `config.rs` (`DEFAULT_MAX_TOKENS = 8191`); if the truncation fn has a different name (e.g. `Tokenizer::new(...).truncate(...)`), adapt the call. Add `epigraph-embeddings` to `epigraph-mcp/Cargo.toml` deps if not already present (it is — `McpEmbedder` lives there).

- [ ] **Step 7: Add a truncation unit test**

In `embed.rs` `#[cfg(test)]`, assert a > 8191-token string truncates to ≤ limit tokens (call the tokenizer directly; no network).

- [ ] **Step 8: fmt + clippy + commit**

Run: `cargo fmt --all && cargo clippy -p epigraph-mcp -p epigraph-ingest --all-targets -- -D warnings`
```bash
git add crates/epigraph-mcp/src/tools/ingestion.rs crates/epigraph-ingest/src/document/structure.rs \
        crates/epigraph-mcp/src/embed.rs crates/epigraph-mcp/tests/ingest_document_smoke.rs
git commit  # feat(mcp): writer re-verifies verbatim spans; v2 version gate; embed-input truncation
```

---

## Task 9: Update inline tool schema description

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs`
- Test: `crates/epigraph-mcp/tests/ingest_document_smoke.rs` (existing `inline_tool_wire_schema_is_self_contained`)

- [ ] **Step 1: Update the `IngestDocumentInlineParams` description (types.rs ~844–850)**

Replace the `#[schemars(description = "…")]` string so it documents the new shape: "each paragraph has **text** (verbatim), optional **span** {start,end}, atoms, generality, confidence, methodology, evidence_type; each section has title + optional heading_span; the top-level extraction may carry **source_text** for writer-side verbatim re-verification." Remove the words `compound`, `supporting_text`, `summary`.

- [ ] **Step 2: Run the wire-schema tests**

Run: `cargo test -p epigraph-mcp --test ingest_document_smoke inline_tool_wire_schema_is_self_contained inline_params_expose_hierarchical_json_schema`
Expected: PASS — the derived JSON schema now reflects `text`/`span`/`source_text` with resolvable `$defs` (incl. `ByteSpan`).

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-mcp/src/types.rs
git commit  # docs(mcp): inline ingest schema description tracks the verbatim shape
```

---

## Task 10: The `structure_source` MCP tool

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/ingestion.rs` (add `structure_source` fn + a builder that maps `StructuredDoc`→`DocumentExtraction`)
- Modify: `crates/epigraph-mcp/src/types.rs` (params)
- Modify: `crates/epigraph-mcp/src/server.rs` (register)
- Modify: `crates/epigraph-mcp/src/scope_map.rs` (scope)
- Test: `crates/epigraph-mcp/tests/structure_source_smoke.rs` (new)

- [ ] **Step 1: Add params type to `types.rs`**

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StructureSourceParams {
    #[schemars(description = "Raw source text to structure into a verbatim section/paragraph tree.")]
    pub text: String,
    #[schemars(description = "Document source metadata (title, doi/uri, source_type, authors, year, …) — same shape as DocumentExtraction.source.")]
    pub source: epigraph_ingest::schema::DocumentSource,
    #[schemars(description = "Format of `text`: \"markdown\" or \"plaintext\". Determines the deterministic parser.")]
    pub format: String,
    #[schemars(description = "Optional messy-input boundary segmentation: per-section heading + verbatim paragraph block strings, located in order. When present, overrides deterministic parsing.")]
    #[serde(default)]
    pub segmentation: Option<epigraph_ingest::document::structure::SegmentationWire>,
}
```
(Define a small `Serialize/Deserialize/JsonSchema` mirror `SegmentationWire { sections: Vec<SegSectionWire> }` / `SegSectionWire { heading: Option<String>, paragraphs: Vec<String> }` in `structure.rs` and a `From<SegmentationWire> for Segmentation`, since the internal `Segmentation` doesn't derive serde.)

- [ ] **Step 2: Add the mapper + tool fn to `ingestion.rs`**

```rust
use epigraph_ingest::document::structure::{parse_structure, slice_segmentation, SourceFormat, StructuredDoc};
use epigraph_ingest::schema::{ByteSpan, DocumentExtraction, Paragraph, Section};

/// Map a verbatim `StructuredDoc` into a `DocumentExtraction` with atoms EMPTY.
/// The agent fills `atoms` per paragraph and resubmits via ingest_document_inline.
fn structured_doc_to_extraction(doc: StructuredDoc, source: epigraph_ingest::schema::DocumentSource) -> DocumentExtraction {
    let sections = doc.sections.into_iter().map(|s| Section {
        title: s.heading.as_ref().map(|h| h.text.clone()).unwrap_or_default(),
        heading_span: s.heading.map(|h| ByteSpan { start: h.start, end: h.end }),
        paragraphs: s.paragraphs.into_iter().map(|p| Paragraph {
            text: p.span.text,
            span: Some(ByteSpan { start: p.span.start, end: p.span.end }),
            atoms: Vec::new(),
            generality: Vec::new(),
            confidence: 0.8,
            methodology: Some("verbatim_structurer".to_string()),
            evidence_type: None,
            page: None,
            instruments_used: Vec::new(),
            reagents_involved: Vec::new(),
            conditions: Vec::new(),
        }).collect(),
    }).collect();
    DocumentExtraction {
        source,
        thesis: None,
        thesis_derivation: Default::default(),
        sections,
        relationships: Vec::new(),
        source_text: Some(doc.source_text),
    }
}

pub async fn structure_source(
    _server: &EpiGraphMcpFull,
    params: StructureSourceParams,
) -> Result<CallToolResult, McpError> {
    let doc = if let Some(seg) = params.segmentation {
        slice_segmentation(&params.text, &seg.into())
            .map_err(|e| invalid_params(format!("segmentation failed: {e}")))?
    } else {
        let fmt = match params.format.as_str() {
            "markdown" => SourceFormat::Markdown,
            "plaintext" => SourceFormat::PlainText,
            other => return Err(invalid_params(format!("unknown format {other:?}; use markdown|plaintext"))),
        };
        parse_structure(&params.text, fmt).map_err(|e| invalid_params(format!("structuring failed: {e}")))?
    };
    let extraction = structured_doc_to_extraction(doc, params.source);
    let json = serde_json::to_string(&extraction).map_err(internal_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
}
```
(Reuse whatever `Content::text(...)`/`CallToolResult::success(...)` constructors the other tools in this file use — match the existing return style.)

- [ ] **Step 3: Register the tool in `server.rs`**

Inside the `#[tool_router] impl EpiGraphMcpFull` block:
```rust
#[tool(
    description = "Deterministically structure raw markdown/plaintext into a verbatim DocumentExtraction (sections + paragraphs as byte-exact source slices, source_text + spans populated, atoms EMPTY). Fill atoms per paragraph and resubmit via ingest_document_inline. Read-only / no DB writes."
)]
async fn structure_source(
    &self,
    Parameters(params): Parameters<StructureSourceParams>,
) -> Result<CallToolResult, McpError> {
    tools::ingestion::structure_source(self, params).await
}
```
(No `reject_if_read_only()` — it does not write.)

- [ ] **Step 4: Add the scope mapping in `scope_map.rs`**

In `SCOPE_MAP`, in the `claims:read` bucket (alphabetical), add:
```rust
("structure_source", "claims:read"),
```

- [ ] **Step 5: Write the tool test**

Create `crates/epigraph-mcp/tests/structure_source_smoke.rs`:
```rust
// harness mirrors ingest_document_smoke.rs make_server/result_text
#[sqlx::test(migrations = "../../migrations")]
async fn structures_markdown_into_verbatim_extraction(pool: PgPool) {
    let server = make_server(pool);
    let params = StructureSourceParams {
        text: "# Intro\n\nAlpha para.\n\nBeta para.".to_string(),
        source: serde_json::from_value(serde_json::json!({ "title": "Doc", "doi": "10.1/x" })).unwrap(),
        format: "markdown".to_string(),
        segmentation: None,
    };
    let result = structure_source(&server, params).await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&result_text(&result)).unwrap();
    assert_eq!(json["sections"][0]["title"], "Intro");
    assert_eq!(json["sections"][0]["paragraphs"][0]["text"], "Alpha para.");
    assert!(json["sections"][0]["paragraphs"][0]["atoms"].as_array().unwrap().is_empty());
    assert_eq!(json["source_text"], "# Intro\n\nAlpha para.\n\nBeta para.");
}
```
Plus a `#[test] every_registered_tool_has_a_scope`-style check already exists in `scope_map.rs`; run it.

- [ ] **Step 6: Run, fmt, clippy**

Run: `cargo test -p epigraph-mcp --test structure_source_smoke && cargo test -p epigraph-mcp scope_map`
Expected: PASS — including the scope-coverage tests (`every_registered_tool_has_a_scope`, `scope_map_has_no_stale_entries`).
Run: `cargo fmt --all && cargo clippy -p epigraph-mcp --all-targets -- -D warnings`

- [ ] **Step 7: Commit**

```bash
git add crates/epigraph-mcp/src/tools/ingestion.rs crates/epigraph-mcp/src/types.rs \
        crates/epigraph-mcp/src/server.rs crates/epigraph-mcp/src/scope_map.rs \
        crates/epigraph-mcp/tests/structure_source_smoke.rs crates/epigraph-ingest/src/document/structure.rs
git commit  # feat(mcp): add structure_source tool — verbatim DocumentExtraction with empty atoms
```

---

## Task 11: Python emitters → verbatim Tier 2

**Files:**
- Modify: `scripts/lib/document_extraction.py`
- Modify: `scripts/extract_html.py`
- Modify: `scripts/extract_textbook.py`
- Modify: `scripts/tests/test_structured_source_parsers.py`
- Regenerate: `crates/epigraph-ingest/tests/fixtures/sample_arxiv_extraction.json`, `sample_openstax_extraction.json` (self-heal)

- [ ] **Step 1: Update the test assertions first (red)**

In `scripts/tests/test_structured_source_parsers.py`:
- `:31` `assert p["compound"].strip(), "compound required + non-empty"` → `assert p["text"].strip(), "verbatim text required + non-empty"`
- `:56` and `:94` `p["supporting_text"]` → `p["text"]`

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest scripts/tests/test_structured_source_parsers.py -q`
Expected: FAIL — KeyError `text` (parsers still emit `compound`).

- [ ] **Step 3: Update `document_extraction.py`**

In `ParagraphOut` (lines ~98–121): rename field `compound: str` → `text: str`; delete `supporting_text: str = ""`. In `to_dict` (`:107–108`): emit `"text": self.text`; delete the `"supporting_text"` line. In `SectionOut` (`:129`, `:135`): delete `summary` field + `"summary"` emission. Delete now-dead `_COMPOUND_MAX` (`:60`) and `first_sentence` (`:63–77`).

- [ ] **Step 4: Update `extract_html.py` (Tier 2: full text, no first_sentence)**

In `html_to_document_extraction` (lines ~231–235): delete `summary=...`; replace `compound=first_sentence(s.text)` + `supporting_text=s.text` with a single `text=s.text` (the FULL recovered section text). Keep `methodology="structured_html_parse"`. Do NOT emit `source_text`/spans (Tier 2 has none).

- [ ] **Step 5: Update `extract_textbook.py`**

In `_module_to_section` (lines ~285–311): for each block, replace `compound=first_sentence(...)` + `supporting_text=<full>` with `text=<full>` (`text`, `stmt`, or `block.get("text","")` respectively); delete the section `summary=...` (`:310`). Keep `methodology="textbook_assertion"`. CNXML parser otherwise unchanged (retained, not retired).

- [ ] **Step 6: Run + regenerate goldens**

Run: `python -m pytest scripts/tests/test_structured_source_parsers.py -q`
Expected: PASS — and the test rewrites `sample_arxiv_extraction.json` + `sample_openstax_extraction.json` (they self-heal; do not hand-edit).

- [ ] **Step 7: Verify the regenerated goldens still ingest**

Run: `cargo test -p epigraph-ingest --test structured_source_glue`
Expected: PASS — the glue test now reads `p.text`; the regenerated goldens carry `text`, no `summary`/`supporting_text`. (`sample_hierarchical.json` was already fixed in Task 7.)

- [ ] **Step 8: Commit**

```bash
git add scripts/lib/document_extraction.py scripts/extract_html.py scripts/extract_textbook.py \
        scripts/tests/test_structured_source_parsers.py \
        crates/epigraph-ingest/tests/fixtures/sample_arxiv_extraction.json \
        crates/epigraph-ingest/tests/fixtures/sample_openstax_extraction.json
git commit  # feat(ingest): Python HTML/CNXML emitters emit verbatim `text` (Tier 2, no paraphrase)
```

---

## Task 12: Rewrite the `extract-claims` skill

**Files:**
- Modify: `.claude/skills/extract-claims/SKILL.md`

- [ ] **Step 1: Replace the 4-stage cascade**

Rewrite so the flow is: **(1) Structure** — call `structure_source(text, source, format)` for clean markdown/plaintext (it returns a `DocumentExtraction` with verbatim sections/paragraphs + `source_text` + spans, atoms empty); for messy text, supply a `segmentation` of verbatim boundary strings. **(2) Atomize** — for each returned paragraph's verbatim `text`, decompose into atoms (single S-P-O propositions) with generality + evidence_type + cross-atom relationships; write them into that paragraph's `atoms`. **(3) Thesis** — verbatim abstract span if present, else `BottomUp` synthesis flagged via `thesis_derivation`. **(4) Submit** — `ingest_document_inline(extraction)`; the writer re-verifies the spans.

- [ ] **Step 2: Remove the compound concept**

Delete "Stage 2: Paragraph-Level Compound Extraction" and every mention of `compound`/`supporting_text`/`summary`. Re-aim the Council-of-Critics at: (a) atom faithfulness to the verbatim paragraph, (b) no atom invents content absent from `text`. Update the JSON example to the new shape (`text`, optional `span`, `atoms`, no `compound`/`summary`/`supporting_text`).

- [ ] **Step 3: Sanity-check references**

Grep the file: `grep -nE 'compound|supporting_text|summary' .claude/skills/extract-claims/SKILL.md` → expect no matches except possibly in a "removed in v2" note.

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/extract-claims/SKILL.md
git commit  # docs(skill): extract-claims structures verbatim then atomizes (no paragraph paraphrase)
```

---

## Task 13: End-to-end acceptance test (no live LLM)

**Files:**
- Test: `crates/epigraph-mcp/tests/verbatim_spine_e2e.rs` (new)

- [ ] **Step 1: Write the acceptance test**

```rust
// harness: make_server / result_text mirror ingest_document_smoke.rs
#[sqlx::test(migrations = "../../migrations")]
async fn structure_then_ingest_yields_verbatim_spine(pool: PgPool) {
    let server = make_server(pool.clone());
    let src = "# Intro\n\nAlpha is a fact.\n\n## Body\n\nBeta follows alpha.";

    // 1) structure
    let sp = StructureSourceParams {
        text: src.to_string(),
        source: serde_json::from_value(serde_json::json!({ "title": "E2E", "doi": "10.1/e2e" })).unwrap(),
        format: "markdown".to_string(),
        segmentation: None,
    };
    let structured = structure_source(&server, sp).await.unwrap();
    let mut extraction: DocumentExtraction =
        serde_json::from_str(&result_text(&structured)).unwrap();

    // 2) inject canned atoms (stands in for the LLM atomizer — Approach C)
    extraction.sections[0].paragraphs[0].atoms = vec!["Alpha is a fact".to_string()];
    extraction.sections[1].paragraphs[0].atoms = vec!["Beta follows alpha".to_string()];

    // 3) ingest inline; writer re-verifies the threaded source_text+spans
    let result = ingest_document_inline(&server, IngestDocumentInlineParams { extraction }).await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&result_text(&result)).unwrap();
    let paper_id = uuid::Uuid::parse_str(json["paper_id"].as_str().unwrap()).unwrap();

    // 4a) paragraph node content is byte-equal to the source paragraph
    let para = sqlx::query_scalar!(
        "SELECT content FROM claims WHERE paper_id IS NOT DISTINCT FROM $1 AND properties->>'level' = '2' ORDER BY content LIMIT 1",
        Some(paper_id)
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(para, "Alpha is a fact."); // verbatim, includes the period; NOT an atom/paraphrase

    // 4b) tier stamp + spine edges
    let kind: Option<String> = sqlx::query_scalar(
        "SELECT properties->>'spine_text_kind' FROM claims WHERE properties->>'level'='2' LIMIT 1"
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(kind.as_deref(), Some("verbatim_v2"));
    let follows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'section_follows'"
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(follows, 1);
}
```
(Adjust the exact SQL column/table names to the migrations — verify against `ingest_document_smoke.rs`'s own queries, which this test should mirror.)

- [ ] **Step 2: Run**

Run: `cargo test -p epigraph-mcp --test verbatim_spine_e2e`
Expected: PASS — proves the §2 Tier-1 invariant end to end (paragraph node = verbatim source, not a paraphrase), the tier stamp, and the deterministic spine.

- [ ] **Step 3: Full gate + commit**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p epigraph-ingest -p epigraph-mcp`
Expected: green.

```bash
git add crates/epigraph-mcp/tests/verbatim_spine_e2e.rs
git commit  # test(mcp): e2e — structure_source -> inline ingest yields a verbatim spine
```

**→ PR2 complete.**

---

## Self-review (run before opening PR2)

1. **Spec coverage:** D1 (markdown/plaintext parser + segmentation) → Tasks 4/5/6; D2 (offset-segmenter, byte offsets) → Task 6 + guard; D3 (hybrid: Rust structure + agent atoms) → Tasks 10/12/13; D4 (verbatim heading, no summary) → Tasks 4/7; D5 (thesis verbatim-first) → Task 12; D6 (drop compound/supporting_text) → Task 7; D7/migration (v2 gate) → Task 8; D8 (workflow out of scope) → untouched; D9 (source_text+spans, writer re-verify) → Tasks 7/8/10; D10 (HTML→Python, md/plaintext→Rust) → Tasks 1–6/11. §7 guard → Task 3. §10 embed limit → Task 8. Two-tier §2 + `spine_text_kind` → Tasks 7/13.
2. **Placeholder scan:** none — every code step shows code; fixture edits cite exact lines.
3. **Type consistency:** `Span{start,end,text}`, `ByteSpan{start,end}`, `StructuredDoc/Section/Paragraph`, `Segmentation`/`SegSection` (+ `SegmentationWire`/`SegSectionWire` mirrors), `parse_structure`/`slice_segmentation`/`verify_verbatim`/`verify_extraction_verbatim`, `spine_text_kind` — names used consistently across Tasks 2–13.

## Known follow-ups (out of scope — do NOT do here)
- True byte-spans for HTML/CNXML (Tier 1 promotion of the Python paths).
- Corpus backfill to v2 (supersede v1 spine + null embeddings in one txn).
- The `workflow`/`Step.compound` path (symmetric change).
