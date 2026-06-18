//! Deterministic source→tree structurer for the verbatim ingest spine.
//!
//! Parses clean markdown/plaintext into a tree of BYTE-EXACT verbatim spans
//! (Tier 1 of the §2 invariant). The LLM never paraphrases; for messy input it
//! supplies boundary strings (`Segmentation`) that we LOCATE verbatim and slice.
//! Every public function is pure (no I/O) and enforces [`verify_verbatim`].

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
    TextMismatch {
        start: usize,
        end: usize,
        expected: String,
        got: String,
    },
    #[error("spans out of order or overlapping at {prev_end} -> {next_start}")]
    OrderOverlap { prev_end: usize, next_start: usize },
    #[error("uncaptured prose in inter-span gap {start}..{end}: {gap:?}")]
    UncapturedProse {
        start: usize,
        end: usize,
        gap: String,
    },
    #[error("empty or whitespace-only paragraph at {start}..{end}")]
    EmptyParagraph { start: usize, end: usize },
    #[error("segmentation boundary not found at/after byte {cursor}: {needle:?}")]
    BoundaryNotFound { cursor: usize, needle: String },
}

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
            .ok_or(StructureError::BadSpan {
                start: span.start,
                end: span.end,
            })?;
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
            return Err(StructureError::OrderOverlap {
                prev_end,
                next_start: span.start,
            });
        }
        // (3) coverage — no uncaptured prose between prev span and this one
        if span.start > prev_end {
            let gap = source
                .get(prev_end..span.start)
                .ok_or(StructureError::BadSpan {
                    start: prev_end,
                    end: span.start,
                })?;
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
                    let (s, e) =
                        heading_content_span(source, range.start, range.end, level as usize);
                    sections.push(StructuredSection {
                        heading: Some(Span {
                            start: s,
                            end: e,
                            text: source[s..e].to_string(),
                        }),
                        paragraphs: Vec::new(),
                    });
                } else {
                    let (s, e) = trim_block(source, range.start, range.end);
                    let para = StructuredParagraph {
                        span: Span {
                            start: s,
                            end: e,
                            text: source[s..e].to_string(),
                        },
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
        sections.insert(
            0,
            StructuredSection {
                heading: None,
                paragraphs: leading,
            },
        );
    }
    if sections.is_empty() {
        sections.push(StructuredSection {
            heading: None,
            paragraphs: Vec::new(),
        });
    }
    StructuredDoc {
        source_text: source.to_string(),
        sections,
    }
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
            span: Span {
                start: block_start,
                end,
                text: source[block_start..end].to_string(),
            },
        });
    }
    StructuredDoc {
        source_text: source.to_string(),
        sections: vec![StructuredSection {
            heading: None,
            paragraphs,
        }],
    }
}

/// Slice an agent [`Segmentation`] into a verbatim [`StructuredDoc`]. Locates each
/// boundary string by the FIRST exact match at/after a forward cursor (handles
/// duplicates + enforces order); never trusts agent-supplied text otherwise.
pub fn slice_segmentation(
    source: &str,
    seg: &Segmentation,
) -> Result<StructuredDoc, StructureError> {
    let mut cursor = 0usize;
    let mut locate = |needle: &str| -> Result<Span, StructureError> {
        let rel =
            source[cursor..]
                .find(needle)
                .ok_or_else(|| StructureError::BoundaryNotFound {
                    cursor,
                    needle: needle.to_string(),
                })?;
        let start = cursor + rel;
        let end = start + needle.len();
        cursor = end;
        Ok(Span {
            start,
            end,
            text: needle.to_string(),
        })
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
        sections.push(StructuredSection {
            heading,
            paragraphs,
        });
    }
    let doc = StructuredDoc {
        source_text: source.to_string(),
        sections,
    };
    verify_verbatim(source, &doc)?;
    Ok(doc)
}

/// Writer-side re-verification (D9). When `extraction.source_text` is present,
/// rebuild a [`StructuredDoc`] from the carried spans and run [`verify_verbatim`]
/// against the original bytes — catching any drift between a paragraph's stored
/// `text` and the span it claims to come from. When `source_text` is absent
/// (Tier 2 HTML/CNXML), this is a no-op: the writer does its own non-empty check.
///
/// Only span-backed paragraphs are re-verified; span-less paragraphs (Tier 2)
/// are skipped, so coverage-checking spans exactly the nodes that carry offsets.
pub fn verify_extraction_verbatim(
    extraction: &crate::document::schema::DocumentExtraction,
) -> Result<(), StructureError> {
    let Some(source) = extraction.source_text.as_deref() else {
        return Ok(());
    };
    let sections = extraction
        .sections
        .iter()
        .map(|sec| StructuredSection {
            heading: sec.heading_span.as_ref().and_then(|sp| {
                source.get(sp.start..sp.end).map(|t| Span {
                    start: sp.start,
                    end: sp.end,
                    text: t.to_string(),
                })
            }),
            paragraphs: sec
                .paragraphs
                .iter()
                .filter_map(|p| {
                    p.span.as_ref().map(|sp| StructuredParagraph {
                        span: Span {
                            start: sp.start,
                            end: sp.end,
                            text: p.text.clone(),
                        },
                    })
                })
                .collect(),
        })
        .collect();
    verify_verbatim(
        source,
        &StructuredDoc {
            source_text: source.to_string(),
            sections,
        },
    )
}

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
                        span: Span {
                            start: s,
                            end: e,
                            text: src[s..e].to_string(),
                        },
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
        assert!(matches!(
            verify_verbatim(src, &d),
            Err(StructureError::TextMismatch { .. })
        ));
    }

    #[test]
    fn rejects_overlap() {
        let src = "alphabeta";
        let d = doc(src, &[(0, 5), (4, 9)]);
        assert!(matches!(
            verify_verbatim(src, &d),
            Err(StructureError::OrderOverlap { .. })
        ));
    }

    #[test]
    fn rejects_uncaptured_prose_in_gap() {
        let src = "alpha DROPPEDWORD beta";
        // capture "alpha" and "beta" but leave "DROPPEDWORD" in the gap
        let d = doc(src, &[(0, 5), (18, 22)]);
        assert!(matches!(
            verify_verbatim(src, &d),
            Err(StructureError::UncapturedProse { .. })
        ));
    }

    #[test]
    fn allows_markup_punctuation_in_gap() {
        let src = "# Title\n\nbody";
        // heading content "Title" (2..7) then body (9..13); gap "# " before and "\n\n" between
        let d = StructuredDoc {
            source_text: src.to_string(),
            sections: vec![StructuredSection {
                heading: Some(Span {
                    start: 2,
                    end: 7,
                    text: "Title".to_string(),
                }),
                paragraphs: vec![StructuredParagraph {
                    span: Span {
                        start: 9,
                        end: 13,
                        text: "body".to_string(),
                    },
                }],
            }],
        };
        assert_eq!(verify_verbatim(src, &d), Ok(()));
    }

    #[test]
    fn rejects_empty_paragraph() {
        let src = "a\n\n   \n\nb";
        let d = doc(src, &[(2, 5)]); // "   " whitespace-only
        assert!(matches!(
            verify_verbatim(src, &d),
            Err(StructureError::EmptyParagraph { .. })
        ));
    }

    #[test]
    fn mid_codepoint_span_errors_not_panics() {
        let src = "β-barrel"; // 'β' is 2 bytes; byte 1 is mid-codepoint
                              // Build the span directly: doc()'s `src[1..8]` would panic at construction,
                              // which is exactly what verify_verbatim must avoid. text is a non-empty
                              // placeholder so the empty-paragraph check passes; get() then returns None
                              // for the mid-codepoint range, so BadSpan fires before any text comparison.
        let d = StructuredDoc {
            source_text: src.to_string(),
            sections: vec![StructuredSection {
                heading: None,
                paragraphs: vec![StructuredParagraph {
                    span: Span {
                        start: 1,
                        end: 8,
                        text: "x".to_string(),
                    },
                }],
            }],
        };
        assert!(matches!(
            verify_verbatim(src, &d),
            Err(StructureError::BadSpan { .. })
        ));
    }
}

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
        assert_eq!(
            d.sections[0].paragraphs[0].span.text,
            "Para one line one.\nstill para one."
        );
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

#[cfg(test)]
mod segmentation_tests {
    use super::*;

    #[test]
    fn locates_boundary_strings_verbatim_in_order() {
        let src = "Intro heading line\nAlpha block text.\nBeta block text.";
        let seg = Segmentation {
            sections: vec![SegSection {
                heading: Some("Intro heading line".to_string()),
                paragraphs: vec![
                    "Alpha block text.".to_string(),
                    "Beta block text.".to_string(),
                ],
            }],
        };
        let d = slice_segmentation(src, &seg).unwrap();
        assert_eq!(
            d.sections[0].heading.as_ref().unwrap().text,
            "Intro heading line"
        );
        assert_eq!(d.sections[0].paragraphs[1].span.text, "Beta block text.");
        // spans are real byte slices ⇒ guard passes
        assert_eq!(verify_verbatim(src, &d), Ok(()));
    }

    #[test]
    fn errors_when_boundary_absent() {
        let src = "only this text";
        let seg = Segmentation {
            sections: vec![SegSection {
                heading: None,
                paragraphs: vec!["MISSING".to_string()],
            }],
        };
        assert!(matches!(
            slice_segmentation(src, &seg),
            Err(StructureError::BoundaryNotFound { .. })
        ));
    }

    #[test]
    fn duplicate_text_resolved_by_forward_cursor() {
        // Plan's `dup\nmiddle\ndup` source has dropped prose ("middle") between the
        // two captured spans, which the Task 3 coverage guard correctly rejects.
        // Use a whitespace-only gap so the scenario is a LEGAL verbatim doc while
        // still exercising the duplicate-forward-cursor discriminator (start 5 != 0).
        let src = "dup\n\ndup";
        let seg = Segmentation {
            sections: vec![SegSection {
                heading: None,
                paragraphs: vec!["dup".to_string(), "dup".to_string()],
            }],
        };
        let d = slice_segmentation(src, &seg).unwrap();
        assert_eq!(d.sections[0].paragraphs[0].span.start, 0);
        assert_eq!(d.sections[0].paragraphs[1].span.start, 5); // the SECOND "dup"
    }
}
