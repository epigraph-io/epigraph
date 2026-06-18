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
