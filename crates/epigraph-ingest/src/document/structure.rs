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
