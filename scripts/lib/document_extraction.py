"""Map structured-source parser output to the live hierarchical DocumentExtraction JSON.

This is the net-new glue for backlog b5518801. The fetch/parse layer
(extract_html.py, extract_textbook.py) recovers source structure
(title/authors/sections/paragraphs/supporting_text). This module maps that
recovered structure onto the schema the live MCP `ingest_document` tool parses:
`epigraph_ingest::schema::DocumentExtraction` (crates/epigraph-ingest/src/document/schema.rs).

IMPORTANT — emit the RUST shape, not the SKILL.md example shape:
  * paragraph key is `compound` (a String), NOT `compound_claim`
  * `atoms` is a list[str], NOT a list of objects
  * `thesis` is a plain string|null, NOT an object {claim, confidence, source}
  * cross-claim edges use `source_path`/`target_path`, NOT `source_atom`/`target_atom`
The builder `build_ingest_plan` (crates/epigraph-ingest/src/document/builder.rs)
is what consumes this; its tests in lib.rs pin these exact field names.

SCOPE: structure recovery only. This preprocessor does NOT produce atoms or
generality scores — those require the LLM Stage-3 decomposition in the
extract-claims skill (.claude/skills/extract-claims/SKILL.md), which rewrites
`compound` and fills `atoms`/`generality` downstream. Every paragraph here is
emitted with `atoms: []` and a provisional `compound` (the first sentence /
truncation of the recovered text); the full text is preserved verbatim in
`supporting_text` so the LLM stage has the source material.

CANONICAL evidence_type set (crates/epigraph-ingest/src/common/evidence_type.rs):
regulatory, empirical, statistical, logical, testimonial, circumstantial,
conversational. Anything outside this set is dropped to None by the Rust
normalizer, so we omit the field rather than guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

# Canonical SourceType variants (serde renames are PascalCase — match schema.rs).
SOURCE_TYPES = {
    "Paper",
    "Textbook",
    "InternalDocument",
    "Report",
    "Transcript",
    "Legal",
    "Tabular",
}

# Canonical evidence_type values (lower-case keys per evidence_type.rs).
EVIDENCE_TYPES = {
    "regulatory",
    "empirical",
    "statistical",
    "logical",
    "testimonial",
    "circumstantial",
    "conversational",
}

# Max chars for the provisional compound (mirrors V2 statement = text[:500]).
_COMPOUND_MAX = 500


def first_sentence(text: str, max_chars: int = _COMPOUND_MAX) -> str:
    """Provisional compound = first sentence, else a hard truncation.

    The LLM Stage-3 decomposition rewrites this; we only need a non-empty,
    representative string because `Paragraph.compound` is a required field with
    no serde default and `build_ingest_plan` hashes it into the claim id.
    """
    text = re.sub(r"\s+", " ", text or "").strip()
    if not text:
        return ""
    # First sentence terminator followed by whitespace; keep the terminator.
    m = re.search(r"[.!?](?:\s|$)", text)
    if m and m.end() <= max_chars:
        return text[: m.end()].strip()
    return text[:max_chars].strip()


@dataclass
class Author:
    name: str
    affiliations: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "affiliations": self.affiliations,
            "roles": self.roles,
        }


@dataclass
class ParagraphOut:
    """Maps to Rust `Paragraph`. compound is required + non-empty."""

    compound: str
    supporting_text: str = ""
    confidence: float = 0.8
    methodology: Optional[str] = None
    evidence_type: Optional[str] = None
    page: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "compound": self.compound,
            "supporting_text": self.supporting_text,
            # atoms intentionally empty: filled by the LLM Stage-3 decomposition.
            "atoms": [],
            "generality": [],
            "confidence": self.confidence,
        }
        if self.methodology:
            out["methodology"] = self.methodology
        et = (self.evidence_type or "").strip().lower()
        if et in EVIDENCE_TYPES:
            out["evidence_type"] = et
        if self.page is not None:
            out["page"] = self.page
        return out


@dataclass
class SectionOut:
    """Maps to Rust `Section`."""

    title: str
    summary: str = ""
    paragraphs: list[ParagraphOut] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "summary": self.summary,
            "paragraphs": [p.to_dict() for p in self.paragraphs],
        }


@dataclass
class DocumentExtractionOut:
    """Maps to Rust `DocumentExtraction` — the JSON ingest_document parses."""

    title: str
    source_type: str = "Paper"
    doi: Optional[str] = None
    uri: Optional[str] = None
    authors: list[Author] = field(default_factory=list)
    journal: Optional[str] = None
    year: Optional[int] = None
    metadata: Optional[dict[str, Any]] = None
    thesis: Optional[str] = None
    thesis_derivation: str = "TopDown"
    sections: list[SectionOut] = field(default_factory=list)
    # relationships use source_path/target_path (claim-path strings), not atoms.
    relationships: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        if self.source_type not in SOURCE_TYPES:
            raise ValueError(
                f"source_type {self.source_type!r} not in canonical set {sorted(SOURCE_TYPES)}"
            )
        source: dict[str, Any] = {
            "title": self.title,
            "source_type": self.source_type,
            "authors": [a.to_dict() for a in self.authors],
        }
        if self.doi:
            source["doi"] = self.doi
        if self.uri:
            source["uri"] = self.uri
        if self.journal:
            source["journal"] = self.journal
        if self.year is not None:
            source["year"] = self.year
        if self.metadata is not None:
            source["metadata"] = self.metadata
        doc: dict[str, Any] = {
            "source": source,
            "thesis": self.thesis,
            "thesis_derivation": self.thesis_derivation,
            "sections": [s.to_dict() for s in self.sections],
            "relationships": self.relationships,
        }
        return doc
