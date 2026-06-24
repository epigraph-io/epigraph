"""Map structured-source parser output to the live hierarchical DocumentExtraction JSON.

This is the net-new glue for backlog b5518801. The fetch/parse layer
(extract_html.py, extract_textbook.py) recovers source structure
(title/authors/sections/paragraphs). This module maps that recovered structure
onto the schema the live MCP `ingest_document` tool parses:
`epigraph_ingest::schema::DocumentExtraction` (crates/epigraph-ingest/src/document/schema.rs).

IMPORTANT — emit the RUST shape, not the SKILL.md example shape:
  * paragraph key is `text` (a String, the FAITHFUL full recovered text — Tier 2,
    §2 of the verbatim-spine spec), NOT `compound`/`compound_claim`
  * `atoms` is a list[str], NOT a list of objects
  * `thesis` is a plain string|null, NOT an object {claim, confidence, source}
  * cross-claim edges use `source_path`/`target_path`, NOT `source_atom`/`target_atom`
The builder `build_ingest_plan` (crates/epigraph-ingest/src/document/builder.rs)
is what consumes this; its tests in lib.rs pin these exact field names.

SCOPE: structure recovery only. This preprocessor does NOT produce atoms or
generality scores — those require the LLM atomization stage in the extract-claims
skill (.claude/skills/extract-claims/SKILL.md), which decomposes each paragraph's
verbatim `text` into `atoms`/`generality` downstream. Every paragraph here is
emitted with `atoms: []` and the full faithful `text` so the LLM stage has the
source material. These Python emitters are Tier 2 (faithful full text, no byte
spans / `source_text`); the markdown/plaintext Rust structurer is Tier 1.

CANONICAL evidence_type set (crates/epigraph-ingest/src/common/evidence_type.rs):
regulatory, empirical, statistical, logical, testimonial, circumstantial,
conversational. Anything outside this set is dropped to None by the Rust
normalizer, so we omit the field rather than guess.
"""

from __future__ import annotations

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
    """Maps to Rust `Paragraph`. `text` is the verbatim/faithful full source
    text (Tier 2) and is required + non-empty (no serde default in Rust)."""

    text: str
    confidence: float = 0.8
    methodology: Optional[str] = None
    evidence_type: Optional[str] = None
    page: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "text": self.text,
            # atoms intentionally empty: filled by the LLM atomization stage.
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
    paragraphs: list[ParagraphOut] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
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
