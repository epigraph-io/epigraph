#!/usr/bin/env python3
"""Structured-source-first parser for OpenStax textbooks (CNXML source).

Harvested from EpigraphV2/scripts/extract_textbook.py — STRUCTURAL SYMBOLS ONLY:
parse_books_xml, parse_collection_xml, _parse_content_level, _parse_chapter,
parse_module, _extract_content_blocks, _extract_text, _extract_terms,
_parse_table_rows. The V2 LLM stage (llm_complete / filter_chapter_claims /
extract_relationships, including the litellm `anthropic` provider branch) is
DELIBERATELY NOT PORTED: it is superseded by the extract-claims skill
(hierarchical compound->atoms decomposition), and the litellm/Anthropic-SDK path
violates the prepaid-OAuth claude-CLI invariant (feedback_claude_cli_oauth).
Structure recovery needs no LLM.

This layer recovers source structure (book/chapter/module/paragraph) and maps it
onto the live hierarchical DocumentExtraction (crates/epigraph-ingest/src/document/schema.rs):
  * source_type=Textbook, doi=openstax:<slug>, authors=[OpenStax publisher].
  * thesis = book title sentence (TopDown).
  * Each module -> one Section (title = 'Ch N: <chapter> > <module>').
  * Each real <para> >=50 chars and each glossary <definition> -> one Paragraph
    (CNXML preserves real paragraph boundaries, unlike arbitrary HTML).
  * atoms/generality LEFT EMPTY — the extract-claims LLM Stage-3 fills them.
  * <math>/MathML inside a paragraph is replaced by the literal token
    '[equation]' (V2 _extract_text behaviour); equations are not extracted.

Usage:
    git clone --depth 1 https://github.com/openstax/osbooks-college-physics.git /tmp/phys
    python3 scripts/extract_textbook.py /tmp/phys --output /home/jeremy/tmp/extractions/
    python3 scripts/extract_textbook.py /tmp/phys --book college-physics --max-modules 5
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.document_extraction import (  # noqa: E402
    Author,
    DocumentExtractionOut,
    ParagraphOut,
    SectionOut,
    first_sentence,
)

NS = {
    "col": "http://cnx.rice.edu/collxml",
    "md": "http://cnx.rice.edu/mdml",
    "cnxml": "http://cnx.rice.edu/cnxml",
    "m": "http://www.w3.org/1998/Math/MathML",
    "container": "https://openstax.org/namespaces/book-container",
}


@dataclass
class Module:
    module_id: str
    title: str
    uuid: str
    content_blocks: list[dict] = field(default_factory=list)
    is_introduction: bool = False


@dataclass
class Chapter:
    title: str
    chapter_number: int
    module_ids: list[str] = field(default_factory=list)


@dataclass
class Part:
    title: str
    chapters: list[Chapter] = field(default_factory=list)


@dataclass
class BookStructure:
    title: str
    slug: str
    license: str
    parts: list[Part] = field(default_factory=list)

    def all_chapters(self) -> list[Chapter]:
        return [ch for part in self.parts for ch in part.chapters]


def _local_tag(el) -> str:
    tag = el.tag
    return tag.split("}")[-1] if "}" in tag else tag


def _text_of(el):
    return el.text.strip() if el is not None and el.text else None


# ── Collection (book) parser — verbatim V2 structural logic ──────────────────

def parse_books_xml(repo_path: Path) -> list[dict]:
    tree = ET.parse(repo_path / "META-INF" / "books.xml")
    root = tree.getroot()
    return [
        {"slug": b.get("slug", ""), "style": b.get("style", ""), "href": b.get("href", "")}
        for b in root.findall("container:book", NS)
    ]


def parse_collection_xml(collection_path: Path) -> BookStructure:
    tree = ET.parse(collection_path)
    root = tree.getroot()
    title = _text_of(root.find("col:metadata/md:title", NS)) or ""
    slug = _text_of(root.find("col:metadata/md:slug", NS)) or ""
    license_el = root.find("col:metadata/md:license", NS)
    license_text = license_el.get("url", "") if license_el is not None else ""
    content_el = root.find("col:content", NS)
    parts = _parse_content_level(content_el, chapter_counter=[0])
    return BookStructure(title=title, slug=slug, license=license_text, parts=parts)


def _parse_content_level(content_el, chapter_counter: list[int]) -> list[Part]:
    if content_el is None:
        return []
    parts: list[Part] = []
    for child in content_el:
        tag = _local_tag(child)
        if tag != "subcollection":
            continue
        sub_title = _text_of(child.find("md:title", NS)) or "Untitled"
        sub_content = child.find("col:content", NS)
        has_nested = sub_content is not None and any(
            _local_tag(c) == "subcollection" for c in sub_content
        )
        if has_nested:
            part = Part(title=sub_title)
            for inner in sub_content:
                if _local_tag(inner) == "subcollection":
                    chapter_counter[0] += 1
                    part.chapters.append(_parse_chapter(inner, chapter_counter[0]))
            parts.append(part)
        else:
            chapter_counter[0] += 1
            ch = _parse_chapter(child, chapter_counter[0])
            if not parts or parts[-1].chapters:
                parts.append(Part(title=""))
            parts[-1].chapters.append(ch)
    return parts


def _parse_chapter(subcoll_el, chapter_num: int) -> Chapter:
    title = _text_of(subcoll_el.find("md:title", NS)) or "Untitled"
    content_el = subcoll_el.find("col:content", NS)
    module_ids = []
    if content_el is not None:
        for mod_el in content_el.findall("col:module", NS):
            doc_id = mod_el.get("document", "")
            if doc_id:
                module_ids.append(doc_id)
    return Chapter(title=title, chapter_number=chapter_num, module_ids=module_ids)


# ── Module (CNXML) parser — verbatim V2 structural logic ─────────────────────

def parse_module(module_path: Path) -> Module:
    tree = ET.parse(module_path)
    root = tree.getroot()
    doc_class = root.get("class", "")
    title = _text_of(root.find("cnxml:title", NS)) or ""
    md_id = _text_of(root.find("cnxml:metadata/md:content-id", NS)) or module_path.parent.name
    uuid = _text_of(root.find("cnxml:metadata/md:uuid", NS)) or ""
    module = Module(module_id=md_id, title=title, uuid=uuid,
                    is_introduction=(doc_class == "introduction"))
    content_el = root.find("cnxml:content", NS)
    if content_el is not None:
        _extract_content_blocks(content_el, module)
    glossary_el = root.find("cnxml:glossary", NS)
    if glossary_el is not None:
        for defn in glossary_el.findall("cnxml:definition", NS):
            term_el = defn.find("cnxml:term", NS)
            meaning_el = defn.find("cnxml:meaning", NS)
            if term_el is not None and meaning_el is not None:
                module.content_blocks.append({
                    "type": "definition",
                    "term": _extract_text(term_el),
                    "meaning": _extract_text(meaning_el),
                })
    return module


def _extract_content_blocks(element, module: Module, section_title: str = ""):
    for child in element:
        tag = _local_tag(child)
        if tag == "section":
            sec_class = child.get("class", "")
            if sec_class in ("knowledge-check", "references", "learning-objectives"):
                continue
            sec_title_el = child.find("cnxml:title", NS)
            sec_title = _extract_text(sec_title_el) if sec_title_el is not None else ""
            _extract_content_blocks(child, module, section_title=sec_title or section_title)
        elif tag == "para":
            text = _extract_text(child).strip()
            if len(text) >= 50:
                module.content_blocks.append({
                    "type": "paragraph",
                    "id": child.get("id", ""),
                    "text": text,
                    "section": section_title,
                })
        elif tag == "table":
            caption_el = child.find("cnxml:caption", NS)
            caption = _extract_text(caption_el) if caption_el is not None else ""
            rows = _parse_table_rows(child)
            if caption or rows:
                row_text = "; ".join(" | ".join(c) for c in rows[:6])
                module.content_blocks.append({
                    "type": "table", "caption": caption, "text": row_text[:1000],
                    "section": section_title,
                })


def _extract_text(el) -> str:
    """Recursively extract text; <math> becomes the literal token '[equation]'."""
    if el is None:
        return ""
    parts = []
    if el.text:
        parts.append(el.text)
    for child in el:
        ct = _local_tag(child)
        if ct in ("term", "emphasis", "link", "span", "sup", "sub"):
            parts.append(_extract_text(child))
        elif ct == "list":
            items = [_extract_text(i).strip() for i in child.findall("cnxml:item", NS)]
            if items:
                parts.append("; ".join(items))
        elif ct in ("cite", "note", "media", "iframe"):
            pass
        elif ct == "math" or ct.endswith("}math"):
            parts.append("[equation]")
        else:
            parts.append(_extract_text(child))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def _parse_table_rows(table_el) -> list[list[str]]:
    rows = []
    for tgroup in table_el.findall("cnxml:tgroup", NS):
        for sect in ("thead", "tbody"):
            section = tgroup.find(f"cnxml:{sect}", NS)
            if section is None:
                continue
            for row_el in section.findall("cnxml:row", NS):
                cells = [_extract_text(e).strip() for e in row_el.findall("cnxml:entry", NS)]
                if cells:
                    rows.append(cells)
    return rows


# ── Mapping to the live DocumentExtraction ───────────────────────────────────

_TRANSITIONAL = [
    re.compile(r"^in this (section|chapter|module), (we|you) will", re.I),
    re.compile(r"^by the end of this section", re.I),
    re.compile(r"^(refer to |see |consider |imagine )", re.I),
]


def _is_transitional(text: str) -> bool:
    if text.count(".") + text.count("?") + text.count("!") <= 2:
        return any(p.search(text) for p in _TRANSITIONAL)
    return False


def _module_to_section(module: Module, chapter: Chapter, book_title: str) -> SectionOut | None:
    sect_title = f"Ch {chapter.chapter_number}: {chapter.title} > {module.title}"
    paragraphs: list[ParagraphOut] = []
    for block in module.content_blocks:
        if block["type"] == "paragraph":
            text = block["text"]
            if len(text) < 80 or _is_transitional(text):
                continue
            paragraphs.append(ParagraphOut(
                compound=first_sentence(text), supporting_text=text,
                confidence=0.85, methodology="textbook_assertion",
            ))
        elif block["type"] == "definition":
            stmt = f"{block['term']} is defined as: {block['meaning']}"
            paragraphs.append(ParagraphOut(
                compound=first_sentence(stmt), supporting_text=stmt,
                confidence=0.90, methodology="textbook_assertion",
            ))
        elif block["type"] == "table" and block.get("caption"):
            paragraphs.append(ParagraphOut(
                compound=first_sentence(f"Table: {block['caption']}"),
                supporting_text=block.get("text", ""),
                confidence=0.80, methodology="textbook_assertion",
            ))
    if not paragraphs:
        return None
    # Derive the L1 summary from the section TITLE, not the first paragraph's
    # supporting_text. first_sentence(paragraphs[0].supporting_text) is verbatim
    # paragraphs[0].compound; since compound_claim_id hashes content with no
    # level in the material, that identical string collides the section (L1) and
    # its first paragraph (L2) onto the SAME UUID — a decomposes_to self-loop and
    # a duplicate-id insert (backlog b5518801). A title-derived summary is
    # hash-distinct from every child compound.
    return SectionOut(title=sect_title, summary=f"Section: {sect_title}",
                      paragraphs=paragraphs)


def book_to_document_extraction(repo_path: Path, book_info: dict, max_modules: int = 0) -> DocumentExtractionOut:
    collection_path = (repo_path / "META-INF" / book_info["href"]).resolve()
    book = parse_collection_xml(collection_path)
    sections_out: list[SectionOut] = []
    seen = 0
    for chapter in book.all_chapters():
        for mod_id in chapter.module_ids:
            module_path = repo_path / "modules" / mod_id / "index.cnxml"
            if not module_path.exists():
                continue
            sec = _module_to_section(parse_module(module_path), chapter, book.title)
            if sec is not None:
                sections_out.append(sec)
            seen += 1
            if max_modules and seen >= max_modules:
                break
        if max_modules and seen >= max_modules:
            break
    return DocumentExtractionOut(
        title=book.title or book.slug,
        source_type="Textbook",
        doi=f"openstax:{book.slug}",
        authors=[Author(name="OpenStax", affiliations=["Rice University"], roles=["publisher"])],
        journal="OpenStax Textbook",
        thesis=first_sentence(book.title) if book.title else None,
        thesis_derivation="TopDown",
        sections=sections_out,
        metadata={
            "extractor": "extract_textbook.py",
            "extraction_stage": "structure_recovery_only",
            "book_slug": book.slug,
            "license": book.license,
        },
    )


def main():
    ap = argparse.ArgumentParser(description="Parse OpenStax CNXML into DocumentExtraction JSON")
    ap.add_argument("repo_path", help="Path to a cloned OpenStax repo")
    ap.add_argument("--book", help="Process only this book slug (default: all)")
    ap.add_argument("--max-modules", type=int, default=0, help="Cap modules per book (0 = all)")
    ap.add_argument("--output", default="/home/jeremy/tmp/extractions/")
    args = ap.parse_args()

    repo_path = Path(args.repo_path)
    books = parse_books_xml(repo_path)
    if args.book:
        books = [b for b in books if b["slug"] == args.book]
        if not books:
            print(f"book {args.book!r} not found", file=sys.stderr)
            sys.exit(1)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    for b in books:
        doc = book_to_document_extraction(repo_path, b, max_modules=args.max_modules).to_dict()
        out_path = out_dir / f"openstax_{b['slug']}_extraction.json"
        out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False))
        print(f"Book:     {doc['source']['title'][:60]}")
        print(f"Sections: {len(doc['sections'])}")
        print(f"Wrote:    {out_path}")


if __name__ == "__main__":
    main()
