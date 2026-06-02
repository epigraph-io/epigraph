#!/usr/bin/env python3
"""Structured-source-first parser for scientific-paper HTML (arXiv/ar5iv/PMC).

Harvested from EpigraphV2/scripts/extract_html.py (HTMLTextExtractor,
html_to_structure, extract_arxiv_id, fetch_html). Ported LLM-free: this layer
recovers SOURCE STRUCTURE (title/authors/abstract/sections), then maps it onto
the live hierarchical DocumentExtraction (crates/epigraph-ingest/src/document/schema.rs)
so the output can be handed to the extract-claims LLM stage and then
`mcp__epigraph__ingest_document`.

SCOPE — structure recovery only:
  * Emits levels 0-2 (thesis from abstract, one Section per heading, one
    Paragraph per section). atoms/generality are LEFT EMPTY; the extract-claims
    skill's Stage-3 decomposition fills them.
  * HTML collapses each section's prose into a single text blob (no reliable
    paragraph boundaries in arbitrary HTML), so each Section maps to exactly
    ONE Paragraph. (CNXML, by contrast, preserves real <para> boundaries.)
  * <math>/MathML is SKIPPED by the parser (SKIP_TAGS); equations are not
    extracted. Flagged limitation, acceptable for structure recovery.

Usage:
    python3 scripts/extract_html.py https://arxiv.org/html/2603.04139v1 \
        --output /home/jeremy/tmp/extractions/
    python3 scripts/extract_html.py path/to/page.html --from-file \
        --uri https://arxiv.org/html/2603.04139v1 --output /home/jeremy/tmp/extractions/

The --from-file mode parses a local HTML file (no network) — used by tests and
for offline/airgapped operation.
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

# Import the shared mapping module (scripts/ is the package root at runtime).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.document_extraction import (  # noqa: E402
    Author,
    DocumentExtractionOut,
    ParagraphOut,
    SectionOut,
    first_sentence,
)


class _ParsedSection:
    __slots__ = ("title", "text", "level")

    def __init__(self, title: str, level: int = 2):
        self.title = title
        self.text = ""
        self.level = level


class HTMLTextExtractor(HTMLParser):
    """Minimal HTML-to-text parser preserving section structure.

    Verbatim port of V2 HTMLTextExtractor: <math> is in SKIP_TAGS so equations
    are dropped; h1=title, h2-h4=section boundaries; abstract + author blocks
    detected by class/id substring.
    """

    SKIP_TAGS = {"script", "style", "nav", "footer", "header", "noscript", "svg", "math"}
    HEADING_TAGS = {"h1", "h2", "h3", "h4"}

    def __init__(self):
        super().__init__()
        self.title = ""
        self.authors = ""
        self.abstract = ""
        self.sections: list[_ParsedSection] = []
        self._current_section: _ParsedSection | None = None
        self._skip_depth = 0
        self._in_abstract = False
        self._abstract_buf: list[str] = []
        self._text_buf: list[str] = []
        self._heading_buf: list[str] = []
        self._in_heading = False
        self._heading_level = 0
        self._title_found = False
        self._in_authors = False
        self._authors_buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth > 0:
            return
        cls = attrs_dict.get("class", "") or ""
        tid = attrs_dict.get("id", "") or ""
        if "abstract" in cls.lower() or "abstract" in tid.lower():
            self._in_abstract = True
        if "author" in cls.lower() and tag in ("div", "span", "p", "section"):
            self._in_authors = True
        if tag in self.HEADING_TAGS:
            self._in_heading = True
            self._heading_level = int(tag[1])
            self._heading_buf = []
        if tag == "h1" and not self._title_found:
            self._in_heading = True
            self._heading_level = 1
            self._heading_buf = []

    def handle_endtag(self, tag):
        if tag in self.SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth > 0:
            return
        if tag in self.HEADING_TAGS or (tag == "h1" and not self._title_found):
            self._in_heading = False
            heading_text = re.sub(r"\s+", " ", " ".join(self._heading_buf)).strip()
            if self._heading_level == 1 and not self._title_found:
                self.title = heading_text
                self._title_found = True
            elif heading_text and self._heading_level >= 2:
                self._flush_section()
                self._current_section = _ParsedSection(title=heading_text, level=self._heading_level)
            self._heading_buf = []
        if tag in ("div", "section", "blockquote") and self._in_abstract and self._abstract_buf:
            self.abstract = re.sub(r"\s+", " ", " ".join(self._abstract_buf)).strip()
            self._in_abstract = False
        if tag in ("div", "section") and self._in_authors:
            self._in_authors = False
            authors_text = re.sub(r"\s+", " ", " ".join(self._authors_buf)).strip()
            if authors_text and not self.authors:
                self.authors = authors_text

    def handle_data(self, data):
        if self._skip_depth > 0:
            return
        text = data.strip()
        if not text:
            return
        if self._in_heading:
            self._heading_buf.append(text)
            return
        if self._in_abstract:
            self._abstract_buf.append(text)
        if self._in_authors:
            self._authors_buf.append(text)
        if self._current_section is not None:
            self._text_buf.append(text)

    def _flush_section(self):
        if self._current_section and self._text_buf:
            self._current_section.text = re.sub(r"\s+", " ", " ".join(self._text_buf)).strip()
            if len(self._current_section.text) > 50:  # skip tiny sections (V2 rule)
                self.sections.append(self._current_section)
        self._text_buf = []

    def finalize(self):
        self._flush_section()
        if not self.abstract and self.sections:
            for s in self.sections:
                if "abstract" in s.title.lower():
                    self.abstract = s.text[:2000]
                    break


def extract_arxiv_id(url: str) -> str:
    """Extract an arXiv ID from a URL (verbatim V2 regex)."""
    m = re.search(r"(\d{4}\.\d{4,5})(v\d+)?", url or "")
    return m.group(1) if m else ""


def fetch_html(url: str) -> str:
    """Download HTML content from a URL (verbatim V2 fetch)."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "EpiGraph/1.0 (epistemic-research; +https://github.com/epigraph-io)",
            "Accept": "text/html",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (trusted source URLs)
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def _split_authors(joined: str) -> list[Author]:
    """HTML yields one joined author blob; best-effort comma/semicolon split."""
    if not joined:
        return []
    parts = re.split(r"\s*(?:,|;| and )\s*", joined)
    names = [p.strip() for p in parts if p.strip() and len(p.strip()) > 1]
    return [Author(name=n, roles=["author"]) for n in names] or [Author(name=joined, roles=["author"])]


def html_to_document_extraction(html: str, url: str = "") -> DocumentExtractionOut:
    """Parse HTML and map to the live DocumentExtraction shape.

    arXiv: source_type=Paper, uri=url, doi=10.48550/arXiv.<id>; abstract becomes
    the (top-down) thesis; each recovered section -> one Section with one
    Paragraph (HTML has no reliable intra-section paragraph boundaries).
    """
    parser = HTMLTextExtractor()
    parser.feed(html)
    parser.finalize()

    doi = None
    arxiv_id = extract_arxiv_id(url) if "arxiv.org" in (url or "") else ""
    if arxiv_id:
        doi = f"10.48550/arXiv.{arxiv_id}"
    if not doi:
        m = re.search(r"10\.\d{4,}/[^\s<>\"]+", html)
        if m:
            doi = m.group(0).rstrip(".,;)")

    sections_out: list[SectionOut] = []
    for s in parser.sections:
        if "abstract" in s.title.lower():
            continue  # abstract becomes the thesis, not a body section
        sections_out.append(
            SectionOut(
                title=s.title,
                # Derive the L1 summary from the section TITLE, not the body's
                # first sentence. The body first sentence is verbatim the first
                # paragraph's `compound`; since compound_claim_id hashes content
                # with no level in the material, an identical string collides the
                # section (L1) and its first paragraph (L2) onto the SAME UUID,
                # producing a decomposes_to self-loop and a duplicate-id insert
                # (backlog b5518801). A title-derived summary is hash-distinct.
                summary=f"Section: {s.title}",
                paragraphs=[
                    ParagraphOut(
                        compound=first_sentence(s.text),
                        supporting_text=s.text,
                        confidence=0.8,
                        methodology="structured_html_parse",
                    )
                ],
            )
        )

    return DocumentExtractionOut(
        title=parser.title or (f"arXiv:{arxiv_id}" if arxiv_id else "Untitled"),
        source_type="Paper",
        doi=doi,
        uri=url or None,
        authors=_split_authors(parser.authors),
        thesis=(parser.abstract or None),
        thesis_derivation="TopDown",
        sections=sections_out,
        metadata={
            "extractor": "extract_html.py",
            "extraction_stage": "structure_recovery_only",
            "arxiv_id": arxiv_id or None,
        },
    )


def _basename_for(url: str, title: str) -> str:
    arxiv_id = extract_arxiv_id(url)
    base = arxiv_id if arxiv_id else hashlib.md5(url.encode()).hexdigest()[:12]  # noqa: S324
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", (title or "")[:50]).strip("_")
    return f"{base}_{slug}" if slug else base


def main():
    ap = argparse.ArgumentParser(description="Parse paper HTML into DocumentExtraction JSON")
    ap.add_argument("input", help="URL, or local .html path with --from-file")
    ap.add_argument("--from-file", action="store_true", help="Treat input as a local HTML file (no network)")
    ap.add_argument("--uri", default="", help="Source URI to record when reading --from-file")
    ap.add_argument("--output", "-o", default="/home/jeremy/tmp/extractions/")
    args = ap.parse_args()

    if args.from_file:
        html = Path(args.input).read_text(encoding="utf-8", errors="replace")
        url = args.uri or args.input
    else:
        url = args.input.strip()
        html = fetch_html(url)

    doc = html_to_document_extraction(html, url).to_dict()
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{_basename_for(url, doc['source']['title'])}_extraction.json"
    out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    print(f"Title:    {doc['source']['title'][:70]}")
    print(f"Sections: {len(doc['sections'])}")
    print(f"DOI:      {doc['source'].get('doi') or '(none)'}")
    print(f"Wrote:    {out_path}")


if __name__ == "__main__":
    main()
