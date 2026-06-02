"""Offline tests for the structured-source preprocessors (backlog b5518801).

Run: python3 -m unittest scripts/tests/test_structured_source_parsers.py
No network, no API keys, no LLM — pure stdlib parsing of committed fixtures.
Also (re)writes the two Rust fixtures consumed by
crates/epigraph-ingest/tests/structured_source_glue.rs so Python and Rust
never drift; CI runs this before `cargo test -p epigraph-ingest`.
"""

import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import extract_html  # noqa: E402
import extract_textbook  # noqa: E402
from lib.document_extraction import EVIDENCE_TYPES, SOURCE_TYPES  # noqa: E402

FIX = REPO / "crates" / "epigraph-ingest" / "tests" / "fixtures"


def _assert_canonical(doc: dict) -> None:
    """Every contract the Rust ingester depends on, checked structurally."""
    assert doc["source"]["source_type"] in SOURCE_TYPES
    for sec in doc["sections"]:
        assert sec["title"], "section title required"
        for p in sec["paragraphs"]:
            assert p["compound"].strip(), "compound required + non-empty"
            assert p["atoms"] == [], "structure recovery emits no atoms"
            assert isinstance(p["generality"], list)
            if "evidence_type" in p:
                assert p["evidence_type"] in EVIDENCE_TYPES
    for rel in doc["relationships"]:
        assert "source_path" in rel and "target_path" in rel, (
            "relationships use source_path/target_path (Rust shape), "
            "NOT source_atom/target_atom (SKILL.md shape)"
        )


class TestArxivHtml(unittest.TestCase):
    def test_maps_and_skips_math(self):
        html = (FIX / "sample_arxiv.html").read_text()
        doc = extract_html.html_to_document_extraction(
            html, "https://arxiv.org/html/2603.04139v1"
        ).to_dict()
        _assert_canonical(doc)
        self.assertEqual(doc["source"]["source_type"], "Paper")
        self.assertEqual(doc["source"]["doi"], "10.48550/arXiv.2603.04139")
        self.assertEqual(len(doc["source"]["authors"]), 3)
        self.assertEqual(len(doc["sections"]), 2, "two h2 sections (abstract excluded)")
        self.assertTrue(doc["thesis"], "abstract becomes thesis")
        body = " ".join(
            p["supporting_text"] for s in doc["sections"] for p in s["paragraphs"]
        )
        self.assertNotIn("E=m", body, "<math> must be skipped")
        # Regenerate the Rust fixture deterministically.
        (FIX / "sample_arxiv_extraction.json").write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        )


class TestOpenStaxCnxml(unittest.TestCase):
    def test_module_maps_filters_transitional_and_placeholders_math(self):
        mod = extract_textbook.parse_module(FIX / "sample_openstax_module.cnxml")
        chapter = extract_textbook.Chapter(
            title="Electrostatics", chapter_number=1, module_ids=[mod.module_id]
        )
        section = extract_textbook._module_to_section(mod, chapter, "Sample Physics")
        self.assertIsNotNone(section)
        doc = extract_textbook.DocumentExtractionOut(
            title=mod.title,
            source_type="Textbook",
            doi="openstax:sample-physics",
            authors=[
                extract_textbook.Author(
                    name="OpenStax", affiliations=["Rice University"], roles=["publisher"]
                )
            ],
            journal="OpenStax Textbook",
            sections=[section],
            metadata={
                "extractor": "extract_textbook.py",
                "extraction_stage": "structure_recovery_only",
                "book_slug": "sample-physics",
                "license": "",
            },
        ).to_dict()
        _assert_canonical(doc)
        paras = doc["sections"][0]["paragraphs"]
        self.assertEqual(len(paras), 2, "1 real para + 1 definition; transitional dropped")
        joined = " ".join(p["supporting_text"] for p in paras)
        self.assertIn("[equation]", joined, "inline MathML -> [equation] placeholder")
        self.assertNotIn("In this section, we will explore", joined)
        (FIX / "sample_openstax_extraction.json").write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        )


if __name__ == "__main__":
    unittest.main()
