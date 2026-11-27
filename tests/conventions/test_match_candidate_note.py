"""docs/architecture/match-candidate-edge-provenance.md agrees with the code
(backlog c8f16097).

The note said only `decide_match_candidate("promote")` CORROBORATES edges
carry `properties.candidate_id`, and listed the entity types of a CHECK that
migration 055 dropped. These tests tie the note to the tree: every source file
that stamps `"candidate_id"` into edge properties is named in the note, and
the note cites the `entity_types` registry instead of a copied allowlist.
Standard library only.
"""

import re
import unittest

from .convention_pins import REPO, normalize

NOTE = REPO / "docs" / "architecture" / "match-candidate-edge-provenance.md"

# A `"candidate_id":` key in a json! literal, as every writer spells it.
STAMP = re.compile(r'"candidate_id":\s')


def note():
    return NOTE.read_text(encoding="utf-8")


def stamping_sources():
    """Every crate source file that stamps `"candidate_id"` into a JSON object."""
    out = []
    for path in sorted((REPO / "crates").glob("*/src/**/*.rs")):
        if STAMP.search(path.read_text(encoding="utf-8")):
            out.append(path.relative_to(REPO).as_posix())
    return out


class MatchCandidateEdgeProvenanceNote(unittest.TestCase):
    def test_note_does_not_name_the_dropped_check(self):
        self.assertNotIn("edges_entity_types_valid", note())

    def test_note_cites_the_entity_types_registry(self):
        text = note()
        self.assertIn("REFERENCES entity_types(type_name)", text)
        self.assertIn("migrations/055_entity_types_fk_and_trigger.sql", text)
        migration = (REPO / "migrations" / "055_entity_types_fk_and_trigger.sql").read_text(encoding="utf-8")
        for fk in ("edges_source_type_fkey", "edges_target_type_fkey"):
            with self.subTest(fk=fk):
                self.assertIn(fk, text)
                self.assertIn(fk, migration)

    def test_every_candidate_id_writer_is_named_in_the_note(self):
        sources = stamping_sources()
        # The auto-promote path is the one the note used to deny.
        self.assertIn("crates/epigraph-engine/src/matching/policy.rs", sources)
        for path in sources:
            with self.subTest(source=path):
                self.assertIn(path, note())

    def test_note_names_policy_write_edge(self):
        self.assertIn("policy.rs::write_edge", note())
        policy = (REPO / "crates/epigraph-engine/src/matching/policy.rs").read_text(encoding="utf-8")
        self.assertIn("async fn write_edge(", policy)

    def test_note_no_longer_limits_candidate_id_to_promote_corroborates(self):
        self.assertNotIn(
            normalize('Only `CORROBORATES` edges written by `decide_match_candidate("promote")` ever populate'),
            normalize(note()),
        )


if __name__ == "__main__":
    unittest.main()
