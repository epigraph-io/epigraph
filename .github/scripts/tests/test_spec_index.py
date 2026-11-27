"""The design-spec status index, docs/superpowers/README.md, must match the specs.

Fails when a spec has no row, a row names a missing file, a status word is
outside the vocabulary, or a spec's first `Status` line disagrees with its
row or (unless it is `proposed`) cites no check. A row still marked
`unverified` (transitional; it leaves VOCABULARY once every spec is checked)
does not constrain its spec's line yet. Stdlib only, so the `plan` job runs it with no install:

    python3 -m unittest discover -s .github/scripts/tests -v

SPEC_INDEX_ROOT points the live-repository test at another checkout.
"""

import os
import re
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("SPEC_INDEX_ROOT") or os.path.join(HERE, "..", "..", "..")

VOCABULARY = {
    "proposed",
    "approved",
    "in-progress",
    "implemented",
    "implemented-with-deviations",
    "superseded",
    "abandoned",
    "unverified",
}

# A spec's status line: the first line whose first word is "Status", in any
# markup (`**Status:**`, `- **Status:**`, `Status:`, front-matter `status:`).
STATUS_LINE_RE = re.compile(r"^\W*status\W", re.I)
# The word after the label.
STATUS_WORD_RE = re.compile(r"^\W*status\W+([A-Za-z-]+)", re.I)
# The citation a checked spec carries on its status line.
CHECKED_RE = re.compile(r"\(checked against origin/main [0-9a-f]{9,40}, \d{4}-\d{2}-\d{2}\)")
# Statuses that make no claim about the tree, so their line needs no citation:
# a new spec is written `proposed`, before anything exists to check it against.
# `approved` still cites one: it says no implementation is in the tree yet.
UNCHECKED_OK = {"proposed"}
# A table row of the index: | `file.md` | status | ... |
ROW_RE = re.compile(r"^\|\s*`([^`]+\.md)`\s*\|\s*([^|]*?)\s*\|")


def index_rows(readme_text):
    """{file name: status} for every row of the index table."""
    rows = {}
    for line in readme_text.splitlines():
        m = ROW_RE.match(line)
        if m:
            rows[m.group(1)] = m.group(2).strip()
    return rows


def status_line(spec_text):
    """The spec's first Status line, or None."""
    for line in spec_text.splitlines():
        if STATUS_LINE_RE.match(line):
            return line
    return None


def problems(readme_text, specs, vocabulary=VOCABULARY):
    """Every disagreement between the index and <specs> ({file name: text})."""
    out = []
    rows = index_rows(readme_text)
    for name in sorted(set(specs) - set(rows)):
        out.append(f"{name}: spec has no row in docs/superpowers/README.md")
    for name in sorted(set(rows) - set(specs)):
        out.append(f"{name}: row names a spec file that does not exist")
    for name in sorted(set(rows) & set(specs)):
        status = rows[name]
        if status not in vocabulary:
            out.append(f"{name}: row status {status!r} is not in the vocabulary")
            continue
        if status == "unverified":
            continue
        line = status_line(specs[name])
        if line is None:
            out.append(f"{name}: no Status line (row says {status!r})")
            continue
        m = STATUS_WORD_RE.match(line)
        word = m.group(1).lower() if m else None
        if word != status:
            out.append(f"{name}: Status line says {word!r}, row says {status!r}")
        if status not in UNCHECKED_OK and not CHECKED_RE.search(line):
            out.append(f"{name}: Status line cites no '(checked against origin/main <sha>, <date>)'")
    return out


def read_tree(root):
    with open(os.path.join(root, "docs", "superpowers", "README.md"), encoding="utf-8") as fh:
        readme = fh.read()
    spec_dir = os.path.join(root, "docs", "superpowers", "specs")
    specs = {}
    for name in sorted(os.listdir(spec_dir)):
        if name.endswith(".md"):
            with open(os.path.join(spec_dir, name), encoding="utf-8") as fh:
                specs[name] = fh.read()
    return readme, specs


CHECK = "(checked against origin/main ad30094c5, 2026-11-27)"
README = (
    "| File | Status | PR | Deviations |\n|---|---|---|---|\n"
    "| `a.md` | implemented | #1 | |\n"
    "| `b.md` | unverified | | |\n"
)
SPECS = {
    "a.md": f"# A\n\n**Status:** implemented {CHECK}. It shipped.\n**Original status:** draft\n",
    "b.md": "# B\n\n**Status:** Design, awaiting review\n",
}


class Checks(unittest.TestCase):
    def test_a_consistent_index_passes(self):
        self.assertEqual(problems(README, SPECS), [])

    def test_a_spec_without_a_row_fails(self):
        specs = dict(SPECS, **{"c.md": f"**Status:** implemented {CHECK}\n"})
        self.assertEqual(problems(README, specs), ["c.md: spec has no row in docs/superpowers/README.md"])

    def test_a_row_for_a_missing_file_fails(self):
        specs = {"a.md": SPECS["a.md"]}
        self.assertEqual(problems(README, specs), ["b.md: row names a spec file that does not exist"])

    def test_a_status_word_that_disagrees_with_its_row_fails(self):
        specs = dict(SPECS, **{"a.md": SPECS["a.md"].replace("implemented", "approved", 1)})
        self.assertEqual(problems(README, specs), ["a.md: Status line says 'approved', row says 'implemented'"])

    def test_a_word_outside_the_vocabulary_fails(self):
        readme = README.replace("| implemented |", "| done |")
        self.assertEqual(problems(readme, SPECS), ["a.md: row status 'done' is not in the vocabulary"])

    def test_a_checked_spec_must_cite_the_check(self):
        specs = dict(SPECS, **{"a.md": SPECS["a.md"].replace(CHECK, "")})
        self.assertEqual(len(problems(README, specs)), 1)
        self.assertIn("cites no", problems(README, specs)[0])

    def test_a_new_proposed_spec_needs_a_row_but_no_citation(self):
        readme = README + "| `c.md` | proposed | | |\n"
        specs = dict(SPECS, **{"c.md": "# C\n\n**Status:** proposed\n"})
        self.assertEqual(problems(readme, specs), [])
        # The word must still match its row, and an approved spec still cites.
        self.assertEqual(problems(readme.replace("| proposed |", "| approved |"),
                                  dict(specs, **{"c.md": "**Status:** approved\n"})),
                         ["c.md: Status line cites no '(checked against origin/main <sha>, <date>)'"])

    def test_the_first_status_line_is_the_one_read(self):
        text = f"# A\n\n**Status:** approved {CHECK}\n\n## Notes\n\nStatus: implemented {CHECK}\n"
        self.assertEqual(problems(README, dict(SPECS, **{"a.md": text})),
                         ["a.md: Status line says 'approved', row says 'implemented'"])

    def test_front_matter_and_list_markup_are_read(self):
        for text in (f"---\nstatus: implemented {CHECK}\n---\n", f"- **Status:** implemented {CHECK}\n"):
            with self.subTest(text=text):
                self.assertEqual(problems(README, dict(SPECS, **{"a.md": text})), [])

    def test_unverified_leaves_the_vocabulary_when_dropped(self):
        self.assertEqual(problems(README, SPECS, VOCABULARY - {"unverified"}),
                         ["b.md: row status 'unverified' is not in the vocabulary"])


class LiveTree(unittest.TestCase):
    def test_the_index_matches_the_specs(self):
        readme, specs = read_tree(ROOT)
        self.assertTrue(specs)
        self.assertEqual(problems(readme, specs), [])

    def test_the_live_check_reads_this_tree(self):
        # The fixture above is not the only input: break a copy of the tree.
        readme, specs = read_tree(ROOT)
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "docs", "superpowers", "specs"))
            with open(os.path.join(d, "docs", "superpowers", "README.md"), "w", encoding="utf-8") as fh:
                fh.write(readme)
            for name, text in list(specs.items()) + [("2099-01-01-new-design.md", "# New\n")]:
                with open(os.path.join(d, "docs", "superpowers", "specs", name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            got = problems(*read_tree(d))
        self.assertEqual(got, ["2099-01-01-new-design.md: spec has no row in docs/superpowers/README.md"])


if __name__ == "__main__":
    unittest.main()
