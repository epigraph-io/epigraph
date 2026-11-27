"""Tests for .github/scripts/docs-hygiene-lint.py: home paths, private-memory
citations and private-repository file citations in the published tree.

Run from the repository root (the `plan` job does):

    python3 -m unittest discover -s .github/scripts/tests -v

DOCS_LINT_ROOT points the live-repository test at another checkout.
"""

import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "docs-hygiene-lint.py")
ROOT = os.environ.get("DOCS_LINT_ROOT") or os.path.join(HERE, "..", "..", "..")


def load():
    spec = importlib.util.spec_from_file_location("docs_hygiene_lint", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lint = load()

# Built from parts so this file never carries a literal developer path.
HOME = "/" + "home" + "/"
USERS = "/" + "Users" + "/"


def classes(rel, text):
    return [cls for _, cls, _ in lint.scan_text(rel, text)]


class ScanText(unittest.TestCase):
    def test_home_path_in_markdown_is_d1(self):
        self.assertEqual(classes("docs/a.md", "run `cd " + HOME + "alice/epigraph`"), ["D1"])
        self.assertEqual(classes("docs/a.md", "see " + USERS + "bob/x/y"), ["D1"])

    def test_generic_account_names_pass(self):
        # The commit lint's allowlist, reused, not copied.
        for name in ("user", "runner", "you"):
            self.assertEqual(classes("docs/a.md", HOME + name + "/epigraph"), [], name)

    def test_d1_is_markdown_only(self):
        self.assertEqual(classes("scripts/x.py", "DEFAULT = '" + HOME + "alice/out.json'"), [])

    def test_d1_uses_the_commit_lint_pattern(self):
        cml = lint._commit_lint()
        self.assertEqual(lint.HOME_RE.pattern, cml.HOME_RE.pattern)
        self.assertEqual(lint.HOME_OK_NAMES, cml.HOME_OK_NAMES)

    def test_memory_citation_is_d2(self):
        self.assertEqual(classes("docs/a.md", "(user-memory `feedback_x.md`)"), ["D2"])
        self.assertEqual(classes("src/a.rs", "// see auto-memory note"), ["D2"])
        # A label named after a memory file is not a citation of one.
        self.assertEqual(classes("src/a.rs", 'labels: ["src:MEMORY.md"]'), [])

    def test_bare_memory_note_filename_is_d2(self):
        # Cited without the "user-memory" words: still a note nobody can open.
        self.assertEqual(classes("scripts/a.py", "Per feedback_no_raw_sql.md: call the API"), ["D2"])
        self.assertEqual(classes("src/a.rs", "/// (see `project_bp_primary.md`)"), ["D2"])
        self.assertEqual(classes("docs/a.md", "per reference_oauth_mint.md"), ["D2"])
        # Ordinary Markdown names are not memory-note names.
        for ok in ("README.md", "user-guide.md", "projects.md", "references.md", "docs/feedback.md"):
            self.assertEqual(classes("docs/a.md", "see " + ok), [], ok)

    def test_private_repo_citation_is_d3(self):
        self.assertEqual(classes("CLAUDE.md", "through `release/epiclaw/CLAUDE.md`'s"), ["D3"])
        wrapped = "/// labels the writers in epiclaw-host's\n///   `deploy/` prompts write\n"
        self.assertEqual(lint.scan_text("src/a.rs", wrapped), [(1, "D3", "citation of a private file outside this repository")])
        # Naming the host component is fine; citing its files is not.
        self.assertEqual(classes("src/a.rs", "// epiclaw-host's ProvenanceRecorder signs"), [])

    def test_private_source_file_and_notes_citations_are_d3(self):
        self.assertEqual(classes("src/a.rs", "/// matches the epiclaw-host `container.rs` convention"), ["D3"])
        self.assertEqual(classes("src/a.rs", "/// epiclaw-host's `container.rs` documents X"), ["D3"])
        self.assertEqual(classes("m.sql", "-- (epiclaw-host/src/host/provenance.rs) signs"), ["D3"])
        notes = "~/" + "ops-" + "private/"
        self.assertEqual(classes("docs/a.md", "recorded in `" + notes + "2026-mapping.md`"), ["D3"])
        self.assertEqual(classes("tests/a.rs", "// in " + notes + "r.md (R4)"), ["D3"])
        # A `~/` path that names nothing private, and a host-side env var, pass.
        self.assertEqual(classes("docs/a.md", "install to `~/.cargo/bin/`"), [])
        self.assertEqual(classes("src/a.rs", "// epiclaw-host exports `EPIGRAPH_OAUTH_TOKEN_URL`"), [])


class Scan(unittest.TestCase):
    def tree(self, files):
        d = tempfile.mkdtemp()
        for rel, text in files.items():
            path = os.path.join(d, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(text)
        return d

    def test_historical_surfaces_are_skipped(self):
        root = self.tree({
            "docs/superpowers/plans/p.md": "cd " + HOME + "alice/wt (user-memory `x.md`)\n",
            "docs/tenancy/progress.json": '{"a": "release/epiclaw/CLAUDE.md"}\n',
            "migrations/048_label_provenance_telemetry.sql": "-- (epiclaw-host/src/host/provenance.rs)\n",
        })
        self.assertEqual(lint.scan(root), [])

    def test_findings_name_file_and_line(self):
        root = self.tree({"docs/ops/r.md": "ok\n  --dir=" + HOME + "alice/wt \\\n"})
        self.assertEqual(lint.scan(root), [("docs/ops/r.md", 2, "D1", "home-directory path /home/<redacted>/")])
        self.assertEqual(lint.main(["lint", "--root", root]), 1)


class LiveRepository(unittest.TestCase):
    def test_the_published_tree_is_clean(self):
        findings = lint.scan(ROOT)
        self.assertEqual(findings, [], "\n".join(f"{r}:{n}: {c} {d}" for r, n, c, d in findings))


if __name__ == "__main__":
    unittest.main()
