"""Tests for the `--pr-text` mode of .github/scripts/commit-message-lint.py and
the workflow that runs it (.github/workflows/pr-text-lint.yml).

The commit-message mode has its own self-test, which builds a git repository:
.github/scripts/test-commit-message-lint.sh. A pull request's title and body
are as public as a commit message and can be edited after the commits were
checked, so they get the privacy rules (E1 e-mail address, E2 home-directory
path, E3 address-encoding host or public IPv4, E6 private deny-list term)
without the commit-only ones. Every value here is synthetic.

Run from the repository root (the `plan` job does):

    python3 -m unittest discover -s .github/scripts/tests -v
"""

import contextlib
import importlib.util
import io
import os
import re
import subprocess
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "commit-message-lint.py")
WORKFLOW = os.path.join(HERE, "..", "..", "workflows", "pr-text-lint.yml")


def load():
    spec = importlib.util.spec_from_file_location("commit_message_lint", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lint = load()

# Built from parts so this file never carries a literal developer path or a
# deliverable-looking address.
BAD_EMAIL = "someone" + "@" + "corp.invalid"
BAD_HOME = "/" + "home" + "/" + "alice" + "/project"
BAD_IP = "203.0.114.7"
DENY_TERM = "Zorblax Widgets"
FOOTER = (
    "\U0001f916 Generated with [Claude Code](https://claude.com/claude-code)\n\n"
    "https://claude.ai/code/session_0123456789abcdef"
)


def run_cli(title, body, deny=""):
    """Run the script as CI does; return (exit code, combined output)."""
    env = dict(os.environ, PR_TITLE=title, PR_BODY=body, COMMIT_LINT_DENY_TERMS=deny)
    env.pop("COMMIT_LINT_DENY_FILE", None)
    p = subprocess.run([sys.executable, SCRIPT, "--pr-text"], env=env,
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


class PrTextFindings(unittest.TestCase):
    def classes(self, title, body, deny=()):
        return [(where, cls) for where, cls, _ in lint.lint_pr_text(title, body, list(deny))]

    def test_email_in_body_is_e1_with_its_line(self):
        self.assertEqual(self.classes("t", "first\n\ncontact " + BAD_EMAIL), [("body line 3", "E1")])

    def test_email_in_title_is_e1(self):
        self.assertEqual(self.classes("feat(x): mail " + BAD_EMAIL, ""), [("title", "E1")])

    def test_home_path_is_e2(self):
        self.assertEqual(self.classes("t", "see " + BAD_HOME), [("body line 1", "E2")])

    def test_public_ipv4_is_e3(self):
        self.assertEqual(self.classes("t", "host at " + BAD_IP), [("body line 1", "E3")])

    def test_deny_term_is_e6(self):
        deny = [re.compile(re.escape(DENY_TERM), re.I)]
        self.assertEqual(self.classes("t", "for zorblax widgets only", deny), [("body line 1", "E6")])

    def test_trailer_shaped_line_is_still_read(self):
        # In a commit, a trailer carries git attribution and is skipped; a PR
        # body has none to protect.
        self.assertEqual(self.classes("t", "Co-Authored-By: A Person <" + BAD_EMAIL + ">"),
                         [("body line 1", "E1")])

    def test_cr_and_crlf_bodies_number_lines_like_lf(self):
        # A bare CR (and a mix of endings) must split too: with an LF-only
        # split, both bodies below would be one line and report "body line 1".
        for body in ("a\rb\rsee " + BAD_HOME, "a\r\nb\rsee " + BAD_HOME, "a\r\nb\r\nsee " + BAD_HOME):
            with self.subTest(body=body[:6]):
                self.assertEqual(self.classes("t", body), [("body line 3", "E2")])

    def test_clean_text_passes(self):
        body = ("Backlog: 82f1faf6\n\nExample: user@example.com in "
                "/" + "home/user/x and 192.0.2.1 (documentation).\n\n"
                "Co-Authored-By: Claude <noreply@anthropic.com>\n\n" + FOOTER)
        self.assertEqual(self.classes("feat(ci): lint PR text (backlog burndown D0000-01)", body), [])

    def test_empty_or_missing_body_passes(self):
        self.assertEqual(self.classes("t", ""), [])
        self.assertEqual(self.classes("t", None), [])


class PrTextCli(unittest.TestCase):
    """The script as the workflow runs it: exit status and redaction."""

    def test_each_rule_fails_and_never_prints_the_value(self):
        cases = [
            ("E1", "t", "contact " + BAD_EMAIL, "", BAD_EMAIL),
            ("E1", "mail " + BAD_EMAIL, "clean", "", BAD_EMAIL),
            ("E2", "t", "see " + BAD_HOME, "", "alice"),
            ("E3", "t", "host at " + BAD_IP, "", BAD_IP),
            ("E6", "t", "for " + DENY_TERM + " only", "other, " + DENY_TERM, DENY_TERM),
        ]
        for cls, title, body, deny, value in cases:
            with self.subTest(cls=cls, title=title):
                rc, out = run_cli(title, body, deny)
                self.assertEqual(rc, 1, out)
                self.assertRegex(out, rf"(?m)^error {cls} (title|body line \d+): ")
                self.assertNotIn(value, out)

    def test_no_line_of_the_text_is_printed(self):
        title = "feat(x): secret-title-marker " + BAD_EMAIL
        body = "secret-body-marker " + BAD_HOME
        rc, out = run_cli(title, body)
        self.assertEqual(rc, 1)
        self.assertNotIn("secret-title-marker", out)
        self.assertNotIn("secret-body-marker", out)

    def test_clean_text_exits_zero_with_no_finding(self):
        rc, out = run_cli("docs(x): clean", "Backlog: 82f1faf6\n\n" + FOOTER)
        self.assertEqual(rc, 0, out)
        self.assertNotRegex(out, r"(?m)^error ")
        self.assertIn("0 error(s)", out)

    def test_deny_list_comes_from_the_environment(self):
        rc, out = run_cli("t", "for " + DENY_TERM, deny="")
        self.assertEqual(rc, 0, out)
        self.assertIn("not configured", out)

    def test_the_main_entry_reads_the_given_environment(self):
        with mock.patch.dict(os.environ, {"COMMIT_LINT_DENY_TERMS": DENY_TERM}):
            env = {"PR_TITLE": "t", "PR_BODY": "for " + DENY_TERM}
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(lint.main_pr_text(env), 1)


class PrTextWorkflow(unittest.TestCase):
    """The workflow must run on every edit and never put PR text in a shell line."""

    @classmethod
    def setUpClass(cls):
        with open(WORKFLOW) as fh:
            cls.text = fh.read()
        try:
            import yaml
        except ImportError:  # the `plan` job installs PyYAML; locally optional
            cls.wf = None
            return
        cls.wf = yaml.safe_load(cls.text)

    def test_runs_on_open_edit_and_push(self):
        if self.wf is None:
            self.skipTest("PyYAML not installed")
        # PyYAML reads the bare key `on` as the boolean True.
        on = self.wf.get("on", self.wf.get(True))
        types = set(on["pull_request"]["types"])
        self.assertLessEqual({"opened", "edited", "synchronize", "reopened"}, types)
        self.assertEqual(self.wf["permissions"], {"contents": "read"})

    def test_text_reaches_the_script_only_through_env(self):
        if self.wf is None:
            self.skipTest("PyYAML not installed")
        steps = [s for job in self.wf["jobs"].values() for s in job["steps"]]
        lint_steps = [s for s in steps if "--pr-text" in s.get("run", "")]
        self.assertEqual(len(lint_steps), 1)
        step = lint_steps[0]
        self.assertEqual(step["env"]["PR_TITLE"], "${{ github.event.pull_request.title }}")
        self.assertEqual(step["env"]["PR_BODY"], "${{ github.event.pull_request.body }}")
        self.assertEqual(step["env"]["COMMIT_LINT_DENY_TERMS"], "${{ secrets.COMMIT_LINT_DENY_TERMS }}")
        for s in steps:
            self.assertNotIn("${{", s.get("run", ""), s.get("name"))

    def test_actions_are_pinned_to_a_full_sha(self):
        for ref in re.findall(r"uses:\s*(\S+)", self.text):
            self.assertRegex(ref, r"@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
