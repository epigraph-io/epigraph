#!/usr/bin/env python3
"""Lint the tree for references a reader of this PUBLIC repository cannot follow
(stdlib only).

    .github/scripts/docs-hygiene-lint.py [--root <dir>]

Reports, per file and line, and exits 1 on any finding:
  D1 a developer's home-directory path in a Markdown file: `/home/<name>/` or
     `/Users/<name>/`, with the trailing slash. The pattern and the allowed
     generic account names are the commit-message lint's E2
     (commit-message-lint.py), loaded from that script so the two cannot drift;
     so a bare `/home/<name>` at the end of a word, and any `~/` path, are not D1.
  D2 a citation of an assistant's private memory file: the words "user-memory"
     or "auto-memory", or a memory-note filename (`feedback_<x>.md`,
     `project_<x>.md`, `reference_<x>.md`, `user_<x>.md`). The note is on one
     developer's machine; state the rule it holds instead.
  D3 a citation of a file outside this repository that a reader cannot open:
     the private host repository's files (`release/epiclaw/...`, its `deploy/`
     prompts, `epiclaw-host/src/...`, or the host named beside a quoted source
     file such as `container.rs`), or the operator's private notes directory
     under `~/`. State what the file says instead.

Not scanned, on purpose:
  docs/superpowers/ (dated historical plans, specs and reports, kept as written)
  and docs/tenancy/progress.json (a historical run log);
  this lint, its tests and the commit-message lint and its self-test, which
  carry these patterns as fixtures;
  migrations/048_label_provenance_telemetry.sql, an applied migration, which
  cannot be edited (its D3 citation stays).
D1 covers Markdown only: home paths in code defaults, examples and experiments
are a separate surface.

Files are the tracked files (`git ls-files`) when <root> is a git work tree,
otherwise every file under <root>. The account name in a D1 finding is redacted
(CI logs are public). Exit 0 when clean.
"""
import importlib.util
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _commit_lint():
    path = os.path.join(HERE, "commit-message-lint.py")
    spec = importlib.util.spec_from_file_location("commit_message_lint", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_CML = _commit_lint()
# E2 of the commit-message lint: group 1 is home|Users, group 2 the account.
HOME_RE = _CML.HOME_RE
HOME_OK_NAMES = _CML.HOME_OK_NAMES

MEMORY_RE = re.compile(
    r"\b(?:user|auto)-memory\b|\b(?:feedback|project|reference|user)_[a-z0-9_]+\.md\b",
    re.I,
)
# The operator's private notes directory, built from parts so this source never
# carries the literal a pre-push scan looks for.
_PRIVATE_NOTES = re.escape("~/" + "ops-" + "private/")
# Matched over the whole file, so a citation wrapped across a comment line
# (`... epiclaw-host's\n///   `deploy/` ...`) is still one match.
_HOST_THEN = r"epiclaw-host\S*\s+(?:(?://+|#)\s*)?"
PRIVATE_REPO_RE = re.compile(
    r"release/epiclaw/"
    r"|epiclaw-host/src/"
    + "|" + _HOST_THEN + r"`deploy/`"
    + "|" + _HOST_THEN + r"`[\w./-]+\.(?:rs|py|ts|js|sh|toml|md)`"
    + "|" + _PRIVATE_NOTES
)

SKIP_PREFIXES = ("docs/superpowers/",)
SKIP_FILES = {
    "docs/tenancy/progress.json",
    ".github/scripts/docs-hygiene-lint.py",
    ".github/scripts/tests/test_docs_hygiene_lint.py",
    ".github/scripts/commit-message-lint.py",
    ".github/scripts/test-commit-message-lint.sh",
    # Applied (in production): never edited, so its header citation stays.
    "migrations/048_label_provenance_telemetry.sql",
}
# Text files scanned for D2 and D3; D1 is Markdown only.
TEXT_EXTS = (".md", ".rs", ".py", ".sh", ".toml", ".yml", ".yaml", ".sql", ".js", ".json")
WALK_SKIP_DIRS = {".git", "target", "node_modules", ".claude", ".sqlx"}


def list_files(root):
    """Repo-relative paths, '/'-separated."""
    try:
        out = subprocess.run(
            ["git", "-C", root, "ls-files", "-z"],
            check=True,
            capture_output=True,
        ).stdout
        if out:
            return [p for p in out.decode("utf-8", "replace").split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        pass
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in WALK_SKIP_DIRS]
        for name in filenames:
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            files.append(rel.replace(os.sep, "/"))
    return files


def skipped(rel):
    return rel in SKIP_FILES or rel.startswith(SKIP_PREFIXES)


def scan_text(rel, text):
    """Return [(line number, class, redacted description)] for one file."""
    found = []
    markdown = rel.endswith(".md")
    for n, line in enumerate(text.split("\n"), 1):
        if markdown:
            for m in HOME_RE.finditer(line):
                if m.group(2) not in HOME_OK_NAMES:
                    found.append((n, "D1", f"home-directory path /{m.group(1)}/<redacted>/"))
        if MEMORY_RE.search(line):
            found.append((n, "D2", "citation of a private assistant-memory file"))
    for m in PRIVATE_REPO_RE.finditer(text):
        n = text.count("\n", 0, m.start()) + 1
        found.append((n, "D3", "citation of a private file outside this repository"))
    return sorted(found)


def scan(root):
    findings = []
    for rel in sorted(list_files(root)):
        if skipped(rel) or not rel.endswith(TEXT_EXTS):
            continue
        try:
            with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for n, cls, desc in scan_text(rel, text):
            findings.append((rel, n, cls, desc))
    return findings


def main(argv):
    root = "."
    if len(argv) == 3 and argv[1] == "--root":
        root = argv[2]
    elif len(argv) != 1:
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 2
    findings = scan(root)
    for rel, n, cls, desc in findings:
        print(f"{rel}:{n}: {cls} {desc}")
    if findings:
        print(f"docs-hygiene-lint: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("docs-hygiene-lint: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
