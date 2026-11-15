#!/usr/bin/env python3
"""Pre-commit sensitive-data check.

Scans the content that is about to be committed (the staged blobs, not the
working tree) for:

  * generic AWS identifiers: resource ids (i-, vol-, sg-, vpc-, ...), EC2
    public/private hostnames, and account ids embedded in ARNs or private
    ECR registry hosts;
  * org-specific terms and patterns from a GITIGNORED local list,
    .check_sensitive_local.yaml, because the list of terms we protect is
    itself sensitive. A committed template, .check_sensitive_local.example.yaml,
    documents the format with placeholder values only.

File paths are checked as well as content (a directory or file named after an
internal host leaks as much as its contents). Findings are reported as
path:line plus the rule name (or the entry number in the local list); a path
that itself matches is replaced by a redacted label carrying the blob id. The
matched value is never printed, so the output is safe to land in CI logs or
agent transcripts.

Enable once per clone:   git config core.hooksPath .githooks
Audit the whole tree:    python3 scripts/check_sensitive.py --all-files

Exit codes: 0 clean, 1 findings, 2 configuration error (fails closed).
Standard library only.
"""

import os
import re
import subprocess
import sys

LOCAL_YAML = ".check_sensitive_local.yaml"
TEMPLATE = ".check_sensitive_local.example.yaml"
PREFIX = "check-sensitive"
# Reserved prefix for the template's placeholder entries. Local entries that
# start with it are dropped, so a verbatim copy of the template contributes no
# org terms. The template file itself is scanned like any other file: it is
# the tracked file most likely to receive the real list by mistake, so it
# gets no exemption.
PLACEHOLDER = "example-"

# AWS resource ids: a known prefix followed by 8 (legacy) or 17 hex digits.
AWS_RESOURCE_ID = re.compile(
    r"\b(?:i|ami|snap|vol|sg|subnet|vpc|eni|igw|nat|rtb|acl|eipalloc|tgw"
    r"|vpce|pcx|lt|fs|dopt)-(?:[0-9a-f]{17}|[0-9a-f]{8})\b"
)
# EC2 hostnames encode the address: ec2-A-B-C-D.<...>.amazonaws.com (public)
# and ip-A-B-C-D[.ec2.internal | .<region>.compute.internal] (private).
EC2_HOSTNAME = re.compile(r"\b(?:ec2|ip)-\d{1,3}(?:-\d{1,3}){3}\b")
# The 12-digit account field of an ARN (arn:partition:service:region:account:).
ARN_ACCOUNT_ID = re.compile(r"\barn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}:")
# A private ECR registry host carries the account id:
# <account>.dkr.ecr.<region>.amazonaws.com
ECR_REGISTRY = re.compile(r"\b\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com")

GENERIC_RULES = [
    ("aws-resource-id", AWS_RESOURCE_ID),
    ("ec2-hostname", EC2_HOSTNAME),
    ("aws-arn-account-id", ARN_ACCOUNT_ID),
    ("aws-ecr-registry", ECR_REGISTRY),
]


class ConfigError(Exception):
    pass


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, check=True).stdout


def _unquote(raw, lineno):
    value = raw.strip()
    if value[:1] in ("'", '"'):
        quote = value[0]
        if len(value) < 2 or value[-1] != quote:
            raise ConfigError("line %d: unterminated quoted value" % lineno)
        value = value[1:-1]
        if quote == "'":
            value = value.replace("''", "'")
        elif "\\" in value:
            raise ConfigError(
                "line %d: use single quotes for values containing backslashes"
                % lineno
            )
    else:
        value = re.sub(r"\s+#.*$", "", value).strip()
    if not value:
        raise ConfigError("line %d: empty entry" % lineno)
    return value


def parse_local_yaml(text):
    """Parse the supported YAML subset: top-level `terms:` / `patterns:` keys,
    each followed by `- value` items. Anything else is an error, so a list we
    cannot read is never mistaken for an empty one."""
    lists = {"terms": [], "patterns": []}
    current = None
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key = re.fullmatch(r"(terms|patterns):\s*(\[\s*\])?\s*(#.*)?", line.rstrip())
        if key:
            current = key.group(1)
            continue
        item = re.fullmatch(r"\s+-\s+(.*)", line.rstrip())
        if item and current is not None:
            lists[current].append(_unquote(item.group(1), lineno))
            continue
        raise ConfigError(
            "line %d: expected `terms:` / `patterns:` or an indented `- value` item"
            % lineno
        )
    patterns = []
    for n, pattern in enumerate(lists["patterns"], 1):
        try:
            patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            raise ConfigError("patterns entry #%d is not a valid regex" % n)
    terms = [t.casefold() for t in lists["terms"]]
    # Drop placeholders AFTER validation (a malformed placeholder still fails
    # closed) and BEFORE numbering, so "org term #N" counts real entries only.
    kept_terms = [t for t in terms if not t.startswith(PLACEHOLDER)]
    kept_patterns = [p for p in patterns
                     if not p.pattern.casefold().startswith(PLACEHOLDER)]
    dropped = len(terms) - len(kept_terms) + len(patterns) - len(kept_patterns)
    return kept_terms, kept_patterns, dropped


def find_local_yaml():
    """The local list lives at the checkout root. Linked worktrees fall back to
    the main checkout's copy, since the file is gitignored and per-clone."""
    top = git("rev-parse", "--show-toplevel").decode().strip()
    candidates = [os.path.join(top, LOCAL_YAML)]
    common = git("rev-parse", "--path-format=absolute", "--git-common-dir").decode().strip()
    if os.path.basename(common) == ".git":
        candidates.append(os.path.join(os.path.dirname(common), LOCAL_YAML))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def staged_blobs():
    """(path, blob sha) for every added/copied/modified/type-changed file in
    the index the commit will be made from (honours GIT_INDEX_FILE, e.g.
    `commit -a`). Type changes (T) cover a symlink or gitlink replaced by a
    regular file, whose new content is otherwise never seen."""
    raw = git("diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames",
              "--diff-filter=ACMT")
    fields = raw.split(b"\0")
    out = []
    for header, path in zip(fields[0::2], fields[1::2]):
        if not header:
            continue
        _, new_mode, _, new_sha, _ = header.decode().lstrip(":").split(" ")
        if new_mode != "160000":  # skip submodule gitlinks
            out.append((path.decode("utf-8", "surrogateescape"), new_sha))
    return out


def tracked_blobs():
    out = []
    for entry in git("ls-files", "-s", "-z").split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, sha, _stage = meta.decode().split(" ")
        if mode != "160000":
            out.append((path.decode("utf-8", "surrogateescape"), sha))
    return out


def scan_line(line, terms, patterns):
    """Names of every rule / local entry that matches one line of text."""
    hits = [name for name, rule in GENERIC_RULES if rule.search(line)]
    folded = line.casefold()
    hits += ["org term #%d" % n for n, term in enumerate(terms, 1) if term in folded]
    hits += ["org pattern #%d" % n for n, pattern in enumerate(patterns, 1)
             if pattern.search(line)]
    return hits


def scan_text(path, text, terms, patterns):
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for name in scan_line(line, terms, patterns):
            findings.append((path, lineno, name))
    return findings


def scan_blob(path, sha, terms, patterns):
    """Findings for one file: its path, then its content. A path that matches
    is itself sensitive, so every line reported for that file shows a
    redacted label (with the blob id, enough to locate it via
    `git ls-files -s`) instead of the path."""
    path_hits = scan_line(path, terms, patterns)
    label = "<path redacted, blob %s>" % sha[:12] if path_hits else path
    findings = [(label, None, name + " (in path)") for name in path_hits]
    data = git("cat-file", "blob", sha)
    if b"\0" not in data:  # skip binary content; its path is still checked
        findings.extend(scan_text(label, data.decode("utf-8", "replace"),
                                  terms, patterns))
    return findings


def main(argv):
    all_files = "--all-files" in argv[1:]
    unknown = [a for a in argv[1:] if a != "--all-files"]
    if unknown:
        print("usage: check_sensitive.py [--all-files]", file=sys.stderr)
        return 2

    terms, patterns = [], []
    config = find_local_yaml()
    if config is None:
        why = "no %s found" % LOCAL_YAML
    else:
        try:
            with open(config, encoding="utf-8") as fh:
                terms, patterns, dropped = parse_local_yaml(fh.read())
        except (ConfigError, OSError, UnicodeDecodeError) as exc:
            print("%s: cannot read %s: %s -- refusing to continue"
                  % (PREFIX, LOCAL_YAML, exc), file=sys.stderr)
            return 2
        why = "%s lists no org terms or patterns" % LOCAL_YAML
        if dropped:
            # Count only: the entries themselves are never printed.
            print("%s: ignoring %d placeholder entr%s (prefix %r) in %s"
                  % (PREFIX, dropped, "y" if dropped == 1 else "ies",
                     PLACEHOLDER, LOCAL_YAML), file=sys.stderr)
    if not terms and not patterns:
        # Same warning for a missing and an empty list: both mean generic-only
        # coverage, and the operator must not believe org terms are checked.
        print(
            "%s: warning: %s; checking generic AWS rules only. Copy %s to %s "
            "and add your org terms." % (PREFIX, why, TEMPLATE, LOCAL_YAML),
            file=sys.stderr,
        )

    findings = []
    for path, sha in (tracked_blobs() if all_files else staged_blobs()):
        findings.extend(scan_blob(path, sha, terms, patterns))

    for path, lineno, rule in findings:
        where = path if lineno is None else "%s:%d" % (path, lineno)
        print("%s: %s: %s" % (PREFIX, where, rule), file=sys.stderr)
    if findings:
        print(
            "%s: %d finding(s). Remove them%s, or bypass deliberately with "
            "`git commit --no-verify`." % (
                PREFIX, len(findings), "" if all_files else " from the staged content"),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
