#!/usr/bin/env python3
"""Lint the messages of the commits a change adds (CI gate, stdlib only).

    .github/scripts/commit-message-lint.py <base> <head>
    .github/scripts/commit-message-lint.py --cited-shas <base> <head>

Reads the NON-MERGE commits in <base>..<head> (only <head> when <base> is empty
or all zeros) and reports per commit. ERRORS fail the run (exit 1):
  E1 an e-mail address outside a trailer line;
  E2 a developer's home-directory path;
  E3 an IP-encoding wildcard-DNS host or a bare public IPv4;
  E4 a Verification section that records something not run ("Not run",
     "CI to confirm", "to be run") with no line starting `Unverified:`;
  E5 a commit that changes a SECURITY DEFINER function while its Verification
     records no run (or it has no Verification section). `Unverified:` does not
     silence E5; a LATER commit in the same range that names this commit's sha
     (7+ hex characters) does, the "follow-up commit that cites it";
  E6 a term from the private deny-list (customer and deployment names), read
     from the COMMIT_LINT_DENY_TERMS environment variable (newline- or
     comma-separated; CI fills it from a repository secret) and from the file
     named by COMMIT_LINT_DENY_FILE. The list is never committed: a public
     deny-list of customer names would publish them.
WARNINGS never change the exit status: W2 a subject outside
`<type>(<scope>)?: <text>`, W3 none of the Evidence/Reasoning/Verification
sections. Offending values are NEVER printed (public CI logs): each finding is
redacted, and a subject that itself holds an error is withheld. Run from the
repository root.

`--cited-shas` runs ONLY W4 and always exits 0 (a workflow on every push to
main runs it, .github/workflows/cited-sha-check.yml): W4 a token in a message
that looks like a commit sha (9-40 lowercase hex characters holding a digit and
a letter, not part of a UUID or a longer hex run and not right after `@`; or
7-8 hex characters right after `commit(s)`, `commit hash`, `sha(s)`,
`revert(s|ed)` or `cherry-pick(s|ed)`, also through a list such as "commits a, b
and c") that names no commit REACHABLE from <head>. A bare 7-8 hex token is not
read: it cannot be told from an 8-hex backlog or claim-id prefix. Reachability, not `git cat-file -e`: a full clone holds
every branch's objects, so a sha that lives only on an unmerged or rebased-away
branch still resolves there but is not on main. Trailer lines are not read.
The rule it enforces: cite a commit by sha only once it is on main (or earlier
in the same change); cite anything else by PR number and subject.
"""
import bisect
import os
import ipaddress
import re
import subprocess
import sys

# A candidate e-mail address; group 1 is its domain.
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# Domains whose addresses are placeholders or bot identities, never a person.
EMAIL_OK_DOMAINS = {"example.com", "example.org", "users.noreply.github.com"}
# The one allowed full address outside those domains.
EMAIL_OK_ADDRS = {"noreply@anthropic.com"}
# Trailer lines carry attribution, so e-mail addresses there are not scanned.
TRAILER_RE = re.compile(r"^(Co-Authored-By|Signed-off-by|Reviewed-by):", re.I)
# A home-directory path with a trailing slash; group 2 is the account name.
HOME_RE = re.compile(r"/(home|Users)/([A-Za-z0-9_.-]+)/")
# Generic account names that identify nobody.
HOME_OK_NAMES = {"user", "runner", "dev", "you", "me", "USER"}
# Wildcard-DNS host encoding an address (same services as the Rust source guard
# crates/epigraph-mcp/tests/no_deployment_host_literals.rs; any such name fails,
# documentation ranges included, exactly as there).
WILDCARD_RE = re.compile(r"(?<![0-9])[0-9]+-[0-9]+-[0-9]+-[0-9]+\.(?:nip|sslip|xip)\.io\b")
# A dotted quad not embedded in a longer number or dotted version string.
IPV4_RE = re.compile(r"(?<![0-9.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9]|\.[0-9])")
# RFC 5737 documentation blocks, allowed in messages.
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
# Subject shape of the Epistemic Commit Protocol.
SUBJECT_RE = re.compile(r"^(feat|fix|refactor|perf|test|docs|chore|security)(\([^)\s][^)]*\))?: \S")
# Subjects exempt from W2.
SUBJECT_EXEMPT = ("Merge ", "Revert ", "merge(", "style(")
# The three protocol sections, as they appear in a message body.
SECTIONS = ("**Evidence:**", "**Reasoning:**", "**Verification:**")
# Phrases that say a verification was not actually performed.
NOT_RUN_RE = re.compile(r"Not run|not run|CI to confirm|to be run")
# Marker a commit carries when its Verification records something not run: a
# line starting `Unverified:`, also as a list item (`- Unverified:`).
UNVERIFIED_RE = re.compile(r"^\s*(?:[-*]\s+)?Unverified:", re.M)
# Next bold section heading, which ends the Verification section.
HEADING_RE = re.compile(r"^\*\*[A-Za-z ]+:\*\*", re.M)
# Start of a function definition in SQL, and the attribute E5 looks for.
CREATE_FN_RE = re.compile(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b", re.I)
DEFINER_RE = re.compile(r"SECURITY\s+DEFINER", re.I)
# A unified-diff hunk header: old start/count, new start/count.
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# W4: a sha-like token. Not inside a word, a UUID (hyphen) or a longer hex run
# such as a 64-hex content hash (the 40 cap plus the boundary), and not right
# after `@` (an action pin or another repository's revision).
CITED_SHA_RE = re.compile(r"(?<![0-9A-Za-z_@-])([0-9a-f]{9,40})(?![0-9A-Za-z_-])")
# W4: a short sha (7-8 hex) counts only after a word that names a commit
# ("commit", "commit hash", "sha", "reverts", "cherry-picked"), also through a
# list of hex tokens ("commits a, b and c"). A bare 8-hex token elsewhere is
# most often a backlog or claim-id prefix, which no git object can resolve.
SHA_LIST_RE = re.compile(
    r"\b(?:commits?(?:\s+hash(?:es)?)?|shas?|reverts?|reverted|cherry-pick(?:s|ed)?)\b"
    r"[\s:`(]*(`?[0-9a-f]{7,40}`?(?:\s*(?:[,;/&]|\band\b|\bor\b)\s*`?[0-9a-f]{7,40}`?)*)"
    r"(?![0-9A-Za-z_-])", re.I)
SHORT_HEX_RE = re.compile(r"(?<![0-9A-Za-z_@-])([0-9a-f]{7,8})(?![0-9A-Za-z_-])", re.I)
# W4: a hex run labelled as a content hash just before it ("sha256 <hex>",
# "blake3: <hex>", "hash=<hex>") is a digest, not a commit; "commit hash" is not.
HASH_LABEL_RE = re.compile(
    r"(?:sha-?256|sha-?512|blake3|md5|(?<!commit\s)(?<!commit-)hash)[\s:=]*`?$", re.I)


def is_public_ipv4(text):
    """True for a valid dotted quad outside documentation/loopback/private/0.0.0.0."""
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_private or ip == ipaddress.IPv4Address("0.0.0.0"):
        return False
    return not any(ip in net for net in DOC_NETS)


def commits(base, head):
    """Yield (sha, subject, message) for each non-merge commit in the range."""
    if not base or re.fullmatch(r"0+", base):
        args = ["git", "log", "--no-walk", "--no-merges", head]
    else:
        args = ["git", "log", "--no-merges", f"{base}..{head}"]
    out = subprocess.run(args + ["--format=%H%x1f%B%x1e"], check=True,
                         capture_output=True, text=True).stdout
    for rec in out.split("\x1e"):
        if rec.strip():
            sha, _, msg = rec.lstrip("\n").partition("\x1f")
            yield sha, msg.strip("\n").split("\n", 1)[0], msg


def deny_terms():
    """The private deny-list: env COMMIT_LINT_DENY_TERMS plus COMMIT_LINT_DENY_FILE."""
    raw = os.environ.get("COMMIT_LINT_DENY_TERMS", "")
    path = os.environ.get("COMMIT_LINT_DENY_FILE", "")
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            raw += "\n" + "\n".join(l for l in fh.read().splitlines() if not l.lstrip().startswith("#"))
    terms = [t.strip() for t in re.split(r"[\n,]", raw) if t.strip()]
    return [re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])", re.I) for t in terms]


DENY = deny_terms()


def scan_deny(line):
    """Return the redacted E6 findings of one line (any line, trailers included)."""
    return [("E6", f"deny-listed term (entry {i + 1} of the private list)")
            for i, rx in enumerate(DENY) if rx.search(line)]


def verification_not_run(message):
    """True when the Verification section records something not run, or is absent."""
    body = "\n".join(l for l in message.split("\n") if not TRAILER_RE.match(l))
    pos = body.find(SECTIONS[2])
    if pos < 0:
        return None  # no section at all
    rest = body[pos + len(SECTIONS[2]):]
    nxt = HEADING_RE.search(rest)
    return bool(NOT_RUN_RE.search(rest[:nxt.start()] if nxt else rest))


def definer_ranges(text):
    """1-based [start, end] line ranges of the CREATE FUNCTION statements in an
    SQL text whose statement carries SECURITY DEFINER. A statement runs from its
    CREATE FUNCTION line to the line before the next CREATE FUNCTION (or EOF): a
    deliberate over-approximation, since a function's trailing ALTER/GRANT lines
    then count as part of it."""
    lines = text.split("\n")
    starts = [i for i, l in enumerate(lines) if CREATE_FN_RE.match(l)]
    out = []
    for k, st in enumerate(starts):
        end = starts[k + 1] - 1 if k + 1 < len(starts) else len(lines) - 1
        if DEFINER_RE.search("\n".join(lines[st:end + 1])):
            out.append((st + 1, end + 1))
    return out


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True).stdout


def touches_definer(sha):
    """True when the commit adds or removes a line inside a SECURITY DEFINER
    function of a *.sql file (post-image for added lines, pre-image for removed)."""
    diff = git("show", "--format=", "--unified=0", "--no-color", sha, "--", "*.sql")
    files = []  # [old_path or None, new_path or None, [hunks]]
    old_path = None
    for line in diff.split("\n"):
        if line.startswith("--- "):
            old_path = line[6:] if line.startswith("--- a/") else None
        elif line.startswith("+++ "):
            files.append([old_path, line[6:] if line.startswith("+++ b/") else None, []])
        elif files:
            m = HUNK_RE.match(line)
            if m:
                files[-1][2].append((int(m[1]), int(m[2] or 1), int(m[3]), int(m[4] or 1)))
    for old_p, new_p, hunks in files:
        new_r = definer_ranges(git("show", f"{sha}:{new_p}")) if new_p else []
        old_r = definer_ranges(git("show", f"{sha}^:{old_p}")) if old_p else []
        for o0, oc, n0, nc in hunks:
            if any(a <= ln <= b for ln in range(n0, n0 + nc) for a, b in new_r):
                return True
            if any(a <= ln <= b for ln in range(o0, o0 + oc) for a, b in old_r):
                return True
    return False


def scan_line(line):
    """Return the redacted E1-E3 findings of one non-trailer line."""
    found = []
    for m in EMAIL_RE.finditer(line):
        addr = m.group(0)
        # `role@10.0.0.5` in a connection string is not an address; a public
        # IP there is still caught below as E3.
        if re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", m.group(1)):
            continue
        if m.group(1).lower() not in EMAIL_OK_DOMAINS and addr.lower() not in EMAIL_OK_ADDRS:
            found.append(("E1", f"e-mail address ({addr[0]}..., {len(addr)} chars)"))
    for m in HOME_RE.finditer(line):
        if m.group(2) not in HOME_OK_NAMES:
            found.append(("E2", f"home-directory path /{m.group(1)}/<redacted>/"))
    if WILDCARD_RE.search(line):
        found.append(("E3", "wildcard-DNS host that encodes an address <ip-host>"))
    for m in IPV4_RE.finditer(line):
        if is_public_ipv4(m.group(1)):
            found.append(("E3", "bare public IPv4 address <ip-host>"))
    return found


def lint(subject, message):
    """Return (errors, warnings) as lists of (class, redacted description)."""
    non_trailer = [l for l in message.split("\n") if not TRAILER_RE.match(l)]
    errors = [f for line in non_trailer for f in scan_line(line)]
    errors += [f for line in message.split("\n") for f in scan_deny(line)]
    warnings = []
    if verification_not_run(message) and not UNVERIFIED_RE.search(message):
        errors.append(("E4", "Verification records something not run and the message has no Unverified: line"))
    if not subject.startswith(SUBJECT_EXEMPT) and not SUBJECT_RE.match(subject):
        warnings.append(("W2", "subject does not match <type>(<scope>)?: <text>"))
    if not any(s in message for s in SECTIONS):
        warnings.append(("W3", "none of the Evidence/Reasoning/Verification sections"))
    return errors, warnings


def cited_shas(message):
    """The sha-like tokens a message cites (W4), in order, trailers skipped. A
    token needs a digit and a letter: an all-digit run is a number or a date,
    an all-letter one a word. A 32-hex run is a hyphenless UUID or an MD5, and a
    run labelled as a hash is a digest; neither is read as a sha."""
    found = []
    for line in message.split("\n"):
        if TRAILER_RE.match(line):
            continue
        hits = [(m.start(1), m.group(1)) for m in CITED_SHA_RE.finditer(line)]
        for lm in SHA_LIST_RE.finditer(line):
            hits += [(lm.start(1) + m.start(1), m.group(1))
                     for m in SHORT_HEX_RE.finditer(lm.group(1))]
        spans = []
        for start, tok in hits:
            tok = tok.lower()
            if not (re.search(r"[0-9]", tok) and re.search(r"[a-f]", tok)):
                continue
            if len(tok) == 32 or HASH_LABEL_RE.search(line[:start]):
                continue
            spans.append((start, tok))
        found += [tok for _, tok in sorted(set(spans))]
    return found


def reachable_from(head):
    """Sorted full shas of every commit reachable from <head>, for prefix lookup."""
    out = subprocess.run(["git", "rev-list", head], check=True,
                         capture_output=True, text=True).stdout
    return sorted(out.split())


def resolves(token, reachable):
    """True when <token> is a prefix of a commit in the sorted <reachable> list."""
    i = bisect.bisect_left(reachable, token)
    return i < len(reachable) and reachable[i].startswith(token)


def main_cited(base, head):
    """`--cited-shas`: report W4 for each cited sha not reachable from <head>."""
    reachable = reachable_from(head)
    n = n_tok = n_warn = 0
    for sha, subject, message in commits(base, head):
        n += 1
        shown = ("<subject withheld: holds an error or a cited token>"
                 if scan_line(subject) or scan_deny(subject) or cited_shas(subject)
                 else subject[:72])
        for k, tok in enumerate(cited_shas(message), 1):
            n_tok += 1
            if not resolves(tok, reachable):
                n_warn += 1
                # The token itself is never printed: a hex run could be a secret.
                print(f"warning W4 {sha[:10]} [{shown}]: cited sha-like token #{k} "
                      f"({len(tok)} hex chars) names no commit reachable from the scanned head; "
                      "cite work not on main by PR number and subject")
    print(f"commit-message-lint --cited-shas: {n} commit(s), {n_tok} cited token(s), "
          f"{n_warn} warning(s)")
    return 0


def main(argv):
    if len(argv) == 4 and argv[1] == "--cited-shas":
        return main_cited(argv[2], argv[3])
    if len(argv) != 3:
        print("usage: commit-message-lint.py [--cited-shas] <base> <head>", file=sys.stderr)
        return 2
    n = n_err = n_warn = 0
    print(f"commit-message-lint: private deny-list {'configured' if DENY else 'not configured'}")
    rows = list(commits(argv[1], argv[2]))  # newest first
    for idx, (sha, subject, message) in enumerate(rows):
        n += 1
        errors, warnings = lint(subject, message)
        if verification_not_run(message) is not False and touches_definer(sha):
            cited = any(sha[:7] in m for _, _, m in rows[:idx])
            if not cited:
                errors.append(("E5", "changes a SECURITY DEFINER function but its Verification records no run; "
                               "add a later commit that names this sha with the test result"))
        n_err += len(errors)
        n_warn += len(warnings)
        shown = ("<subject withheld: holds an error>" if scan_line(subject) or scan_deny(subject)
                 else subject[:72])
        for cls, text in errors + warnings:
            level = "error" if cls[0] == "E" else "warning"
            print(f"{level} {cls} {sha[:10]} [{shown}]: {text}")
    print(f"commit-message-lint: {n} commit(s), {n_err} error(s), {n_warn} warning(s)")
    return 1 if n_err else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
