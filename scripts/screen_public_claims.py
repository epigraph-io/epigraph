#!/usr/bin/env python3
"""Screen public claims for text that should not be readable without a login.

Read-only. Selects every public claim (`visibility = 'public'`), current or
superseded, and flags the ones a reviewer should look at before guest reads
are turned on, so they can be made private first (`epigraph-operator
restrict-claims --claims-file <ids file>`). Superseded claims are screened
too: the guest claim card reads a claim by id with no `is_current` filter, so
a superseded public claim is as readable as a current one. It never writes:
the session is set read-only before the first query.

Reasons (a claim gets every one that applies):

  verbatim text (content only)
    long_content        the content is longer than 300 characters (a lifted
                        passage rather than an atomic claim);
    long_quoted_span    a span inside quote marks ("...", curly double or
                        single quotes, guillemets) holds more than 40 words.
  internal identifiers (content and labels)
    uuid_like_id        a full 8-4-4-4-12 hex identifier;
    internal_hostname   localhost, a loopback/private/link-local IPv4
                        address, a name under .internal/.local/.lan/.corp/
                        .intranet/.localdomain/.home.arpa, or an EC2 private
                        host name (scripts/check_sensitive.py's pattern);
    private_path        a home-directory path (/home/<u>/, /Users/<u>/,
                        /root/, ~/, C:\\Users\\, and their file:// URLs),
                        a directory named `*-private/`, or a term from
                        --private-markers;
    private_group_name  a name from --private-groups.
  personal data (content and labels)
    email_address, phone_number (North American or +country forms),
    street_address (a number, capitalised words and a street suffix, or a
    P.O. box).

The private names and markers are read from files the operator supplies and
are never built in: the list of names to protect is itself private. Both
files are required (either may be empty), so a run cannot silently skip the
operator's private directory names. One term per line; blank lines and `#`
comments are ignored; matching is case-insensitive on whole words.

Output:
  --out FILE (default stdout)  one JSON line per flagged claim,
                               {"claim_id": ..., "is_current": ..., "reasons": [...]};
  --claims-file-out FILE       the flagged ids, one per line, in the format
                               restrict-claims --claims-file reads;
  stderr                       `summary: {"scanned", "flagged", "by_reason"}`.

Nothing else is printed: never a claim's content or labels (a hit's included:
the reason codes say what to look at), never a matched term, and never the
DSN (a connection error is reported without its libpq detail, which can carry
the DSN).

DSN: `--database-url` only, and required. It is never read from the
environment: an exported application or maintenance DSN belongs to another
job and is usually privileged. Give it a read-only login.

Usage:
    python3 scripts/screen_public_claims.py --database-url <read-only DSN> \\
        --private-groups groups.txt --private-markers markers.txt \\
        --out hits.jsonl --claims-file-out restrict-candidates.txt
"""
from __future__ import annotations

import argparse
import json
import re
import sys

import psycopg2

from check_sensitive import EC2_HOSTNAME

REASONS = (
    "long_content",
    "long_quoted_span",
    "uuid_like_id",
    "internal_hostname",
    "private_path",
    "private_group_name",
    "email_address",
    "phone_number",
    "street_address",
)

MAX_CONTENT_CHARS = 300
MAX_QUOTED_WORDS = 40

QUOTED = re.compile(
    r'"([^"]+)"|\u201c([^\u201d]+)\u201d|\u2018([^\u2019]+)\u2019|\u00ab([^\u00bb]+)\u00bb'
)
UUID_LIKE = re.compile(
    r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])",
    re.I,
)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
INTERNAL_HOST = re.compile(
    r"(?<![\w.])(?:"
    r"localhost"
    rf"|(?:10|127)\.{_OCTET}\.{_OCTET}\.{_OCTET}"
    rf"|172\.(?:1[6-9]|2\d|3[01])\.{_OCTET}\.{_OCTET}"
    rf"|192\.168\.{_OCTET}\.{_OCTET}"
    rf"|169\.254\.{_OCTET}\.{_OCTET}"
    r"|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*"
    r"\.(?:internal|local|lan|corp|intranet|localdomain|home\.arpa)"
    r")(?![\w-]|\.\d)",
    re.I,
)
PRIVATE_PATH = re.compile(
    r"(?:(?:(?<![\w.~/])|(?<=file://))(?:/home/|/Users/|/root/)[\w.-]"
    r"|(?<![\w/])~/[\w.-]"
    r"|\b[A-Za-z]:\\Users\\"
    r"|(?<![\w-])[\w.]+(?:-[\w.]+)*-private/)",
)
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
PHONE_NANP = re.compile(r"(?<![\w.])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\w])")
PHONE_INTL = re.compile(r"(?<![\w+])\+\d[\d\s().-]{6,}\d(?![\w])")
STREET_SUFFIX = (
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|"
    r"Place|Pl|Terrace|Way|Parkway|Pkwy|Highway|Hwy|Square|Sq)"
)
STREET = re.compile(
    rf"\b\d{{1,6}}\s+(?:[A-Z][A-Za-z'-]*\s+){{1,4}}{STREET_SUFFIX}\b"
    r"|\bP\.?\s?O\.?\s+Box\s+\d+",
)


def compile_terms(terms):
    """Whole-word, case-insensitive patterns for operator-supplied terms."""
    out = []
    for term in terms:
        term = term.strip()
        if not term or term.startswith("#"):
            continue
        words = [re.escape(w) for w in term.split()]
        out.append(re.compile(r"(?<!\w)" + r"\s+".join(words) + r"(?!\w)", re.I))
    return out


def read_terms(path):
    with open(path, encoding="utf-8") as fh:
        return compile_terms(fh.read().splitlines())


def _any(patterns, texts):
    return any(p.search(t) for p in patterns for t in texts)


def _phone(text):
    if PHONE_NANP.search(text):
        return True
    for m in PHONE_INTL.finditer(text):
        digits = sum(c.isdigit() for c in m.group(0))
        if 8 <= digits <= 15:
            return True
    return False


def screen(content, labels, private_groups, private_markers):
    """The reason codes for one claim, in REASONS order."""
    content = content or ""
    texts = [content, *[label for label in (labels or []) if label]]
    hit = set()
    if len(content) > MAX_CONTENT_CHARS:
        hit.add("long_content")
    for m in QUOTED.finditer(content):
        span = next(g for g in m.groups() if g is not None)
        if len(span.split()) > MAX_QUOTED_WORDS:
            hit.add("long_quoted_span")
            break
    if _any([UUID_LIKE], texts):
        hit.add("uuid_like_id")
    if _any([INTERNAL_HOST, EC2_HOSTNAME], texts):
        hit.add("internal_hostname")
    if _any([PRIVATE_PATH, *private_markers], texts):
        hit.add("private_path")
    if _any(private_groups, texts):
        hit.add("private_group_name")
    if _any([EMAIL], texts):
        hit.add("email_address")
    if any(_phone(t) for t in texts):
        hit.add("phone_number")
    if _any([STREET], texts):
        hit.add("street_address")
    return [r for r in REASONS if r in hit]


SELECT_SQL = """
SELECT id::text, content, labels, is_current IS TRUE
  FROM claims
 WHERE visibility = 'public'
 ORDER BY id
"""


def run(conn, private_groups, private_markers, out, ids_out, err):
    """Screen every public claim on `conn`, current or not; return the counts."""
    conn.set_session(readonly=True)
    counts = {"scanned": 0, "flagged": 0, "by_reason": dict.fromkeys(REASONS, 0)}
    if ids_out is not None:
        ids_out.write("# public claims flagged by screen_public_claims.py\n")
    cur = conn.cursor(name="screen_public_claims")
    cur.itersize = 2000
    try:
        cur.execute(SELECT_SQL)
        for claim_id, content, labels, is_current in cur:
            counts["scanned"] += 1
            reasons = screen(content, labels, private_groups, private_markers)
            if not reasons:
                continue
            counts["flagged"] += 1
            for r in reasons:
                counts["by_reason"][r] += 1
            out.write(json.dumps(
                {"claim_id": claim_id, "is_current": is_current, "reasons": reasons}
            ) + "\n")
            if ids_out is not None:
                ids_out.write(claim_id + "\n")
    finally:
        cur.close()
        conn.rollback()
    err.write("summary: " + json.dumps(counts, sort_keys=True) + "\n")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--database-url",
        required=True,
        help="DSN of a read-only login. Required; never read from the environment.",
    )
    parser.add_argument(
        "--private-groups",
        required=True,
        help="File of private group names, one per line (may be empty).",
    )
    parser.add_argument(
        "--private-markers",
        required=True,
        help="File of private markers (private directory names, project names), one per "
             "line (may be empty).",
    )
    parser.add_argument("--out", default=None, help="JSONL of flagged claims (default stdout).")
    parser.add_argument(
        "--claims-file-out",
        default=None,
        help="Write the flagged ids here, one per line (restrict-claims --claims-file format).",
    )
    args = parser.parse_args()

    groups = read_terms(args.private_groups)
    markers = read_terms(args.private_markers)

    try:
        # MAINTENANCE-DSN-EXEMPT: read-only by design (the session is set
        # read-only before its one SELECT) and meant for a read-only login named
        # only by --database-url. Reading MAINTENANCE_DATABASE_URL would hand a
        # privacy screen the writer's role whenever a sibling job exports it.
        conn = psycopg2.connect(args.database_url)
    except psycopg2.Error as exc:
        # libpq's message can echo the DSN, password included: withhold it.
        print(
            f"ERROR: could not connect to the database named by --database-url "
            f"({type(exc).__name__}; details withheld because they can contain the DSN)",
            file=sys.stderr,
        )
        return 2

    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    ids_out = open(args.claims_file_out, "w", encoding="utf-8") if args.claims_file_out else None
    try:
        run(conn, groups, markers, out, ids_out, sys.stderr)
    finally:
        conn.close()
        if args.out:
            out.close()
        if ids_out is not None:
            ids_out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
