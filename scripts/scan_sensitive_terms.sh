#!/usr/bin/env bash
#
# scan_sensitive_terms.sh — fail the build if a tracked file contains a term
# from the sensitive-term list.
#
# Runs in CI (.github/workflows/ci.yml, job `sensitive-scan`) and from
# scripts/verify.sh. KEEP THE CI JOB AND verify.sh IN SYNC WITH THIS FILE.
#
# Term lists (both optional individually, at least one must exist):
#   scripts/sensitive-terms.example.txt  committed; generic secret markers
#   scripts/sensitive-terms.txt          gitignored; org-specific terms
# The effective list is the UNION of the two.
#
# Usage:
#   ./scripts/scan_sensitive_terms.sh                  # redacted (CI default)
#   ./scripts/scan_sensitive_terms.sh --show-matches   # full lines (local only)
#
# Exit codes:  0 clean   1 term(s) found   2 configuration error
#
# By default only `path:count` is printed, never the matched line. CI logs on a
# public repo are themselves a disclosure channel; echoing the hit would leak
# the very string the scan exists to catch. Use --show-matches locally.
#
# Matching is CASE-SENSITIVE fixed-string (`git grep -F`). Cloud and chat
# credential prefixes are case-sensitive by construction, and folding case
# turns short terms into prose false positives (the 4-letter AWS temporary-key
# prefix, case-folded, matched 25 lines of ordinary prose in this repo). Add
# both casings explicitly if a term needs them.
#
# NOTE: this file and its test are scanned like any other tracked file, so
# neither may quote a live term verbatim — that is why the comments above
# describe the markers instead of spelling them. Keep it that way; widening
# the exclude pathspec to cover the tool would blind the scan to real secrets
# hidden in these two files.

set -euo pipefail

SHOW_MATCHES=0
case "${1:-}" in
  "") ;;
  --show-matches) SHOW_MATCHES=1 ;;
  *) echo "usage: $0 [--show-matches]" >&2; exit 2 ;;
esac

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: not inside a git repository" >&2; exit 2
}
cd "$REPO_ROOT"

EXAMPLE_LIST="${EPIGRAPH_SENSITIVE_TERMS_EXAMPLE:-scripts/sensitive-terms.example.txt}"
LOCAL_LIST="${EPIGRAPH_SENSITIVE_TERMS_LOCAL:-scripts/sensitive-terms.txt}"

if [ ! -f "$EXAMPLE_LIST" ] && [ ! -f "$LOCAL_LIST" ]; then
  echo "ERROR: no term list found (looked for $EXAMPLE_LIST and $LOCAL_LIST)" >&2
  exit 2
fi

EFFECTIVE="$(mktemp)"
trap 'rm -f "$EFFECTIVE"' EXIT

# A line whose first non-blank character is '#' is a comment; every other
# non-blank line is one fixed-string term, trailing whitespace trimmed.
# Inline comments are NOT supported: terms are matched literally and may
# legitimately contain '#'.
for list in "$EXAMPLE_LIST" "$LOCAL_LIST"; do
  [ -f "$list" ] || continue
  sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*#/d' -e '/^$/d' "$list" >> "$EFFECTIVE"
done

# LOAD-BEARING: `git grep -F -f <empty file>` matches EVERY line of EVERY
# tracked file (measured: 129762 hits on this repo), so an all-comments or
# empty list would fail the build on all content. Bail out clean instead.
if [ ! -s "$EFFECTIVE" ]; then
  echo "scan_sensitive_terms: term list is empty — nothing to scan."
  exit 0
fi

# ':(exclude)scripts/sensitive-terms*' is LOAD-BEARING: without it the term
# lists match themselves and the scan can never pass.
GREP_FLAGS="-cIF"
[ "$SHOW_MATCHES" -eq 1 ] && GREP_FLAGS="-nIF"

set +e
OUTPUT="$(git grep $GREP_FLAGS -f "$EFFECTIVE" -- . ':(exclude)scripts/sensitive-terms*')"
RC=$?
set -e

case "$RC" in
  1) echo "✅ scan_sensitive_terms: no sensitive terms in tracked files ($(wc -l < "$EFFECTIVE" | tr -d ' ') terms)"; exit 0 ;;
  0) ;;
  *) echo "ERROR: git grep failed (exit $RC)" >&2; exit 2 ;;
esac

echo "❌ scan_sensitive_terms: sensitive term(s) found in tracked files:" >&2
echo "$OUTPUT" >&2
if [ "$SHOW_MATCHES" -eq 0 ]; then
  echo >&2
  echo "Matched lines are redacted. Re-run LOCALLY to see them:" >&2
  echo "    ./scripts/scan_sensitive_terms.sh --show-matches" >&2
fi
exit 1
