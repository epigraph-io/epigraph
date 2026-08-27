#!/usr/bin/env bash
#
# Unit tests for scripts/scan_sensitive_terms.sh.
#
# Pure shell + git. No database, no cargo, no network. Each case builds a
# throwaway git repo under $TMPDIR and runs the scanner against it, so the
# seeded-hit cases can commit a "leak" without ever writing one into this repo.
#
# Run:  ./scripts/tests/test_scan_sensitive_terms.sh

set -uo pipefail

SCANNER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scan_sensitive_terms.sh"
FAILURES=0

fail() { printf '  FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
pass() { printf '  ok: %s\n' "$*"; }

# mkrepo <example-list-contents> [local-list-contents]
mkrepo() {
  local dir; dir="$(mktemp -d)"
  git -C "$dir" init -q .
  git -C "$dir" config user.email test@example.invalid
  git -C "$dir" config user.name test
  mkdir -p "$dir/scripts"
  printf '%s' "$1" > "$dir/scripts/sensitive-terms.example.txt"
  if [ "$#" -ge 2 ]; then printf '%s' "$2" > "$dir/scripts/sensitive-terms.txt"; fi
  printf 'fn main() {}\n' > "$dir/clean.rs"
  git -C "$dir" add -A
  git -C "$dir" commit -qm init
  printf '%s' "$dir"
}

run_in() { ( cd "$1" && shift && "$SCANNER" "$@" ) 2>&1; }
rc_in()  { ( cd "$1" && shift && "$SCANNER" "$@" >/dev/null 2>&1 ); echo $?; }

# Fixture terms deliberately do NOT appear on the shipped example list: this
# test file is itself a tracked file that the real scan reads, so a live term
# here would make the repo fail its own scan.
EXAMPLE='# marker list
FIXTURE_SENSITIVE_TERM_XY
FIXTURE_SECOND_TERM_XY
'

test_clean_tree_exits_zero() {
  local d; d="$(mkrepo "$EXAMPLE")"
  [ "$(rc_in "$d")" = 0 ] && pass "$FUNCNAME" || fail "$FUNCNAME: expected exit 0"
  rm -rf "$d"
}

test_seeded_hit_exits_one() {
  local d; d="$(mkrepo "$EXAMPLE")"
  printf 'let k = "FIXTURE_SENSITIVE_TERM_XY";\n' > "$d/leak.rs"; git -C "$d" add leak.rs
  [ "$(rc_in "$d")" = 1 ] && pass "$FUNCNAME" || fail "$FUNCNAME: expected exit 1"
  rm -rf "$d"
}

test_term_list_excluded_from_own_scan() {
  # The example list literally contains the fixture term; without ':(exclude)'
  # pathspec the scan matches its own term list and can never pass.
  local d; d="$(mkrepo "$EXAMPLE")"
  local out; out="$(run_in "$d")"
  case "$out" in
    *sensitive-terms.example.txt*) fail "$FUNCNAME: term list matched itself" ;;
    *) pass "$FUNCNAME" ;;
  esac
  rm -rf "$d"
}

test_empty_term_list_short_circuits() {
  # Regression guard. On the epigraph tree `git grep -F -f <empty file>`
  # matches EVERY line of EVERY tracked file (measured: 2184 files / 129801
  # lines, exit 0), so an all-comment list would fail the build on all
  # content. A throwaway repo does NOT reproduce that git behaviour, so
  # asserting "exit 0" alone would pass with the guard deleted — assert the
  # guard's own message too.
  local d; d="$(mkrepo '# nothing but a comment
')"
  local out; out="$(run_in "$d")"
  local rc;  rc="$(rc_in "$d")"
  if [ "$rc" = 0 ] && case "$out" in *"term list is empty"*) true ;; *) false ;; esac; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME: expected exit 0 + empty-list short-circuit (rc=$rc, out=$out)"
  fi
  rm -rf "$d"
}

test_comments_and_blank_lines_ignored() {
  local d; d="$(mkrepo '# FIXTURE_SENSITIVE_TERM_XY appears here in a comment

FIXTURE_SECOND_TERM_XY
')"
  printf 'let k = "FIXTURE_SENSITIVE_TERM_XY";\n' > "$d/leak.rs"; git -C "$d" add leak.rs
  [ "$(rc_in "$d")" = 0 ] && pass "$FUNCNAME" || fail "$FUNCNAME: commented term was still matched"
  rm -rf "$d"
}

test_local_list_unions_with_example_list() {
  local d; d="$(mkrepo "$EXAMPLE" 'FIXTURE_LOCAL_TERM_XY
')"
  printf 'partner is FIXTURE_LOCAL_TERM_XY\n' > "$d/doc.md"; git -C "$d" add doc.md
  [ "$(rc_in "$d")" = 1 ] && pass "$FUNCNAME" || fail "$FUNCNAME: local list term not scanned"
  rm -rf "$d"
}

test_missing_term_list_is_config_error() {
  local d; d="$(mkrepo "$EXAMPLE")"
  rm "$d/scripts/sensitive-terms.example.txt"
  [ "$(rc_in "$d")" = 2 ] && pass "$FUNCNAME" || fail "$FUNCNAME: expected exit 2"
  rm -rf "$d"
}

test_redacted_output_omits_matched_line() {
  local d; d="$(mkrepo "$EXAMPLE")"
  printf 'let k = "FIXTURE_SENSITIVE_TERM_XY";\n' > "$d/leak.rs"; git -C "$d" add leak.rs
  local out; out="$(run_in "$d")"
  case "$out" in
    *FIXTURE_SENSITIVE_TERM_XY*) fail "$FUNCNAME: matched line leaked into default output" ;;
    *leak.rs*)     pass "$FUNCNAME" ;;
    *)             fail "$FUNCNAME: offending path not reported" ;;
  esac
  rm -rf "$d"
}

test_show_matches_includes_matched_line() {
  local d; d="$(mkrepo "$EXAMPLE")"
  printf 'let k = "FIXTURE_SENSITIVE_TERM_XY";\n' > "$d/leak.rs"; git -C "$d" add leak.rs
  local out; out="$(run_in "$d" --show-matches)"
  case "$out" in
    *FIXTURE_SENSITIVE_TERM_XY*) pass "$FUNCNAME" ;;
    *) fail "$FUNCNAME: --show-matches did not print the line" ;;
  esac
  rm -rf "$d"
}

echo "scan_sensitive_terms tests:"
test_clean_tree_exits_zero
test_seeded_hit_exits_one
test_term_list_excluded_from_own_scan
test_empty_term_list_short_circuits
test_comments_and_blank_lines_ignored
test_local_list_unions_with_example_list
test_missing_term_list_is_config_error
test_redacted_output_omits_matched_line
test_show_matches_includes_matched_line

if [ "$FAILURES" -ne 0 ]; then
  printf '\n%d test(s) failed\n' "$FAILURES" >&2
  exit 1
fi
printf '\nall tests passed\n'
