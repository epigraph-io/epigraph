#!/usr/bin/env bash
# Self-test for the CI commit-message lint: .github/scripts/commit-message-lint.py.
#
# Builds a throwaway git repository, commits messages with known-bad and
# known-good content (all synthetic) and asserts that:
#   1. errors   — E1 e-mail, E2 home path, E3 wildcard-DNS host, E3 public
#                 IPv4, E4 an unrun Verification without `Unverified:`, E5 an
#                 unrun change to a SECURITY DEFINER function, E6 a private
#                 deny-list term each exit 1 and name their class;
#   2. warnings — W2, W3 are reported and exit 0;
#   3. allowed  — trailers, example.com, /home/user/, documentation, private
#                 and loopback addresses, and a clean protocol message pass
#                 with no finding at all;
#   4. redacted — no output ever contains the offending value (public CI logs);
#   5. range    — only <base>..<head> is read; an empty base reads <head> only.
#
# Host-shaped values are assembled from pieces at run time so no encoded
# wildcard-DNS name appears in this file (the repo's source guard scans *.sh).
#
# Usage: .github/scripts/test-commit-message-lint.sh
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
lint="$repo_root/.github/scripts/commit-message-lint.py"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

bad_email="someone@corp.invalid"
bad_home="/home/alice/project"
bad_host="203-0-114-7.nip""".io
bad_ip="203.0.114.7"

r=$work/repo
git init -q -b main "$r"
good_body=$'\n**Evidence:**\n- e\n\n**Reasoning:**\n- r\n\n**Verification:**\n- cargo test passes'

# commit <subject-and-body>: one commit on top of the previous one.
commit() {
  git -C "$r" -c user.name=ci -c user.email=ci@example.invalid commit -q --allow-empty -m "$1"
}

# check <name> <want rc> <message> <class|-> <value|->: lints exactly the one
# commit, asserts rc, that <class> appears (or, for "-", that nothing is
# reported), and that <value> is absent from the output.
check() {
  local name=$1 want=$2 message=$3 class=$4 value=$5 rc=0 base out
  base=$(git -C "$r" rev-parse HEAD 2>/dev/null || true)
  commit "$message"
  out=$(cd "$r" && python3 "$lint" "$base" HEAD 2>&1) || rc=$?
  local ok=1
  [[ $rc == "$want" ]] || { echo "FAIL - $name: want rc=$want, got rc=$rc"; ok=0; }
  if [[ $class == - ]]; then
    grep -Eq '^(error|warning) ' <<<"$out" && { echo "FAIL - $name: unexpected finding"; ok=0; }
  else
    grep -q " $class " <<<"$out" || { echo "FAIL - $name: class $class not reported"; ok=0; }
  fi
  if [[ $value != - ]] && grep -qF -- "$value" <<<"$out"; then
    echo "FAIL - $name: output contains the offending value"; ok=0
  fi
  if ((ok)); then echo "ok   - $name"; else sed 's/^/       | /' <<<"$out"; failures=$((failures + 1)); fi
}

commit "chore(ci): base"   # something to diff against

# --- errors ------------------------------------------------------------------
check "E1 e-mail in body"        1 "feat(x): t$good_body"$'\n\ncontact '"$bad_email" E1 "$bad_email"
check "E1 e-mail in subject"     1 "feat(x): mail $bad_email$good_body" E1 "$bad_email"
check "E2 home path"             1 "feat(x): t$good_body"$'\n\nsee '"$bad_home" E2 "alice"
check "E2 macOS home path"       1 "feat(x): t$good_body"$'\n\nsee /Users/bob/src/' E2 "bob"
check "E3 wildcard-DNS host"     1 "feat(x): t$good_body"$'\n\nhost https://'"$bad_host" E3 "$bad_host"
check "E3 public IPv4"           1 "feat(x): t$good_body"$'\n\nat '"$bad_ip" E3 "$bad_ip"

check "E4 Verification not run"  1 "feat(x): t"$'\n\n**Evidence:**\n- e\n\n**Verification:**\n- Not run' E4 -
check "E4 CI to confirm"         1 "feat(x): t"$'\n\n**Verification:**\n- CI to confirm' E4 -
check "E4 silenced by Unverified" 0 "feat(x): t"$'\n\n**Verification:**\n- Not run\n\nUnverified: tests not run here' - -
check "ok not-run outside Verification" 0 "feat(x): t"$'\n\n**Evidence:**\n- the job was not run before\n\n**Reasoning:**\n- r\n\n**Verification:**\n- cargo test passes' - -

# E6: the deny-list comes only from the environment (and a private file), never
# from the repository. The term is synthetic.
deny_term="Zorblax Widgets"
COMMIT_LINT_DENY_TERMS="$deny_term" check "E6 deny-listed term in body" 1 "feat(x): t$good_body"$'\n\nfor '"$deny_term"' only' E6 "$deny_term"
COMMIT_LINT_DENY_TERMS="other, $deny_term" check "E6 term in subject, list comma-separated" 1 "feat(x): fix for ${deny_term}$good_body" E6 "$deny_term"
COMMIT_LINT_DENY_TERMS="$deny_term" check "ok deny term inside a longer word" 0 "feat(x): t$good_body"$'\n\nZorblax WidgetsX is unrelated' - -
check "ok deny-list not configured" 0 "feat(x): t$good_body"$'\n\nfor '"$deny_term"' only' - -

# E5: a change inside a SECURITY DEFINER function with an unrun Verification.
# file_commit <path> <content> <message>: commit one file.
file_commit() {
  printf '%s\n' "$2" > "$r/$1"
  git -C "$r" add "$1"
  git -C "$r" -c user.name=ci -c user.email=ci@example.invalid commit -q -m "$3"
}
definer=$'CREATE OR REPLACE FUNCTION f() RETURNS int\nLANGUAGE sql SECURITY DEFINER\nAS $$ SELECT 1 $$;'
invoker=$'CREATE OR REPLACE FUNCTION g() RETURNS int\nLANGUAGE sql\nAS $$ SELECT 1 $$;'
notrun=$'\n\n**Verification:**\n- Not run\n\nUnverified: no database here'
# check_range <name> <want rc> <base> <class|->: lint base..HEAD.
check_range() {
  local name=$1 want=$2 base=$3 class=$4 rc=0 out ok=1
  out=$(cd "$r" && python3 "$lint" "$base" HEAD 2>&1) || rc=$?
  [[ $rc == "$want" ]] || { echo "FAIL - $name: want rc=$want, got rc=$rc"; ok=0; }
  if [[ $class == - ]]; then
    grep -Eq '^error ' <<<"$out" && { echo "FAIL - $name: unexpected error"; ok=0; }
  else
    grep -q " $class " <<<"$out" || { echo "FAIL - $name: class $class not reported"; ok=0; }
  fi
  if ((ok)); then echo "ok   - $name"; else sed 's/^/       | /' <<<"$out"; failures=$((failures + 1)); fi
}
file_commit d.sql "$invoker" "chore(db): base$good_body"
b0=$(git -C "$r" rev-parse HEAD)
file_commit d.sql "$definer" "fix(db): definer$notrun"
check_range "E5 definer change, Unverified does not silence" 1 "$b0" E5
b1=$(git -C "$r" rev-parse HEAD)
file_commit d.sql "$definer"$'\n-- comment' "test(db): run it"$'\n\n**Verification:**\n- cites '"${b1:0:7}"$': cargo test definer_test 3 passed'
check_range "E5 silenced by a later commit citing the sha" 0 "$b0" -
b2=$(git -C "$r" rev-parse HEAD)
file_commit e.sql "$invoker"$'\n-- changed' "fix(db): invoker only$notrun"
check_range "ok invoker function change with Unverified" 0 "$b2" -
b3=$(git -C "$r" rev-parse HEAD)
file_commit d.sql "$definer"$'\n-- comment\n-- more' "fix(db): definer, ran tests$good_body"
check_range "ok definer change with a recorded run" 0 "$b3" -

# --- warnings (exit 0) -------------------------------------------------------
check "W2 bad subject"           0 "did some stuff$good_body" W2 -
check "W3 no sections"           0 "fix(x): plain message" W3 -

# --- allowed -----------------------------------------------------------------
check "ok trailer e-mail"        0 "feat(x): t$good_body"$'\n\nCo-Authored-By: A Person <'"$bad_email"'>' - "$bad_email"
check "ok Signed-off-by"         0 "feat(x): t$good_body"$'\n\nSigned-off-by: A <'"$bad_email"'>' - "$bad_email"
check "ok example.com"           0 "feat(x): t$good_body"$'\n\nowner@example.com' - -
check "ok noreply addresses"     0 "feat(x): t$good_body"$'\n\nnoreply@anthropic.com 7@users.noreply.github.com' - -
check "ok /home/user/"           0 "feat(x): t$good_body"$'\n\n/home/user/epigraph and /home/runner/work/' - -
check "ok role@private-IP DSN"   0 "feat(x): t$good_body"$'\n\npostgres://epigraph@127.0.0.1/db and app@10.0.0.5' - -
check "ok documentation IP"      0 "feat(x): t$good_body"$'\n\n192.0.2.9 198.51.100.4 203.0.113.250' - -
check "ok private and loopback"  0 "feat(x): t$good_body"$'\n\n10.0.0.5 172.16.3.4 192.168.1.1 127.0.0.1 0.0.0.0' - -
check "ok version string"        0 "feat(x): t$good_body"$'\n\nbump to 1.2.3.4.5 and v8.30.1' - -
check "ok exempt subjects"       0 "Merge branch x$good_body" - -
check "ok clean message"         0 "fix(db): t$good_body" - -

# --- range and no-base -------------------------------------------------------
# A bad commit BEFORE the base is not read; head alone is read for an empty or
# all-zeros base.
commit "feat(x): old"$'\n\n'"$bad_email"
base=$(git -C "$r" rev-parse HEAD)
commit "fix(db): clean$good_body"
head=$(git -C "$r" rev-parse HEAD)
for b in "$base" ""  "0000000000000000000000000000000000000000"; do
  rc=0; (cd "$r" && python3 "$lint" "$b" "$head") >/dev/null 2>&1 || rc=$?
  if [[ $rc == 0 ]]; then echo "ok   - range: base '${b:0:7}' reads only the added commit(s)"
  else echo "FAIL - range: base '${b:0:7}' read history it should not (rc=$rc)"; failures=$((failures + 1)); fi
done

if ((failures)); then
  echo "test-commit-message-lint: $failures case(s) failed" >&2
  exit 1
fi
echo "test-commit-message-lint: all cases passed"
