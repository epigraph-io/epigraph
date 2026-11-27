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
#   5. range    — only <base>..<head> is read; an empty base reads <head> only;
#   6. W4       — `--cited-shas` warns (exit 0) for a cited sha that names no
#                 commit reachable from <head> (a side-branch sha included),
#                 bare 7-8 hex short shas included; skips UUIDs, labelled
#                 backlog/claim/decision ids, digests, numbers and trailers,
#                 never prints the token, and the default run never reports W4.
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
check "E4 silenced by a list-item Unverified" 0 "feat(x): t"$'\n\n**Verification:**\n- cargo test passes\n- Unverified: clippy not run here' - -
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

# --- W4: cited commit shas (--cited-shas mode) --------------------------------
# A cited sha must name a commit reachable from <head> (on main, from main).
# Reachability, not object existence: a sha on a side branch exists in a full
# clone (`git cat-file -e` succeeds) but is not on main, so it must still warn.
anc=$(git -C "$r" rev-parse HEAD)          # an ancestor of every later commit
side=$(git -C "$r" commit-tree "HEAD^{tree}" -p HEAD -m "side")
git -C "$r" update-ref refs/heads/side "$side"   # exists, not reachable from main
git -C "$r" cat-file -e "${side:0:12}^{commit}"  # premise: the object resolves
missing="5e1f0c0ffee12"                    # a commit-like token naming nothing
# check_cited <name> <message> <want W4 count> <value|->: commit <message>, run
# --cited-shas over exactly that commit, assert exit 0, the W4 count and that
# <value> never appears in the output (a hex run could be a secret).
check_cited() {
  local name=$1 message=$2 want=$3 value=$4 rc=0 base out got ok=1
  base=$(git -C "$r" rev-parse HEAD)
  commit "$message"
  out=$(cd "$r" && python3 "$lint" --cited-shas "$base" HEAD 2>&1) || rc=$?
  got=$(grep -c '^warning W4 ' <<<"$out" || true)
  [[ $rc == 0 ]] || { echo "FAIL - $name: want rc=0, got rc=$rc"; ok=0; }
  [[ $got == "$want" ]] || { echo "FAIL - $name: want $want W4, got $got"; ok=0; }
  grep -Eq '^(error|warning) (E|W[23] )' <<<"$out" && { echo "FAIL - $name: mode reported a non-W4 class"; ok=0; }
  if [[ $value != - ]] && grep -qF -- "$value" <<<"$out"; then
    echo "FAIL - $name: output contains the cited token"; ok=0
  fi
  if ((ok)); then echo "ok   - $name"; else sed 's/^/       | /' <<<"$out"; failures=$((failures + 1)); fi
}
check_cited "W4 ok full sha of an ancestor"        "fix(x): t$good_body"$'\n\nfollows '"$anc" 0 -
check_cited "W4 ok 12-char prefix of an ancestor"  "fix(x): t$good_body"$'\n\nfollows '"${anc:0:12}" 0 -
check_cited "W4 ok 7 hex after 'commit', ancestor" "fix(x): t$good_body"$'\n\nas in commit `'"${anc:0:7}"'`' 0 -
check_cited "W4 side-branch sha not on main"       "fix(x): t$good_body"$'\n\nfollows '"${side:0:12}" 1 "${side:0:12}"
check_cited "W4 sha that names nothing"            "fix(x): t$good_body"$'\n\nfollows '"$missing" 1 "$missing"
check_cited "W4 7 hex after 'commit', unresolved"  "fix(x): t$good_body"$'\n\nreverts commit 5e1f0c0' 1 "5e1f0c0"
# The commonest citation shape in this repository is a bare 8-hex short sha
# ("Scoped gate on <sha>", "Review of <sha>"); 8-hex backlog and claim ids are
# told apart by the word that labels them, also through a list of ids.
check_cited "W4 bare 8-hex short sha, unresolved"  "fix(x): t$good_body"$'\n\n- Scoped gate on 5e1f0c0f: failed' 1 "5e1f0c0f"
check_cited "W4 ok bare 8-hex prefix of an ancestor" "fix(x): t$good_body"$'\n\n- Review of '"${anc:0:8}"': fine' 0 -
check_cited "W4 labelled id lists are not shas"    "fix(x): t$good_body"$'\n\nBacklog 114b17a4, 2a2d527f and 9f86d081; claims 5e1f0c0f / 0a97ba24;\nruling R-9 (decision 2bb5a33f); key type ed25519' 0 -
check_cited "W4 counts each unresolved token"      "fix(x): t $missing$good_body"$'\n\nsee '"${side:0:12}"' and '"$anc" 2 "$missing"
check_cited "W4 not-sha shapes are not cited"      "fix(x): t$good_body"$'\n\nclaim 2a2d527f-387f-4ef4-89e0-1a645dfeaf49, backlog 114b17a4,\nhash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08,\nnumber 17000000001234, word deadbeefcafe, pin actions/checkout@'"$missing"$',\nuuid 2a2d527f387f4ef489e01a645dfeaf49, digest (sha256 '"$missing"') blake3: '"$missing" 0 -
check_cited "W4 trailer lines are not read"        "fix(x): t$good_body"$'\n\nCo-Authored-By: A <a@example.com> '"$missing" 0 -
# The default (no-flag) run is unchanged: it never reports W4.
rc=0; base=$(git -C "$r" rev-parse HEAD)
commit "fix(x): t$good_body"$'\n\nfollows '"$missing"
out=$(cd "$r" && python3 "$lint" "$base" HEAD 2>&1) || rc=$?
if [[ $rc == 0 ]] && ! grep -q ' W4 ' <<<"$out"; then echo "ok   - W4 default run does not check cited shas"
else echo "FAIL - W4 default run does not check cited shas (rc=$rc)"; sed 's/^/       | /' <<<"$out"; failures=$((failures + 1)); fi

if ((failures)); then
  echo "test-commit-message-lint: $failures case(s) failed" >&2
  exit 1
fi
echo "test-commit-message-lint: all cases passed"
