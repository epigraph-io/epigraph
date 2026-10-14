#!/usr/bin/env bash
# Self-test for the CI secret scan: .gitleaks.toml + .github/scripts/gitleaks-scan.sh.
#
# Runs the real gitleaks binary against throwaway git repos that carry this
# checkout's config and scan script, and asserts the six properties the CI job
# depends on:
#   1. range-only   — a secret already in the base history does not fail a PR
#                     whose own commits are clean (the job must not fail on
#                     existing history), while the same secret added inside
#                     the range does;
#   2. fixtures     — the known test fixtures / public identifiers allowlisted
#                     in .gitleaks.toml do not fail the scan when re-added;
#   3. value-scoped — the allowlist is keyed on the fixture VALUES, so a new
#                     secret in the very file that holds the fixtures is still
#                     caught;
#   4. defaults     — the default gitleaks ruleset is still active (an AWS
#                     access key id is caught);
#   5. no-base      — with an empty or all-zeros <base> (a push that created
#                     the branch) only <head> itself is scanned: a secret in
#                     older history passes, one added by <head> fails;
#   6. redacted     — every failing scan's log names the finding REDACTED and
#                     never contains the planted value (public CI logs).
#
# Planted secrets are deterministic and assembled from pieces at run time, so
# no secret-shaped literal appears in this file (it is itself scanned in CI).
#
# Usage: .github/scripts/test-gitleaks-scan.sh   (GITLEAKS=<path> to override
# the binary; defaults to `gitleaks` on PATH)
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export GITLEAKS=${GITLEAKS:-gitleaks}
command -v "$GITLEAKS" >/dev/null || { echo "test-gitleaks-scan: gitleaks binary not found ($GITLEAKS)" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

# Deterministic high-entropy values, never written literally in this file.
generic_secret="Qz7Rw$(printf 'K3pV')9tLm2Xc8NbH4sYdG6jF1aE5uTq"
aws_key_id="AKIA$(printf 'QW7R')T3YP5ZK2LM6N"

new_repo() {
  local dir=$1
  git init -q -b main "$dir"
  mkdir -p "$dir/.github/scripts"
  cp "$repo_root/.gitleaks.toml" "$dir/.gitleaks.toml"
  cp "$repo_root/.github/scripts/gitleaks-scan.sh" "$dir/.github/scripts/gitleaks-scan.sh"
  commit "$dir" "base: config + scan script"
}

commit() {
  local dir=$1 msg=$2
  git -C "$dir" add -A
  git -C "$dir" -c user.name=ci -c user.email=ci@example.invalid commit -q --allow-empty -m "$msg"
}

# expect <name> <expected rc> <dir> <base> <head>
expect() {
  local name=$1 want=$2 dir=$3 base=$4 head=$5 rc=0
  (cd "$dir" && bash .github/scripts/gitleaks-scan.sh "$base" "$head") >"$work/$name.log" 2>&1 || rc=$?
  if [[ $rc == "$want" ]]; then
    echo "ok   - $name (rc=$rc)"
  else
    echo "FAIL - $name: want rc=$want, got rc=$rc"
    sed 's/^/       | /' "$work/$name.log"
    failures=$((failures + 1))
  fi
}

# redacted <name> <value>: the log of case <name> reports the finding redacted
# and never carries the secret value itself.
redacted() {
  local name=$1 value=$2
  if grep -qF -- "$value" "$work/$name.log"; then
    echo "FAIL - redacted: $name: the log contains the planted secret value"
    failures=$((failures + 1))
  elif ! grep -q 'REDACTED' "$work/$name.log"; then
    echo "FAIL - redacted: $name: the log has no REDACTED finding"
    failures=$((failures + 1))
  else
    echo "ok   - redacted: $name"
  fi
}

# --- 1. range-only -----------------------------------------------------------
r=$work/range
new_repo "$r"
mkdir -p "$r/src"
printf 'let secret = "%s";\n' "$generic_secret" >"$r/src/old.rs"
commit "$r" "history: a secret that predates the PR"
base=$(git -C "$r" rev-parse HEAD)
printf 'fn clean() {}\n' >"$r/src/clean.rs"
commit "$r" "pr: clean change"
expect "range-only: secret in base history, clean PR passes" 0 "$r" "$base" "$(git -C "$r" rev-parse HEAD)"
printf 'let secret = "%s";\n' "$generic_secret" >"$r/src/new.rs"
commit "$r" "pr: adds the secret again"
expect "range-only: the same secret added inside the range fails" 1 "$r" "$base" "$(git -C "$r" rev-parse HEAD)"
redacted "range-only: the same secret added inside the range fails" "$generic_secret"

# --- 2. fixtures -------------------------------------------------------------
f=$work/fixtures
new_repo "$f"
base=$(git -C "$f" rev-parse HEAD)
mkdir -p "$f/crates/epigraph-api/src/routes" "$f/crates/epigraph-crypto/src" "$f/docs"
cat >"$f/crates/epigraph-api/src/routes/webhooks.rs" <<'RS'
let secret = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s";
let body = json!({ "secret": "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s" });
let secret = "0123456789abcdef".repeat(4);
let idempotency_key = "unique_idempotency_key_12345".to_string();
RS
cat >"$f/crates/epigraph-crypto/src/did_key.rs" <<'RS'
"did:key:z6MkgnfY62EYiJb6kdRrkuviJYsGGoC2J3Zc9bem2TxnPVY1",
RS
printf 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\n' >"$f/docs/concepts.md"
commit "$f" "pr: re-adds the known fixtures"
expect "fixtures: allowlisted fixtures and did:key ids pass" 0 "$f" "$base" "$(git -C "$f" rev-parse HEAD)"

# --- 3. value-scoped ---------------------------------------------------------
printf 'let secret = "%s";\n' "$generic_secret" >>"$f/crates/epigraph-api/src/routes/webhooks.rs"
commit "$f" "pr: a new secret next to the fixtures"
expect "value-scoped: new secret in the fixture file fails" 1 "$f" "$base" "$(git -C "$f" rev-parse HEAD)"
redacted "value-scoped: new secret in the fixture file fails" "$generic_secret"

# --- 4. defaults -------------------------------------------------------------
d=$work/defaults
new_repo "$d"
base=$(git -C "$d" rev-parse HEAD)
printf 'aws_access_key_id = %s\n' "$aws_key_id" >"$d/creds.ini"
commit "$d" "pr: an AWS access key id"
expect "defaults: AWS access key id fails" 1 "$d" "$base" "$(git -C "$d" rev-parse HEAD)"
redacted "defaults: AWS access key id fails" "$aws_key_id"

# --- 5. no-base --------------------------------------------------------------
# ci.yml passes `github.event.before`, which is all zeros on a push that created
# the branch (and empty for a trigger without `before`). The scan must then
# cover <head> alone: never the history reachable from it, never the base.
n=$work/nobase
new_repo "$n"
mkdir -p "$n/src"
printf 'let secret = "%s";\n' "$generic_secret" >"$n/src/old.rs"
commit "$n" "history: a secret that predates the pushed head"
printf 'fn clean() {}\n' >"$n/src/clean.rs"
commit "$n" "head: clean change"
zeros=0000000000000000000000000000000000000000
expect "no-base: all-zeros base, clean head passes" 0 "$n" "$zeros" "$(git -C "$n" rev-parse HEAD)"
expect "no-base: empty base, clean head passes" 0 "$n" "" "$(git -C "$n" rev-parse HEAD)"
printf 'aws_access_key_id = %s\n' "$aws_key_id" >"$n/creds.ini"
commit "$n" "head: adds an AWS access key id"
expect "no-base: all-zeros base, secret in head fails" 1 "$n" "$zeros" "$(git -C "$n" rev-parse HEAD)"
expect "no-base: empty base, secret in head fails" 1 "$n" "" "$(git -C "$n" rev-parse HEAD)"

if ((failures)); then
  echo "test-gitleaks-scan: $failures case(s) failed" >&2
  exit 1
fi
echo "test-gitleaks-scan: all cases passed"
