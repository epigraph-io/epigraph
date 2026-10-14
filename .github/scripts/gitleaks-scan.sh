#!/usr/bin/env bash
# Secret scan for CI: run gitleaks over the commits in <base>..<head> ONLY.
#
#   .github/scripts/gitleaks-scan.sh <base> <head>
#
# Scanning only the range is what lets the job be a hard gate without failing
# on history that predates it; the full-history audit is the operator command
# documented at the top of .gitleaks.toml. Findings are printed REDACTED: CI
# logs of a public repo are public, so the secret value must never reach them.
#
# <base> may be empty or all zeros (a push that created the branch); then only
# <head> itself is scanned. Run from the repository root. GITLEAKS overrides
# the binary (default: `gitleaks` on PATH).
#
# Known gap: `git log -p` prints no diff for a merge commit, so a line that
# exists ONLY in a merge commit (typed while resolving a conflict) is not
# scanned; the commits on either side of the merge are. Adding `-m` to
# --log-opts would close it but re-scans every change a merge brings in from
# the base branch, which reintroduces failures on pre-existing history. An
# operator can cover merges by hand with --log-opts="-m --first-parent <range>".
set -euo pipefail

base=${1-}
head=${2:?usage: gitleaks-scan.sh <base> <head>}
gitleaks=${GITLEAKS:-gitleaks}

if [[ -z $base || $base =~ ^0+$ ]]; then
  range=(-1 "$head")
  echo "gitleaks-scan: no base commit; scanning $head only"
else
  range=("$base..$head")
  echo "gitleaks-scan: scanning $(git rev-list --count "$base..$head") commit(s) in $base..$head"
fi

exec "$gitleaks" git . \
  --config .gitleaks.toml \
  --log-opts="${range[*]}" \
  --redact \
  --verbose \
  --no-banner \
  --exit-code 1
