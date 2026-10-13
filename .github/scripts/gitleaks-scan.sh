#!/usr/bin/env bash
# STUB: scans the whole history reachable from <head>; <base> is ignored.
set -euo pipefail
base=${1:?usage: gitleaks-scan.sh <base> <head>}
head=${2:?usage: gitleaks-scan.sh <base> <head>}
exec "${GITLEAKS:-gitleaks}" git . --config .gitleaks.toml --log-opts="$head" --redact --no-banner --exit-code 1
