#!/usr/bin/env bash
# The Atlas latency gate at STAGING scale (backlog W12 824ac5ac, design §6).
#
#   ./probe-atlas-latency.sh <report dir> [small|full|<theme count>]
#
# Runs, in --release, from the repository root:
#   KERNEL  crates/epigraph-api/tests/atlas_latency_gate.rs at the given scale
#           (default full: 210 themes, about 366k claims, 13,860 levels),
#           including its red-on-regression test;
#   BFF     services/explorer/tests/atlas_latency.rs (per document: the same
#           at any map scale), including its red-on-regression test;
#   BROWSER only with ATLAS_LATENCY_BROWSER=1: the Explorer's fixture preview
#           and scripts/e2e/atlas-latency-browser.mjs (needs node and
#           playwright or playwright-core; ATLAS_BROWSER_EXECUTABLE may name a
#           system Chrome).
# Each writes a JSON report to <report dir> (kernel.json, bff.json,
# browser.json) with p50 and p95 per level type; one PASS/FAIL line per arm
# is printed, and the exit code is non-zero when any arm fails.
#
# DATABASE_URL must name a THROWAWAY Postgres the test harness may create
# databases on (every #[sqlx::test] creates and drops its own, migrated from
# empty). It is refused, like every DSN in this directory (dsn-guard.sh),
# when it names no explicit port, the production port 5432, or no host.
#
# The cold samples are a fresh pool, server and client per sample inside one
# process, not a fresh process: see the plan,
# docs/superpowers/plans/2026-11-13-atlas-w12-latency-gate-plan.md.
set -uo pipefail

OUT="${1:?usage: probe-atlas-latency.sh <report dir> [small|full|<theme count>]}"
SCALE="${2:-full}"
: "${DATABASE_URL:?set DATABASE_URL to a throwaway Postgres the harness may create databases on}"

E2E="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$E2E/../.." && pwd)"
# The guard reads E2E_SU_DSN / E2E_APP_DSN; both name DATABASE_URL here.
E2E_SU_DSN="$DATABASE_URL"
E2E_APP_DSN="$DATABASE_URL"
# shellcheck source=dsn-guard.sh
. "$E2E/dsn-guard.sh"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
rc_all=0

arm() {
  local name="$1" rc="$2" report="$3"
  if [ "$rc" -eq 0 ]; then
    echo "ATLAS-LATENCY-$name PASS report=$report"
  else
    echo "ATLAS-LATENCY-$name FAIL rc=$rc report=$report"
    rc_all=1
  fi
}

# KERNEL: one test thread, so no other test competes for the database.
(
  cd "$ROOT" &&
    ATLAS_LATENCY_SCALE="$SCALE" ATLAS_LATENCY_REPORT="$OUT/kernel.json" \
      cargo test --release --locked -p epigraph-api --test atlas_latency_gate \
      -- --test-threads=1 --nocapture
)
arm KERNEL "$?" "$OUT/kernel.json"

# BFF
(
  cd "$ROOT/services/explorer" &&
    ATLAS_LATENCY_BFF_REPORT="$OUT/bff.json" \
      cargo test --release --locked --test atlas_latency -- --test-threads=1 --nocapture
)
arm BFF "$?" "$OUT/bff.json"

# BROWSER (opt-in)
if [ "${ATLAS_LATENCY_BROWSER:-0}" = "1" ]; then
  port="${ATLAS_LATENCY_PREVIEW_PORT:-18097}"
  (cd "$ROOT/services/explorer" && cargo build --release --locked --bin epigraph-explorer) || exit 1
  bin="$(cd "$ROOT/services/explorer" && cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/epigraph-explorer"
  "$bin" --atlas-fixture-preview "127.0.0.1:$port" >"$OUT/preview.log" 2>&1 &
  preview=$!
  # Stop only the preview this script started.
  trap 'kill "$preview" 2>/dev/null' EXIT
  for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1 && break
    sleep 0.2
  done
  ATLAS_LATENCY_BROWSER_REPORT="$OUT/browser.json" \
    node "$E2E/atlas-latency-browser.mjs" "http://127.0.0.1:$port" "${ATLAS_LATENCY_BROWSER_ROUNDS:-5}"
  arm BROWSER "$?" "$OUT/browser.json"
else
  echo "ATLAS-LATENCY-BROWSER SKIPPED (set ATLAS_LATENCY_BROWSER=1; needs node and playwright)"
fi

exit "$rc_all"
