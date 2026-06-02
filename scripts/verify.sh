#!/usr/bin/env bash
#
# verify.sh — local / agent pre-commit gate.
#
# Runs the same static checks the CI `test` job enforces (see
# .github/workflows/ci.yml), so `cargo build` + `cargo test` alone don't let a
# formatting or lint failure slip through to CI. KEEP THIS IN SYNC WITH ci.yml.
#
# Usage:
#   ./scripts/verify.sh            # fmt + clippy + build (+ workspace tests if DATABASE_URL is set)
#   DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/<testdb> ./scripts/verify.sh
#
# The DB-backed (#[sqlx::test]) tests require a reachable Postgres; they are run
# only when DATABASE_URL is set (CI provides a postgres service). Without it,
# the static gates that local dev most often forgets — fmt + clippy — still run.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

step() { printf '\n==> %s\n' "$*"; }

step "cargo fmt --check"
cargo fmt --check

step "cargo clippy --workspace --locked -- -D warnings"
cargo clippy --workspace --locked -- -D warnings

step "cargo build --workspace --locked"
cargo build --workspace --locked

if [ -n "${DATABASE_URL:-}" ]; then
  step "cargo test --workspace --locked"
  cargo test --workspace --locked

  # DB crates use #[sqlx::test]; serialize within each binary (CI does the same).
  for pkg in epigraph-db epigraph-api epigraph-engine epigraph-mcp; do
    step "cargo test -p ${pkg} --locked -- --test-threads=1"
    cargo test -p "${pkg}" --locked -- --test-threads=1
  done
else
  step "SKIP tests — set DATABASE_URL to run the workspace + DB-backed suites"
fi

printf '\n\xE2\x9C\x85 verify passed\n'
