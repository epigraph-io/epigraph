#!/usr/bin/env bash
#
# verify.sh — local / agent pre-commit gate.
#
# Runs the cargo steps of the CI `lint` and `test` jobs (see
# .github/workflows/ci.yml), so `cargo build` + `cargo test` alone don't let a
# formatting or lint failure slip through to CI. KEEP THIS IN SYNC WITH ci.yml.
#
# What it runs, in CI's terms:
#   lint job: fmt, workspace clippy, the no-db check, the genai clippy pair,
#             the tls clippy and the two tls tests (none needs a database);
#   test job: build, then (only with DATABASE_URL) the non-DB workspace tests
#             and each DB package on its own, with CI's excludes and thread
#             counts.
# What it does NOT run: CI's `Run migrations` step (bring your own migrated
# test database, see below), the purge of linked test executables between test
# steps, and the kanban, python, audit and secrets jobs.
#
# Usage:
#   ./scripts/verify.sh            # the lint steps + build (+ the test steps if DATABASE_URL is set),
#                                  # then the standalone services/explorer crate (always)
#   DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/<testdb> ./scripts/verify.sh
#
# The DB-backed (#[sqlx::test]) tests require a reachable Postgres; they are run
# only when DATABASE_URL is set (CI provides a postgres service). Without it,
# the static gates that local dev most often forgets — fmt + clippy — still run.
#
# <testdb> must be a DISPOSABLE database — a name matching `_sqlx_test*` or
# `*_test` (e.g. epigraph_db_repo_test). Some fixtures DROP
# uq_claims_content_hash_agent and run a table-wide dedup DELETE on `claims`;
# pointing DATABASE_URL at a long-lived graph is what silently removed that
# constraint from the deployed schema. Those fixtures now panic rather than
# mutate an unrecognised database. Override with EPIGRAPH_TEST_DESTRUCTIVE_DB=1
# only when you are certain the target is throwaway.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

step() { printf '\n==> %s\n' "$*"; }

step "cargo fmt --check"
cargo fmt --check

# --all-targets is load-bearing: without it cargo lints only lib+bin targets,
# leaving tests/, examples/ and benches/ completely unlinted. Keep in sync with
# the Clippy step in ci.yml.
step "cargo clippy --workspace --all-targets --locked -- -D warnings"
cargo clippy --workspace --all-targets --locked -- -D warnings

# The feature-gated checks of the CI `lint` job. No other step compiles the
# no-db variant of epigraph-api or the off-by-default `genai` and `tls`
# features, so without these a change passes here and fails CI.
step "cargo check -p epigraph-api --no-default-features --locked"
cargo check -p epigraph-api --no-default-features --locked

# One invocation per package, as in ci.yml: a combined `-p a -p b` run unifies
# features and can hide a break that only one package alone shows.
for pkg in epigraph-api epigraph-cli; do
  step "cargo clippy -p ${pkg} --features genai --all-targets --locked -- -D warnings"
  cargo clippy -p "${pkg}" --features genai --all-targets --locked -- -D warnings
done

step "cargo clippy -p epigraph-api --features tls --all-targets --locked -- -D warnings"
cargo clippy -p epigraph-api --features tls --all-targets --locked -- -D warnings

step "cargo test -p epigraph-api --features tls --locked --test tls_pem_loading --test tls_provider_choice"
cargo test -p epigraph-api --features tls --locked --test tls_pem_loading --test tls_provider_choice

step "cargo build --workspace --locked"
cargo build --workspace --locked

if [ -n "${DATABASE_URL:-}" ]; then
  # The packages with #[sqlx::test] or live-DB tests are excluded here and run
  # one at a time below, as in ci.yml (they race on _sqlx_migrations when run
  # together, and running them here as well ran each of them twice).
  step "cargo test --workspace --locked (non-DB packages)"
  cargo test --workspace --locked \
    --exclude epigraph-db \
    --exclude epigraph-api \
    --exclude epigraph-engine \
    --exclude epigraph-mcp \
    --exclude epigraph-embeddings

  # epigraph-db is cleared to run 4 tests at a time; the explicit flag is what
  # overrides RUST_TEST_THREADS=1 from .cargo/config.toml.
  step "cargo test -p epigraph-db --locked -- --test-threads=4"
  cargo test -p epigraph-db --locked -- --test-threads=4

  # The rest serialize within each binary (CI does the same).
  for pkg in epigraph-api epigraph-engine epigraph-mcp epigraph-embeddings; do
    step "cargo test -p ${pkg} --locked -- --test-threads=1"
    cargo test -p "${pkg}" --locked -- --test-threads=1
  done
else
  step "SKIP tests — set DATABASE_URL to run the workspace + DB-backed suites"
fi

# services/explorer is a standalone crate (its own [workspace], Cargo.lock and
# target/), so none of the --workspace commands above reach it. Mirrors the
# `test` job in .github/workflows/explorer.yml — KEEP THIS IN SYNC WITH IT TOO.
# Its tests stub the API with wiremock and need no database, so they always run.
explorer() { (cd services/explorer && "$@"); }

step "services/explorer: cargo fmt --check"
explorer cargo fmt --check

step "services/explorer: cargo clippy --all-targets --locked -- -D warnings"
explorer cargo clippy --all-targets --locked -- -D warnings

step "services/explorer: cargo test --locked"
explorer cargo test --locked

step "services/explorer: cargo build --release --locked"
explorer cargo build --release --locked

printf '\n\xE2\x9C\x85 verify passed\n'
