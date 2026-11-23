#!/usr/bin/env bash
# Blocking check: no build of this workspace compiles SQLite.
#
# .cargo/audit.toml ignores RUSTSEC-2026-0459 (libsqlite3-sys < 0.39) on the
# condition that SQLite is NEVER COMPILED: libsqlite3-sys is in Cargo.lock only
# as an optional dependency of sqlx-sqlite, which nothing enables. Once the ID
# is ignored, `cargo audit` is silent if that breaks. The Rust ratchet
# crates/epigraph-auth/tests/sqlite_never_compiled.rs scans the workspace
# manifests and Cargo.lock, which cannot show a crate that is not a workspace
# member enabling sqlx's `sqlite` feature in its own manifest (the lockfile
# records no features). This check asks cargo for the resolved, feature-unified
# graph instead, so it sees that case. It needs the registry (network or a warm
# cache), which is why it is a CI step and not a test.
#
# It lists every package any workspace member can compile (--all-features,
# every target, normal + build + dev edges) and fails when one is
# libsqlite3-sys, sqlx-sqlite or rusqlite. It parses package lines, not cargo's
# warnings, and requires the control crate sqlx-postgres to be present, so an
# invocation that stopped listing the real graph fails instead of passing.
#
# Usage: .github/scripts/sqlite-never-compiled.sh [path/to/Cargo.toml]
# Exit: 0 clean; 1 SQLite is compiled; 2 cargo failed or the graph is vacuous.
set -uo pipefail

manifest=${1:-Cargo.toml}
sqlite='^(libsqlite3-sys|sqlx-sqlite|rusqlite) v'
control='^sqlx-postgres v'
tree_args=(--manifest-path "$manifest" --workspace --locked --all-features
  --target all --edges normal,build,dev --charset ascii)

if ! graph=$(cargo tree "${tree_args[@]}" --prefix none); then
  echo "sqlite-never-compiled: cargo tree failed (see above) -- refusing to pass" >&2
  exit 2
fi

# Here-strings, not `printf | grep -q`: under pipefail, grep -q exiting at the
# first match makes printf die of SIGPIPE on a large graph, and the pipeline
# reports failure for a line that IS there.
crates=$(grep -E "$sqlite" <<<"$graph" | cut -d' ' -f1 | sort -u)
if [ -n "$crates" ]; then
  echo "sqlite-never-compiled: SQLite is compiled into this workspace:" >&2
  sed 's/^/  /' <<<"$crates" >&2
  echo "RUSTSEC-2026-0459 is ignored in .cargo/audit.toml only while SQLite is never compiled;" >&2
  echo "drop the dependency or re-triage that entry. What enables it:" >&2
  for crate in $crates; do
    cargo tree "${tree_args[@]}" --invert "$crate" --edges features >&2 || true
  done
  exit 1
fi

if ! grep -qE "$control" <<<"$graph"; then
  echo "sqlite-never-compiled: the graph has no sqlx-postgres -- the check would be vacuous; refusing to pass" >&2
  exit 2
fi
echo "sqlite-never-compiled: no libsqlite3-sys, sqlx-sqlite or rusqlite in the resolved graph ($(sort -u <<<"$graph" | wc -l) distinct lines)"
