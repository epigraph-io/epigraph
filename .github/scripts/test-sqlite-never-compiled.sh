#!/usr/bin/env bash
# Self-test for the CI dependency-graph check that SQLite is never compiled:
# .github/scripts/sqlite-never-compiled.sh (the blocking ratchet behind the
# RUSTSEC-2026-0459 ignore in .cargo/audit.toml).
#
# Builds throwaway cargo workspaces OUTSIDE this repository (a crate under the
# repo root would join the epigraph workspace) and asserts that the check:
#   1. clean       — passes a workspace whose sqlx is postgres-only;
#   2. third-party — fails when a crate that is NOT a workspace member enables
#                    sqlx's `sqlite` feature in its own manifest. This is the
#                    case crates/epigraph-auth/tests/sqlite_never_compiled.rs
#                    cannot see: the lockfile records no features, and the
#                    manifest scan reads workspace members only;
#   3. dev-only    — fails when that crate is only a dev-dependency (tests
#                    compile SQLite too);
#   4. vacuous     — exits 2, not 0, when the graph lacks the control crate
#                    (sqlx-postgres), so a cargo invocation that stopped
#                    listing the real graph cannot pass silently.
#
# Needs cargo and network access to crates.io (it resolves sqlx 0.8).
# Usage: .github/scripts/test-sqlite-never-compiled.sh
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
check="$repo_root/.github/scripts/sqlite-never-compiled.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

# The non-member crate a third-party dependency stands for: it asks sqlx for
# the `sqlite` feature in its own manifest.
mkdir -p "$work/thirdparty/src"
cat > "$work/thirdparty/Cargo.toml" <<'TOML'
[package]
name = "thirdparty"
version = "0.1.0"
edition = "2021"

[dependencies]
sqlx = { version = "0.8", default-features = false, features = ["sqlite"] }
TOML
: > "$work/thirdparty/src/lib.rs"

# new_ws <name> <extra [dependencies] lines> <extra [dev-dependencies] lines>
new_ws() {
  local dir="$work/$1"
  mkdir -p "$dir/app/src"
  printf '[workspace]\nmembers = ["app"]\nresolver = "2"\n' > "$dir/Cargo.toml"
  cat > "$dir/app/Cargo.toml" <<TOML
[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
$2

[dev-dependencies]
$3
TOML
  : > "$dir/app/src/lib.rs"
  cargo generate-lockfile --quiet --manifest-path "$dir/Cargo.toml"
  echo "$dir/Cargo.toml"
}

# expect <name> <expected rc> <manifest>
expect() {
  local name=$1 want=$2 manifest=$3 rc=0
  "$check" "$manifest" > "$work/$name.log" 2>&1 || rc=$?
  if [ "$rc" -eq "$want" ]; then
    echo "ok   $name (rc=$rc)"
  else
    echo "FAIL $name: expected rc=$want, got rc=$rc"
    sed 's/^/     | /' "$work/$name.log"
    failures=$((failures + 1))
  fi
}

postgres='sqlx = { version = "0.8", default-features = false, features = ["postgres"] }'
third='thirdparty = { path = "../../thirdparty" }'

expect clean 0 "$(new_ws clean "$postgres" "")"
expect third-party 1 "$(new_ws third "$postgres
$third" "")"
expect dev-only 1 "$(new_ws dev "$postgres" "$third")"
expect vacuous 2 "$(new_ws bare "" "")"

# A failure must name the crate that compiles SQLite.
if ! grep -q 'libsqlite3-sys' "$work/third-party.log"; then
  echo "FAIL third-party: the failure does not name libsqlite3-sys"
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo "test-sqlite-never-compiled: $failures failure(s)"
  exit 1
fi
echo "test-sqlite-never-compiled: all cases passed"
